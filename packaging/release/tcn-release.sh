#!/usr/bin/env bash
# TCN release signing (PQ-REL; pq.md PQ-4, review 0007 AP-19, OPERATIONS §9).
#
# Two standard detached signatures over SHA256SUMS, both required:
#   SHA256SUMS.slhdsa.sig   SLH-DSA-SHA2-128s (FIPS 205), 7856 bytes
#   SHA256SUMS.ed25519.sig  Ed25519ctx (RFC 8032), 64 bytes
# both with the context string "TCN release SHA256SUMS v1", so that neither key's signature can
# be replayed from any other use. Everything is done by OpenSSL >= 3.5: no zt-* binary signs or
# verifies a release, and no SLH-DSA code enters the shipped binaries.
#
#   tcn-release.sh keygen DIR            new key pairs in DIR (offline machine only)
#   tcn-release.sh fingerprint DIR       SHA-256 of each public key, to publish out of band
#   tcn-release.sh sign DIR SHA256SUMS   writes SHA256SUMS.slhdsa.sig and SHA256SUMS.ed25519.sig
#   tcn-release.sh verify DIR SHA256SUMS [SIGDIR]
#                                        both signatures, against the public keys in DIR
#
# Needs bash and GNU coreutils (Linux). OPENSSL names the openssl binary (default: openssl on
# PATH). The private keys never leave the offline machine and never reach CI.

set -euo pipefail

: "${OPENSSL:=openssl}"
readonly CONTEXT="TCN release SHA256SUMS v1"
readonly SLH_KEY=release-slhdsa.key.pem SLH_PUB=release-slhdsa.pub.pem
readonly ED_KEY=release-ed25519.key.pem ED_PUB=release-ed25519.pub.pem
readonly SLH_SIG_LEN=7856 ED_SIG_LEN=64
readonly SUMS_LINE='^[0-9a-f]{64}  (tcn-v[0-9A-Za-z._+-]+\.tar\.gz)$'

die() {
  printf 'tcn-release: %s\n' "$*" >&2
  exit 1
}

# OpenSSL >= 3.5, the first with SLH-DSA: an older one must never be taken for a verifier.
need_openssl() {
  local version major minor
  version=$("$OPENSSL" version 2>/dev/null) || die "cannot run $OPENSSL (set OPENSSL)"
  [[ $version =~ ^OpenSSL\ ([0-9]+)\.([0-9]+)\. ]] || die "not OpenSSL: $version"
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  if ((major < 3 || (major == 3 && minor < 5))); then
    die "$version has no SLH-DSA: OpenSSL 3.5 or later is required"
  fi
  "$OPENSSL" list -signature-algorithms 2>/dev/null | grep -q 'SLH-DSA-SHA2-128s' ||
    die "$version does not offer SLH-DSA-SHA2-128s"
}

# The algorithm of a public key, as OpenSSL names it on the first line of -text_pub.
key_is() {
  local pub=$1 want=$2
  "$OPENSSL" pkey -pubin -in "$pub" -text_pub -noout 2>/dev/null | head -n1 | grep -qi -- "$want"
}

file_size() { stat -c %s -- "$1"; }

# SHA256SUMS as the release workflow writes it: "<64 lower-case hex>  tcn-v<...>.tar.gz", one
# per line, LF only, no paths, no duplicates, at least one.
check_sums() {
  local sums=$1 line name names=() n
  [ -s "$sums" ] || die "$sums is empty"
  if LC_ALL=C grep -q $'\r' "$sums"; then die "$sums has CR line ends"; fi
  [ "$(tail -c1 "$sums" | od -An -c | tr -d ' ')" = '\n' ] || die "$sums does not end with a newline"
  while IFS= read -r line; do
    [[ $line =~ $SUMS_LINE ]] ||
      die "$sums: malformed line: ${line:0:120}"
    name=${BASH_REMATCH[1]}
    for n in "${names[@]}"; do
      [ "$n" != "$name" ] || die "$sums: $name appears twice"
    done
    names+=("$name")
  done <"$sums"
}

cmd_keygen() {
  local dir=${1:?usage: keygen DIR}
  need_openssl
  for f in "$SLH_KEY" "$ED_KEY" "$SLH_PUB" "$ED_PUB"; do
    [ ! -e "$dir/$f" ] || die "$dir/$f exists: never overwritten"
  done
  (
    umask 077
    mkdir -p "$dir"
    "$OPENSSL" genpkey -algorithm SLH-DSA-SHA2-128s -out "$dir/$SLH_KEY"
    "$OPENSSL" genpkey -algorithm ED25519 -out "$dir/$ED_KEY"
  )
  chmod 0600 "$dir/$SLH_KEY" "$dir/$ED_KEY"
  "$OPENSSL" pkey -in "$dir/$SLH_KEY" -pubout -out "$dir/$SLH_PUB"
  "$OPENSSL" pkey -in "$dir/$ED_KEY" -pubout -out "$dir/$ED_PUB"
  chmod 0644 "$dir/$SLH_PUB" "$dir/$ED_PUB"
  cmd_fingerprint "$dir"
}

cmd_fingerprint() {
  local dir=${1:?usage: fingerprint DIR}
  local slh ed
  slh=$("$OPENSSL" pkey -pubin -in "$dir/$SLH_PUB" -outform DER | sha256sum | cut -d' ' -f1)
  ed=$("$OPENSSL" pkey -pubin -in "$dir/$ED_PUB" -outform DER | sha256sum | cut -d' ' -f1)
  printf 'slh-dsa-sha2-128s sha256:%s\ned25519 sha256:%s\n' "$slh" "$ed"
}

cmd_sign() {
  local dir=${1:?usage: sign DIR FILE} file=${2:?usage: sign DIR FILE}
  need_openssl
  local k
  for k in "$dir/$SLH_KEY" "$dir/$ED_KEY"; do
    [ -f "$k" ] || die "$k: no such private key"
    [ "$(stat -c %a -- "$k")" = 600 ] || die "$k is readable by others: chmod 0600 it first"
  done
  key_is "$dir/$SLH_PUB" SLH-DSA-SHA2-128s || die "$dir/$SLH_PUB is not an SLH-DSA-SHA2-128s key"
  key_is "$dir/$ED_PUB" ED25519 || die "$dir/$ED_PUB is not an Ed25519 key"
  "$OPENSSL" pkeyutl -sign -rawin -inkey "$dir/$SLH_KEY" -in "$file" \
    -out "$file.slhdsa.sig" -pkeyopt "context-string:$CONTEXT"
  "$OPENSSL" pkeyutl -sign -rawin -inkey "$dir/$ED_KEY" -in "$file" \
    -out "$file.ed25519.sig" -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$CONTEXT"
  [ "$(file_size "$file.slhdsa.sig")" = "$SLH_SIG_LEN" ] || die "unexpected SLH-DSA signature size"
  [ "$(file_size "$file.ed25519.sig")" = "$ED_SIG_LEN" ] || die "unexpected Ed25519 signature size"
  # Verify after sign, with the public keys that will be published.
  verify_one slh "$dir/$SLH_PUB" "$file" "$file.slhdsa.sig"
  verify_one ed "$dir/$ED_PUB" "$file" "$file.ed25519.sig"
  printf 'signed %s: %s.slhdsa.sig %s.ed25519.sig\n' "$file" "$file" "$file"
}

verify_one() {
  local kind=$1 pub=$2 file=$3 sig=$4
  case $kind in
    slh)
      "$OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$pub" -in "$file" -sigfile "$sig" \
        -pkeyopt "context-string:$CONTEXT" >/dev/null 2>&1 ||
        die "$sig: SLH-DSA signature INVALID"
      ;;
    ed)
      "$OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$pub" -in "$file" -sigfile "$sig" \
        -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$CONTEXT" >/dev/null 2>&1 ||
        die "$sig: Ed25519 signature INVALID"
      ;;
  esac
}

cmd_verify() {
  local dir=${1:?usage: verify DIR SHA256SUMS [SIGDIR]} sums=${2:?usage: verify DIR SHA256SUMS [SIGDIR]}
  local sigdir=${3:-$(dirname -- "$sums")}
  local base slh_sig ed_sig
  need_openssl
  base=$(basename -- "$sums")
  slh_sig="$sigdir/$base.slhdsa.sig"
  ed_sig="$sigdir/$base.ed25519.sig"
  [ -f "$dir/$SLH_PUB" ] || die "$dir/$SLH_PUB: no SLH-DSA public key"
  [ -f "$dir/$ED_PUB" ] || die "$dir/$ED_PUB: no Ed25519 public key"
  key_is "$dir/$SLH_PUB" SLH-DSA-SHA2-128s || die "$dir/$SLH_PUB is not an SLH-DSA-SHA2-128s key"
  key_is "$dir/$ED_PUB" ED25519 || die "$dir/$ED_PUB is not an Ed25519 key"
  check_sums "$sums"
  # Both signatures, always (AP-19): a missing one is a failure, never a skip.
  [ -f "$slh_sig" ] || die "$slh_sig: missing (both signatures are required)"
  [ -f "$ed_sig" ] || die "$ed_sig: missing (both signatures are required)"
  [ "$(file_size "$slh_sig")" = "$SLH_SIG_LEN" ] || die "$slh_sig: not a $SLH_SIG_LEN-byte SLH-DSA-SHA2-128s signature"
  [ "$(file_size "$ed_sig")" = "$ED_SIG_LEN" ] || die "$ed_sig: not a $ED_SIG_LEN-byte Ed25519 signature"
  verify_one slh "$dir/$SLH_PUB" "$sums" "$slh_sig"
  verify_one ed "$dir/$ED_PUB" "$sums" "$ed_sig"
  printf 'OK: %s signed by both release keys\n' "$sums"
  cmd_fingerprint "$dir"
}

case ${1:-} in
  keygen) shift; cmd_keygen "$@" ;;
  fingerprint) shift; cmd_fingerprint "$@" ;;
  sign) shift; cmd_sign "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  *) die "usage: tcn-release.sh keygen|fingerprint|sign|verify ..." ;;
esac
