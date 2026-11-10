#!/usr/bin/env bash
# PQ-REL attacks (pq.md PQ-4 catalogue, review 0007 AP-19): stripping one of the two
# signatures, tampering with SHA256SUMS, signatures of another key, artefact or context,
# malformed checksum files, an OpenSSL without SLH-DSA, and private keys left readable.
#
#   OPENSSL=/path/to/openssl-3.5 packaging/release/tests/attacks.sh

# shellcheck source=packaging/release/tests/lib.sh
source "$(dirname "$0")/lib.sh"

rel="$work/rel"
signed_release "$rel" || true
mkdir -p "$rel/pub"
cp "$rel/keys/"*.pub.pem "$rel/pub/" 2>/dev/null || true

# A copy of the signed release in a fresh directory, to damage one thing at a time.
fresh() {
  local dir="$work/$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp -r "$rel/pub" "$dir/pub" 2>/dev/null || true
  cp "$rel/SHA256SUMS" "$rel"/SHA256SUMS.*.sig "$dir/" 2>/dev/null || true
  printf '%s' "$dir"
}

expect_ok "the untouched release verifies (control)" "$tool" verify --pins "$rel/pins" "$rel/pub" "$rel/SHA256SUMS"

# --- AP-19: both signatures are required --------------------------------------------------
d=$(fresh strip-slh)
rm -f "$d/SHA256SUMS.slhdsa.sig"
expect_refused "the SLH-DSA signature stripped: refused" 'missing \(both signatures are required\)' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh strip-ed)
rm -f "$d/SHA256SUMS.ed25519.sig"
expect_refused "the Ed25519 signature stripped: refused" 'missing \(both signatures are required\)' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh empty-slh)
: >"$d/SHA256SUMS.slhdsa.sig"
expect_refused "an empty SLH-DSA signature: refused" 'not a 7856-byte' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh no-slh-key)
rm -f "$d/pub/release-slhdsa.pub.pem"
expect_refused "the SLH-DSA public key missing: refused" 'no SLH-DSA public key' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
expect_refused "no public keys at all: refused" 'no SLH-DSA public key' "$tool" verify --pins "$rel/pins" "$work/nowhere" "$rel/SHA256SUMS"

# --- tampering ------------------------------------------------------------------------------
d=$(fresh tamper)
first=$(head -c1 "$d/SHA256SUMS" 2>/dev/null || true)
if [ "$first" = 0 ]; then sed -i '1s/^./1/' "$d/SHA256SUMS"; else sed -i '1s/^./0/' "$d/SHA256SUMS"; fi
expect_refused "a changed checksum: refused" 'signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh append)
printf '%s  %s\n' "$(printf c | sha256sum | cut -d' ' -f1)" "tcn-v1.2.3-evil.tar.gz" >>"$d/SHA256SUMS"
expect_refused "an appended archive: refused" 'signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh swap)
mv "$d/SHA256SUMS.slhdsa.sig" "$d/tmp.sig" 2>/dev/null || true
mv "$d/SHA256SUMS.ed25519.sig" "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
mv "$d/tmp.sig" "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_refused "swapped signature files: refused" 'not a (7856|64)-byte' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh truncate)
head -c 7855 "$rel/SHA256SUMS.slhdsa.sig" >"$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
expect_refused "a truncated SLH-DSA signature: refused" 'not a 7856-byte' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh flip)
# A real flip (XOR 1): writing a fixed byte was no change when the signature already had it.
b=$(od -An -tu1 -j100 -N1 "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null | tr -d ' ' || true)
# shellcheck disable=SC2059 # the format is the octal escape of the flipped byte
printf "\\$(printf '%03o' $((${b:-0} ^ 1)))" |
  dd of="$d/SHA256SUMS.slhdsa.sig" bs=1 seek=100 conv=notrunc status=none 2>/dev/null || true
expect_refused "a bit flipped in the SLH-DSA signature: refused" 'SLH-DSA signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"

# --- identity: wrong key, wrong artefact, wrong context ------------------------------------
other="$work/other"
signed_release "$other" || true
d=$(fresh other-key)
cp "$other/SHA256SUMS.slhdsa.sig" "$d/" 2>/dev/null || true
cp "$other/SHA256SUMS" "$d/SHA256SUMS" 2>/dev/null || true
cp "$rel/SHA256SUMS.ed25519.sig" "$d/" 2>/dev/null || true
expect_refused "an SLH-DSA signature by another key: refused" 'SLH-DSA signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh other-pub)
cp "$other/keys/release-ed25519.pub.pem" "$d/pub/" 2>/dev/null || true
expect_refused "verified against another Ed25519 key: refused" 'not pinned' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh wrong-alg)
cp "$rel/pub/release-ed25519.pub.pem" "$d/pub/release-slhdsa.pub.pem" 2>/dev/null || true
expect_refused "an Ed25519 key in the SLH-DSA slot: refused" 'is not an SLH-DSA-SHA2-128s key' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh no-context)
"$OPENSSL" pkeyutl -sign -rawin -inkey "$rel/keys/release-slhdsa.key.pem" -in "$d/SHA256SUMS" \
  -out "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
expect_refused "an SLH-DSA signature without the release context: refused" 'SLH-DSA signature INVALID' \
  "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh plain-ed)
"$OPENSSL" pkeyutl -sign -rawin -inkey "$rel/keys/release-ed25519.key.pem" -in "$d/SHA256SUMS" \
  -out "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_refused "a pure Ed25519 signature (no context): refused" 'Ed25519 signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"
d=$(fresh other-artefact)
printf 'not the checksums\n' >"$d/archive"
raw_sign "$rel/keys" "$d/archive"
cp "$d/archive.slhdsa.sig" "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
cp "$d/archive.ed25519.sig" "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_refused "signatures of another artefact: refused" 'signature INVALID' "$tool" verify --pins "$rel/pins" "$d/pub" "$d/SHA256SUMS"

# --- parsing of SHA256SUMS: a malformed file is refused even when validly signed -----------
malformed() {
  local name=$1 reason=$2 content=$3
  local d="$work/malformed-$name"
  rm -rf "$d"
  mkdir -p "$d"
  printf '%b' "$content" >"$d/SHA256SUMS"
  # `sign` refuses to sign it (A13-5); signed anyway, `verify` refuses it too.
  expect_refused "sign refuses a SHA256SUMS with $name" "$reason" "$tool" sign "$rel/keys" "$d/SHA256SUMS"
  raw_sign "$rel/keys" "$d/SHA256SUMS"
  expect_refused "a validly signed SHA256SUMS with $name: refused" "$reason" \
    "$tool" verify --pins "$rel/pins" "$rel/pub" "$d/SHA256SUMS"
}
h=$(printf a | sha256sum | cut -d' ' -f1)
h2=$(printf b | sha256sum | cut -d' ' -f1)
malformed "a path" "byte that is not allowed" "$h  ../tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "a directory" "byte that is not allowed" "$h  bin/tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "a short hash" "malformed line" "${h:1}  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "upper-case hex" "malformed line" "${h^^}  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "CRLF line ends" "byte that is not allowed" "$h  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\r\n"
malformed "CRLF and a path (A13-R1)" "byte that is not allowed" "$h  ../../etc/evil.tar.gz\r\n"
malformed "a duplicate name" "appears twice" "$h  tcn-v1.2.3-a.tar.gz\n$h  tcn-v1.2.3-a.tar.gz\n"
malformed "no entries" "is empty" ""
malformed "a foreign archive name" "malformed line" "$h  evil.sh\n"
malformed "no final newline" "newline" "$h  tcn-v1.2.3-a.tar.gz"
# A NUL byte, which bash's `read` drops: a second entry for the same archive (A13-R2).
malformed "a NUL byte hiding a duplicate (A13-R2)" "byte that is not allowed" \
  "$h  tcn-v1.2.3-a.tar.gz\n$h2  tcn-v1.2.3-a.tar.gz\0.tar.gz\n"
malformed "a tab" "byte that is not allowed" "$h\ttcn-v1.2.3-a.tar.gz\n"

# --- trust anchor: only pinned keys (A13-4) --------------------------------------------------
# An attacker who controls the download (or the tag) brings a consistent set: keys, SHA256SUMS
# and signatures. Verified against the pins, it is refused (A13-R3).
att="$work/attacker"
signed_release "$att" || true
mkdir -p "$att/pub"
cp "$att/keys/"*.pub.pem "$att/pub/" 2>/dev/null || true
expect_refused "a self-consistent attacker key set is refused against the pins (A13-R3)" 'not pinned' \
  "$tool" verify --pins "$rel/pins" "$att/pub" "$att/SHA256SUMS"
expect_refused "without --pins, keys not built into the script are refused" 'not pinned|no release key is pinned' \
  "$tool" verify "$rel/pub" "$rel/SHA256SUMS"
d=$(fresh half-pinned)
grep '^slh-dsa' "$rel/pins" >"$d/pins" || true
grep '^ed25519' "$att/pins" >>"$d/pins" || true
expect_refused "a pin file that pins only the SLH-DSA key refuses the Ed25519 key" 'not pinned' \
  "$tool" verify --pins "$d/pins" "$d/pub" "$d/SHA256SUMS"
printf 'ed25519 sha256:%s\n' "$(printf x | sha256sum | cut -d' ' -f1)" >"$work/bad-pins"
printf 'not a pin\n' >>"$work/bad-pins"
expect_refused "a malformed pin file is refused" 'pin' \
  "$tool" verify --pins "$work/bad-pins" "$rel/pub" "$rel/SHA256SUMS"
: >"$work/empty-pins"
expect_refused "an empty pin file pins nothing" 'no release key is pinned' \
  "$tool" verify --pins "$work/empty-pins" "$rel/pub" "$rel/SHA256SUMS"
expect_refused "--pins without a file is refused" 'usage|pins' "$tool" verify --pins
expect_refused "archives of another tag are refused with --tag" 'v9\.9\.9' \
  "$tool" verify --pins "$rel/pins" --tag v9.9.9 "$rel/pub" "$rel/SHA256SUMS"
expect_refused "an invalid --tag is refused" 'tag' \
  "$tool" verify --pins "$rel/pins" --tag 'v1;rm' "$rel/pub" "$rel/SHA256SUMS"

# --- tooling ------------------------------------------------------------------------------
fake="$work/fake-openssl"
cat >"$fake" <<'FAKE'
#!/bin/sh
if [ "$1" = version ]; then echo "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)"; exit 0; fi
exit 0
FAKE
chmod +x "$fake"
expect_refused "an OpenSSL older than 3.5 (that would 'verify' anything) is refused" 'OpenSSL 3.5 or later is required' \
  env OPENSSL="$fake" "$tool" verify --pins "$rel/pins" "$rel/pub" "$rel/SHA256SUMS"
expect_refused "keygen with an OpenSSL older than 3.5 is refused" 'OpenSSL 3.5 or later is required' \
  env OPENSSL="$fake" "$tool" keygen "$work/old-keys"

d="$work/loose-keys"
signed_release "$d" || true
chmod 0644 "$d/keys/release-slhdsa.key.pem" 2>/dev/null || true
expect_refused "sign refuses a private key readable by others" 'readable by others' "$tool" sign "$d/keys" "$d/SHA256SUMS"
expect_refused "an unknown subcommand fails" 'usage' "$tool" publish "$rel/pub"

summary
