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

expect_ok "the untouched release verifies (control)" "$tool" verify "$rel/pub" "$rel/SHA256SUMS"

# --- AP-19: both signatures are required --------------------------------------------------
d=$(fresh strip-slh)
rm -f "$d/SHA256SUMS.slhdsa.sig"
expect_fail "the SLH-DSA signature stripped: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh strip-ed)
rm -f "$d/SHA256SUMS.ed25519.sig"
expect_fail "the Ed25519 signature stripped: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh empty-slh)
: >"$d/SHA256SUMS.slhdsa.sig"
expect_fail "an empty SLH-DSA signature: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh no-slh-key)
rm -f "$d/pub/release-slhdsa.pub.pem"
expect_fail "the SLH-DSA public key missing: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
expect_fail "no public keys at all: refused" "$tool" verify "$work/nowhere" "$rel/SHA256SUMS"

# --- tampering ------------------------------------------------------------------------------
d=$(fresh tamper)
first=$(head -c1 "$d/SHA256SUMS" 2>/dev/null || true)
if [ "$first" = 0 ]; then sed -i '1s/^./1/' "$d/SHA256SUMS"; else sed -i '1s/^./0/' "$d/SHA256SUMS"; fi
expect_fail "a changed checksum: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh append)
printf '%s  %s\n' "$(printf c | sha256sum | cut -d' ' -f1)" "tcn-v1.2.3-evil.tar.gz" >>"$d/SHA256SUMS"
expect_fail "an appended archive: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh swap)
mv "$d/SHA256SUMS.slhdsa.sig" "$d/tmp.sig" 2>/dev/null || true
mv "$d/SHA256SUMS.ed25519.sig" "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
mv "$d/tmp.sig" "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_fail "swapped signature files: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh truncate)
head -c 7855 "$rel/SHA256SUMS.slhdsa.sig" >"$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
expect_fail "a truncated SLH-DSA signature: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh flip)
printf '\x01' | dd of="$d/SHA256SUMS.slhdsa.sig" bs=1 seek=100 conv=notrunc status=none 2>/dev/null || true
expect_fail "a bit flipped in the SLH-DSA signature: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"

# --- identity: wrong key, wrong artefact, wrong context ------------------------------------
other="$work/other"
signed_release "$other" || true
d=$(fresh other-key)
cp "$other/SHA256SUMS.slhdsa.sig" "$d/" 2>/dev/null || true
cp "$other/SHA256SUMS" "$d/SHA256SUMS" 2>/dev/null || true
cp "$rel/SHA256SUMS.ed25519.sig" "$d/" 2>/dev/null || true
expect_fail "an SLH-DSA signature by another key: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh other-pub)
cp "$other/keys/release-ed25519.pub.pem" "$d/pub/" 2>/dev/null || true
expect_fail "verified against another Ed25519 key: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh wrong-alg)
cp "$rel/pub/release-ed25519.pub.pem" "$d/pub/release-slhdsa.pub.pem" 2>/dev/null || true
expect_fail "an Ed25519 key in the SLH-DSA slot: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh no-context)
"$OPENSSL" pkeyutl -sign -rawin -inkey "$rel/keys/release-slhdsa.key.pem" -in "$d/SHA256SUMS" \
  -out "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
expect_fail "an SLH-DSA signature without the release context: refused" \
  "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh plain-ed)
"$OPENSSL" pkeyutl -sign -rawin -inkey "$rel/keys/release-ed25519.key.pem" -in "$d/SHA256SUMS" \
  -out "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_fail "a pure Ed25519 signature (no context): refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"
d=$(fresh other-artefact)
printf 'not the checksums\n' >"$d/archive"
"$tool" sign "$rel/keys" "$d/archive" >/dev/null 2>&1 || true
cp "$d/archive.slhdsa.sig" "$d/SHA256SUMS.slhdsa.sig" 2>/dev/null || true
cp "$d/archive.ed25519.sig" "$d/SHA256SUMS.ed25519.sig" 2>/dev/null || true
expect_fail "signatures of another artefact: refused" "$tool" verify "$d/pub" "$d/SHA256SUMS"

# --- parsing of SHA256SUMS: a malformed file is refused even when validly signed -----------
malformed() {
  local name=$1 content=$2
  local d="$work/malformed-$name"
  rm -rf "$d"
  mkdir -p "$d"
  printf '%b' "$content" >"$d/SHA256SUMS"
  "$tool" sign "$rel/keys" "$d/SHA256SUMS" >/dev/null 2>&1 || true
  expect_fail "a validly signed SHA256SUMS with $name: refused" "$tool" verify "$rel/pub" "$d/SHA256SUMS"
}
h=$(printf a | sha256sum | cut -d' ' -f1)
malformed "a path" "$h  ../tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "a directory" "$h  bin/tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "a short hash" "${h:1}  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "upper-case hex" "${h^^}  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\n"
malformed "CRLF line ends" "$h  tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz\r\n"
malformed "a duplicate name" "$h  tcn-v1.2.3-a.tar.gz\n$h  tcn-v1.2.3-a.tar.gz\n"
malformed "no entries" ""
malformed "a foreign archive name" "$h  evil.sh\n"

# --- tooling ------------------------------------------------------------------------------
fake="$work/fake-openssl"
cat >"$fake" <<'FAKE'
#!/bin/sh
if [ "$1" = version ]; then echo "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)"; exit 0; fi
exit 0
FAKE
chmod +x "$fake"
expect_fail "an OpenSSL older than 3.5 (that would 'verify' anything) is refused" \
  env OPENSSL="$fake" "$tool" verify "$rel/pub" "$rel/SHA256SUMS"
expect_fail "keygen with an OpenSSL older than 3.5 is refused" \
  env OPENSSL="$fake" "$tool" keygen "$work/old-keys"

d="$work/loose-keys"
signed_release "$d" || true
chmod 0644 "$d/keys/release-slhdsa.key.pem" 2>/dev/null || true
expect_fail "sign refuses a private key readable by others" "$tool" sign "$d/keys" "$d/SHA256SUMS"
expect_fail "an unknown subcommand fails" "$tool" publish "$rel/pub"

summary
