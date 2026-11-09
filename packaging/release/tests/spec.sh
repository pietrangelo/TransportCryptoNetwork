#!/usr/bin/env bash
# PQ-REL specification (pq.md PQ-4, review 0007 AP-19): an offline SLH-DSA-SHA2-128s key and an
# Ed25519 key each sign SHA256SUMS with a standard detached signature; both are required, and
# OpenSSL >= 3.5 alone verifies them, never a downloaded zt-* binary.
#
#   OPENSSL=/path/to/openssl-3.5 packaging/release/tests/spec.sh

# shellcheck source=packaging/release/tests/lib.sh
source "$(dirname "$0")/lib.sh"

rel="$work/rel"
mkdir -p "$rel"

# --- keygen ---------------------------------------------------------------------------------
expect_ok "keygen creates the two key pairs" "$tool" keygen "$rel/keys"
for f in release-slhdsa.key.pem release-ed25519.key.pem release-slhdsa.pub.pem release-ed25519.pub.pem; do
  expect_ok "keygen wrote $f" test -s "$rel/keys/$f"
done
expect_ok "private keys are 0600" \
  test "$(stat -c %a "$rel/keys/release-slhdsa.key.pem") $(stat -c %a "$rel/keys/release-ed25519.key.pem")" = "600 600"
expect_ok "the SLH-DSA public key is SLH-DSA-SHA2-128s" \
  sh -c '"$OPENSSL" pkey -pubin -in "$1" -text_pub -noout | grep -q "SLH-DSA-SHA2-128s"' _ "$rel/keys/release-slhdsa.pub.pem"
expect_ok "the Ed25519 public key is Ed25519" \
  sh -c '"$OPENSSL" pkey -pubin -in "$1" -text_pub -noout | grep -qi "ED25519"' _ "$rel/keys/release-ed25519.pub.pem"
expect_fail "keygen never overwrites existing keys" "$tool" keygen "$rel/keys"

# --- fingerprint ----------------------------------------------------------------------------
fp_of() { "$OPENSSL" pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || true; }
expected="slh-dsa-sha2-128s sha256:$(fp_of "$rel/keys/release-slhdsa.pub.pem")
ed25519 sha256:$(fp_of "$rel/keys/release-ed25519.pub.pem")"
expect_ok "fingerprint prints the SHA-256 of each DER public key" \
  test "$("$tool" fingerprint "$rel/keys")" = "$expected"

# --- sign -----------------------------------------------------------------------------------
sample_sums >"$rel/SHA256SUMS"
expect_ok "sign writes both detached signatures" "$tool" sign "$rel/keys" "$rel/SHA256SUMS"
expect_ok "the SLH-DSA-SHA2-128s signature is 7856 bytes" \
  test "$(stat -c %s "$rel/SHA256SUMS.slhdsa.sig")" = 7856
expect_ok "the Ed25519 signature is 64 bytes" \
  test "$(stat -c %s "$rel/SHA256SUMS.ed25519.sig")" = 64

# --- verify ---------------------------------------------------------------------------------
# Only the public keys, as a user has them (from the repository at the release tag).
mkdir -p "$rel/pub"
cp "$rel/keys/"*.pub.pem "$rel/pub/" 2>/dev/null || true
expect_ok "verify accepts both signatures" "$tool" verify "$rel/pub" "$rel/SHA256SUMS"
expect_ok "verify accepts signatures from another directory" \
  sh -c 'mkdir -p "$1/sigs" && cp "$1"/SHA256SUMS.*.sig "$1/sigs/" && "$2" verify "$1/pub" "$1/SHA256SUMS" "$1/sigs"' _ "$rel" "$tool"

# AP-19: standard detached signatures that OpenSSL verifies with the documented commands,
# without this script (OPERATIONS §9).
expect_ok "OpenSSL alone verifies the SLH-DSA signature" \
  "$OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$rel/pub/release-slhdsa.pub.pem" \
  -in "$rel/SHA256SUMS" -sigfile "$rel/SHA256SUMS.slhdsa.sig" -pkeyopt "context-string:$CONTEXT"
expect_ok "OpenSSL alone verifies the Ed25519 signature" \
  "$OPENSSL" pkeyutl -verify -rawin -pubin -inkey "$rel/pub/release-ed25519.pub.pem" \
  -in "$rel/SHA256SUMS" -sigfile "$rel/SHA256SUMS.ed25519.sig" \
  -pkeyopt instance:Ed25519ctx -pkeyopt "context-string:$CONTEXT"

# The checksums still check the archives as before.
expect_ok "SHA256SUMS keeps the sha256sum format" \
  sh -c 'grep -Eq "^[0-9a-f]{64}  tcn-v1\.2\.3-x86_64-unknown-linux-musl\.tar\.gz$" "$1"' _ "$rel/SHA256SUMS"

summary
