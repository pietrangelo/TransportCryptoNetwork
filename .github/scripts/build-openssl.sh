#!/usr/bin/env bash
# Builds a pinned OpenSSL >= 3.5 (SLH-DSA) into PREFIX, for verifying release signatures
# (PQ-REL). The runners' system OpenSSL is 3.0, which has no SLH-DSA.
#
#   build-openssl.sh PREFIX
#
# The tarball is pinned by its SHA-256 (the value published next to it on the OpenSSL release
# page, cross-checked against the downloaded file when the pin was set).
set -euo pipefail

readonly VERSION=3.5.9
readonly SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
readonly URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"

prefix=${1:?usage: build-openssl.sh PREFIX}
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "$src/openssl.tar.gz" "$URL"
echo "$SHA256  $src/openssl.tar.gz" | sha256sum --check --strict -
tar -C "$src" -xzf "$src/openssl.tar.gz"
cd "$src/openssl-${VERSION}"
./Configure --prefix="$prefix" --libdir=lib no-shared no-tests no-docs >/dev/null
make -j"$(nproc)" >/dev/null
make install_sw >/dev/null
"$prefix/bin/openssl" version
