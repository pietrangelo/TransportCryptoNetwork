#!/usr/bin/env bash
# Fails if a libcrux build script enabled the NEON (`simd128`) backend (finding A8-6 of
# review 0008). Usage: check-libcrux-backend.sh <cargo build directory>, for example
# target/aarch64-unknown-linux-musl/release/build.
set -euo pipefail
dir="${1:?usage: check-libcrux-backend.sh <build dir>}"
shopt -s nullglob
outputs=("$dir"/libcrux-ml-kem-*/output "$dir"/libcrux-sha3-*/output "$dir"/libcrux-intrinsics-*/output)
if [ "${#outputs[@]}" -lt 3 ]; then
  echo "::error::libcrux build-script output not found under $dir"
  exit 1
fi
if grep -l 'simd128' "${outputs[@]}"; then
  echo "::error::a libcrux build script enabled the unverified NEON backend (simd128)"
  exit 1
fi
echo "libcrux backend ok: ${#outputs[@]} build-script outputs without simd128"
