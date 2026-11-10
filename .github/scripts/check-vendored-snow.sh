#!/usr/bin/env bash
# Checks that vendor/snow is the crates.io release of snow plus exactly the patches in
# vendor/patches/snow, and optionally runs the patched crate's own tests (finding A9-1 of
# review 0009).
#
# Usage: check-vendored-snow.sh [--test]
#
# 1. vendor/ holds only the directories this script and vendor/upstream-advisories cover.
# 2. The release is downloaded from static.crates.io and its SHA-256 must be the one pinned
#    here, in vendor/snow/PATCHES.md and in vendor/upstream-advisories/Cargo.lock.
# 3. The patches are applied in order, without fuzz; each must be listed in PATCHES.md.
# 4. The result, without the published Cargo.lock and plus PATCHES.md, must equal the files
#    git tracks under vendor/snow, byte for byte.
# 5. With --test: `cargo test --locked --features "hfs pqclean_kyber1024"` in the patched
#    release, with the published Cargo.lock as patched (upstream's HFS tests, Kyber1024).
set -euo pipefail

name=snow
version=0.10.0
sha256=599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82

root="$(git rev-parse --show-toplevel)"
cd "$root"
fail() {
  echo "::error::$*"
  exit 1
}

# 1. Every vendored crate needs this check and an advisory entry: a new one fails here.
expected_vendor="patches snow upstream-advisories"
actual_vendor="$(git ls-files vendor | cut -d/ -f2 | sort -u | tr '\n' ' ' | sed 's/ $//')"
[ "$actual_vendor" = "$expected_vendor" ] ||
  fail "vendor/ holds '$actual_vendor', expected '$expected_vendor': a new vendored crate needs its own identity and advisory check"
actual_patches="$(git ls-files vendor/patches | cut -d/ -f3 | sort -u | tr '\n' ' ' | sed 's/ $//')"
[ "$actual_patches" = "$name" ] || fail "vendor/patches holds '$actual_patches', expected '$name'"

# 2. One pinned hash, in every place that names it.
grep -qF "$sha256" vendor/snow/PATCHES.md || fail "vendor/snow/PATCHES.md does not pin $sha256"
grep -qF "version = \"=$version\"" vendor/upstream-advisories/Cargo.toml ||
  fail "vendor/upstream-advisories/Cargo.toml does not depend on $name =$version"
grep -A3 "^name = \"$name\"\$" vendor/upstream-advisories/Cargo.lock | grep -qF "checksum = \"$sha256\"" ||
  fail "vendor/upstream-advisories/Cargo.lock does not lock $name $version with checksum $sha256"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --proto '=https' --tlsv1.2 -sSfL --retry 3 \
  "https://static.crates.io/crates/$name/$name-$version.crate" -o "$work/release.crate"
echo "$sha256  $work/release.crate" | sha256sum --check --quiet ||
  fail "the downloaded $name-$version.crate does not have the pinned SHA-256"
mkdir "$work/release"
tar -xzf "$work/release.crate" -C "$work/release"
patched="$work/release/$name-$version"
[ -d "$patched" ] || fail "the release does not unpack to $name-$version/"

# 3. The patch series, exactly (no fuzz, no offset tolerance beyond `patch`'s line offsets).
shopt -s nullglob
patches=(vendor/patches/"$name"/*.patch)
[ "${#patches[@]}" -gt 0 ] || fail "no patch under vendor/patches/$name"
for p in "${patches[@]}"; do
  grep -qF "$(basename "$p")" vendor/snow/PATCHES.md || fail "$p is not listed in vendor/snow/PATCHES.md"
  patch --quiet --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 -d "$patched" <"$p" ||
    fail "$p does not apply to the pristine $name $version"
done

# 4. Compare with what git tracks (an ignored local Cargo.lock does not count).
expected="$work/expected"
cp -a "$patched" "$expected"
rm "$expected/Cargo.lock"
cp vendor/snow/PATCHES.md "$expected/PATCHES.md"
committed="$work/committed"
mkdir "$committed"
git ls-files -z vendor/snow | while IFS= read -r -d '' f; do
  mkdir -p "$committed/$(dirname "${f#vendor/snow/}")"
  cp -a "$f" "$committed/${f#vendor/snow/}"
done
if ! diff -r "$expected" "$committed"; then
  fail "vendor/snow is not $name $version plus the patches in vendor/patches/$name"
fi
echo "vendor/snow = $name $version ($sha256) + ${#patches[@]} patches"

# 5. Upstream's own tests on the patched release.
if [ "${1:-}" = "--test" ]; then
  (cd "$patched" && cargo test --locked --features "hfs pqclean_kyber1024")
fi
