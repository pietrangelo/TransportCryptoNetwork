# Shared helpers of the PQ-REL release-signing tests (sourced, not run).
#
# OPENSSL must name an OpenSSL >= 3.5 (SLH-DSA). The tests generate throwaway keys in a
# temporary directory; no real release key is ever involved.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tool="$here/../tcn-release.sh"
: "${OPENSSL:=openssl}"
export OPENSSL

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

passed=0
failed=0

# The context string both signatures carry (domain separation from any other use of a key).
CONTEXT="TCN release SHA256SUMS v1"

pass() {
  passed=$((passed + 1))
  printf 'ok   %s\n' "$1"
}

fail() {
  failed=$((failed + 1))
  printf 'FAIL %s\n' "$1"
  if [ -f "$work/out" ]; then sed 's/^/     | /' "$work/out"; fi
}

# expect_ok NAME CMD...: CMD must succeed.
expect_ok() {
  local name=$1
  shift
  if "$@" >"$work/out" 2>&1; then pass "$name"; else fail "$name"; fi
}

# expect_fail NAME CMD...: CMD must fail (exit status not 0).
expect_fail() {
  local name=$1
  shift
  if "$@" >"$work/out" 2>&1; then fail "$name (succeeded)"; else pass "$name"; fi
}

# A SHA256SUMS like the release workflow's: two archives.
sample_sums() {
  printf '%s  %s\n' \
    "$(printf a | sha256sum | cut -d' ' -f1)" "tcn-v1.2.3-x86_64-unknown-linux-musl.tar.gz" \
    "$(printf b | sha256sum | cut -d' ' -f1)" "tcn-v1.2.3-aarch64-unknown-linux-musl.tar.gz"
}

# A fresh signed release in $1: keys/ (private and public), SHA256SUMS and its signatures.
signed_release() {
  local dir=$1
  mkdir -p "$dir"
  "$tool" keygen "$dir/keys" >/dev/null
  sample_sums >"$dir/SHA256SUMS"
  "$tool" sign "$dir/keys" "$dir/SHA256SUMS" >/dev/null
}

summary() {
  printf '\n%d passed, %d failed\n' "$passed" "$failed"
  [ "$failed" -eq 0 ]
}
