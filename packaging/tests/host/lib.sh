# shellcheck shell=bash disable=SC2034 # variables used by the scripts that source this file
# Shared helpers of the relay host-hardening tests (sourced, not run). See
# docs/analysis/relay-hardening.md §3.7 and §4 (rows F-*, K-*, U-*).
#
# The tests need root (network namespaces, nftables, systemd). They never change the host's
# own firewall or sysctls, except where a script says so behind an explicit variable
# (APPLY_SYSCTL=1, LOAD_HOST_RULESET=1): those are for the ephemeral CI runner only.
#
# STRICT=1 turns every skip (a kernel without IPv6, a missing tool) into a failure: CI sets it,
# so a check cannot silently stop running.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
unit="$repo/packaging/systemd/zt-relay.service"
ruleset="$repo/packaging/nftables/zt-relay.nft"
sysctl_conf="$repo/packaging/sysctl/90-zt-relay.conf"
modules_conf="$repo/packaging/sysctl/zt-relay.modules-load.conf"
pkt="$here/pkt.py"

work=$(mktemp -d)
cleanups=()
cleanup() {
  local i
  for ((i = ${#cleanups[@]} - 1; i >= 0; i--)); do eval "${cleanups[$i]}" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT
# on_exit CMD: run CMD (a string) when the script ends, in reverse order of registration.
on_exit() { cleanups+=("$1"); }

passed=0
failed=0
skipped=0

pass() {
  passed=$((passed + 1))
  printf 'ok   %s\n' "$1"
  # VERBOSE=1 shows what was measured: a pass for the wrong reason proves nothing.
  if [ -n "${VERBOSE:-}" ] && [ -s "$work/out" ]; then sed 's/^/     > /' "$work/out" | head -n 8; fi
}

fail() {
  failed=$((failed + 1))
  printf 'FAIL %s\n' "$1"
  if [ -s "$work/out" ]; then sed 's/^/     | /' "$work/out" | head -n 20; fi
}

skip() {
  : >"$work/out"
  if [ -n "${STRICT:-}" ]; then
    fail "$1 (skipped under STRICT: $2)"
  else
    skipped=$((skipped + 1))
    printf 'skip %s (%s)\n' "$1" "$2"
  fi
}

# check NAME CMD...: CMD must succeed; its output is shown on failure.
check() {
  local name=$1
  shift
  : >"$work/out"
  if "$@" >"$work/out" 2>&1; then pass "$name"; else fail "$name"; fi
}

# check_fails NAME CMD...: CMD must fail.
check_fails() {
  local name=$1
  shift
  : >"$work/out"
  if "$@" >"$work/out" 2>&1; then fail "$name (succeeded)"; else pass "$name"; fi
}

# note TEXT: explanation for the next failure (written into the captured output).
note() { printf '%s\n' "$*" >>"$work/out"; }

summary() {
  printf '\n%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
  [ "$failed" -eq 0 ]
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (namespaces, nftables): sudo $0" >&2
    exit 2
  fi
}

# Directive values of a unit file (last assignment wins for single-valued directives; the
# caller decides). unit_values FILE KEY prints every value of KEY, one per line.
unit_values() {
  sed -n "s/^$2=//p" "$1"
}

# The port of the --listen argument of the unit's ExecStart=.
unit_listen_port() {
  unit_values "$1" ExecStart | sed -n 's/.*--listen [^ ]*:\([0-9]*\).*/\1/p' | tail -n1
}

# The value of an nft `define NAME = VALUE` of a ruleset file.
nft_define() {
  sed -n "s/^define $2 = \\([0-9]*\\)\$/\\1/p" "$1"
}

has_ipv6() { [ -d /proc/sys/net/ipv6 ]; }
