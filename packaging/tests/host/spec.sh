#!/usr/bin/env bash
# Static host-hardening checks of the relay (docs/analysis/relay-hardening.md §3.2-§3.4, rows
# U-1, U-6, U-7, F-8, F-12, K-1..K-3): the systemd unit, the nftables ruleset and the sysctl
# file, checked with the real tools (systemd-analyze, nft through the kernel, /proc/sys).
#
#   sudo ZT_RELAY=target/x86_64-unknown-linux-musl/release/zt-relay packaging/tests/host/spec.sh
#
# Needs root, nftables, systemd-analyze, python3 and the `tcn` user (systemd-sysusers
# packaging/systemd/tcn.sysusers): the ruleset matches on it. APPLY_SYSCTL=1 (ephemeral CI
# runners only) also applies the sysctl file to the host and reads every value back.

# shellcheck source=packaging/tests/host/lib.sh
source "$(dirname "$0")/lib.sh"
need_root

: "${ZT_RELAY:=$repo/target/x86_64-unknown-linux-musl/release/zt-relay}"

# The admission defaults of PROTOCOL §10.1 that bound the descriptors the relay needs.
MAX_PREAUTH=1024
MAX_ESTABLISHED=8192

# The only checks of `systemd-analyze security` that the relay unit may leave unset: inherent
# to a network service that uses sd_notify (relay-hardening.md §2(b)). Anything else flagged
# is a regression.
ALLOWED_UNSET="DeviceAllow IPAddressDeny PrivateNetwork RestrictAddressFamilies_AF_INET_INET6 RestrictAddressFamilies_AF_UNIX RootDirectoryOrRootImage"

# --- systemd unit (U-1, U-6, U-7) -----------------------------------------------------------

unit_security_score() {
  # --threshold=11: exposure 1.1 or lower (the shipped unit was 1.2).
  systemd-analyze security --offline=yes --threshold=11 "$unit" >"$work/score" 2>&1
  local rc=$?
  tail -n1 "$work/score"
  return $rc
}
check "U-1 unit_security_score: exposure at most 1.1" unit_security_score

unit_flagged_set_is_exact() {
  systemd-analyze security --offline=yes --json=short "$unit" 2>/dev/null | python3 -c '
import json, sys
allowed = set(sys.argv[1].split())
flagged = {c["json_field"] for c in json.load(sys.stdin) if not c["set"] and c["exposure"] not in (None, "0.0")}
print("flagged:", " ".join(sorted(flagged)))
print("unexpected:", " ".join(sorted(flagged - allowed)) or "-")
print("no longer flagged (tighten the allow-list):", " ".join(sorted(allowed - flagged)) or "-")
sys.exit(0 if flagged == allowed else 1)' "$ALLOWED_UNSET"
}
check "U-1 unit_flagged_set_is_exact: only the inherent checks are unset" unit_flagged_set_is_exact

unit_has() {
  local key=$1 want=$2
  if unit_values "$unit" "$key" | grep -Fxq -- "$want"; then return 0; fi
  note "missing: $key=$want (has: $(unit_values "$unit" "$key" | tr '\n' ' '))"
  return 1
}

the_relay_unit_is_hardened() {
  local port ok=0
  port=$(unit_listen_port "$unit")
  unit_has NoExecPaths / || ok=1
  unit_has ExecPaths /usr/local/bin/zt-relay || ok=1
  unit_has SocketBindAllow "tcp:${port:-?}" || ok=1
  unit_has SocketBindDeny any || ok=1
  unit_has PrivateIPC yes || ok=1
  unit_has MemoryHigh 70% || ok=1
  unit_has MemoryMax 80% || ok=1
  unit_has MemorySwapMax 0 || ok=1
  unit_has TasksMax 512 || ok=1
  # What was already there must stay.
  unit_has NoNewPrivileges yes || ok=1
  unit_has ProtectSystem strict || ok=1
  unit_has ReadOnlyPaths /etc/tcn || ok=1
  unit_has User tcn || ok=1
  return $ok
}
check "the_relay_unit_is_hardened: exec, bind, memory and task directives" the_relay_unit_is_hardened

syscall_filter_excludes() {
  # U-6: io_uring (@aio), the keyring and @resources are denied on top of @system-service.
  local denied group ok=0
  denied=$(unit_values "$unit" SystemCallFilter | sed -n 's/^~//p' | tr '\n' ' ')
  for group in @privileged @resources @aio @keyring; do
    case " $denied " in
      *" $group "*) ;;
      *) note "SystemCallFilter=~ lacks $group (denied: $denied)"; ok=1 ;;
    esac
  done
  # The groups hold what the analysis says they hold on this systemd version.
  systemd-analyze syscall-filter @aio | grep -qx '    io_uring_setup' || { note "@aio without io_uring_setup?"; ok=1; }
  systemd-analyze syscall-filter @keyring | grep -qx '    keyctl' || { note "@keyring without keyctl?"; ok=1; }
  return $ok
}
check "U-6 syscall_filter_excludes: ~@privileged @resources @aio @keyring" syscall_filter_excludes

ports_agree() {
  # U-7: the port of --listen, SocketBindAllow= and the firewall's RELAY_PORT are one value.
  local listen bind nft
  listen=$(unit_listen_port "$unit")
  bind=$(unit_values "$unit" SocketBindAllow | sed -n 's/^tcp:\([0-9]*\)$/\1/p')
  nft=$(nft_define "$ruleset" RELAY_PORT 2>/dev/null || true)
  echo "--listen ${listen:-?}, SocketBindAllow ${bind:-?}, RELAY_PORT ${nft:-?}"
  [ -n "$listen" ] && [ "$listen" = "$bind" ] && [ "$listen" = "$nft" ]
}
check "U-7 ports_agree: --listen, SocketBindAllow= and RELAY_PORT" ports_agree

descriptors_cover_the_pools() {
  # 2 x max_preauth (PROXY header pool + admission) + max_established + fixed descriptors.
  local limit need=$((2 * MAX_PREAUTH + MAX_ESTABLISHED + 64))
  limit=$(unit_values "$unit" LimitNOFILE | tail -n1)
  echo "LimitNOFILE=$limit, needed $need"
  [ "${limit:-0}" -ge "$need" ]
}
check "descriptors_cover_the_pools: LimitNOFILE >= 2*max_preauth + max_established + 64" descriptors_cover_the_pools

unit_verifies() {
  # A copy whose binary paths point at the built binary: verify then has nothing to report.
  [ -x "$ZT_RELAY" ] || { echo "no zt-relay binary at $ZT_RELAY (set ZT_RELAY)"; return 1; }
  sed "s#/usr/local/bin/zt-relay#$ZT_RELAY#g" "$unit" >"$work/zt-relay.service"
  systemd-analyze verify "$work/zt-relay.service" >"$work/verify" 2>&1 || { cat "$work/verify"; return 1; }
  cat "$work/verify"
  [ ! -s "$work/verify" ]
}
check "unit_verifies: systemd-analyze verify reports nothing" unit_verifies

# --- nftables (F-8, F-12) --------------------------------------------------------------------

check "the ruleset file exists" test -f "$ruleset"
check "the tcn user exists (the ruleset matches on it)" id -u tcn
check "ruleset_compiles: nft -c in a fresh network namespace" unshare -n nft -c -f "$ruleset"

# A scratch network namespace for loading the ruleset for real.
ip netns add zt-spec
on_exit "ip netns del zt-spec"
nsx() { ip netns exec zt-spec "$@"; }

ruleset_loads_twice() {
  # The file deletes and recreates its own table: loading it again is an atomic replace.
  nsx nft -f "$ruleset" && nsx nft -f "$ruleset" && nsx nft list table inet zt_relay >/dev/null
}
check "ruleset_loads_twice: atomic replace of the zt_relay table" ruleset_loads_twice

nsx nft -j list table inet zt_relay >"$work/table.json" 2>/dev/null || : >"$work/table.json"

chains_are_as_designed() {
  python3 - "$work/table.json" <<'EOF'
import json, sys
text = open(sys.argv[1]).read()
items = json.loads(text)["nftables"] if text else []
chains = {c["chain"]["name"]: c["chain"] for c in items if "chain" in c}
want = {
    "raw_pre": ("prerouting", -300, "accept"),
    "raw_out": ("output", -300, "accept"),
    "input": ("input", 0, "drop"),
    "forward": ("forward", 0, "drop"),
    "output": ("output", 0, "accept"),
}
ok = True
for name, (hook, prio, policy) in want.items():
    c = chains.get(name)
    got = (c.get("hook"), c.get("prio"), c.get("policy")) if c else None
    print(f"{name}: {got}")
    if got != (hook, prio, policy):
        print(f"  expected {(hook, prio, policy)}")
        ok = False
sys.exit(0 if ok else 1)
EOF
}
check "chains_are_as_designed: hooks, priorities and policies" chains_are_as_designed

icmp_errors_are_never_rate_limited() {
  # F-8: a global limit on ICMP errors would let anyone starve path-MTU discovery.
  python3 - "$work/table.json" <<'EOF'
import json, sys
text = open(sys.argv[1]).read()
items = json.loads(text)["nftables"] if text else []
errors = {"destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"}
found = set()
for r in (i["rule"] for i in items if "rule" in i and i["rule"]["chain"] == "input"):
    blob = json.dumps(r["expr"])
    hit = {e for e in errors if e in blob}
    if not hit:
        continue
    found |= hit
    if '"limit"' in blob:
        print("rate-limited ICMP error rule:", blob)
        sys.exit(1)
    if '"accept"' not in blob:
        print("ICMP error rule that does not accept:", blob)
        sys.exit(1)
print("accepted without a limit:", ", ".join(sorted(found)))
sys.exit(0 if found == errors else 1)
EOF
}
check "F-8 icmp_errors_are_never_rate_limited" icmp_errors_are_never_rate_limited

rule_order() {
  # rule_order CHAIN FIRST SECOND: in CHAIN, the first rule whose JSON contains FIRST comes
  # before the first rule that contains SECOND.
  python3 - "$work/table.json" "$@" <<'EOF'
import json, sys
path, chain, first, second = sys.argv[1:5]
text = open(path).read()
items = json.loads(text)["nftables"] if text else []
rules = [json.dumps(i["rule"]["expr"]) for i in items if "rule" in i and i["rule"]["chain"] == chain]
a = next((n for n, r in enumerate(rules) if first in r), None)
b = next((n for n, r in enumerate(rules) if second in r), None)
print(f"{chain}: {first!r} at rule {a}, {second!r} at rule {b}")
sys.exit(0 if a is not None and b is not None and a < b else 1)
EOF
}
# A15-2: the relay port is untracked, so an ICMP error about one of its connections is
# "invalid" to conntrack: it must be accepted before the invalid drop (attacks.sh F-16).
check "F-16 icmp_errors_come_before_the_invalid_drop (PMTUD)" rule_order input packet-too-big '"invalid"'
check "F-16 neighbour_discovery_comes_before_the_invalid_drop" rule_order input nd-neighbor-solicit '"invalid"'
# A15-1: the relay may answer from its port, never open a connection from it (attacks.sh F-9).
check "F-9 egress_refuses_syns_from_the_relay_port_first" rule_order output '"reject"' '"accept"'

a_ruleset_with_a_missing_user_is_rejected_atomically() {
  # F-12: a broken file (here: a user that does not exist) is refused as a whole, and the
  # table already loaded stays exactly as it was.
  sed 's/meta skuid "tcn"/meta skuid "zt-no-such-user"/' "$ruleset" >"$work/broken.nft"
  grep -q zt-no-such-user "$work/broken.nft" || { echo "no skuid rule to break"; return 1; }
  nsx nft list table inet zt_relay >"$work/before" || return 1
  if nsx nft -f "$work/broken.nft" 2>/dev/null; then echo "the broken ruleset loaded"; return 1; fi
  nsx nft list table inet zt_relay >"$work/after" || return 1
  diff -u "$work/before" "$work/after"
}
check "F-12 a_ruleset_with_a_missing_user_is_rejected_atomically" a_ruleset_with_a_missing_user_is_rejected_atomically

no_variables_in_meters() {
  # nft 1.0.9 refuses $VARIABLES inside `limit rate` and `ct count`: they must be literals
  # (the Ansible template renders them).
  [ -f "$ruleset" ] && ! grep -nE '(limit rate|ct count)[^;]*\$' "$ruleset"
}
check "no_variables_in_meters: meter numbers are literal" no_variables_in_meters

# --- sysctl (K-1..K-3) ----------------------------------------------------------------------

check "the sysctl file exists" test -f "$sysctl_conf"
check "K-2 the modules-load file loads nf_conntrack" grep -qx nf_conntrack "$modules_conf"

# key=value lines of the file, '-' prefix kept.
sysctl_entries() {
  sed -e 's/#.*//' -e '/^[[:space:]]*$/d' -e 's/[[:space:]]*=[[:space:]]*/=/' -e 's/[[:space:]]*$//' "$sysctl_conf" 2>/dev/null
}

modprobe nf_conntrack 2>/dev/null || true

every_sysctl_key_exists() {
  # K-1: a typo would silently do nothing. Keys with the '-' prefix may be absent on some
  # distributions; every other key must exist. A whole subsystem absent from this kernel (no
  # IPv6, no Yama) is reported as a skip, a failure under STRICT.
  local line key path top ok=0 n=0
  [ -f "$sysctl_conf" ] || { echo "no sysctl file"; return 1; }
  while IFS= read -r line; do
    key=${line%%=*}
    case $key in -*) continue ;; esac
    n=$((n + 1))
    path=/proc/sys/${key//.//}
    if [ -e "$path" ]; then continue; fi
    top=/proc/sys/$(cut -d. -f1-2 <<<"$key" | tr . /)
    if [[ $key == *.*.* ]] && [ ! -d "$top" ]; then
      echo "absent subsystem on this kernel: $key"
      absent_subsystems+=("$key")
      continue
    fi
    echo "no such key: $key"
    ok=1
  done < <(sysctl_entries)
  echo "$n mandatory keys checked"
  return $ok
}
absent_subsystems=()
check "K-1 every_sysctl_key_exists" every_sysctl_key_exists
if [ "${#absent_subsystems[@]}" -gt 0 ]; then
  skip "K-1 keys of subsystems absent from this kernel" "${absent_subsystems[*]}"
fi

values_are_integers() {
  local line bad=0
  [ -f "$sysctl_conf" ] || return 1
  while IFS= read -r line; do
    [[ ${line#*=} =~ ^[0-9]+$ ]] || { echo "not an integer: $line"; bad=1; }
  done < <(sysctl_entries)
  return $bad
}
check "sysctl values are plain integers" values_are_integers

user_namespaces_are_not_disabled_globally() {
  # K-3: user.max_user_namespaces=0 would break the unit's PrivateUsers=yes.
  [ -f "$sysctl_conf" ] && ! sysctl_entries | grep -E '^-?user\.max_user_namespaces='
}
check "K-3 user_namespaces_are_not_disabled_globally" user_namespaces_are_not_disabled_globally

# The values the design requires (relay-hardening.md §2(d)); the file may add, not weaken.
declare -A required=(
  [net.ipv4.tcp_syncookies]=1 [net.ipv4.tcp_max_syn_backlog]=8192 [net.core.somaxconn]=4096
  [net.ipv4.tcp_synack_retries]=2 [net.ipv4.tcp_min_snd_mss]=536 [net.ipv4.tcp_rfc1337]=1
  [net.ipv4.tcp_fin_timeout]=15 [net.ipv4.conf.all.rp_filter]=1 [net.ipv4.conf.default.rp_filter]=1
  [net.ipv4.conf.all.accept_redirects]=0 [net.ipv4.conf.all.send_redirects]=0
  [net.ipv6.conf.all.accept_redirects]=0 [net.ipv4.conf.all.accept_source_route]=0
  [net.ipv6.conf.all.accept_source_route]=0 [net.ipv4.conf.all.log_martians]=0
  [net.ipv4.ip_forward]=0 [kernel.kptr_restrict]=2 [kernel.dmesg_restrict]=1
  [kernel.unprivileged_bpf_disabled]=1 [net.core.bpf_jit_harden]=2 [kernel.yama.ptrace_scope]=2
  [-kernel.kexec_load_disabled]=1 [-kernel.sysrq]=0 [fs.protected_symlinks]=1
  [fs.protected_hardlinks]=1 [fs.protected_fifos]=2 [fs.protected_regular]=2 [fs.suid_dumpable]=0
  [-net.netfilter.nf_conntrack_max]=262144
)

the_required_values_are_set() {
  local key want got ok=0
  for key in "${!required[@]}"; do
    want=${required[$key]}
    got=$(sysctl_entries | sed -n "s/^${key//./\\.}=//p" | tail -n1)
    [ "$got" = "$want" ] || { echo "$key: want $want, file has ${got:-nothing}"; ok=1; }
  done
  return $ok
}
check "the_required_values_are_set (relay-hardening.md §2(d))" the_required_values_are_set

forwarding_is_set_before_the_conf_keys() {
  # Writing ip_forward / conf.all.forwarding resets the conf.* keys to their defaults: on a host
  # that had forwarding on (a CI runner with Docker), a later write undid accept_redirects=0.
  local last_fwd first_conf
  last_fwd=$(sysctl_entries | grep -nE '^-?net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)=' | tail -n1 | cut -d: -f1)
  first_conf=$(sysctl_entries | grep -nE '^-?net\.ipv[46]\.conf\.' | grep -v forwarding | head -n1 | cut -d: -f1)
  if [ -n "$last_fwd" ] && [ -n "$first_conf" ] && [ "$last_fwd" -lt "$first_conf" ]; then
    return 0
  fi
  echo "forwarding at line ${last_fwd:-none}, first conf.* key at line ${first_conf:-none}"
  return 1
}
check "forwarding_is_set_before_the_conf_keys" forwarding_is_set_before_the_conf_keys

if [ -n "${APPLY_SYSCTL:-}" ]; then
  applied_values_read_back() {
    # Ephemeral runner only: apply the file the way the host would at boot, read back.
    local line key want got ok=0
    /usr/lib/systemd/systemd-sysctl "$sysctl_conf" || ok=1
    while IFS= read -r line; do
      key=${line%%=*}
      want=${line#*=}
      got=$(sysctl -n "${key#-}" 2>/dev/null) || { [ "${key:0:1}" = - ] && continue; echo "unreadable: $key"; ok=1; continue; }
      [ "$got" = "$want" ] || { echo "$key: applied $want, reads $got"; ok=1; }
    done < <(sysctl_entries)
    return $ok
  }
  check "K-1/K-2 applied_values_read_back (systemd-sysctl on this host)" applied_values_read_back
else
  skip "applied_values_read_back" "set APPLY_SYSCTL=1 on an ephemeral host"
fi

summary
