#!/usr/bin/env bash
# Tests of the zt_relay Ansible role (docs/analysis/relay-hardening.md §3.6, rows A-1..A-4,
# U-7, F-15, P-19; adversary review 0015 findings A15-4..A15-6): syntax, lint, rendering of every variant, drift against the packaged
# files, nft -c of every rendered ruleset, zt-relay check of every rendered relay.toml, and the
# fail-closed binary verification run for real on localhost.
#
#   sudo ZT_RELAY=target/x86_64-unknown-linux-musl/release/zt-relay OUT=/tmp/render \
#     deploy/ansible/tests/check.sh
#
# Needs ansible-core, nftables, systemd-analyze and the `tcn` user (nft -c resolves it); root
# for `unshare -n`. ansible-lint runs when installed (STRICT=1 requires it). OUT keeps the
# renderings (the PROXY ruleset feeds packaging/tests/host/attacks.sh, P-19).

# shellcheck source=packaging/tests/host/lib.sh
source "$(cd "$(dirname "$0")/../../../packaging/tests/host" && pwd)/lib.sh"
need_root

ans="$repo/deploy/ansible"
role="$ans/roles/zt_relay"
: "${ZT_RELAY:=$repo/target/x86_64-unknown-linux-musl/release/zt-relay}"
: "${OUT:=$work/render}"
export ANSIBLE_ROLES_PATH="$ans/roles" ANSIBLE_LOCALHOST_WARNING=False ANSIBLE_INVENTORY_UNPARSED_WARNING=False ANSIBLE_NOCOLOR=1
variants=(direct proxy proxy-allow-direct colocated-agent no-ssh invalid invalid-args big-pools)
# The variants a host would run as rendered (the others must be refused).
valid=(direct proxy proxy-allow-direct colocated-agent no-ssh)

check "syntax: playbooks/relay.yml" ansible-playbook --syntax-check -i "$ans/inventory.example.ini" "$ans/playbooks/relay.yml"
check "syntax: tests/render.yml" ansible-playbook --syntax-check -i localhost, "$ans/tests/render.yml"
if command -v ansible-lint >/dev/null; then
  check "ansible-lint (production profile)" bash -c "cd '$ans' && ansible-lint --profile production --offline playbooks/relay.yml roles/zt_relay"
else
  skip "ansible-lint" "not installed"
fi

for v in "${variants[@]}"; do
  check "render: $v" ansible-playbook -i localhost, -c local "$ans/tests/render.yml" \
    -e "@$ans/tests/variants/$v.yml" -e "out=$OUT/$v"
done

check "drift: the direct rendering is byte-identical to packaging/nftables/zt-relay.nft" \
  diff -u "$ruleset" "$OUT/direct/zt-relay.nft"
for v in "${variants[@]}"; do
  check "nft -c: $v" unshare -n nft -c -f "$OUT/$v/zt-relay.nft"
done

proxy_mode_has_no_syn_meter() {
  # The meter would throttle every user behind a proxy at once; the proxies are the sources.
  ! grep -n 'add @syn_v' "$OUT/proxy/zt-relay.nft" &&
    grep -q 'set relay_src_v4 { type ipv4_addr; flags interval; elements = { 198.51.100.3/32 } }' "$OUT/proxy/zt-relay.nft"
}
check "P-19 the PROXY ruleset accepts the relay port from the proxies only, no SYN meter" proxy_mode_has_no_syn_meter

no_ssh_has_empty_admin_sets() {
  grep -q 'set admin_v4 { type ipv4_addr; flags interval; }' "$OUT/no-ssh/zt-relay.nft" &&
    ! grep -q 'chain forward' "$OUT/no-ssh/zt-relay.nft" && ! grep -q 'fib saddr' "$OUT/no-ssh/zt-relay.nft"
}
check "no-ssh variant: empty admin sets, no forward chain, no fib rule" no_ssh_has_empty_admin_sets

# --- the drop-in against the shipped unit (U-7) ---------------------------------------------
dropin_agrees() {
  # The drop-in's ExecStart= is the shipped one plus --config (and extra arguments), and its
  # SocketBindAllow= / ExecPaths= follow the same port and binary.
  local v=$1 d="$OUT/$1/10-ansible.conf" shipped exec port bind
  shipped=$(unit_values "$unit" ExecStart | sed 's/--listen [^ ]*//')
  exec=$(unit_values "$d" ExecStart | grep . | sed 's/--listen [^ ]*//')
  port=$(unit_values "$d" ExecStart | grep . | sed -n 's/.*--listen [^ ]*:\([0-9]*\) .*/\1/p')
  bind=$(unit_values "$d" SocketBindAllow | grep . | sed -n 's/^tcp://p')
  echo "shipped: $shipped"
  echo "drop-in: $exec (port $port, SocketBindAllow $bind)"
  [[ $exec == "$shipped --config /etc/tcn/relay.toml"* ]] && [ -n "$port" ] && [ "$port" = "$bind" ] &&
    grep -qx "define RELAY_PORT = $port" "$OUT/$v/zt-relay.nft" &&
    [ "$(unit_values "$d" ExecPaths | grep .)" = "$(unit_values "$unit" ExecPaths)" ]
}
for v in "${valid[@]}"; do
  check "U-7 drop-in agrees with the unit and the ruleset: $v" dropin_agrees "$v"
done

# --- the pre-restart check runs exactly ExecStart= (A15-4) ----------------------------------
handler_checks_the_run_arguments() {
  # The handler's `check` is given the role's check vector, and that vector is ExecStart='s
  # with `run` replaced by `check` (the extra arguments included).
  python3 - "$role/handlers/main.yml" "$OUT/$1/argv.json" "$OUT/$1/10-ansible.conf" <<'EOF'
import json, shlex, sys, yaml
handlers = yaml.safe_load(open(sys.argv[1]))
task = next(h for h in handlers if h.get("name") == "Check zt-relay as tcn")
argv_expr = task["ansible.builtin.command"]["argv"]
rendered = json.load(open(sys.argv[2]))
lines = [l for l in open(sys.argv[3]) if l.startswith("ExecStart=") and l.strip() != "ExecStart="]
run = shlex.split(lines[-1].split("=", 1)[1])
want = ["check" if a == "run" else a for a in run]
print("handler argv:", argv_expr)
print("ExecStart=:  ", run)
print("check:       ", rendered.get("check"))
ok = argv_expr.replace(" ", "") == "{{zt_relay__check_argv}}" and rendered.get("check") == want and rendered.get("run") == run
sys.exit(0 if ok else 1)
EOF
}
for v in "${valid[@]}" invalid-args; do
  check "A15-4 the pre-restart check is given exactly ExecStart='s arguments: $v" handler_checks_the_run_arguments "$v"
done

# --- allow_direct really admits direct peers (A15-6) ----------------------------------------
allow_direct_admits_direct_peers() {
  local d="$OUT/proxy-allow-direct"
  grep -qx 'allow_direct = true' "$d/relay.toml" &&
    grep -q 'set relay_src_v4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/0 } }' "$d/zt-relay.nft" &&
    grep -q 'set relay_src_v6 { type ipv6_addr; flags interval; elements = { ::/0 } }' "$d/zt-relay.nft" &&
    ! grep -nE '^IPAddress(Allow|Deny)=.' "$d/10-ansible.conf" &&
    # Direct peers are metered per source, the proxies (every user at once) are not.
    grep -q 'ip saddr != @proxy_v4 .*update @syn_v4' "$d/zt-relay.nft" &&
    grep -q 'ip6 saddr != @proxy_v6 .*update @syn_v6' "$d/zt-relay.nft" &&
    grep -q "set proxy_v4 { type ipv4_addr; flags interval; elements = { $(sed -n 's/^zt_relay_proxy_v4: \[\(.*\)\]$/\1/p' "$ans/tests/variants/proxy-allow-direct.yml") } }" "$d/zt-relay.nft"
}
check "A15-6 allow_direct: relay.toml, firewall and unit all admit direct peers" allow_direct_admits_direct_peers
proxy_only_keeps_the_unit_allow_list() {
  grep -qx 'allow_direct = false' "$OUT/proxy/relay.toml" && grep -q '^IPAddressDeny=any$' "$OUT/proxy/10-ansible.conf"
}
check "A15-6 control: without allow_direct the unit admits the proxies only" proxy_only_keeps_the_unit_allow_list

merged_score() {
  # The unit with the drop-in appended (later assignments win; empty ones reset) and scored.
  cat "$unit" "$OUT/$1/10-ansible.conf" >"$work/merged-$1.service"
  systemd-analyze security --offline=yes --threshold="$2" "$work/merged-$1.service" 2>&1 | tail -n1
  return "${PIPESTATUS[0]}"
}
check "the direct drop-in keeps the exposure at most 1.1" merged_score direct 11
check "the allow_direct drop-in keeps the exposure at most 1.1" merged_score proxy-allow-direct 11
check "P-19 the PROXY drop-in (IPAddressAllow=) scores at most 1.0" merged_score proxy 10

# --- relay.toml through the real binary (A-2) ------------------------------------------------
if [ -x "$ZT_RELAY" ]; then
  install -d -m 0755 "$work/etc"
  "$ZT_RELAY" keygen --out "$work/etc/relay.key" >/dev/null
  install -m 0644 /dev/null "$work/etc/policy.toml"
  relay_check() {
    "$ZT_RELAY" check --key "$work/etc/relay.key" --policy "$work/etc/policy.toml" --config "$OUT/$1/relay.toml"
  }
  for v in "${valid[@]}"; do
    check "A-2 zt-relay check accepts the rendered relay.toml: $v" relay_check "$v"
  done
  # local_argv VARIANT: the rendered check vector, with the host's paths mapped to the test's.
  local_argv() {
    python3 - "$OUT/$1/argv.json" "$ZT_RELAY" "$work/etc" "$OUT/$1/relay.toml" <<'EOF'
import json, sys
argv, binary, etc, toml = json.load(open(sys.argv[1]))["check"], *sys.argv[2:5]
mapped = {"/etc/tcn/relay.toml": toml, "/etc/tcn/relay.key": etc + "/relay.key",
          "/etc/tcn/policy.toml": etc + "/policy.toml"}
print(json.dumps([binary] + [mapped.get(a, a) for a in argv[1:]]))
EOF
  }
  check_as_rendered() {
    local argv
    argv=$(local_argv "$1") || return 1
    python3 -c 'import json, subprocess, sys; sys.exit(subprocess.run(json.loads(sys.argv[1])).returncode)' "$argv"
  }
  for v in "${valid[@]}"; do
    check "A15-4 the rendered pre-restart check passes: $v" check_as_rendered "$v"
  done
  check_fails "A15-4 the rendered pre-restart check refuses an out-of-range extra argument" check_as_rendered invalid-args

  # The role's descriptor assertion (tasks/descriptors.yml), run for real on localhost with
  # the rendered check vector (A15-5).
  descriptors_play() {
    local v=$1 argv
    shift
    argv=$(local_argv "$v") || return 1
    cat >"$work/descriptors.yml" <<EOF
- hosts: localhost
  gather_facts: false
  vars_files: [$role/defaults/main.yml, $role/vars/main.yml]
  tasks:
    - ansible.builtin.import_tasks: $role/tasks/descriptors.yml
EOF
    ansible-playbook -i localhost, -c local "$work/descriptors.yml" -e "@$ans/tests/variants/$v.yml" \
      -e "{\"zt_relay__check_argv\": $argv}" "$@"
  }
  for v in direct proxy; do
    check "A15-5 LimitNOFILE covers the default pools: $v" descriptors_play "$v"
  done
  check_fails "A15-5 pools beyond LimitNOFILE are refused (2 x 4096 + 60000 + 64 > 16384)" descriptors_play big-pools
  check "A15-5 control: the same pools pass with LimitNOFILE raised to 65536" \
    descriptors_play big-pools -e zt_relay_limit_nofile=65536
  limit_nofile_is_rendered() {
    grep -qx 'LimitNOFILE=16384' "$OUT/direct/10-ansible.conf" && grep -qx 'LimitNOFILE=16384' "$unit"
  }
  check "A15-5 the drop-in sets the LimitNOFILE= the role checked" limit_nofile_is_rendered
  invalid_is_refused() {
    relay_check invalid
    local rc=$?
    echo "exit $rc"
    [ "$rc" -eq 78 ]
  }
  check "A-2 zt-relay check refuses the invalid rendering with exit 78" invalid_is_refused
else
  skip "A-2 zt-relay check of the renderings" "no binary at $ZT_RELAY"
fi

# --- structure (A-1, A-3, A-4, F-15) ---------------------------------------------------------
serial_one() {
  python3 -c '
import sys, yaml
plays = yaml.safe_load(open(sys.argv[1]))
print([p.get("serial") for p in plays])
sys.exit(0 if plays and all(p.get("serial") == 1 for p in plays) else 1)' "$ans/playbooks/relay.yml"
}
check "A-3 the example playbook restarts one relay at a time (serial: 1)" serial_one

rollback_is_wired() {
  local f="$role/tasks/nftables.yml"
  grep -q 'systemd-run' "$f" && grep -q -- '--on-active=' "$f" && grep -q 'reset_connection' "$f" &&
    grep -q 'wait_for_connection' "$f" && grep -q 'zt-relay-firewall-rollback.timer' "$f" &&
    grep -q 'validate: nft -c -f %s' "$f"
}
check "F-15 the firewall is applied behind a rollback timer, validated first" rollback_is_wired

verification_cannot_be_skipped() {
  # No escape hatch in the verification or install path.
  ! grep -nE 'ignore_errors|failed_when: false|skip_verif|insecure' "$role/tasks/verify.yml" "$role/tasks/binary.yml"
}
check "A-1 no task can skip or ignore the binary verification" verification_cannot_be_skipped

key_never_read() {
  ! grep -rnE '(slurp|fetch|lookup\(.file).*relay\.key|relay\.key.*(slurp|fetch))' "$role" &&
    grep -A3 'Key - generate on the host' "$role/tasks/files.yml" | grep -q 'creates: /etc/tcn/relay.key'
}
check "A-4 the key is generated on the host and never read by a task" key_never_read

# --- the controller-side verification, run for real (A-1) -----------------------------------
verify_play() {
  cat >"$work/verify.yml" <<EOF
- hosts: localhost
  gather_facts: false
  vars_files: [$role/defaults/main.yml, $role/vars/main.yml]
  tasks:
    - ansible.builtin.import_tasks: $role/tasks/verify.yml
EOF
  ansible-playbook -i localhost, -c local "$work/verify.yml" "$@"
}
printf 'zt-relay stand-in\n' >"$work/bin"
good=$(sha256sum "$work/bin" | cut -d' ' -f1)
check "A-1 local binary with its SHA-256: accepted (control)" \
  verify_play -e "zt_relay_binary_local_path=$work/bin" -e "zt_relay_binary_sha256=$good"
check_fails "A-1 local binary with a wrong SHA-256: refused" \
  verify_play -e "zt_relay_binary_local_path=$work/bin" -e "zt_relay_binary_sha256=${good//?/0}"
check_fails "A-1 local binary without a SHA-256: refused" \
  verify_play -e "zt_relay_binary_local_path=$work/bin"
install -m 0644 "$repo/packaging/release/release-keys.fingerprints" "$work/pins"
check_fails "A-1 release mode with nothing pinned: refused (fail closed)" \
  verify_play -e zt_relay_binary_source=release -e "zt_relay_release_dir=$work" \
  -e zt_relay_release_tag=v1.2.3 -e "zt_relay_release_pins_file=$work/pins"

summary
