#!/usr/bin/env bash
# The shipped relay unit at run time (docs/analysis/relay-hardening.md §3.7 steps 5-6, rows
# U-2..U-5, U-8, C-6, C-7, F-9): the real zt-relay under the real unit (seccomp, NoExecPaths,
# SocketBind*, Memory*, TasksMax), then a sandbox probe under the same unit that tries what an
# attacker with code execution would try.
#
#   sudo ZT_RELAY=... ZT_PROBE=... packaging/tests/host/systemd-e2e.sh
#
# Needs root on a host booted with systemd: it installs files under /usr/local/bin, /etc/tcn
# and /etc/systemd/system, and removes them at the end. LOAD_HOST_RULESET=1 (ephemeral CI
# runners only) also loads packaging/nftables/zt-relay.nft on the host, so the egress probes
# meet the firewall. SD_EXEC is an optional command prefix for systemctl/journalctl (e.g.
# "nsenter -t <pid> -a" for a systemd running in a container's namespace).

# shellcheck source=packaging/tests/host/lib.sh
source "$(dirname "$0")/lib.sh"
need_root

: "${ZT_RELAY:=$repo/target/x86_64-unknown-linux-musl/release/zt-relay}"
: "${ZT_PROBE:=$repo/target/x86_64-unknown-linux-musl/release/zt-relay-probe}"
# shellcheck disable=SC2086 # SD_EXEC is a command prefix, split on purpose
sd() { ${SD_EXEC:-} "$@"; }

state=$(sd systemctl is-system-running 2>/dev/null || true)
case $state in
  running | degraded) ;;
  *)
    echo "no running systemd here ($state): nothing to test" >&2
    skip "systemd e2e" "systemd is not running"
    summary
    exit $?
    ;;
esac
for f in "$ZT_RELAY" "$ZT_PROBE"; do
  [ -x "$f" ] || { echo "missing binary: $f (set ZT_RELAY / ZT_PROBE)" >&2; exit 2; }
done
id -u tcn >/dev/null 2>&1 || { echo "no tcn user: systemd-sysusers packaging/systemd/tcn.sysusers" >&2; exit 2; }

[ -e /etc/tcn ] && { echo "/etc/tcn exists: refusing to touch a real installation" >&2; exit 2; }
units=/etc/systemd/system
on_exit "rm -rf /etc/tcn /usr/local/bin/zt-relay /usr/local/bin/zt-relay-probe $units/zt-relay.service $units/zt-relay.service.d $units/zt-relay-probe.service; ${SD_EXEC:-} systemctl daemon-reload"
on_exit "${SD_EXEC:-} systemctl stop zt-relay.service zt-relay-probe.service"

install -m 0755 "$ZT_RELAY" /usr/local/bin/zt-relay
install -m 0755 "$ZT_PROBE" /usr/local/bin/zt-relay-probe
install -d -m 0755 -o root -g root /etc/tcn
/usr/local/bin/zt-relay keygen --out /etc/tcn/relay.key >/dev/null
chown tcn:tcn /etc/tcn/relay.key
install -m 0644 /dev/null /etc/tcn/policy.toml
install -m 0644 "$unit" "$units/zt-relay.service"
# Only the memory limit changes: 512 MiB, so the queue budget must be 128 MiB (a quarter).
install -d "$units/zt-relay.service.d"
printf '[Service]\nMemoryMax=512M\n' >"$units/zt-relay.service.d/50-test.conf"
sd systemctl daemon-reload

# The journal of one run (an invocation id) only: earlier runs on the same host do not count.
journal() { sd journalctl -o cat --no-pager "_SYSTEMD_INVOCATION_ID=$1" 2>/dev/null; }
invocation() { sd systemctl show -p InvocationID --value "$1"; }

# --- the relay under its unit ----------------------------------------------------------------
check "the relay starts under the hardened unit (Type=notify: ready)" sd systemctl start zt-relay.service
relay_run=$(invocation zt-relay.service)
sleep 3
check "C-7/U-6 it is still active after 3 s (no SIGSYS, no TasksMax abort)" sd systemctl is-active zt-relay.service
check "systemctl reload succeeds (ExecReload= runs under NoExecPaths=)" sd systemctl reload zt-relay.service
check "a TCP connect to the relay port succeeds" python3 "$pkt" connect --dst 127.0.0.1 --port 7443

budget_follows_the_cgroup() {
  # U-8 / C-6: the default queue budget is a quarter of the unit's MemoryMax.
  journal "$relay_run" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        event = json.loads(line)
    except ValueError:
        continue
    fields = event.get("fields", event)
    if fields.get("message") == "queue budget in use":
        print("budget", fields.get("budget"))
        sys.exit(0 if int(fields.get("budget", 0)) == 128 * 1024 * 1024 else 1)
print("no \"queue budget in use\" event")
sys.exit(1)'
}
check "U-8/C-6 budget_follows_the_cgroup: 128 MiB under MemoryMax=512M" budget_follows_the_cgroup

check "the relay stops cleanly (drain)" sd systemctl stop zt-relay.service
check "the relay is inactive after stop" bash -c "! ${SD_EXEC:-} systemctl is-active --quiet zt-relay.service"
journal "$relay_run" | tail -n 5 | sed 's/^/     # /'

# --- the sandbox probe under the same unit ----------------------------------------------------
# The shipped unit with the probe as its only executable; runs once.
sed -e 's#/usr/local/bin/zt-relay#/usr/local/bin/zt-relay-probe#g' \
  -e 's/^Type=notify/Type=exec/' -e 's/^Restart=always/Restart=no/' \
  -e '/^WatchdogSec=/d' -e '/^NotifyAccess=/d' -e 's/^\[Service\]$/\[Service\]\nRemainAfterExit=yes/' \
  "$unit" >"$units/zt-relay-probe.service"
sd systemctl daemon-reload

# A root service on loopback that only the firewall can keep the relay user away from.
python3 "$pkt" listen --addr 127.0.0.1 --port 2222 &
on_exit "kill $!"
if [ -n "${LOAD_HOST_RULESET:-}" ]; then
  nft -f "$ruleset"
  on_exit "nft delete table inet zt_relay"
fi

sd systemctl start zt-relay-probe.service
probe_run=$(invocation zt-relay-probe.service)
for _ in $(seq 100); do
  case $(sd systemctl show -p SubState --value zt-relay-probe.service) in exited | failed | dead) break ;; esac
  sleep 0.1
done
sleep 0.5 # journald may still be reading the last lines
journal "$probe_run" | grep '^{"probe"' >"$work/probe" || true
sed 's/^/     # /' "$work/probe"

# probe NAME RESULT [DETAIL-REGEX]
probe() {
  grep -E "\"probe\":\"$1\",\"result\":\"$2\",\"detail\":\"${3:-}" "$work/probe"
}

check "U-2 exec_is_denied: /bin/sh (NoExecPaths=/)" probe exec_sh denied 'errno 13 '
check "U-2 exec_is_denied: /usr/bin/env" probe exec_usr_bin_env denied 'errno 13 '
# SocketBindDeny= is a libbpf program: systemd built without BPF_FRAMEWORK (Ubuntu's packages,
# hence the GitHub runner) accepts the setting and does not enforce it. There the other port can
# be bound but not reached: the firewall drops every inbound port but the relay's (F-1).
if systemctl --version | grep -q -- '+BPF_FRAMEWORK'; then
  check "U-3 bind_is_denied: another port (SocketBindDeny=any)" probe bind_other_port denied 'errno (1|13) '
else
  echo "note U-3 bind_is_denied not enforceable: this systemd is built without BPF_FRAMEWORK"
fi
check "U-3 the relay port can still be bound (SocketBindAllow=)" probe bind_relay_port allowed
check "U-4 writes_are_denied: /etc/tcn (read-only)" probe write_etc_tcn denied 'errno 30 '
check "U-4 writes_are_denied: /usr/local/bin (ProtectSystem=strict)" probe write_usr_local_bin denied 'errno 30 '

tasks_are_bounded() {
  probe threads denied || return 1
  local started
  started=$(sed -n 's/.*"probe":"threads".*"detail":"\([0-9]*\) threads.*/\1/p' "$work/probe")
  echo "threads started before refusal: $started"
  [ "${started:-9999}" -lt 512 ]
}
check "U-5 tasks_are_bounded: thread creation fails before 512 (TasksMax=512)" tasks_are_bounded

if [ -n "${LOAD_HOST_RULESET:-}" ]; then
  check "F-9 the probe cannot dial a loopback service (nftables egress)" probe connect_loopback denied 'errno 111 '
  # Refused by the firewall where the address routes (cloud runners), unreachable elsewhere.
  check "F-9 the probe cannot dial the cloud metadata address" probe connect_metadata denied 'errno (111|101|113) '
else
  skip "F-9 egress probes under the unit" "set LOAD_HOST_RULESET=1 on an ephemeral host"
fi

summary
