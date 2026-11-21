#!/usr/bin/env bash
# Firewall attack tests of the relay host (docs/analysis/relay-hardening.md §4.3, rows F-1 to
# F-14): two network namespaces joined by a veth pair, the packaged ruleset loaded in the
# "relay" one, the namespace-scoped keys of the sysctl file applied there, and small Python
# listeners standing in for zt-relay (user tcn, port 7443) and for other services.
#
#   sudo packaging/tests/host/attacks.sh
#   sudo PROXY_RULESET=/path/to/rendered-proxy.nft packaging/tests/host/attacks.sh   # + P-19
#
# Needs root, iproute2, nftables, python3 and the `tcn` user. Nothing outside the two
# namespaces is touched.

# shellcheck source=packaging/tests/host/lib.sh
source "$(dirname "$0")/lib.sh"
need_root

R=zt-relay-ns
A=zt-attacker-ns
RELAY=198.51.100.1
ATTACKER=198.51.100.2
LEGIT=198.51.100.3   # a second, well-behaved source on the attacker side
ADMIN=192.0.2.10     # inside admin_v4 of the packaged ruleset
SPOOF_NET=203.0.113.0/24
RELAY6=2001:db8:5::1
ATTACKER6=2001:db8:5::2
PORT=$(nft_define "$ruleset" RELAY_PORT 2>/dev/null || true)
PORT=${PORT:-7443}

rx() { ip netns exec "$R" "$@"; }
ax() { ip netns exec "$A" "$@"; }
as_tcn() { rx setpriv --reuid tcn --regid tcn --clear-groups "$@"; }

ip netns add "$R"
on_exit "ip netns del $R"
ip netns add "$A"
on_exit "ip netns del $A"
# Every process left in the namespaces (listeners, sniffers) ends with them.
on_exit "ip netns pids $R | xargs -r kill; ip netns pids $A | xargs -r kill; sleep 0.2"
ip link add zr0 netns "$R" type veth peer name za0 netns "$A"
rx ip link set lo up
ax ip link set lo up
rx ip addr add "$RELAY/24" dev zr0
ax ip addr add "$ATTACKER/24" dev za0
ax ip addr add "$LEGIT/32" dev za0
ax ip addr add "$ADMIN/32" dev za0
rx ip link set zr0 up
ax ip link set za0 up
# The admin network and the "internet" of spoofed sources are behind the attacker; 10.66.0.0/16
# has no route at all (an unroutable source).
rx ip route add 192.0.2.0/24 via "$ATTACKER"
rx ip route add "$SPOOF_NET" via "$ATTACKER"
if has_ipv6; then
  rx ip addr add "$RELAY6/64" dev zr0 nodad
  ax ip addr add "$ATTACKER6/64" dev za0 nodad
  rx ip -6 route add 2001:db8:77::/48 via "$ATTACKER6"
fi

# The namespace-scoped keys of the sysctl file (TCP and per-interface IPv4 settings), applied
# in the relay namespace only.
if [ -f "$sysctl_conf" ]; then
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$sysctl_conf" |
    grep -E '^-?net\.(ipv4\.(tcp_|conf\.|icmp_)|core\.somaxconn)' |
    while IFS='=' read -r key value; do rx sysctl -q -w "${key#-}=$value" || true; done
fi

load() { rx nft -f "$1"; }
# A copy of the ruleset without the lines that match REGEX: the control runs.
without() {
  local out="$work/without-$2.nft"
  grep -vE "$1" "$ruleset" >"$out"
  printf '%s' "$out"
}

# Listeners: the relay (user tcn, echo) on the relay port, root services on 22 and 8080, and a
# service on the attacker side that a compromised relay might dial.
as_tcn python3 "$pkt" listen --addr 0.0.0.0 --port "$PORT" --echo >/dev/null 2>&1 &
rx python3 "$pkt" listen --addr 0.0.0.0 --port 22 >/dev/null 2>&1 &
rx python3 "$pkt" listen --addr 0.0.0.0 --port 8080 >/dev/null 2>&1 &
ax python3 "$pkt" listen --addr 0.0.0.0 --port 8081 >/dev/null 2>&1 &
for _ in $(seq 50); do
  if rx ss -ltn | grep -q ":$PORT " && rx ss -ltn | grep -q ':8080 ' && ax ss -ltn | grep -q ':8081 '; then break; fi
  sleep 0.1
done

check "the relay stand-in listens on $PORT as user tcn" bash -c "ip netns exec $R ss -ltnpe | grep ':$PORT ' | grep -q 'uid:$(id -u tcn)'"
check "the ruleset loads in the relay namespace" load "$ruleset"

# from_attacker ARGS...: pkt.py in the attacker namespace.
pa() { ax python3 "$pkt" "$@"; }

# sniff_during SECONDS WHAT DST_NET -- CMD...: count packets of kind WHAT towards DST_NET seen on
# the attacker's interface while CMD runs; prints "<total> <unique>".
sniff_during() {
  local seconds=$1 what=$2 net=$3
  shift 4
  ax python3 "$pkt" sniff --iface za0 --seconds "$seconds" --what "$what" --dst-net "$net" >"$work/sniff" 2>"$work/sniff.err" &
  local pid=$!
  for _ in $(seq 50); do grep -q ready "$work/sniff.err" 2>/dev/null && break; sleep 0.05; done
  "$@" >/dev/null
  wait "$pid"
  cat "$work/sniff"
}

# expect_line WANT CMD...: CMD's output (one line) must equal WANT.
expect_line() {
  local want=$1 got
  shift
  got=$("$@" 2>&1 | tail -n1)
  echo "got: $got (want: $want)"
  [ "$got" = "$want" ]
}

# --- F-1 ------------------------------------------------------------------------------------
other_ports_are_silently_dropped() {
  local ok=0
  expect_line timeout pa connect --dst "$RELAY" --port 8080 --timeout 1.5 || ok=1
  # No ICMP port unreachable either: a UDP probe gets no answer at all.
  expect_line timeout pa udp --dst "$RELAY" --port 9999 --timeout 1.5 || ok=1
  return $ok
}
check "F-1 other_ports_are_silently_dropped (no RST, no ICMP)" other_ports_are_silently_dropped

# --- F-10 -----------------------------------------------------------------------------------
relay_replies_still_flow() {
  expect_line echoed pa connect --dst "$RELAY" --port "$PORT" --echo
}
check "F-10 relay_replies_still_flow (tcn listener, egress rule loaded)" relay_replies_still_flow

# --- F-7 ------------------------------------------------------------------------------------
non_syn_new_tcp_is_dropped() {
  local tracked untracked
  # An ACK out of nowhere to SSH (from an admin address): new, not a SYN, so dropped. Without
  # the rule the kernel would answer with a reset.
  tracked=$(sniff_during 1 rst "$ADMIN/32" -- pa syn --flags A --dst "$RELAY" --dport 22 --src "$ADMIN")
  # Control: the untracked relay port still lets the kernel answer (the sniffer works).
  untracked=$(sniff_during 1 rst "$ADMIN/32" -- pa syn --flags A --dst "$RELAY" --dport "$PORT" --src "$ADMIN")
  echo "resets: ACK to 22 -> ${tracked#* }, ACK to $PORT (control) -> ${untracked#* }"
  [ "${tracked#* }" = 0 ] && [ "${untracked#* }" -ge 1 ]
}
check "F-7 non_syn_new_tcp_is_dropped" non_syn_new_tcp_is_dropped

# --- F-6 ------------------------------------------------------------------------------------
ssh_only_from_admin_networks() {
  local ok=0
  expect_line timeout pa connect --src "$ATTACKER" --dst "$RELAY" --port 22 --timeout 1.5 || ok=1
  expect_line connected pa connect --src "$ADMIN" --dst "$RELAY" --port 22 || ok=1
  return $ok
}
check "F-6 ssh_only_from_admin_networks" ssh_only_from_admin_networks

ssh_connections_per_source_are_capped() {
  pa hold --src "$ADMIN" --dst "$RELAY" --port 22 -n 9 >"$work/hold"
  tr '\n' ' ' <"$work/hold"
  echo
  [ "$(head -n8 "$work/hold" | sort -u)" = connected ] && [ "$(sed -n 9p "$work/hold")" = refused ]
}
check "F-6 ssh_connections_per_source_are_capped (9th of one admin address reset)" ssh_connections_per_source_are_capped

# --- F-8 ------------------------------------------------------------------------------------
echo_is_metered_per_source() {
  local flood other
  flood=$(sniff_during 1.5 echo-reply 203.0.113.70/32 -- pa ping --src 203.0.113.70 --dst "$RELAY" -n 60)
  other=$(sniff_during 1 echo-reply 203.0.113.71/32 -- pa ping --src 203.0.113.71 --dst "$RELAY" -n 1)
  echo "echo replies: 60 requests from one source -> ${flood% *}; another source -> ${other% *}"
  [ "${flood% *}" -ge 5 ] && [ "${flood% *}" -le 15 ] && [ "${other% *}" = 1 ]
}
check "F-8 echo_is_metered_per_source (5/s burst 10)" echo_is_metered_per_source

# --- F-9 ------------------------------------------------------------------------------------
the_relay_user_cannot_dial_out() {
  local ok=0
  expect_line refused as_tcn python3 "$pkt" connect --dst 127.0.0.1 --port 8080 || ok=1
  expect_line refused as_tcn python3 "$pkt" connect --dst "$ATTACKER" --port 8081 || ok=1
  # Root (package updates, NTP) is not restricted.
  expect_line connected rx python3 "$pkt" connect --dst "$ATTACKER" --port 8081 || ok=1
  # Control: without the reject rule the same dial connects (the rule is what stops it).
  load "$(without 'counter reject comment "zt-relay egress"' egress)" || ok=1
  expect_line connected as_tcn python3 "$pkt" connect --dst 127.0.0.1 --port 8080 || ok=1
  load "$ruleset" || ok=1
  return $ok
}
check "F-9 the_relay_user_cannot_dial_out (loopback, internal network)" the_relay_user_cannot_dial_out

# --- F-11 -----------------------------------------------------------------------------------
a_reload_keeps_established_relay_connections() {
  expect_line "before=echoed reload_rc=0 after=echoed" \
    pa reload --dst "$RELAY" --port "$PORT" --cmd "ip netns exec $R nft -f $ruleset"
}
check "F-11 a_reload_keeps_established_relay_connections" a_reload_keeps_established_relay_connections

# --- F-5 ------------------------------------------------------------------------------------
tiny_mss_syns_are_dropped() {
  local tiny normal
  tiny=$(sniff_during 1 synack 203.0.113.61/32 -- pa syn --dst "$RELAY" --dport "$PORT" --src 203.0.113.61 --mss 48)
  normal=$(sniff_during 1 synack 203.0.113.60/32 -- pa syn --dst "$RELAY" --dport "$PORT" --src 203.0.113.60 --mss 1460)
  echo "SYN-ACKs: MSS 48 -> ${tiny#* }, MSS 1460 (control) -> ${normal#* }"
  [ "${tiny#* }" = 0 ] && [ "${normal#* }" = 1 ]
}
check "F-5 tiny_mss_syns_are_dropped" tiny_mss_syns_are_dropped

# --- F-13 -----------------------------------------------------------------------------------
rpf_drops() {
  rx nft -j list chain inet zt_relay raw_pre 2>/dev/null | python3 -c '
import json, sys
for i in json.load(sys.stdin)["nftables"]:
    r = i.get("rule")
    if r and "reverse path" in r.get("comment", ""):
        print(next(e["counter"]["packets"] for e in r["expr"] if "counter" in e))
        break
else:
    print(-1)'
}

unroutable_sources_are_dropped() {
  local before after
  before=$(rpf_drops)
  pa syn --dst "$RELAY" --dport "$PORT" --src 10.66.0.1 >/dev/null
  pa syn --dst "$RELAY" --dport "$PORT" --src "$RELAY" >/dev/null
  sleep 0.2
  after=$(rpf_drops)
  echo "reverse-path drops: $before -> $after"
  [ "$before" -ge 0 ] && [ $((after - before)) -eq 2 ]
}
check "F-13 unroutable_sources_are_dropped (no route back; our own address)" unroutable_sources_are_dropped

# --- F-2 ------------------------------------------------------------------------------------
conntrack_count() { rx cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0; }

flood_delta() {
  local before after
  before=$(conntrack_count)
  pa syn --dst "$RELAY" --dport "$PORT" --src-net "$SPOOF_NET" -n 2000 >/dev/null
  after=$(conntrack_count)
  echo $((after - before))
}

a_syn_flood_to_the_relay_port_creates_no_conntrack_entries() {
  local delta control ok=0
  rx nft list table inet zt_relay >/dev/null || { echo "ruleset not loaded"; return 1; }
  delta=$(flood_delta)
  echo "conntrack entries after 2000 spoofed SYNs: +$delta"
  [ "$delta" -le 5 ] || ok=1
  expect_line echoed pa connect --src "$LEGIT" --dst "$RELAY" --port "$PORT" --echo || ok=1
  # Control: the same ruleset with the relay port tracked does fill the table (the measurement
  # works). Entries are only inserted for accepted packets, so the accept rule stays.
  sed -e '/notrack/d' -e 's/ct state untracked accept/accept/' "$ruleset" >"$work/tracked.nft"
  load "$work/tracked.nft" || return 1
  control=$(flood_delta)
  echo "control, relay port tracked: +$control"
  [ "$control" -ge 500 ] || ok=1
  load "$ruleset" || ok=1
  rx conntrack -F >/dev/null 2>&1 || true
  return $ok
}
check "F-2 a_syn_flood_to_the_relay_port_creates_no_conntrack_entries" a_syn_flood_to_the_relay_port_creates_no_conntrack_entries

# --- F-3 / F-14 -----------------------------------------------------------------------------
one_source_over_the_syn_meter_is_throttled_alone() {
  local counts unique ok=0
  sleep 1 # meters of earlier tests refill
  counts=$(sniff_during 2.5 synack 203.0.113.50/32 -- pa syn --dst "$RELAY" --dport "$PORT" --src 203.0.113.50 -n 2000)
  unique=${counts#* }
  echo "SYN-ACKs to one source for 2000 SYNs: $unique distinct (burst 500 + 50/s)"
  [ "$unique" -ge 400 ] && [ "$unique" -le 700 ] || ok=1
  expect_line echoed pa connect --src "$LEGIT" --dst "$RELAY" --port "$PORT" --echo || ok=1
  return $ok
}
check "F-3 one_source_over_the_syn_meter_is_throttled_alone" one_source_over_the_syn_meter_is_throttled_alone

synack_reflection_is_bounded() {
  local counts total unique
  counts=$(sniff_during 5 synack 203.0.113.99/32 -- pa syn --dst "$RELAY" --dport "$PORT" --src 203.0.113.99 -n 2000)
  total=${counts% *}
  unique=${counts#* }
  echo "SYN-ACKs reflected to a spoofed victim for 2000 SYNs: $total packets, $unique connections"
  # At most the meter's share, each sent at most 1 + tcp_synack_retries (2) times; the burst
  # itself is answered (the relay is reachable, the measurement works).
  [ "$unique" -ge 400 ] && [ "$unique" -le 700 ] && [ "$total" -le $((3 * unique)) ]
}
check "F-14 synack_reflection_is_bounded" synack_reflection_is_bounded

# --- F-4 ------------------------------------------------------------------------------------
rotating_addresses_in_a_slash64_share_one_meter() {
  local counts unique ok=0
  counts=$(sniff_during 2.5 synack 2001:db8:77:1::/64 -- pa syn --dst "$RELAY6" --dport "$PORT" --src-net 2001:db8:77:1::/64 -n 2000)
  unique=${counts#* }
  echo "SYN-ACKs to 2000 addresses of one /64: $unique (burst 500 + 50/s)"
  [ "$unique" -ge 400 ] && [ "$unique" -le 700 ] || ok=1
  counts=$(sniff_during 1 synack 2001:db8:77:2::/64 -- pa syn --dst "$RELAY6" --dport "$PORT" --src 2001:db8:77:2::1 -n 1)
  echo "another /64: ${counts#* } SYN-ACK"
  [ "${counts#* }" = 1 ] || ok=1
  return $ok
}
if has_ipv6; then
  check "F-4 rotating_addresses_in_a_slash64_share_one_meter" rotating_addresses_in_a_slash64_share_one_meter
else
  skip "F-4 rotating_addresses_in_a_slash64_share_one_meter" "no IPv6 in this kernel"
fi

# --- P-19 (PROXY mode ruleset, rendered by the Ansible role) --------------------------------
proxy_mode_drops_non_proxy_sources() {
  # The rendered PROXY ruleset trusts only 198.51.100.3/32 (LEGIT) as a proxy.
  local ok=0
  load "$PROXY_RULESET" || return 1
  expect_line echoed pa connect --src "$LEGIT" --dst "$RELAY" --port "$PORT" --echo || ok=1
  expect_line timeout pa connect --src "$ATTACKER" --dst "$RELAY" --port "$PORT" --timeout 1.5 || ok=1
  load "$ruleset" || ok=1
  return $ok
}
if [ -n "${PROXY_RULESET:-}" ]; then
  check "P-19 proxy_mode_drops_non_proxy_sources" proxy_mode_drops_non_proxy_sources
else
  skip "P-19 proxy_mode_drops_non_proxy_sources" "set PROXY_RULESET to a rendered PROXY-mode ruleset"
fi

summary
