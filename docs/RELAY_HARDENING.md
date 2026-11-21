# Relay host hardening: runbook

The relay is the only TCN component with a public listening port. This runbook covers the host
around it: the hardened systemd unit, the nftables ruleset, the kernel settings, the Ansible
role that installs all of them, what to tune, and what to do under attack. The design and its
attack catalogue are in [`docs/analysis/relay-hardening.md`](analysis/relay-hardening.md);
installation of the binaries themselves is in [OPERATIONS §9](OPERATIONS.md#9-installation-with-systemd).

| File | Installed as | What it does |
| :- | :- | :- |
| `packaging/systemd/zt-relay.service` | `/etc/systemd/system/zt-relay.service` | sandbox: no exec, one bindable port, seccomp without io_uring/keyring, memory and task limits (`systemd-analyze security`: **1.1**, 1.0 in PROXY mode) |
| `packaging/nftables/zt-relay.nft` | `/etc/nftables.d/zt-relay.nft` | own table `inet zt_relay`, inbound default drop, stateless relay port, per-source SYN and echo meters, SSH from admin networks only, egress lock of user `tcn` |
| `packaging/sysctl/90-zt-relay.conf` | `/etc/sysctl.d/90-zt-relay.conf` | SYN cookies and queues, no redirects or source routing, kernel exploit primitives off |
| `packaging/sysctl/zt-relay.modules-load.conf` | `/etc/modules-load.d/zt-relay.conf` | loads conntrack before `systemd-sysctl`, so its key applies at boot |
| `deploy/ansible/roles/zt_relay` | — | installs and verifies all of the above, one relay at a time |

## 1. What the host protects against, and what it cannot

| Threat | Host measure | Residual |
| :- | :- | :- |
| Port scans, exposed services | inbound policy drop, no RST and no ICMP unreachable for closed ports | — |
| Spoofed SYN flood | relay port untracked (conntrack cannot fill), SYN cookies, `tcp_synack_retries=2` | the uplink (§5) |
| One source opening connections fast | 50 SYN/s, burst 500, per IPv4 address or IPv6 /64, before conntrack; once spoofed sources fill the meter (65 536 entries), the sources it cannot track share 1000 SYN/s, burst 1000 | NATs above that rate retry after 1 s; while the meter is full, new sources compete for the shared ceiling (§4) |
| Tiny-MSS segments (CVE-2019-11477 class) | SYNs with MSS < 536 dropped, `tcp_min_snd_mss=536` | — |
| Code execution in `zt-relay` | no `execve` (`NoExecPaths=/`), no other listener (`SocketBindDeny=any`, where systemd enforces it: see the notes below), no dial-out (nftables output rules for user `tcn`: it may answer from the relay port, never send a SYN from it or from anywhere else), no writes, ≤ 512 tasks, memory capped | the key and the policy are readable (they must be): relays need **different** keys (OPERATIONS §8) |
| Handshake floods from many real addresses | the relay's admission (OPERATIONS §4.1) | new sessions refused while `max_preauth` is full; established ones continue. Only §5 helps |
| Volumetric floods (UDP reflection, Mpps) | nothing on the host can help | §5 |

## 2. Install

### 2.1 With Ansible (recommended)

```sh
cd deploy/ansible
cp inventory.example.ini inventory.ini        # admin networks, policy, binary + SHA-256
ansible-playbook -i inventory.ini playbooks/relay.yml
```

The play runs with `serial: 1`: one relay is checked, restarted and verified before the next
is touched (a restart drains the relay; restarting all of them at once leaves no listener).

What the role does, in order:

1. **Preconditions**: a policy is given, the admin set is not empty (unless
   `zt_relay_ssh_inbound: false`), every item of `zt_relay_extra_args` is one plain argument,
   `ufw` and `firewalld` are not active (two managers would fight over the ruleset).
2. **Binary, verified on the controller** (never by running a `zt-*` binary), failing closed:
   - `zt_relay_binary_source: local` (the default): a binary you verified yourself per
     OPERATIONS §9; its SHA-256 is required and compared on the controller and again on the host.
   - `zt_relay_binary_source: release`: a downloaded release directory, verified with the
     `tcn-release.sh` of your checkout against **your out-of-band pins file**
     (`zt_relay_release_pins_file`, never the one from the download), OpenSSL ≥ 3.5, then
     `sha256sum -c` of the archive. While no release key is pinned (before the key ceremony)
     this mode refuses to run.

   The binary is copied to `zt-relay.new`, its hash checked on the host, then renamed atomically.
3. **User** `tcn` from `tcn.sysusers` (`systemd-sysusers`); the ruleset matches on it.
4. **Key**: generated on the host with `zt-relay keygen` (never on the controller, never read
   by a task), `tcn:tcn 0600`. The public key is printed at the end of the play for the agents'
   and clients' `[[relays]]` entries.
5. **Policy, denylist, `relay.toml`**: staged in `/etc/tcn/staged`, then each put in place
   with `validate: zt-relay check …` against the others, so an invalid file never replaces a
   good one. A policy or denylist change is a `systemctl reload` (the relay validates and keeps
   the previous files if they are bad); a `relay.toml`, unit or binary change runs
   `zt-relay check` **as `tcn` with exactly the arguments of `ExecStart=`** (one argument
   vector renders both, `zt_relay_extra_args` included, so a typo or an out-of-range
   `--drain-timeout` fails the check, not the restart) and only then restarts.
6. **Descriptors**: `zt-relay check` prints `descriptors_needed` (`max_preauth`, twice in PROXY
   mode, + `max_established` + 64, the relay's own `fd_limit_low` formula); the role refuses
   to go on if `zt_relay_limit_nofile` is lower.
7. **Unit** (the packaged file) plus the drop-in `10-ansible.conf`: `ExecStart=`,
   `SocketBindAllow=` and the firewall's `RELAY_PORT` are rendered from one variable
   (`zt_relay_port`), so they cannot disagree; `LimitNOFILE=` from `zt_relay_limit_nofile`.
8. **sysctl** and modules-load files, applied with `systemd-sysctl`.
9. **Firewall**, behind a lock-out guard (§2.3).
10. The service is enabled and started, and `systemd-analyze security --threshold=11` must pass
   on the host.

Main variables (all in `roles/zt_relay/defaults/main.yml`):

| Variable | Default | Notes |
| :- | :- | :- |
| `zt_relay_port` | 7443 | renders `--listen`, `SocketBindAllow=`, `RELAY_PORT` |
| `zt_relay_listen_address` | `0.0.0.0` | `[::]` for dual stack |
| `zt_relay_admin_v4` / `_v6` | `[]` | networks allowed to SSH (required unless `zt_relay_ssh_inbound: false`) |
| `zt_relay_proxy_v4` / `_v6` | `[]` | non-empty = PROXY v2 mode (§4) |
| `zt_relay_proxy_allow_direct` | false | PROXY v2 mode that still admits direct peers (a migration, §6) |
| `zt_relay_syn_rate` / `_burst` | 50 / 500 | per-source SYN meter (§4) |
| `zt_relay_syn_overflow_rate` / `_burst` | 1000 / 1000 | shared ceiling of the sources a full meter cannot track (§4) |
| `zt_relay_limit_nofile` | 16384 | `LimitNOFILE=`; checked against relay.toml's pools |
| `zt_relay_extra_args` | `[]` | extra `run` arguments, also given to the pre-restart check |
| `zt_relay_listen_backlog` | unset (relay default 4096) | `relay.toml [network] listen_backlog` |
| `zt_relay_toml_extra` | `""` | further `relay.toml` tables, verbatim |
| `zt_relay_reverse_path_filter` | true | false on multi-homed hosts with asymmetric routes |
| `zt_relay_forward_chain` | true | false on a host that also runs a container runtime |
| `zt_relay_colocated_agent` | false | a `zt-agent` on the same host (also user `tcn`): allows it to dial `zt_relay_peer_relays_*` and local SSH |
| `zt_relay_nft_extra_input` | `[]` | extra input rules (e.g. a provider's DHCPv6) |

### 2.2 By hand

```sh
install -m 0644 packaging/systemd/tcn.sysusers /usr/lib/sysusers.d/tcn.conf && systemd-sysusers
install -m 0644 packaging/sysctl/90-zt-relay.conf /etc/sysctl.d/
install -m 0644 packaging/sysctl/zt-relay.modules-load.conf /etc/modules-load.d/zt-relay.conf
modprobe nf_conntrack && systemd-sysctl
install -m 0644 packaging/systemd/zt-relay.service /etc/systemd/system/
# Edit admin_v4/admin_v6 (the file ships documentation prefixes) BEFORE loading it.
install -D -m 0644 packaging/nftables/zt-relay.nft /etc/nftables.d/zt-relay.nft
nft -c -f /etc/nftables.d/zt-relay.nft
grep -q 'nftables.d' /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' >>/etc/nftables.conf
systemd-run --on-active=120 --unit=fw-rollback nft delete table inet zt_relay   # lock-out guard
nft -f /etc/nftables.d/zt-relay.nft
# From a NEW ssh session: if it works, cancel the guard.
systemctl stop fw-rollback.timer && systemctl enable nftables.service
```

A port other than 7443 must be changed in three places together: `--listen` (a drop-in),
`SocketBindAllow=` (same drop-in; reset it first with an empty `SocketBindAllow=`) and
`define RELAY_PORT` in the ruleset. A mismatch makes the relay fail to bind (exit 1, retried)
with the reason in the journal.

A dynamically linked build needs its loader and library directories in `ExecPaths=` (drop-in);
the release binaries are static.

### 2.3 Lock-out guard

The ruleset replaces only its own table, atomically. Before applying a changed ruleset the role
saves the previous file, arms `systemd-run --on-active=120` to restore it, applies, reconnects
(`reset_connection`, `wait_for_connection`) and only then cancels the timer. If the new rules
cut the controller off, the previous ruleset comes back by itself within two minutes. Test it
once per environment: apply a ruleset whose `admin_v4` excludes the controller, watch the play
fail at "the controller still reaches the host", wait 120 s, and log in again.

## 3. Verify

```sh
systemd-analyze security zt-relay.service             # 1.1 OK (1.0 in PROXY mode)
systemctl show -p NoExecPaths -p SocketBindAllow -p MemoryMax -p TasksMax zt-relay
nft list table inet zt_relay                          # counters per rule
sysctl net.ipv4.tcp_syncookies net.core.somaxconn net.ipv4.tcp_synack_retries
journalctl -u zt-relay -o cat | grep -E 'queue budget in use|admission_limits_in_use'
```

The repository's tests are the reference for each property: `packaging/tests/host/spec.sh`
(unit score and directives, ruleset structure, sysctl keys), `attacks.sh` (firewall behaviour
in network namespaces), `systemd-e2e.sh` (the real relay and a sandbox probe under the unit)
and `deploy/ansible/tests/check.sh` (the role). They run in the `host-hardening` CI job.

## 4. Tuning: firewall meters versus admission limits

The firewall and the relay limit different things; keep the firewall **looser** than the relay
so the relay, which sees identities and refunds, makes the decisions:

| Layer | Limit | Default | Counts |
| :- | :- | :- | :- |
| nftables | SYN per IPv4 address or IPv6 /64 | 50/s, burst 500 | every new TCP connection, completed or not |
| relay | `source_burst`, `source_refill_secs` | 64, then 1 per 3 s | handshakes that do not confirm a key (refunded on success) |
| relay | `max_pending_per_source` / `_per_wide` | 50 / 100 | handshakes in progress per address / per IPv6 /48 |
| relay | `max_preauth` | 1024 | handshakes in progress overall |
| kernel | `somaxconn`, relay `listen_backlog` | 4096 | connections waiting for `accept` |

- A controller or NAT that legitimately opens more than 500 connections at once, or more than
  50 per second for long, needs a higher `zt_relay_syn_rate`/`_burst`; raise the relay's
  `max_pending_per_source` and `source_burst` first if refusals show `source_limit`.
- A dropped SYN is not a failure: the client retransmits after 1 s, 3 s, ….
- The meter sets are bounded (65 536 entries; an entry lives 10 s after its source's last SYN,
  when its bucket would be full again anyway). A flood of random spoofed sources can fill
  them: then a new source cannot be added, so the sources the meter cannot track share one
  ceiling (`zt_relay_syn_overflow_rate`/`_burst`, 1000/s, burst 1000; counter `SYN meter
  full`) instead of going unmetered (finding A15-3). Sources already in the meter keep their
  own allowance; SYN cookies and the relay's admission handle the rest. Keeping a meter full
  takes over 6 500 spoofed SYN/s of distinct sources. An IPv6 attacker with a whole /48 owns
  65 536 /64s and can fill `syn_v6` without spoofing; the shared ceiling bounds that too.
- `LimitNOFILE=16384` covers `2 × max_preauth + max_established + 64` with the defaults.
  Raising `max_established` or `max_preauth` in `relay.toml` needs a drop-in with a larger
  `LimitNOFILE=` (`zt_relay_limit_nofile` with the role, which refuses a smaller one);
  `zt-relay check` prints the need (`descriptors_needed`) and the relay warns at startup
  (`fd_limit_low`) when the limit is too small.
- `MemoryMax=80%` is the last resort; the relay's queue budget (a quarter of the memory limit,
  OPERATIONS §18) sheds the slowest readers before it. Do not set `CPUQuota=`: it caps
  legitimate work during a handshake flood and makes it worse.

## 5. Upstream and volumetric DDoS

A host cannot drop what never reaches it: a reflection flood of tens of Gbit/s fills the uplink
before the NIC, and many providers null-route an attacked address. Patterns, cheapest first
(no vendor is endorsed):

1. **Provider edge ACLs.** TCN needs one inbound protocol: TCP to the relay port, plus SSH from
   the admin networks and ICMP. Allow only that in the provider's stateless network ACL or
   security group, enforced before your link: every UDP reflection flood disappears for free.
   Enable the provider's basic always-on L3/L4 protection if it has one.
2. **Several relays on independent networks** (TCN's own answer). Agents connect to all relays
   at once (up to 8); clients fail over in order (OPERATIONS §4, §8). Put relays with
   **different keys** on different providers or ASNs, some direct, some behind scrubbing: an
   attacker must take all of them down, and one relay under attack does not affect sessions on
   the others. Size `max_preauth` and `agent_reserve_percent` so the reconnect wave of a lost
   relay fits on the remaining ones.
3. **TCP scrubbing or reverse proxies in front of a relay, forwarding PROXY protocol v2**
   (§6). The proxy needs no TLS termination and sees only addresses and timing (the relay
   channel and the sessions are end to end). Move the relay to a **new address** when you put
   it behind a proxy: the old one is known.
4. **One name per relay.** TCN pins a key per relay address; anycasting one name over several
   relays would need a shared key, which widens a key compromise to all of them. Use one DNS
   name (and one proxy front end) per relay, listed as separate `[[relays]]` entries.
5. **DNS.** Short TTLs (60-300 s) on relay names let you move a relay behind a front end
   quickly; clients and agents resolve the name at every connection attempt. Serve the zone
   from a resilient provider with a secondary on another network.

## 6. Behind a proxy: PROXY protocol v2 mode

Without PROXY v2, every connection through a proxy comes from the proxy's address: the
relay's per-source limits then apply to the proxy, so 50 slow handshakes from anyone block
everyone, and logs name the proxy. With it, admission and logs see the real peer.

Set `zt_relay_proxy_v4` / `zt_relay_proxy_v6` to the proxies' egress prefixes. The role then:

- writes `relay.toml`:

  ```toml
  [proxy_protocol]
  trusted = ["203.0.113.0/24", "2001:db8:100::/48"]  # 1 to 64 prefixes, >= /8 and /16
  header_timeout_secs = 3
  allow_direct = false
  ```

  Connections from `trusted` must start with a v2 header (v1 is refused); other sources are
  closed at accept (`allow_direct = false`). A prefix shorter than /8 (IPv4) or /16 (IPv6) is
  refused, so no set of entries can trust the whole internet;
- restricts the relay port in nftables to the proxies (`relay_src_v4/v6`) and **removes the
  SYN meter** for it (it would throttle the whole user base, which arrives from a few proxy
  addresses);
- adds `IPAddressAllow=<proxies>` and `IPAddressDeny=any` to the unit (score 1.0).

Do the same in the provider ACL, so the origin is unreachable even if its address leaks.
Check that the proxy service emits **v2** (binary), not only v1. Proxy health checks without
a header are counted as `proxy_header` failures, aggregated, never one log line each. For a
migration, `allow_direct = true` (variable `zt_relay_proxy_allow_direct`) lets other sources
connect directly without a header: the role then opens the relay port to every source
(`relay_src_v4/v6` = everything, no `IPAddressAllow=`/`IPAddressDeny=`, score 1.1) and keeps
the per-source SYN meter for every source except the proxies (set `proxy_v4/v6`). Turn it off
once the clients use the proxy.

## 7. Under attack: incident playbook

1. **Confirm and classify.**

   ```sh
   zt-relay status                                  # sessions, refusals
   nft list table inet zt_relay | grep -E 'counter packets [1-9]'
   journalctl -u zt-relay -o cat --since -10min | grep -E 'preauth_summary|admission'
   ss -s; cat /proc/sys/net/netfilter/nf_conntrack_count
   ```

   - Link saturated, packet loss to the host, high softirq: **volumetric** → step 2.
   - `syn_v4`/`syn_v6` counters climbing: one or few sources over the meter (already dropped).
   - `tcn_relay_admission_refusals_total{reason="preauth_pool_full"}` climbing, many sources:
     **distributed handshake flood** → step 3.
   - `reverse path` counter climbing: spoofed sources (already dropped).
   - `SYN meter full` counter climbing: random spoofed sources filled the per-source meter;
     new sources share one ceiling until the entries expire (§4).
2. **Volumetric**: tighten the provider ACL to TCP/7443 + admin SSH + ICMP; ask the provider for
   upstream filtering; move the relay behind a scrubbing front end (new address, §6). Clients
   and agents keep working on the other relays meanwhile.
3. **Handshake flood from real addresses**: established sessions are unaffected. Raise
   `max_preauth` (and `LimitNOFILE` with it) if memory allows; lower `max_pending_per_source`
   only if the sources are few; put the relay behind a proxy with PROXY v2; add a relay.
4. **Suspected compromise of the relay host**: take it out of the clients' and agents'
   `[[relays]]`, rotate **its** key only (other relays have their own, OPERATIONS §8), rebuild
   the host from a verified binary. Before rebuilding, record the counter of the `zt-relay
   egress` rule (`nft list chain inet zt_relay output`): it counts dial-out attempts by the
   relay user, which never happen in normal operation, and the counter of `zt-relay dial-out
   from the relay port` (a SYN sent from the relay's own port, which a server never sends).
5. **Afterwards**: record the counters and timings, adjust meters per §4, and add the attack to
   `docs/adversary/` if it revealed something new.

## 8. Known limits

- `meta skuid "tcn"` needs the user when the ruleset loads: the file fails to load (as a whole,
  keeping the previous table) if `tcn` does not exist. At boot `systemd-sysusers.service` runs
  before `nftables.service`.
- `SocketBindAllow=`/`SocketBindDeny=` and `IPAddressAllow=` use cgroup BPF and need the
  unified cgroup hierarchy (cgroup v2, the default on current distributions).
  `SocketBindDeny=` also needs a systemd built with `+BPF_FRAMEWORK` (`systemctl --version`):
  Ubuntu's packages are built without it and accept the setting silently without enforcing it.
  There a compromised relay can bind another port, which the firewall still makes unreachable.
- The ICMP echo meter acts before conntrack's verdict: a ping flood keeps one ICMP identifier,
  so its requests would otherwise count as an established flow.
- ICMP errors (destination unreachable, packet too big, time exceeded, parameter problem) and
  neighbour discovery are accepted before conntrack's verdict, without a limit: the relay
  port is untracked, so an error about one of its connections has no conntrack entry and
  counts as invalid; dropping it would break path-MTU discovery (finding A15-2). The kernel
  matches each error against its own sockets.
- The tiny-MSS rule looks at the first MSS option of a SYN only; a SYN that carries a second,
  smaller one is caught by `net.ipv4.tcp_min_snd_mss = 536`, which must stay (A15-11).
- The sandbox probe of `systemd-e2e.sh` does not try "bind the relay port, then dial": it uses
  the standard library only, which cannot bind a socket before `connect`. `attacks.sh` F-9
  tries it as user `tcn` against the same ruleset; the unit's part (the port is bindable) is
  the probe's `bind_relay_port`.
- `kernel.kexec_load_disabled` and `kernel.sysrq` carry the `-` prefix: kernels built without
  kexec or SysRq have nothing to disable.
