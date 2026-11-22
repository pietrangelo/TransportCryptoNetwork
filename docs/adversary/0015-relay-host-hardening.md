# Adversary review 0015: relay hardening (PROXY v2, accept loop, budget) and host hardening (unit, nftables, sysctl, Ansible, CI)

- **Scope:**
  - **A. Relay code**: `git diff 302baed..2f9795c` on `claude/project-thread-mkiu34` (24 files,
    +3 461/−73). This covers strict PROXY protocol v2 (`zt-proto/src/proxy_v2.rs`), the
    `IpPrefix`/`PrefixSet` types (`zt-domain/src/prefix.rs`), `[network] listen_backlog`,
    `[proxy_protocol]` (`zt-net/src/config.rs`), the header pool and dispatch (`relay.rs`), accept
    error classification and back-off (`net.rs`), the budget from the process's own cgroup
    (`budget.rs`), the blocking-pool cap and the `RLIMIT_NOFILE` warning (`lifecycle.rs`), and
    `fuzz/fuzz_targets/proxy_v2.rs`.
  - **B. Host hardening**: uncommitted in worktree `agent-ac610e16255ef430c` (base `302baed`).
    This covers `packaging/systemd/zt-relay.service`, `packaging/nftables/zt-relay.nft`,
    `packaging/sysctl/*`, `packaging/tests/host/*`, `deploy/ansible/`, `docs/RELAY_HARDENING.md`
    and the `host-hardening` CI job.
- **Requirements checked against:** `docs/analysis/relay-hardening.md` §2–§4. I judged the code,
  not what the design says about it.
- **Reviewer:** independent adversary (step 5 of METHODOLOGY). I did not write this code.
- **Note:** CLAUDE.md says the project's own instructions are encrypted and that a SessionStart
  hook decrypts them. They were **not** visible in this reviewer's context. This review relies
  only on `docs/` and on the code.

## Verdict

There is **one high-severity finding**. It blocks the merge until it is fixed or explicitly
downgraded:

- **A15-1:** the nftables egress lock of user `tcn` can be bypassed. Code running inside
  `zt-relay` can bind the relay port, which `SocketBindAllow=tcp:7443` allows, and dial anywhere
  with source port 7443, because `meta skuid "tcn" tcp sport $RELAY_PORT accept` lets that out.
  That reaches the cloud metadata address, root-only loopback services and the internal network.
  RELAY_HARDENING.md's "no dial-out" claim is therefore false in direct mode.

There is **one medium** finding:

- **A15-2:** path-MTU discovery is broken for every relay-port connection. An ICMP
  fragmentation-needed message about an untracked flow has no conntrack entry, so nftables
  classifies it as `ct state invalid`. The `ct state vmap { invalid : drop … }` rule drops it
  before the ICMP-error accept rule, which comes later in the chain.

There are **six low** findings (A15-3 to A15-8) and **two test-quality** findings (A15-9,
A15-10).

The PROXY v2 parser, the prefix types and the relay integration held against every parsing,
smuggling, spoofing and resource attack I tried.

### Checks run

| Check | Result |
| :- | :- |
| `cargo test -p zt-proto --test proxy_v2`, `-p zt-domain --test prefix`, `-p zt-net --test proxy_v2 --test relay_hardening --test config` | 19 + 9 + 15 + 15 + 23 passed, but `per_source_caps_apply_to_the_real_peer` is **flaky**: it failed 2 times in 9 runs of the whole file (A15-9) |
| `packaging/tests/host/attacks.sh` (temporary `tcn` user, netns) | 15 passed, 2 skipped: this kernel has no IPv6 (F-4), and PROXY_RULESET was not set at first |
| `packaging/tests/host/spec.sh` (no APPLY_SYSCTL) | 21 passed, 2 skipped (IPv6 keys, applied values) |
| `deploy/ansible/tests/check.sh` (ansible-core 2.22.0, `ZT_RELAY` = debug build of 2f9795c) | 35 passed, 0 skipped (ansible-lint production profile included) |
| `shellcheck -x` on the new scripts; `zizmor 1.32.0 --offline` on ci.yml | clean; no findings (5 suppressed) |
| Randomised differential check of `parse` against `fixed`+`body` (3 M structured inputs, fuzz-target properties) | no violation |
| Mutations of the nftables ruleset (6), each through `attacks.sh` | 6 of 6 killed: tiny MSS → F-5, `ct count` → F-6, non-SYN new → F-7, echo meter → F-8, fib → F-13, SYN meter → F-3/F-14 |
| Mutations of the relay code (5), in a copy under the scratchpad | 4 of 5 killed. **M2 survived**: the header slot held for the connection's whole life (A15-10) |
| `systemd-e2e.sh` | **not run**: it needs a booted systemd, and the task forbade starting systemd |
| Reproducers | `scratchpad/adv15/`: `egress.sh` + `egress.py` (A15-1); `pmtu.sh` + `pmtu.py` (A15-2); `meterfill.sh` (A15-3); `mss3.py` (A15-11) |

## Outcome

The findings are fixed as uncommitted working-tree changes in two trees: the Rust code on
`claude/project-thread-mkiu34`, and the host hardening in worktree `agent-ac610e16255ef430c`.
Each regression test was written first and seen failing, then the fix made it pass.

| # | Severity | Outcome |
| :-: | :- | :- |
| A15-1 | High | Mitigated by `F-9 the_relay_user_cannot_dial_out_from_the_relay_port` (`attacks.sh`) |
| A15-2 | Medium | Mitigated by `F-16 icmp_errors_about_relay_connections_reach_the_relay` (`attacks.sh`) |
| A15-3 | Low | Mitigated by `F-3 a_full_syn_meter_still_bounds_new_sources` (`attacks.sh`) |
| A15-4 | Low | Mitigated by `A15-4 the pre-restart check is given exactly ExecStart='s arguments` (`check.sh`) and `check_takes_the_options_of_run_and_agrees_with_it` (zt-relay `lifecycle`) |
| A15-5 | Low | Mitigated by `A15-5 pools beyond LimitNOFILE are refused` (`check.sh`) and `check_prints_the_descriptor_need` (zt-relay `lifecycle`) |
| A15-6 | Low | Mitigated by `A15-6 allow_direct: relay.toml, firewall and unit all admit direct peers` (`check.sh`) and `P-20 allow_direct_admits_direct_peers` (`attacks.sh`) |
| A15-7 | — | No finding carries this ID in the review; the accepted low rows 6.7 and 7.2 stand |
| A15-8 | Low | Mitigated by `whole_space_through_short_prefixes_is_refused` (zt-domain `prefix`) |
| A15-9 | Low (test) | Mitigated by `per_source_caps_apply_to_the_real_peer`, made deterministic (10 runs of the file in a row pass) |
| A15-10 | Low (test) | Mitigated by `the_header_slot_is_released_after_the_header` (kills M2) |
| A15-11 | Info | Documented (rule comment, RELAY_HARDENING §8) |

Checks after the fixes: `cargo fmt --all --check` and `cargo clippy --workspace --all-targets
--all-features -- -D warnings` are clean. The affected Rust test files pass (zt-domain `prefix`,
zt-net `config`, `relay_hardening` and `proxy_v2` (10 runs of the file), zt-proto `proxy_v2`,
zt-relay `lifecycle` and `operations`). `spec.sh`: 24 passed, 2 skipped (no IPv6 keys; applied
values). `attacks.sh` with both PROXY renderings: 20 passed, 2 skipped (no IPv6 in this kernel).
`check.sh` with the relay built from the Rust tree: 63 passed. `shellcheck -x` and `zizmor
--offline` are clean. `systemd-e2e.sh` was not run, as for the review: it needs a booted systemd.

## Findings

### Surface 1: PROXY protocol v2 parser (`zt-proto/src/proxy_v2.rs`)

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 1.1 | A declared length of `u16::MAX` makes the relay read or allocate 64 KiB | **Mitigated**: `fixed` checks the length (`MAX_BODY`, 512) before any body read; the stack buffer is 512 bytes (`a_huge_declared_length_is_refused_without_reading`) |
| 1.2 | A body shorter than the address block (IPv4 len 11, IPv6 len 35) | **Mitigated**: `Length` from `fixed` (proxy_v2 tests); held under 3 M randomised inputs |
| 1.3 | A TLV that overruns the body, or a trailing 1–2 byte partial TLV | **Mitigated**: `check_tlvs` uses only checked slicing; it returns `Tlv` (tests plus the randomised run) |
| 1.4 | A v1 text header, `ver=1`/`3`, command 2–15, UDP families (`0x12`, `0x22`), `AF_UNIX` (`0x31`) | **Mitigated**: refused by reason (`a_v1_header_from_a_trusted_proxy_is_closed`, table tests) |
| 1.5 | The source is `0.0.0.0`, `::`, multicast, broadcast, or `::ffff:224.x` / `::ffff:0.0.0.0` (IPv4-mapped) | **Mitigated**: canonicalised, then refused (`degenerate_source_addresses_are_refused`; mutation M5 is killed) |
| 1.6 | A loopback, link-local or trusted-proxy address as the source | **Accepted**: no privilege is attached to any source address. Admission only *counts* per source, so claiming one only charges that bucket |
| 1.7 | Header and message 1 arrive in one segment, and the parser over-reads into message 1 | **Mitigated**: exact `read_exact` of 16 bytes, then of `len` (`header_and_msg1_in_one_write_complete_the_handshake`) |
| 1.8 | A second header right after the first, to charge a different source | **Mitigated** (`a_second_header_is_not_parsed`) |
| 1.9 | Panics or arithmetic overflow on arbitrary bytes | **Mitigated**: no indexing or unchecked arithmetic; the randomised differential run (fuzz-target properties) found nothing. The fuzz target could not be run locally (no nightly or cargo-fuzz) |
| 1.10 | Error text echoes received bytes | **Mitigated**: static messages (`proxy_header_failures_are_logged_without_bytes`) |

### Surface 2: trusted prefixes and `[proxy_protocol]` (`zt-domain/src/prefix.rs`, `config.rs`)

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 2.1 | `/0`, host bits set, `/33`, `/129`, `/08`, `+8`, IPv4-mapped prefixes, overlap or duplicate entries, 65 entries | **Mitigated** (zt-domain `prefix` tests, config tests) |
| 2.2 | The relay listens on `[::]` and an IPv4 proxy arrives as `::ffff:a.b.c.d`, so it is not matched | **Mitigated**: `contains` canonicalises the address |
| 2.3 | **The `/0` guard is bypassed with `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`)**: every internet source is then "trusted" and can choose its own admission source | **Mitigated by `whole_space_through_short_prefixes_is_refused`** (zt-domain `prefix`) and two new rows of `proxy_protocol_config_is_strict` (zt-net `config`) (A15-8, low): a prefix shorter than /8 (IPv4) or /16 (IPv6) is refused (`PrefixError::TooBroad`), so 64 entries cover at most a quarter of IPv4. As found: `PrefixSet::new` accepts the four halves, and `contains` is true for 1.2.3.4, 203.0.113.9, 2001:db8::1 and fe80::1 (scratch test `adv15_prefix.rs`). Fix: refuse a set whose prefixes together cover a whole family, or require a length of at least /8 and /16 |
| 2.4 | `header_timeout_secs` 0 or 11, `listen_backlog` 127, 65536 or negative | **Mitigated** (config tests) |

### Surface 3: relay dispatch, header pool and accept loop (`relay.rs`, `net.rs`)

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 3.1 | An untrusted source sends a forged header (`allow_direct = true`) | **Mitigated**: no header is parsed; the bytes become an invalid message 1 (`a_header_from_an_untrusted_source_is_never_believed`; mutation M1, "trust everyone", is killed by 3 tests) |
| 3.2 | A trusted source sends no header or trickles it | **Mitigated**: closed at the deadline measured from accept (`a_trickling_header_is_closed_at_its_deadline`) |
| 3.3 | Many idle connections from the proxy exhaust the header pool and starve admission | **Accepted**: the pool is separate and bounded (`the_header_pool_is_bounded_and_spares_established_sessions`). It is global, not per proxy, so one misbehaving proxy (or one that delays the header until client data) can starve the others for `header_timeout`. This is in line with §3.5 |
| 3.4 | Per-source caps apply to the proxy instead of the real peer | **Mitigated** (`per_source_caps_apply_to_the_real_peer`, now deterministic: A15-9) |
| 3.5 | A LOCAL header from a proxy gets a full handshake as the proxy's address | **Accepted**: this is what the specification says; it is charged to the proxy's own bucket (`a_local_header_is_admitted_as_the_proxy`) |
| 3.6 | Connections in the header phase keep the drain waiting | **Mitigated** (`draining_closes_connections_still_in_the_header_phase`; mutation M4 is killed) |
| 3.7 | **The header slot is released only after the header**: this is not pinned by any test | **Mitigated by `the_header_slot_is_released_after_the_header`** (zt-net `proxy_v2`; A15-10, low): it kills M2. As found: mutation M2 (`relay.rs:1072`: keep `slot` alive until `task.serve` returns) passes all 15 proxy tests. A regression would cap *established* proxied sessions at `max_preauth` |
| 3.8 | `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` make the accept loop spin | **Mitigated**: back-off from 10 ms to 1 s (`emfile_backs_off_and_recovers`; mutation M3 is killed) |
| 3.9 | A per-connection error (ECONNABORTED storm) slows accepts or floods logs | **Mitigated**: no delay, and at most one WARN per summary interval (`transient_accept_errors_do_not_stall_the_accept_loop`). A *persistent* non-resource error (EINVAL, EBADF) would now spin without the old 100 ms sleep; I could not trigger one |
| 3.10 | The budget escapes the cgroup through `..` in `/proc/self/cgroup`, a cgroup v1 or hybrid layout, `memory.high`, or a hidden `/proc/meminfo` | **Mitigated** (`no_limit_unreadable_or_odd_cgroups_give_none`, `memory_high_and_ancestors_lower_the_limit`, `meminfo_hidden_still_gives_a_bounded_budget`) |
| 3.11 | The new `sysinfo(2)` or `prlimit64` calls are killed by the new `~@resources` filter (SIGSYS at start) | **Mitigated**: I expanded the groups with systemd 255's `systemd-analyze syscall-filter`. Both stay allowed; only `setrlimit`, `sched_set*`, `mbind`, `set_mempolicy` and `io_uring_*` are removed, and the code calls none of them |

### Surface 4: nftables ruleset (`packaging/nftables/zt-relay.nft` and the template)

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 4.1 | **RCE in zt-relay dials out by binding the relay port**. The output chain accepts any `tcn` packet with `tcp sport 7443`, and `SocketBindAllow=tcp:7443` lets the process bind it | **Mitigated by `F-9 the_relay_user_cannot_dial_out_from_the_relay_port`** (`attacks.sh`, with a control) and `F-9 egress_refuses_syns_from_the_relay_port_first` (`spec.sh`) (A15-1, high). See below |
| 4.2 | **PMTUD: ICMP frag-needed or packet-too-big about relay-port (untracked) flows is dropped** | **Mitigated by `F-16 icmp_errors_about_relay_connections_reach_the_relay`** (`attacks.sh`, with a control; the IPv6 twin runs where IPv6 exists) and `F-16 icmp_errors_come_before_the_invalid_drop` (`spec.sh`) (A15-2, medium). See below |
| 4.3 | **The SYN meter stops limiting anyone once spoofed sources fill its 65 536-entry set** | **Mitigated by `F-3 a_full_syn_meter_still_bounds_new_sources`** (`attacks.sh`) (A15-3, low). See below |
| 4.4 | A SYN flood fills conntrack | **Mitigated**: notrack on the relay port (F-2: +0 entries, control +2000) |
| 4.5 | Non-SYN new TCP, SSH from outside the admin networks, more than 8 SSH connections per admin source, echo floods, unroutable or own-address sources | **Mitigated**: F-7, F-6, F-8, F-13. Every protection was removed in turn and its test failed |
| 4.6 | Tiny-MSS SYNs (CVE-2019-11477 class) | **Mitigated** (F-5). But a SYN with two MSS options (1460, then 48) is **not** dropped by the nft rule: the rule counter went up only for the single-48 SYN (`mss3.py`). The sysctl `net.ipv4.tcp_min_snd_mss = 536` is the real backstop (A15-11, informational). **Outcome:** both copies of the rule now say so in a comment, and RELAY_HARDENING §8 says the sysctl must stay (A15-11) |
| 4.7 | The relay's replies are dropped by the egress lock or by notrack | **Mitigated** (F-10, F-11) |
| 4.8 | IPv6 NDP; MLD queries dropped (they are not in the accept list), so MLD-snooping switches age out the solicited-node group; DHCPv6 replies (unicast reply to a multicast solicit, so not "established") dropped | **Not verified**: this kernel has no IPv6. By reading, MLD (type 130) and UDP 546 fall to `policy drop`. DHCPv6 is documented (`zt_relay_nft_extra_input`); MLD is not. Check in CI (STRICT on ubuntu-24.04 has IPv6). **Outcome:** NDP is now accepted before conntrack's verdict (A15-2); MLD and DHCPv6 are unchanged and still to be checked in CI |
| 4.9 | Rule ordering: a relay-port packet from a non-proxy source in PROXY mode | **Mitigated**: the drop comes before notrack (P-19 in CI; I rendered it locally and the proxy ruleset is what `check.sh` renders) |
| 4.10 | The colocated-agent variant lets an RCE reach local sshd (`oif lo tcp dport 22`) | **Accepted**: the agent needs it; it is documented as the colocated trade-off. SSH credentials are still required |

### Surface 5: systemd unit

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 5.1 | RCE runs `/bin/sh`, opens another listener, or writes to `/etc/tcn` | Not run here (needs systemd). `systemd-e2e.sh` U-2/U-3/U-4 cover it in CI |
| 5.2 | AF_UNIX stays allowed: an RCE can talk to journald and the system D-Bus as `tcn` | **Accepted**: this predates the change (sd_notify needs AF_UNIX) |
| 5.3 | PROXY mode: `IPAddressDeny=any` + `IPAddressAllow=<proxies>` also stops A15-1 there | Not verified here (needs systemd and cgroup BPF). By design it would |

### Surface 6: Ansible role (operator mistakes)

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 6.1 | Unverified binary: wrong or missing SHA-256, release with no pins | **Mitigated** (A-1 checks run for real) |
| 6.2 | An invalid `relay.toml`, policy or denylist goes live | **Mitigated**: `copy … validate: zt-relay check` (A-2: `max_preauth = 0` exits 78) |
| 6.3 | **Invalid `zt_relay_extra_args` (typo, `--drain-timeout 99999`) is not checked**: the handler runs `check` with `zt_relay__relay_args` only, while `ExecStart=` appends the extra arguments. `run` then exits 2, which is not 78, so `Restart=always` loops with the relay down | **Mitigated by `A15-4 the pre-restart check is given exactly ExecStart='s arguments`** and `A15-4 the rendered pre-restart check refuses an out-of-range extra argument` (`check.sh`), and `check_takes_the_options_of_run_and_agrees_with_it` (zt-relay `lifecycle`) (A15-4, low). As found: `check --listen … --config …` exits 0; `run … --drain-timout 120` exits 2; `run … --drain-timeout 99999` exits 2. `serial: 1` and `max_fail_percentage: 0` stop the rollout after the first host |
| 6.4 | **`max_established`/`max_preauth` raised in `zt_relay_toml_extra` beyond `LimitNOFILE=16384`** | **Mitigated by `A15-5 pools beyond LimitNOFILE are refused`** (`check.sh`, the role's assertion run for real, with a control) and `check_prints_the_descriptor_need` (zt-relay `lifecycle`) (A15-5, low). The meters against raised admission limits stay an operator's tuning (RELAY_HARDENING §4). As found: `[admission] max_preauth = 4096, max_established = 60000` passes `zt-relay check` (exit 0). `run` under `ulimit -n 16384` only logs `fd_limit_low limit=16384 needed=64160`. The role neither refuses nor raises `LimitNOFILE`. The same applies to the nft SYN meter (50/s, burst 500) against a raised `source_burst`/`max_pending_per_source`: nothing cross-checks them |
| 6.5 | **`zt_relay_proxy_allow_direct: true` is silently ineffective**: the firewall (`relay_src_*` = proxies) and `IPAddressAllow=` still drop every direct peer, so a "migration" setting causes an outage for direct users | **Mitigated by `A15-6 allow_direct: relay.toml, firewall and unit all admit direct peers`** (`check.sh`) and `P-20 allow_direct_admits_direct_peers` (`attacks.sh`) (A15-6, low). As found: reproduced by rendering `variants/proxy.yml` + `-e zt_relay_proxy_allow_direct=true`: `relay.toml` has `allow_direct = true`; `relay_src_v4 = { <proxy>/32 }`; `IPAddressAllow=<proxies>` and `IPAddressDeny=any` |
| 6.6 | SSH lock-out by a wrong admin set | **Mitigated**: `systemd-run` rollback, `reset_connection`, then `wait_for_connection` (F-15 structure). I rendered the rollback command both ways; it is correct. The timer itself was not run (no systemd) |
| 6.7 | A firewall that drops the relay port (wrong proxy prefixes, or another table that drops untracked traffic) | **Accepted, low**: the rollback guards only SSH, and nothing probes the relay port after applying. There is no cheap controller-side probe in PROXY mode |
| 6.8 | Transient outage when switching to PROXY mode: the firewall is applied before the restart handler, so for a moment the old relay sees PROXY headers | **Accepted**: brief, and a mode switch is a planned change |

### Surface 7: CI job `host-hardening`

| # | Attack hypothesis | Outcome |
| :- | :- | :- |
| 7.1 | Unpinned actions, script injection, write token | **Mitigated**: SHAs are pinned, there is no `${{ }}` in `run:`, `contents: read`, `persist-credentials: false`; zizmor is clean |
| 7.2 | `pipx install ansible-core==… ansible-lint==…` without hashes; the transitive dependencies of ansible-lint are unpinned and later run as root (`sudo env PATH=$PATH`) | **Accepted, low**: the runner is ephemeral and the token read-only; the `ansible` job already uses unpinned `pipx install ansible-core` |
| 7.3 | Do the tests fail when the protection is removed? | Firewall: yes, 6 of 6. Relay: 4 of 5 (A15-10). The egress probe (F-9 and the e2e probe) only tries `connect()` without binding 7443, which is why it misses A15-1. **Outcome:** `attacks.sh` F-9 now binds the relay port, then dials (A15-1); relay mutation M2 is killed by A15-10's test. The e2e probe is unchanged: it is dependency-free safe Rust, and the standard library cannot bind a socket before `connect` |
| 7.4 | B is based on `302baed`: built alone, its `zt-relay` refuses `[proxy_protocol]` (`deny_unknown_fields`) and `check.sh` "A-2 proxy" fails | **Note**: B must land on top of A. The worktree diff also touches the encrypted `.claude/agents/adversary.md` and `.claude/private/CLAUDE.md`, which are unrelated to this change |

## Findings in detail

### A15-1 (high): the egress lock is bypassed through the relay port

**Outcome: Mitigated by `F-9 the_relay_user_cannot_dial_out_from_the_relay_port`.** Both copies of the ruleset (`packaging/nftables/zt-relay.nft` and `zt-relay.nft.j2`, kept identical by the drift check) now reject, before the accept, a SYN without ACK that user `tcn` sends from the relay port (`counter reject with tcp reset comment "zt-relay dial-out from the relay port"`). The test stops the relay stand-in, binds 7443 as `tcn` and dials loopback and the other namespace: both are refused; its control, the same ruleset without the rule, connects; the stand-in then echoes again. Failed before the fix (`connected`, `connected`), passes after. The e2e probe was not extended (see 7.3).

`packaging/nftables/zt-relay.nft:84` (template `zt-relay.nft.j2:103`): `meta skuid "tcn" tcp sport
$RELAY_PORT accept`. The relay is the only process of `tcn` and is allowed to bind 7443
(`SocketBindAllow=tcp:7443`; the e2e probe even asserts `bind_relay_port allowed`).

Code running inside the relay closes its listener fd, binds a new socket to `0.0.0.0:7443` and
calls `connect()`. The SYN leaves with source port 7443 and is accepted by the output chain;
`raw_out` notracks it. The reply SYN-ACK arrives on `tcp dport 7443`, where `relay_src_v4` is
`0.0.0.0/0` in direct mode, so it is notracked and accepted. The connection is established. On
IPv6 the listener can probably stay open (a second, `IPV6_V6ONLY` socket on `[::]:7443`). This
was not verified, because this kernel has no IPv6.

Reproducer (`scratchpad/adv15/egress.sh`, shipped ruleset, user `tcn`, netns):

```
1. tcn dials metadata without binding the relay port:        error 111 Connection refused
2. tcn binds 0.0.0.0:7443 and dials 169.254.169.254:80:      connected   (EXT got connection from ('10.99.0.1', 7443))
3. same, to a root-only service on 127.0.0.1:8080:           connected
4. listener alive, second bind with SO_REUSEADDR:            EADDRINUSE  (so the RCE closes the listener first)
```

The fix was verified with the same script: rule 1 stays refused, and attempts 2 and 3 become
`Connection refused`. A server never sends a bare SYN, so this rule does not affect the relay's
replies:

```
meta skuid "tcn" tcp sport $RELAY_PORT tcp flags & (syn | ack) == syn counter reject with tcp reset
meta skuid "tcn" tcp sport $RELAY_PORT accept
```

Also consider `IPAddressDeny=localhost link-local multicast` in direct mode too, and add a
"bind 7443 then connect" probe to `zt-relay-probe` and to F-9.

### A15-2 (medium): no PMTUD for relay connections

**Outcome: Mitigated by `F-16 icmp_errors_about_relay_connections_reach_the_relay`.** The ICMP and ICMPv6 error rules and the NDP rule now come before the echo meter and the `ct state` vmap; the echo meter is unchanged. The test holds a connection to the relay port, sends a fragmentation-needed quoting it (`pkt.py icmp-error`) and reads `IcmpInDestUnreachs` of the relay namespace from `/proc/net/snmp`: 1 delivered; its control without the accept rules: 0. Failed before (0), passes after. `spec.sh` also checks the order.

`zt-relay.nft:63` (`ct state vmap { invalid : drop, … }`) comes before `:66-67` (ICMP errors
accept). `nf_conntrack_inet_error()` finds no entry for the quoted, untracked relay-port flow
and leaves the ICMP error without a conntrack entry, so `ct state` evaluates to `invalid`. The
input chain therefore drops it before the ICMP-error accept rule.

Reproducer (`scratchpad/adv15/pmtu.sh`): with an established connection to 7443, an ICMP 3/4
(MTU 1280) quoting `relay:7443 → client` is sent, and the relay's `IcmpInDestUnreachs` counter is
read:

- shipped ruleset: 0;
- the same ruleset without `invalid : drop`: 1;
- the ICMP-error accept rules moved above the vmap: 1.

On IPv4 the relay's large segments then black-hole on any path with an MTU below the MSS. On
IPv6, where routers never fragment, the same applies by the same code path to `packet-too-big`;
this was not run here (no IPv6). `F-8 icmp_errors_are_never_rate_limited` only checks the text
of the rules.

Fix: move the two ICMP-error rules above the `ct state vmap`, or add
`untracked`/`invalid` handling for ICMP errors whose inner port is the relay port. Then add a
netns test like `pmtu.sh` with a control.

### A15-3 (low): the SYN meter turns off for everyone once full

**Outcome: Mitigated by `F-3 a_full_syn_meter_still_bounds_new_sources`.** The meter uses `update` (an active source keeps its entry and bucket) with a 10 s timeout, when a bucket of 50/s burst 500 is full again anyway, so keeping the set full takes over 6 500 spoofed SYN/s instead of 1 100. A new rule after each meter drops SYNs over a shared ceiling (1000/s, burst 1000, `zt_relay_syn_overflow_rate`/`_burst`, comment `SYN meter full`) for the sources not in the set, which only happens when it is full. The test fills `@syn_v4` with 80 000 spoofed sources (65 536 entries), then sends 5 000 SYNs from a new source: 5 000 SYN-ACKs before the fix, 1 115 after (bound: 500 to 2 500). RELAY_HARDENING §4 is corrected.

`zt-relay.nft:25-26,43-44`. When `@syn_v4` is full, `add` fails, the rule does not match and
the SYN is accepted.

Reproducer (`scratchpad/adv15/meterfill.sh`): one source sends 2 000 SYNs.

- Before: 503 SYN-ACKs.
- Then 80 000 SYNs from random spoofed sources in 100.64.0.0/11 fill the set in **2 s**
  (65 536 elements).
- The same source sends 2 000 SYNs again: **2 000** SYN-ACKs.

The attacker keeps the meter disabled with about 1.1 kpps of spoofed SYNs. RELAY_HARDENING §4
says only that "further sources are not metered; SYN cookies handle those". In fact every
source, including real ones that complete handshakes, is unmetered; only the relay's admission
remains. On IPv6, a single /48 holds exactly 65 536 /64s and fills `@syn_v6` without spoofing
(not run: no IPv6).

Fix: a fallback rule for sources not in the set, e.g.
`tcp flags & (…) == syn ip saddr != @syn_v4 limit rate over N/second drop`; or a shorter
timeout and a larger set; and a correction to the documentation.

### A15-4 (low): `zt_relay_extra_args` bypass the pre-restart check

**Outcome: Mitigated by `A15-4 the pre-restart check is given exactly ExecStart='s arguments`.** The role builds one argument vector (`zt_relay__run_options`, extra arguments included): `ExecStart=` renders `zt_relay__run_argv`, the handler runs `zt_relay__check_argv` (the same with `check`). `zt-relay check` now accepts and validates every option of `run` (`RunArgs`, flattened into both), so it refuses `--drain-timeout 99999` or a typo with the same exit code as `run`. `assert.yml` also refuses extra arguments with blanks, quotes, `$`, `%` or `\`. The check.sh tests failed before (no such vector, and `check` did not know `--drain-timeout`) and pass after.

`roles/zt_relay/handlers/main.yml:6` and `templates/10-ansible.conf.j2:5`. See 6.3 above.

Fix: validate the extra arguments against an allow-list of known `run` options with
range-checked values; or give `check` the run-only options; or make `run` exit 78 on a usage
error.

### A15-5 (low): pool sizes against `LimitNOFILE` and the firewall meters are not checked by the role

**Outcome: Mitigated by `A15-5 pools beyond LimitNOFILE are refused`.** `zt-relay check` prints `descriptors_needed = N` (`lifecycle::descriptors_needed`, the formula of `fd_limit_low`: max_preauth, twice in PROXY mode, + max_established + 64). The new `tasks/descriptors.yml` runs the check with ExecStart='s arguments and asserts `zt_relay_limit_nofile` (default 16384, rendered as `LimitNOFILE=` in the drop-in) covers it. check.sh runs the task for real: the default pools pass (direct, proxy), 4096/60000 is refused (64 160 > 16 384), and passes with the limit raised to 65 536. Failed before (no task, no line), passes after. The firewall meters against raised admission limits are left to the operator (RELAY_HARDENING §4).

See 6.4 above.

Fix: in `assert.yml`, parse `[admission]` out of `zt_relay_toml_extra`, or turn it into variables,
and assert `LimitNOFILE ≥ 2·max_preauth + max_established + 64`. Render `LimitNOFILE=` in the
drop-in. Make `zt-relay check` print the descriptor need.

### A15-6 (low): `zt_relay_proxy_allow_direct: true` is contradicted by the firewall

**Outcome: Mitigated by `A15-6 allow_direct: relay.toml, firewall and unit all admit direct peers`.** With `allow_direct`, `relay_src_v4/v6` are everything, the drop-in has no `IPAddressAllow=`/`IPAddressDeny=`, and the SYN meter applies to every source except the proxies (new sets `proxy_v4/v6`). The new variant `proxy-allow-direct` goes through every check.sh stage (render, nft -c, U-7, score at most 1.1, zt-relay check) and feeds `P-20 allow_direct_admits_direct_peers` in attacks.sh (the proxy and a direct peer both echo). Failed before, passes after.

`vars/main.yml:5-6` and `10-ansible.conf.j2:11-14`. See 6.5 above.

Fix: when `allow_direct` is true, `relay_src_*` = `0/0` and no `IPAddressDeny=`; or refuse
`allow_direct` in the role.

### A15-8 (low): the `/0` guard is bypassed by complementary halves

**Outcome: Mitigated by `whole_space_through_short_prefixes_is_refused`.** The stricter option: `IpPrefix` refuses a prefix shorter than /8 (IPv4) or /16 (IPv6) (`PrefixError::TooBroad`). OPERATIONS §4.1 says so; PROTOCOL §10.2 does not state the rule. Failed before (the halves parsed), passes after.

See 2.3 above.

### A15-9 (low, test): `per_source_caps_apply_to_the_real_peer` is flaky

**Outcome: Mitigated by `per_source_caps_apply_to_the_real_peer` (rewritten).** It waits for `source_limit` to reach 1, then requires exactly 50 of the 51 connections from one peer still open (whichever one was refused) and the 51 other peers untouched. The old version failed 1 run in 12 here; the new file passed 10 runs in a row.

`crates/zt-net/tests/proxy_v2.rs:495`. Repeated `cargo test -p zt-net --test proxy_v2`: 2
failures in 9 runs, at `assert!(closed_silently(last, …))`, while the preceding
`preauth(source_limit) == 1.0` passed.

The 51 header tasks run concurrently on 4 workers and reach admission in completion order, so
the refused connection is not necessarily the last one opened. CI will fail intermittently.

Fix: assert that exactly one of the 51 is closed, not the last one.

### A15-10 (low, test): releasing the header slot is not pinned

**Outcome: Mitigated by `the_header_slot_is_released_after_the_header`.** A stand-in proxy forwards each client connection from 127.0.0.2 behind a header; with `max_preauth = 2`, four complete sessions through it stay up together and `pool_full` stays 0. With M2 applied the third session is refused (`Closed`); without it the test passes.

`crates/zt-net/src/relay.rs:1072`. Mutation M2 (slot held for the connection's lifetime)
survives all 15 tests.

Fix: a test with `max_preauth = 2` that completes 3 proxied handshakes and keeps them all open.

### A15-11 (informational): the tiny-MSS rule only checks the first MSS option

**Outcome:** documented in the rule's comment and RELAY_HARDENING §8.

See 4.6 above. The sysctl `tcp_min_snd_mss = 536` covers it. Mention it in the comment so that
nobody drops the sysctl because "the firewall handles it".

## Clean-up

The temporary `tcn` user was deleted. The netns `adv15*`, `zt-*-ns` and `/tmp/adv15-h.*` were
removed. The scratch copy and its target directory under the scratchpad were deleted. No tracked
file was modified.
