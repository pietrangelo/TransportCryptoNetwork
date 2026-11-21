# TCN: hardening the internet-facing relay host (analysis for the next phase)

Status: analysis and design proposal. No repository file other than this one was changed.
Baseline: branch `claude/project-thread-mkiu34` at `b524c6e`.

Caveat: `CLAUDE.md` says the project instructions, skills and agent definitions are stored
encrypted and decrypted by a SessionStart hook. They were **not** visible in this session, so
this analysis relies only on `docs/`, the code and the tools run below. Any project rule in
those files is not reflected here.

Sources read: `docs/METHODOLOGY.md`, `docs/OPERATIONS.md` (§4, §4.1, §8, §9, §14, §17, §18),
`docs/PROTOCOL.md` §10.1, `docs/adversary/0004`, `0007` (AP-21), `0008`, `0013`,
`docs/analysis/resilience.md` (G15, §5.2), `packaging/systemd/*`, `packaging/release/*`,
`.github/workflows/*`, `crates/zt-net/src/{relay,net,budget,config,lifecycle,systemd}.rs`,
`crates/zt-application/src/{admission,ratelimit}.rs`, `bins/zt-relay/src/main.rs`,
`bins/zt-relay/tests/lifecycle.rs`, and the crate sources of `mio 1.2.4` and `rustix 1.1.6`
(the versions in `Cargo.lock`).

Tools run (versions of this container: systemd 255.4, nftables 1.0.9, kernel 6.18):

| Check | Result |
| :- | :- |
| `systemd-analyze security --offline=yes packaging/systemd/zt-relay.service` | **1.2 OK**, as OPERATIONS §9 says. Flagged: `SystemCallFilter=~@resources` 0.2, `PrivateNetwork=` 0.5, `RestrictAddressFamilies=~AF_(INET\|INET6)` 0.3, `IPAddressDeny=` 0.2, `RestrictAddressFamilies=~AF_UNIX` 0.1, `RootDirectory=/RootImage=` 0.1, `DeviceAllow=` (char-rtc:r, implied by `ProtectClock=`) 0.1 |
| same, with `--threshold=11` | exit 1 today; exit 0 with the unit proposed in §3.2 (**1.1**); 1.0 in PROXY mode with `IPAddressAllow=` |
| `systemd-analyze verify` | only "`/usr/local/bin/zt-relay` is not executable" (binary absent); clean once `ExecStart=` points at an existing file |
| `nft -c -f` of the ruleset in Appendix A (`unshare -rn`) | exit 0; loaded for real twice in a scratch network namespace (atomic replace works) |
| egress rule of Appendix A, behaviour (`unshare -n`, `setpriv --reuid=tcn`) | with the rule a `tcn` process gets `ECONNREFUSED` dialling a root listener on 127.0.0.1:8080 while its listener on 7443 still answers; **control run without the rule: the dial connects** |
| `nft` `define` inside `limit rate` / `ct count` | **rejected** by nft 1.0.9 ("unexpected '$', expecting number"): rate numbers must be literal, which shapes the Ansible design (§3.6) |
| `nft -c` with `limit rate over 0/second` | rejected by the kernel (`Invalid argument`): `nft -c` really goes through the kernel, so it is a meaningful CI check |

---

## 1. Threat model of an internet-facing relay host

### 1.1 Assets and attacker models

The relay is the only TCN component with a public listening port. Agents dial out, clients dial
out. The relay is blind: client and agent run an end-to-end Noise channel through it, so the
relay never holds session plaintext. What it holds:

- the relay secret key(s) (`/etc/tcn/relay.key`, `--previous-key`): whoever has them can
  impersonate the relay towards every agent and client that pins it (route, drop, observe
  metadata), but **cannot** read or forge end-to-end sessions, nor impersonate a client to an
  agent (the agent authenticates clients end to end);
- the policy (who may reach which node) and the metadata stream (which identity reaches which
  node, when, how much);
- availability of new and existing sessions for the whole fleet that uses this relay.

Attacker models (the 0007/0008 letters, plus two for this phase):

- (a) a remote host with no credentials, up to a botnet with many real source addresses;
- (c) the holder of one valid or stolen identity;
- (f) operator error;
- (g) a volumetric attacker who controls more bandwidth or packet rate than the host's uplink;
- (h) code execution inside `zt-relay` (an RCE through a parser bug, a dependency, a compiler
  bug): what can it reach from the sandbox?

### 1.2 Threats, and what the code already covers

The table states what is already true and which file or test proves it. "Host" means the
operating system around the process; "App" means TCN's own code.

| Threat | Where it bites | Already covered (verified in code) | Gap |
| :- | :- | :- | :- |
| **Volumetric L3/L4 floods** (UDP reflection: DNS, NTP, memcached, CLDAP; GRE; junk TCP) | the uplink and the NIC's packet rate, before any software sees the packet | nothing can be, on the host | §2(e): only upstream filtering helps. A host firewall still makes dropping cheap (no socket lookup, no conntrack) |
| **SYN flood** (spoofed sources) | kernel SYN queue; conntrack table, since every accepted SYN creates an entry; SYN-ACK retransmits towards spoofed victims | kernel default `tcp_syncookies=1` (distribution default, not pinned by TCN) | No pinned sysctl, no firewall: every spoofed SYN to 7443 that is accepted by an (absent) firewall policy enters conntrack if conntrack is loaded (§2(c), §2(d)) |
| **Connection floods** from real addresses (full 3-way handshakes) | accept queue, file descriptors, pre-auth pool | App: `Admission::on_accept` (per-source token bucket per IPv4 address or IPv6 /64, `source_burst` 64 then one per `source_refill` 3 s; a second bucket per /48 for *new* /64s; `max_pending_per_source` 50, `max_pending_per_wide` 100, `max_preauth` 1024), refusal = close without a reply. Tests: `one_source_holds_at_most_max_pending_per_source_slots`, `one_busy_host_cannot_lock_out_its_slash48_neighbours`, `a_whole_slash48_cannot_lock_out_other_networks`, `a_full_preauth_pool_does_not_disturb_established_sessions` | The **listen backlog is 128** (see §2(a)-1); each refused connection still costs an `accept`, a lock and a `close`; the admission happens after the kernel has done all the work |
| **Connection exhaustion: file descriptors** | `EMFILE` on `accept` | Unit `LimitNOFILE=16384` ≥ 1024 + 8192 (+ ~30 fixed descriptors); the accept loop sleeps 100 ms on any accept error (`relay.rs` ~L751, comment "E.g. EMFILE") | The sleep applies to **every** error kind (§2(a)-2); nothing checks `LimitNOFILE` against a `relay.toml` that raises `max_established` up to 1 048 576 (§2(a)-3) |
| **Connection exhaustion: conntrack** | `nf_conntrack: table full, dropping packet` drops *every* new flow on the host, SSH included | nothing | §2(c): make the relay port stateless (`notrack`); only accepted packets ever insert entries, so a default-drop policy also keeps scans out of the table |
| **Slowloris before the handshake** | pre-auth slots held by silent or trickling peers | `msg1_deadline` 5 s (floor 5 s), `handshake_timeout` 10 s, `first_frame_deadline` 5 s; oversized length prefixes refused on sight. Tests: `a_trickling_msg1_is_closed_at_the_msg1_deadline`, `oversized_msg1_prefix_is_refused_without_buffering`, `a_client_that_sends_no_frame_is_closed_at_the_first_frame_deadline`, `slow_handshakes_cannot_starve_established_or_reconnecting_peers` | Residual, accepted in PROTOCOL §10.1/OPERATIONS §4.1: 21 IPv4 addresses (or 11 /48s) fill `max_preauth`; then **new** connections, reconnecting agents included, are refused while established sessions continue. Only upstream protection or more relays help (§2(e)) |
| **Slowloris after the handshake** | established slots, queue memory | Only authenticated identities get there. Per-role idle timeout (`[liveness]`, default 90 s, floor 15 s), write timeout 30 s, kernel `TCP_USER_TIMEOUT` 20 s and keepalive 10 s/5 s×3 on accepted sockets (`net.rs::configure`, applied by the `Acceptor` impl), per-identity cap `max_per_identity` 512, agent reserve, global queue byte budget with per-identity shedding. Tests: `dialed_sockets_have_user_timeout_and_keepalive` (asserts accepted sockets too), `the_relay_idle_is_configured_per_role`, `unanswered_pings_end_the_session`, `one_identity_cannot_monopolise_the_established_pool`, `client_identities_cannot_starve_agent_registration`, `queue_budget_sheds_the_slowest_reader`, `relay_queue_never_exceeds_credit_while_writes_block` | The queue budget default is computed from `/proc/meminfo` and `/sys/fs/cgroup/memory.max`, **both unreadable or meaningless under the shipped unit** (§2(a)-4) |
| **Amplification / reflection** | TCN sends nothing before a valid message 1 from a key the policy admits (PROTOCOL §15.4: an unknown key gets no message 2), and TCP needs a handshake, so there is no application-level reflection | — | Kernel-level: a spoofed SYN makes the host send a SYN-ACK to the victim, retransmitted `tcp_synack_retries` (default 5) times: up to 6 packets per SYN. With syncookies active there are no retransmits. §2(d) lowers retries to 2 and §2(c) caps SYNs per source, which also caps reflection per victim |
| **Source spoofing** | per-source admission | The TCP handshake validates the source of every connection that reaches `accept`, so admission keyed on `addr.ip()` is sound on a direct listener. IPv4-mapped IPv6 is canonicalised (`ratelimit.rs::source_key`, review 0004 #18) | Behind a TCP proxy the source is the proxy (§2(a)-5). Bogon/unroutable sources: no reverse-path filter is configured (§2(c)) |
| **Scanning of other ports** | everything else listening on the host (sshd, cloud agents, exporters) | nothing on the host. The relay port itself reveals nothing: refusals and failed handshakes close without a reply, pre-auth failures are aggregated (`preauth_summary`) | §2(c): default-drop inbound; SSH only from admin networks |
| **Host compromise containment** (attacker h) | see §1.3 | strong sandbox (1.2 OK) | §1.3, §2(b) |
| **Memory exhaustion** | OOM of the relay or of the host | per-connection bounded queues, global queue byte budget (R-6), message size caps, bounded admission tables (`max_tracked_sources`, `max_tracked_wide`, `MAX_DISTINCT`) | no `MemoryMax`/`MemoryHigh` (resilience.md D-13 calls them "the last resort", they were never added); the budget default ignores the cgroup (§2(a)-4) |
| **Task / thread exhaustion** | PID table, a fork bomb after an RCE | tokio tasks are bounded by the admission pools; one task per connection | no `TasksMax=` beyond the system default (15 % of `pid_max`); the tokio blocking pool may grow to 512 threads by default (only `metrics::export` uses it) |
| **CPU exhaustion** | handshake crypto from unauthenticated peers (X25519, ML-KEM decapsulation for hybrid suites) | per-source buckets bound handshakes per source; `max_preauth` bounds concurrency | a botnet with many addresses is a volumetric problem (§2(e)). `CPUQuota=` would make it worse (it caps legitimate work too); sshd keeps its fair share under CFS without any change |
| **Restart storms** | an OOM kill or crash under attack | `Restart=always`, exponential backoff to 60 s, `StartLimitIntervalSec=0`, watchdog, drain on SIGTERM (`a_draining_relay_refuses_new_connections_and_keeps_sessions`) | a relay that crashes under attack loses its sessions; HA (up to 8 relays) is the answer (§2(e)) |

### 1.3 What an RCE inside `zt-relay` reaches today

Measured against the shipped unit (`packaging/systemd/zt-relay.service`) and the kernel's
defaults:

| Capability of the compromised process | Today | After this phase |
| :- | :- | :- |
| Read `/etc/tcn/relay.key` and the policy | yes (needed) | yes (needed; this is why relays must have **different** keys, OPERATIONS §8) |
| Write anywhere persistent | no (`ProtectSystem=strict`, only `/run/zt-relay` writable, `PrivateTmp`) | unchanged |
| Gain privileges | no (no capabilities, `NoNewPrivileges`, `PrivateUsers`, seccomp `~@privileged`) | unchanged |
| **Execute another program** (`/bin/sh`, `curl`, a dropped payload is impossible since nothing is writable and executable, but every installed binary is) | **yes**: `execve` is allowed and every path is executable | **no**: `NoExecPaths=/` + `ExecPaths=/usr/local/bin/zt-relay` |
| **Dial out**: the cloud metadata service (169.254.169.254, credentials of the instance role), the internal network, other relays, loopback services (local admin APIs, sshd on 127.0.0.1) | **yes**, anything | **no**: the nftables output rule allows sockets of user `tcn` to send only from the relay port (verified, see the table at the top). `IPAddressDeny=` cannot do this for a direct relay because it filters both directions (§2(b)) |
| **Open a second listener** (a backdoor port) | **yes**, any unprivileged port | **no**: `SocketBindAllow=tcp:7443`, `SocketBindDeny=any`; the host firewall would also drop it |
| Reach the kernel's large attack surfaces | `io_uring` (`@aio`), the keyring (`@keyring`), `@resources` are allowed by `@system-service` | removed: `SystemCallFilter=~@privileged @resources @aio @keyring` |
| Exhaust host memory / PIDs | yes (no `MemoryMax`, default `TasksMax`) | bounded: `MemoryMax=80%`, `MemoryHigh=70%`, `MemorySwapMax=0`, `TasksMax=512` |
| Talk to local D-Bus/journald over `AF_UNIX` | yes, as an unprivileged user (needed for `sd_notify`) | unchanged (accepted: unprivileged D-Bus access is policy-filtered; see out of scope) |
| Escalate through a kernel bug | the remaining seccomp surface (`@system-service` minus the above) | reduced, not removed; host sysctls (§2(d)) close some generic primitives (unprivileged BPF, kernel pointers in logs) |

---

## 2. Gap analysis

### (a) Relay code gaps

1. **Listen backlog is 128, not configurable** (resilience.md G15 already noted it; still true).
   `RelayServer::bind` calls `tokio::net::TcpListener::bind`, which calls
   `mio::net::TcpListener::bind`; mio 1.2.4 (`src/net/tcp/listener.rs` L85-94) hard-codes
   `listen(fd, 128)` "the same backlog value as the standard library". The kernel default
   `net.core.somaxconn` has been 4096 since Linux 5.4, so the relay asks for less than the
   kernel allows. A reconnect wave (a relay restart: every agent reconnects within
   `--reconnect-spread` 10 s; a NAT with many agents; Ansible forks) overflows the accept queue
   while the accept loop is busy, and the kernel **drops SYNs** (the client retries after 1 s,
   3 s, …): slow reconnects exactly when the relay is busiest. Fix: build the listener with
   `tokio::net::TcpSocket` (`set_reuseaddr`, `bind`, `listen(backlog)`), backlog from
   `relay.toml` `[network] listen_backlog` (default 4096, range 128..=65535; the kernel clamps
   it to `somaxconn`, which §2(d) pins at 4096).

2. **Accept errors: one fixed 100 ms sleep for every error kind** (`relay.rs` L751-758). Right
   for resource exhaustion (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`), wrong for per-connection
   errors (`ECONNABORTED`, `EPROTO`, `EPERM`, `ENETDOWN`, …; `accept(2)`: "Linux passes
   already-pending network errors on the new socket as an error code from accept()… should be
   treated like EAGAIN by retrying"). Each one stalls *all* accepts for 100 ms; whether a remote
   peer can trigger them at will on current kernels is unproven, so this is **low**, but the fix
   is small: retry per-connection errors at once; back off on resource errors exponentially
   (10 ms → 1 s, reset on success); count both in `tcn_relay_accept_errors_total{kind}`; emit at
   most one WARN per summary interval. The `Acceptor` trait already allows a fake acceptor in
   tests.

3. **No coherence check between `RLIMIT_NOFILE` and the pools.** `relay.toml` accepts
   `max_established` up to 1 048 576 (`MAX_POOL`), the unit gives 16 384 descriptors. Past the
   limit, `accept` fails with `EMFILE` *before* admission can refuse anything, and every
   connection (agents included) waits in the backoff. Fix: at startup, read the soft limit
   (`rustix::process::getrlimit`, syscall `prlimit64` is in `@default`) and emit a WARN audit
   event `fd_limit_low` (`limit`, `needed`) and a gauge when `limit < max_preauth × k +
   max_established + 64` (k = 2 in PROXY mode, §2(a)-5). A warning, not a refusal: outside
   systemd a shell's soft limit is often 1024 and the defaults would then refuse to start.

4. **The queue budget ignores the memory limits under the shipped unit** (pre-existing bug,
   **medium**). `budget.rs::memory()` reads `/proc/meminfo` and `/sys/fs/cgroup/memory.max`.
   Under the shipped unit:
   - `ProcSubset=pid` hides every non-process file of `/proc`, `/proc/meminfo` included;
   - without a cgroup namespace (`ProtectControlGroups=yes` on systemd 255 only remounts
     read-only), `/sys/fs/cgroup/memory.max` is the **root** cgroup's, which does not exist on
     cgroup v2.

   So `memory()` returns `None` and `queue_budget_for(None)` is the maximum, **1 GiB, on every
   host**, also on a 512 MiB VPS (OPERATIONS §18 promises "a quarter of the memory, the cgroup
   limit included"). Adding `MemoryMax=` without this fix would make the budget larger than the
   cgroup, and the OOM killer would act before shedding. Fix: physical memory from `sysinfo(2)`
   (`rustix::system::sysinfo`, needs rustix's `system` feature, no new crate; `sysinfo` is in
   `@system-service`); the cgroup limit from the process's own cgroup: parse `/proc/self/cgroup`
   (`0::/system.slice/zt-relay.service`, visible under `ProcSubset=pid`), then take the minimum
   of `memory.max` and `memory.high` of that cgroup and its ancestors under `/sys/fs/cgroup`.

5. **Behind an upstream TCP proxy or load balancer, per-source admission breaks.** Every
   connection then comes from a few proxy addresses: `max_pending_per_source` 50 and
   `source_burst` 64 apply to the proxy, so 50 slow handshakes from *anyone* behind the proxy
   block *everyone*; the audit and the metrics name the proxy, not the peer. Review 0007 AP-21
   already observed that "LB health probes assume an LB topology that the per-IP gate does not
   support without the PROXY protocol". Assessment: **add strict PROXY protocol v2**, accepted
   only from configured trusted prefixes. Design in §3.5. Arguments:
   - It is the only way to keep per-source admission meaningful behind the scrubbing services
     that §2(e) recommends; without it that recommendation would make admission *worse*.
   - The trust it adds is narrow. TCN is end-to-end authenticated: a proxy (or a forged
     header) can only influence which source address admission and logs see, never who
     authenticates or what a session carries. A compromised proxy can already drop or delay
     everything.
   - v2 is binary with fixed offsets; v1 is free text with more room for parsing ambiguity.
     Some managed TCP proxies only emit v1: check the provider; v1 stays out of scope.
   - Header-pool and deadline semantics must not create a new slowloris surface (§3.5).

6. **No per-source cap on ESTABLISHED connections, by design.** Admission caps *pending*
   handshakes per source and per /48; established connections are capped per identity
   (`max_per_identity`), per role (agent reserve) and globally (`max_established`). An attacker
   without credentials never reaches the established pool (key confirmation is required:
   `replayed_msg1_does_not_enter_the_established_pool`). A per-source established cap would only
   hurt legitimate NATs and controllers. **Recommendation: no new cap**; document it. The host
   firewall does not count connections on the relay port either (§2(c)), for the same reason and
   because counting needs conntrack.

7. **TCP keepalive / `TCP_USER_TIMEOUT`: already done** for accepted sockets (`net.rs`,
   `Acceptor for TcpListener` calls `configure`; asserted by
   `dialed_sockets_have_user_timeout_and_keepalive`). No gap.

8. Smaller observations (not in scope unless noted):
   - The tokio blocking pool may grow to 512 threads (default); only `metrics::export` uses it.
     Setting `max_blocking_threads(8)` in `serve()` makes `TasksMax=512` safe on any core count
     below ~500. **In scope** (one line, with §2(b)).
   - Refused connections are closed with FIN, so the relay side keeps a TIME_WAIT (60 s) per
     refusal. With the relay port untracked this costs no conntrack entry, and the kernel bounds
     TIME_WAIT buckets (`tcp_max_tw_buckets`): an RST (`SO_LINGER 0`) would save a little memory
     but changes what peers observe. Out of scope.
   - `TCP_DEFER_ACCEPT` would keep silent connections out of the pre-auth pool entirely, but
     neither rustix 1.1.6 nor the standard library expose it, and `unsafe` is forbidden. Out of
     scope.
   - The listening socket is dual-stack only with `--listen [::]:7443` and
     `net.ipv6.bindv6only=0`; documented already (unit comment).

### (b) systemd unit gaps

The unit is already strong (1.2 OK). What the score does not show, and what is missing:

| Directive | Today | Proposal | Rationale / check |
| :- | :- | :- | :- |
| `SystemCallFilter=` | `@system-service`, `~@privileged` | add `~@resources @aio @keyring` | `@system-service` includes `@aio` (**io_uring**, a major kernel attack surface), `@keyring`, `@resources`. tokio uses epoll; nothing in the relay calls `setrlimit`, `sched_setaffinity`, `setpriority`, `io_uring_*` or `keyctl` (`grep` of the crates; `prlimit64` and `sched_getaffinity` are in `@default`). Removes the 0.2 of `~@resources`. Proven in CI by the systemd e2e job (§3.7), since a missing syscall kills the process with SIGSYS |
| `NoExecPaths=` / `ExecPaths=` | absent | `NoExecPaths=/`, `ExecPaths=/usr/local/bin/zt-relay` | an RCE cannot run `/bin/sh` or any installed tool. `ExecReload=` runs the same binary. A dynamically linked build needs its loader and library directories added in a drop-in (documented; the release binaries are static musl). Not scored by `systemd-analyze` |
| `SocketBindAllow=` / `SocketBindDeny=` | absent | `SocketBindAllow=tcp:7443`, `SocketBindDeny=any` | no backdoor listener. Must change together with `--listen` (one Ansible variable renders both; a test checks the shipped files agree). `AF_UNIX` (`sd_notify`) is not affected |
| `IPAddressDeny=` / `IPAddressAllow=` | absent | **direct relay: not usable**; PROXY mode: `IPAddressAllow=<proxy prefixes>` + `IPAddressDeny=any` in the Ansible drop-in | The relay never dials out (checked: no `connect`, `lookup_host` or `UdpSocket` in `relay.rs`, `systemd.rs`, `lifecycle.rs`, `metrics.rs`, `reload.rs`, `keys.rs`, `bins/zt-relay`; `sd_notify` is `AF_UNIX`). But `IPAddressDeny=` filters packets in both directions, so a relay that accepts from anyone must allow anyone; egress is restricted by nftables instead (§2(c)). Behind proxies the allow list is exact and also scores (1.0) |
| `MemoryMax=` / `MemoryHigh=` / `MemorySwapMax=` | absent | `MemoryHigh=70%`, `MemoryMax=80%`, `MemorySwapMax=0` | a relay host is dedicated; 20 % is left to sshd, journald and the kernel. Socket buffers are charged to the cgroup on cgroup v2, so this also bounds kernel memory spent on the relay's sockets. No swap: keys are never written to swap and latency stays bounded. Requires the budget fix §2(a)-4 so the budget (a quarter of `MemoryMax`) sheds before the OOM killer acts |
| `TasksMax=` | system default | `TasksMax=512` | worker threads = cores, plus the blocking pool capped at 8 (§2(a)-8), plus the main thread; bounds a fork/thread bomb |
| `OOMScoreAdjust=` / `OOMPolicy=` | default | **no change** | with `MemoryMax=` the relay is OOM-killed inside its own cgroup before a global OOM; OpenSSH already protects its listener (`oom_score_adj` -1000). `OOMPolicy=stop` (default) + `Restart=always` turn an OOM kill into a restart |
| `CPUQuota=` / `CPUWeight=` | default | **no change** | a quota caps legitimate work during a handshake flood and makes it worse; CFS already gives sshd its fair share |
| `LimitNOFILE=` | 16384 | keep | coherent with the defaults: PROXY mode worst case 1024 (header pool) + 1024 + 8192 + ~32 = 10 272. Enforced by a test and the startup warning §2(a)-3 |
| `PrivateIPC=` | absent | `PrivateIPC=yes` | no SysV/POSIX IPC is used; free isolation (not scored by systemd 255) |
| `RestrictFileSystems=` | absent | **no** | needs the BPF LSM in the kernel's `lsm=` list, which major distributions do not enable by default; adds little to `ProtectSystem=strict` |
| `KeyringMode=`, `DevicePolicy=` | implied (`private`, `closed` via `PrivateDevices=`) | no change | already ✓; `DeviceAllow=char-rtc:r` (0.1) comes from `ProtectClock=`, which is worth more than the 0.1 |
| `ProtectSystem=` paths | `strict`, `ReadOnlyPaths=/etc/tcn` | keep | `TemporaryFileSystem=/etc:ro` + `BindReadOnlyPaths=/etc/tcn` would hide the rest of `/etc`, but the StrictModes checks on ancestors and future drop-ins make it a moderate risk for little gain: out of scope |
| `RootDirectory=`, `PrivateNetwork=`, `RestrictAddressFamilies=~AF_INET…/~AF_UNIX` | flagged | accept | inherent to a network service using `sd_notify` |

Proposed final diff of the unit (scored 1.1 OK, `systemd-analyze verify` clean):

```diff
 SystemCallFilter=@system-service
-SystemCallFilter=~@privileged
+SystemCallFilter=~@privileged @resources @aio @keyring
+PrivateIPC=yes
+# The relay listens on its port only: no other listener, even after a compromise. Change it
+# together with --listen (a drop-in that changes the port must repeat both).
+SocketBindAllow=tcp:7443
+SocketBindDeny=any
+# Nothing but the relay itself may be executed (a dynamically linked build needs its loader
+# and library directories in ExecPaths=).
+NoExecPaths=/
+ExecPaths=/usr/local/bin/zt-relay
+# The last resort behind the queue budget (a quarter of MemoryMax, OPERATIONS §18).
+MemoryHigh=70%
+MemoryMax=80%
+MemorySwapMax=0
+TasksMax=512
 UMask=0077
```

### (c) Host firewall (nftables)

Nothing exists today. The design (full validated text in Appendix A):

- **Own table, atomic replace**: `table inet zt_relay` + `delete table inet zt_relay` + the
  definition, in one file, loaded in one transaction. No `flush ruleset`, so cloud agents' or
  other tables survive; but in nftables a `drop` in any base chain is final, so our
  default-drop policy holds whatever other tables accept.
- **Stateless relay port** (`notrack` in `prerouting priority raw` and `output priority raw`
  for the relay port). The relay does its own connection accounting; conntrack would only add
  a table that a SYN flood fills (every accepted SYN inserts an entry; entries are inserted
  only for packets that pass all hooks, so dropped scans never fill it). Consequences, all
  intended: `ct state invalid drop` and `ct count` do not apply to the relay port (the kernel's
  TCP stack discards invalid segments itself); ICMP errors about relay flows are not "related"
  and must be accepted explicitly.
- **Per-source SYN meter before conntrack**, keyed on the IPv4 address or the IPv6 /64 (the
  same keys as `ratelimit.rs::source_key`): `50/second burst 500` SYNs. Sized from the admission
  defaults: well above `source_burst` 64 and `max_pending_per_source` 50, because the host
  cannot see refunds (a controller with 50 forks, or many agents behind one NAT after a relay
  restart, are legitimate bursts). Dropping a SYN is back-pressure, not failure: the client
  retransmits after 1 s. The meter is bounded (`size 65536`, `timeout 1m`): a spoofed flood
  with random sources fills it and further sources are simply not metered (syncookies handle
  spoofed SYNs). It also caps SYN-ACK reflection towards any one spoofed victim.
- **No `ct count` on the relay port** (contrary to the first idea in the request): it needs
  conntrack, which we remove from that port on purpose, and the relay already caps what one
  source can hold *without credentials* (50 pending). Established connections need
  credentials and are capped per identity (§2(a)-6). `ct count` is used for SSH (8 per source).
- **Tiny-MSS SYNs dropped** (`tcp option maxseg size 1-535`): the CVE-2019-11477 class
  (many tiny segments for one bulk transfer); paired with `net.ipv4.tcp_min_snd_mss=536`.
- **Reverse-path filter** `fib saddr . iif oif missing drop` (IPv4 and IPv6; the sysctl
  `rp_filter` is IPv4-only). It drops bogons and spoofed sources that do not route back through
  the arrival interface; a multi-homed host with asymmetric routing must turn it off
  (variable). It cannot stop spoofing of routable addresses; TCP's handshake does that.
- **ICMP**: errors (`destination-unreachable`, `packet-too-big`, `time-exceeded`,
  `parameter-problem`) **accepted without a rate limit**. A global limit would let any attacker
  exhaust it and starve path-MTU discovery (critical for IPv6 and for bulk scp through the
  relay); the kernel validates errors against existing sockets and rate-limits what it sends.
  NDP (`nd-neighbor-solicit/advert`, `nd-router-advert`) only with `hoplimit 255` (on-link).
  Echo requests metered per source (5/s burst 10). This deliberately deviates from "ICMP
  rate-limited" in the request.
- **Inbound default drop**; `ct state established,related` accepted; new TCP that is not a
  SYN dropped; loopback accepted.
- **Management SSH** only from `admin_v4`/`admin_v6` (an empty set = no inbound SSH, e.g. when
  the relay host is itself managed through TCN via another relay), at most 8 concurrent
  connections per source (`ct count`, reset beyond).
- **PROXY mode**: `relay_src_v4/v6` hold the proxies' prefixes instead of `0.0.0.0/0` / `::/0`;
  the SYN meter must then **not** apply to the proxies (it would throttle the whole user base),
  so the template omits it in PROXY mode.
- **Forward**: policy drop (a relay does not route; a host that also runs a container runtime
  must not install this chain: documented, variable).
- **Egress**: host-wide accept (package updates, NTP, cloud agents are the operator's choice),
  but sockets of user `tcn` may only send from the relay port. Kernel-generated SYN-ACKs and
  RSTs have no socket owner and are not affected; data of accepted connections has source port
  7443. Verified behaviourally (top table). Limitations, documented: `meta skuid` resolves the
  user name when the ruleset is loaded (the file fails to load if `tcn` does not exist yet:
  sysusers must run first, which it does at boot); a co-located `zt-agent` also runs as `tcn`
  and needs an extra accept rule towards its relays (`tcp dport 7443 ip daddr @peer_relays`)
  and loopback SSH (variable `zt_relay_colocated_agent`). Matching the unit's cgroup
  (`socket cgroupv2`) instead was rejected: nft resolves the path at load time, so a ruleset
  loaded at boot before the service starts would fail as a whole and leave the host open.

### (d) Kernel sysctl (`packaging/sysctl/90-zt-relay.conf`)

| Key | Value | Rationale |
| :- | :- | :- |
| `net.ipv4.tcp_syncookies` | 1 | stateless SYN handling when the SYN queue overflows (pin the distribution default) |
| `net.ipv4.tcp_max_syn_backlog` | 8192 | room before cookies kick in (cookies lose TCP options such as window scaling on older kernels) |
| `net.core.somaxconn` | 4096 | ceiling for the relay's new `listen_backlog` (§2(a)-1) |
| `net.ipv4.tcp_synack_retries` | 2 | half-open lifetime ~7 s instead of ~63 s; fewer reflected SYN-ACKs per spoofed SYN (3 instead of 6) |
| `net.ipv4.tcp_min_snd_mss` | 536 | refuse to segment below 536 bytes (CVE-2019-11477 class); the firewall also drops tiny-MSS SYNs |
| `net.ipv4.tcp_rfc1337` | 1 | TIME_WAIT assassination protection |
| `net.ipv4.tcp_fin_timeout` | 15 | orphaned FIN_WAIT2 sockets (a peer that never closes after a refusal) go away in 15 s |
| `net.ipv4.conf.{all,default}.rp_filter` | 1 | strict reverse path for IPv4 (2 on multi-homed hosts; nft `fib` covers IPv6) |
| `net.ipv4.conf.{all,default}.accept_redirects`, `secure_redirects`, `send_redirects`; `net.ipv6.conf.{all,default}.accept_redirects` | 0 | a relay never needs ICMP redirects; they allow on-link route injection |
| `net.ipv4.conf.{all,default}.accept_source_route`, `net.ipv6.conf.{all,default}.accept_source_route` | 0 | no source routing |
| `net.ipv4.icmp_echo_ignore_broadcasts`, `net.ipv4.icmp_ignore_bogus_error_responses` | 1 | smurf reflection, log noise |
| `net.ipv4.conf.all.log_martians` | 0 | martian logging floods the journal during a spoofed flood; nft counters measure it instead |
| `net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding` | 0 | not a router (a container runtime would need 1: documented) |
| `kernel.kptr_restrict` | 2 | no kernel pointers to anyone (exploit primitive) |
| `kernel.dmesg_restrict` | 1 | kernel log readable by root only |
| `kernel.unprivileged_bpf_disabled` | 1 | no unprivileged BPF (1 is sticky until reboot, intended) |
| `net.core.bpf_jit_harden` | 2 | constant blinding for all JIT users |
| `kernel.yama.ptrace_scope` | 2 | only root may ptrace (the relay is also non-dumpable) |
| `kernel.perf_event_paranoid` | 3 | no perf for unprivileged users (Debian/Ubuntu kernels honour 3; upstream treats it as 2) |
| `kernel.kexec_load_disabled` | 1 | no runtime kernel replacement (sticky) |
| `kernel.sysrq` | 0 | no magic SysRq |
| `fs.protected_symlinks`, `fs.protected_hardlinks` | 1 | classic /tmp races |
| `fs.protected_fifos`, `fs.protected_regular` | 2 | same, for FIFOs and regular files |
| `fs.suid_dumpable` | 0 | no core dumps of set-uid processes |
| `-kernel.unprivileged_userns_clone` | 0 | Debian-only key (the `-` prefix ignores it elsewhere); unprivileged user namespaces are a large LPE surface |
| **not** `user.max_user_namespaces=0` | — | it would break the unit's `PrivateUsers=yes`, which systemd sets up with a user namespace: a test asserts it is absent |
| `-net.netfilter.nf_conntrack_max` | 262144 | explicit size of a table that, with the relay port untracked, only SSH, ICMP and egress use; loaded early via `/etc/modules-load.d/zt-relay.conf` (`nf_conntrack`), otherwise systemd-sysctl runs before the module exists and the value is silently lost |

Not changed, on purpose: `tcp_abort_on_overflow` (0 lets clients retry), `tcp_challenge_ack_limit`
(randomised by the kernel), `netdev_max_backlog` and other throughput tuning (performance, not
security), `accept_ra` (some providers deliver IPv6 by router advertisements).

Several keys did not exist in this container's kernel (no IPv6, no Yama): the file uses the
`-` prefix only for keys that are legitimately absent on some distributions, and the CI lint
(§3.7) runs on a full Ubuntu kernel.

### (e) Upstream and volumetric DDoS

What a single host **cannot** fix:

- **Link saturation.** A reflection flood (DNS, NTP, memcached, CLDAP, SSDP) of tens of Gbit/s
  fills the uplink before the NIC; dropping it in nftables or XDP saves the CPU, not the link.
- **Provider blackholing.** Many providers null-route an attacked address to protect their
  network: the relay is then unreachable whatever it does.
- **Packet rate.** Each dropped packet still costs an interrupt and a softirq; nftables drops
  in the low Mpps per core, XDP more, but a large botnet exceeds both.
- **Distributed handshake floods from real addresses.** Each source stays under its per-source
  limits; together they fill `max_preauth` and new connections are refused (§1.2). The relay
  stays correct (established sessions keep working: `a_full_preauth_pool_does_not_disturb_established_sessions`),
  but it is unavailable for new sessions.

Recommended patterns, cheapest first, without endorsing any vendor:

1. **Provider edge ACLs.** TCN needs exactly one inbound protocol: TCP to the relay port (plus
   SSH from admin networks, and ICMP). Most cloud and hosting providers offer stateless network
   ACLs or security groups enforced *before* the host's link, and a basic always-on L3/L4
   volumetric filter. Allowing only TCP/7443 and ICMP there removes every UDP reflection flood
   for free. This is the highest-value step and needs no code.
2. **Several relays on independent networks: TCN's own answer.** Agents connect to all relays
   at once (up to 8), clients fail over in order (OPERATIONS §4, §8). Put relays with
   **different keys** on different providers or ASNs, some direct, some behind scrubbing. An
   attacker must take all of them down; one relay under attack does not affect sessions on the
   others. Keep `max_preauth` and the agent reserve sized so a reconnect wave fits.
3. **TCP scrubbing / reverse proxies (anycast or regional) in front of a relay, forwarding with
   PROXY protocol v2.** TCN needs no TLS termination and gives the proxy nothing to read: the
   outer Noise channel is end to end between peer and relay, and sessions are end to end
   between client and agent. The proxy sees only addresses and timing. With PROXY v2 (§3.5)
   the relay's admission and audit see the real peer; the relay host then accepts the relay
   port only from the proxy prefixes (nftables `relay_src`, unit `IPAddressAllow=`), and the
   provider ACL does the same, so the origin cannot be attacked directly even if its address
   leaks. Change the origin address when moving a relay behind a proxy: the old one is known.
   Managed TCP proxies differ in their PROXY support (some emit only v1): check before choosing.
4. **One relay per name, one name per relay.** TCN pins a relay key per configured address.
   Anycasting *one* name over several relays only works if they share a key, which widens a
   key compromise to all of them (OPERATIONS §8 wants independent keys). So: one DNS name (or
   address) and one proxy front end per relay, listed as separate `[[relays]]` entries.
5. **DNS.** Short TTLs (60-300 s) on relay names let an operator move a relay behind a
   scrubbing front end quickly; clients and agents resolve the name at every connection attempt
   (`TcpDialer::connect` takes `host:port`). Relay names need not be public: clients can carry
   them in their configuration. DNS itself should be served by a resilient provider (secondary
   on a different network).
6. **Monitoring.** `tcn_relay_admission_refusals_total`, `tcn_relay_preauth_failures_total`
   (OPERATIONS §17) and the nft counters (`nft list table inet zt_relay`) show an attack; the
   runbook says what to do (raise `max_preauth`, move behind a proxy, add a relay).

### (f) Deployment automation (Ansible)

There is no automation today; OPERATIONS §9 is a manual sequence. The role must make the
secure path the easy one and must never weaken verification:

- **Binary**: downloaded and verified **on the controller** (OPERATIONS §9: "verify the new
  release on a machine you trust … before copying the binaries out"): `tcn-release.sh verify
  --pins <operator's trusted fingerprints file> --tag vX.Y.Z keys/ SHA256SUMS`, with OpenSSL
  ≥ 3.5, then `sha256sum -c` of the archive; never by running a `zt-*` binary from the
  download. The pins file is a required variable pointing at the operator's out-of-band copy,
  never at the downloaded one. No release key is pinned yet (`PINNED_FINGERPRINTS` is empty):
  until the key ceremony, the role supports only `zt_relay_binary_source: local` (a binary the
  operator verified, with its SHA-256 given as a variable) and **fails closed** otherwise.
  Copy to `/usr/local/bin/zt-relay.new`, compare checksums, atomic rename.
- **User**: `tcn.sysusers` to `/usr/lib/sysusers.d/tcn.conf`, `systemd-sysusers`.
- **Key**: `zt-relay keygen` **on the host** (`creates:`), `chown tcn:tcn`, 0600; the key never
  passes through the controller; the public key is read with `zt-relay pubkey` and registered
  as a fact for the agent and client configurations.
- **Files**: `/etc/tcn` root 0755; `policy.toml`, `relay.toml` (and `revoked.toml` when the
  policy pins a CA) root 0644, each with `validate: zt-relay check … %s` so an invalid file is
  never put in place.
- **Unit**: the shipped unit plus a drop-in `10-ansible.conf` that sets `ExecStart=` (listen
  address, `--config /etc/tcn/relay.toml`, optional `--revocations`), `SocketBindAllow=` from the
  same port variable, and in PROXY mode `IPAddressAllow=`/`IPAddressDeny=any`.
- **sysctl**: `90-zt-relay.conf` and `modules-load.d/zt-relay.conf`, applied with
  `systemd-sysctl` (handler).
- **nftables**: the rendered ruleset to `/etc/nftables.d/zt-relay.nft` with `validate: nft -c
  -f %s`; the distribution's `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`;
  `nftables.service` enabled; the role refuses to run when `ufw` or `firewalld` is active (two
  managers would fight). **Lock-out protection**: before applying, save `nft list ruleset`, arm
  a `systemd-run --on-active=120` rollback, apply, `reset_connection` + `wait_for_connection`,
  then cancel the rollback; an assertion refuses an empty admin set unless
  `zt_relay_ssh_inbound: false` is explicit.
- **Handlers**: policy or revocations changed → `systemctl reload zt-relay` (the running
  relay validates and reports, OPERATIONS §4); `relay.toml`, unit, drop-in or binary changed →
  `zt-relay check` **as user `tcn`** with exactly the drop-in's arguments (rendered from the
  same variable), then `daemon-reload` and `restart`. The example playbook uses `serial: 1`
  (AP-21: never drain all relays at once).

---

## 3. Design of each item

### 3.1 File layout

| Path | Content |
| :- | :- |
| `packaging/nftables/zt-relay.nft` | the ruleset of Appendix A, rendered from the Ansible template with its defaults (for manual installs); a CI check keeps the two identical |
| `packaging/sysctl/90-zt-relay.conf` | §2(d) |
| `packaging/sysctl/zt-relay.modules-load.conf` | `nf_conntrack` (installed as `/etc/modules-load.d/zt-relay.conf`) |
| `packaging/systemd/zt-relay.service` | §2(b) diff |
| `packaging/tests/host/{lib.sh,spec.sh,attacks.sh}` | static and behavioural host tests, same pattern as `packaging/release/tests/` |
| `packaging/tests/host/probe/` | sandbox probe (§3.7), a tiny test-only binary |
| `deploy/ansible/roles/zt_relay/{defaults,tasks,handlers,templates,meta}/` | the role (§3.6) |
| `deploy/ansible/playbooks/relay.yml` | example playbook, `serial: 1` |
| `deploy/ansible/tests/render.yml` | renders every template with the defaults into a directory, for CI |
| `docs/RELAY_HARDENING.md` | operator runbook (install, PROXY mode, under-attack checklist, verification commands) |
| `docs/OPERATIONS.md` | §4.1 (`[network]`, `[proxy_protocol]`), §9 (new score 1.1, link to the runbook), §17 (new metrics), §18 (budget follows `MemoryMax`) |
| `docs/PROTOCOL.md` | §10.1: PROXY v2 position in the admission sequence |
| `crates/zt-proto/src/proxy_v2.rs` | sans-IO PROXY v2 parser |
| `crates/zt-domain/src/prefix.rs` | `IpPrefix` value object (validated CIDR) |
| `crates/zt-net/src/{relay,net,config,budget,metrics}.rs`, `bins/zt-relay/src/main.rs` | integration |
| `fuzz/fuzz_targets/proxy_v2.rs` | new fuzz target (CI matrix) |
| `docs/adversary/0015-relay-hardening.md` | step 5 review, at the end |

### 3.2 systemd unit

The diff of §2(b). Tests:

- `bins/zt-relay/tests/lifecycle.rs`: extend `the_units_carry_the_lifecycle_directives` with a
  new `the_relay_unit_is_hardened`: asserts each directive of the diff is present, that the
  `SocketBindAllow=` port equals the `--listen` port of `ExecStart=` and `RELAY_PORT` of
  `packaging/nftables/zt-relay.nft`, and that `LimitNOFILE` ≥ `2 × max_preauth +
  max_established + 64` of `AdmissionConfig::default()` (pure file parsing, runs everywhere).
- `packaging/tests/host/spec.sh` (CI job `host-hardening`):
  - `systemd-analyze verify` on a copy whose `ExecStart=`/`ExecReload=`/`ExecPaths=` point at
    the built binary: no output;
  - `systemd-analyze security --offline=yes --threshold=11`: exit 0 (fails today: RED);
  - `--json=short`: the set of unset checks must equal exactly {`RootDirectoryOrRootImage`,
    `RestrictAddressFamilies_AF_UNIX`, `RestrictAddressFamilies_AF_INET_INET6`,
    `PrivateNetwork`, `DeviceAllow`, `IPAddressDeny`}; any new flagged item fails the job.
- The systemd e2e and the sandbox probe of §3.7 prove the directives at run time.

### 3.3 nftables

Appendix A is the design, validated with `nft -c` and loaded twice in a namespace. The
Ansible template renders: ports, admin and relay-source sets, the meter numbers (literal:
nft does not accept `define`s there), the PROXY variant (no SYN meter for proxies), the
co-located-agent variant, the optional forward chain and `fib` rule.

Tests (`packaging/tests/host/`, run with `sudo` on the CI runner; the job first runs
`systemd-sysusers packaging/systemd/tcn.sysusers`, which also tests that file, so `meta skuid
"tcn"` resolves):

- `spec.sh`: `unshare -n nft -c -f packaging/nftables/zt-relay.nft`; every rendered variant
  (direct, PROXY, co-located agent, no SSH) passes `nft -c`; `nft -j list table` after loading
  in a namespace contains the expected chains, hooks, priorities and policies.
- `attacks.sh`: two namespaces joined by a veth pair (`ip netns`), ruleset loaded in the relay
  namespace, small Python listeners standing in for the relay and for "other services". One
  function per row of §4 (F-rows), e.g. SYN burst over the meter, scan of another port, SSH
  from a non-admin address, tiny-MSS SYN (raw socket), egress from `tcn`, `nf_conntrack_count`
  unchanged after a SYN flood to the relay port, established relay connection survives a
  ruleset reload.

### 3.4 sysctl

`packaging/sysctl/90-zt-relay.conf` as §2(d). Tests in `spec.sh`: every non-`-` key exists
under `/proc/sys` on the runner (after `modprobe nf_conntrack`), values parse; the file never
sets `user.max_user_namespaces`; `sudo unshare -n systemd-sysctl` would not apply global keys,
so the job applies the file with `sudo sysctl -p` on the ephemeral runner and reads every value
back (the runner is discarded afterwards).

### 3.5 PROXY protocol v2 (strict)

**Configuration** (`relay.toml`, read at startup only like the rest of the file):

```toml
[network]
listen_backlog = 4096                 # 128..=65535; the kernel clamps it to net.core.somaxconn

[proxy_protocol]
# Connections from these prefixes MUST start with a PROXY v2 header; the address in it is the
# peer for admission, logs and metrics. 1 to 64 prefixes; /0 and host bits set are refused.
trusted = ["203.0.113.0/24", "2001:db8:100::/48"]
header_timeout_secs = 3               # accept -> complete header (1..=10)
allow_direct = false                  # true: other sources connect without a header (migration)
```

Absent section: today's behaviour, byte for byte (no header is ever parsed). `IpPrefix` in
`zt-domain`: built only through `TryFrom<&str>`, canonical form, rejects `/0`, prefix lengths
over 32/128, host bits set, IPv4-mapped IPv6 prefixes, duplicates and overlaps (the list must
be unambiguous). Errors are `ConfigError::Syntax` (exit 78) without echoing more than the
entry index.

**Parser** (`zt-proto::proxy_v2`, sans-IO, no allocation):

- `fn fixed(header: &[u8; 16]) -> Result<Fixed, ProxyError>`: checks the 12-byte signature
  `0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A`, version nibble = 2, command ∈ {LOCAL 0, PROXY 1},
  family/transport ∈ {`0x00` UNSPEC (LOCAL only), `0x11` TCP/IPv4, `0x21` TCP/IPv6}, length
  ≤ `MAX_BODY` (512) and ≥ the family's address block (12 for IPv4, 36 for IPv6, 0 for
  UNSPEC). Returns the body length, so the caller reads **exactly** that many bytes: no
  over-read into message 1, no allocation beyond a 512-byte stack buffer.
- `fn body(fixed: &Fixed, body: &[u8]) -> Result<Proxied, ProxyError>`: for PROXY, the source
  address (destination ignored); IPv4-mapped IPv6 canonicalised to IPv4; unspecified,
  multicast and broadcast sources refused; then the TLV area is walked for framing only (type
  u8, length u16 BE, each TLV entirely inside the body, no trailing partial TLV); TLV values are
  ignored (no TLS or CRC semantics; documented). LOCAL: the address block is ignored per the
  specification and the result is "use the real connection address".
- `ProxyError` has one stable variant per row of §4 (`Signature`, `Version`, `Command`,
  `Family`, `Length`, `Address`, `Tlv`); its `Display` never contains received bytes.

**Relay integration** (`relay.rs`):

1. At accept, a source outside `trusted`: when `allow_direct = false`, closed at once (counted
   `proxy_untrusted`); when true, today's path (admission on the TCP source, no header parsed:
   a forged header from such a source is just an invalid message 1).
2. A source inside `trusted` takes a slot of a **header pool** (`max_preauth` slots, a counter
   separate from admission because the peer's address is not known yet; full → closed,
   `proxy_pool_full`) and the connection task is spawned; the accept loop never reads.
3. The task reads 16 bytes, then exactly the body, all within `header_timeout` from accept
   (`timeout_at`). Any error closes the connection without a reply and counts
   `tcn_relay_proxy_header_failures_total{reason}`.
4. The header slot is released; `Admission::on_accept(real_source)` then runs exactly as for a
   direct connection (same buckets, same caps, same refusals), and the existing handshake
   deadlines start. A connection therefore holds a slot for at most `header_timeout` +
   `handshake_timeout` + `first_frame_deadline` (18 s with the defaults), and the descriptor
   budget is `2 × max_preauth + max_established` (the unit's 16 384 covers it).
5. Logs and metrics carry the real peer as `peer_addr` and the proxy as `via`; audit lines are
   otherwise unchanged.
6. Operationally, in PROXY mode nftables accepts the relay port only from the proxies, the
   unit gets `IPAddressAllow=` for them, and proxy health checks without a header are counted
   as `aborted`/`proxy_header` failures (bounded and aggregated, never per-connection lines).

**Tests**: spec and attack tests in `crates/zt-proto/tests/proxy_v2.rs` (table-driven: every
row P-1…P-13 of §4), a proptest (`encode` test helper → `parse` round trip; arbitrary bytes
never panic and never consume more than `16 + len`), `fuzz/fuzz_targets/proxy_v2.rs` added to
the CI fuzz matrix; integration tests in `crates/zt-net/tests/proxy_v2.rs` over real loopback
TCP (127.0.0.1 as the trusted proxy, header source addresses in 198.51.100.0/24 and
2001:db8::/32); config tests in `crates/zt-net/tests/config.rs`.

### 3.6 Ansible role

```
deploy/ansible/
  playbooks/relay.yml                   # hosts: tcn_relays, serial: 1, roles: [zt_relay]
  tests/render.yml                      # renders templates into $OUT with defaults/variants
  roles/zt_relay/
    meta/main.yml                       # min ansible-core, platforms (Debian 12, Ubuntu 24.04, EL9)
    defaults/main.yml                   # port, listen, admin CIDRs, proxy prefixes, meters, sizes
    tasks/main.yml                      # assert -> binary -> user -> key -> files -> unit -> sysctl -> nftables -> service
    tasks/assert.yml                    # admin CIDRs, no ufw/firewalld, pins file present, source mode
    tasks/binary.yml                    # verify on the controller (delegate_to: localhost, run_once), copy, atomic rename
    tasks/nftables.yml                  # validate, save, arm rollback, apply, reconnect, disarm
    handlers/main.yml                   # check-then-restart, reload, sysctl, nft
    templates/zt-relay.nft.j2
    templates/10-ansible.conf.j2        # ExecStart=, SocketBindAllow=, IPAddressAllow= (PROXY)
    templates/relay.toml.j2
    templates/policy.toml.j2            # or a copy of an operator file
```

Variables that must agree are derived from one source: `zt_relay_port` renders `--listen`,
`SocketBindAllow=` and the nft `RELAY_PORT`; `zt_relay_args` renders both `ExecStart=` and the
`zt-relay check` handler command.

Tests (CI, `pipx install ansible-core==<pinned>` as the `e2e-openssh` job already does):
`ansible-playbook --syntax-check deploy/ansible/playbooks/relay.yml`; `render.yml` with the
defaults and with each variant; the default rendering must be identical to
`packaging/nftables/zt-relay.nft` and the drop-in must agree with the shipped unit (drift
check); each rendered ruleset passes `nft -c`; each rendered `relay.toml` passes `zt-relay
check` (built binary); a rendering with an invalid `relay.toml` makes `zt-relay check` exit
78. A full converge (molecule, containers with systemd) is out of scope.

### 3.7 CI

A new job `host-hardening` in `ci.yml` (`ubuntu-24.04`, pinned like the others, `timeout-minutes:
30`, read-only permissions, no secrets):

1. build `zt-relay` for `x86_64-unknown-linux-musl` (as `release.yml` does), so `ExecPaths=`
   and seccomp are tested against the binary that ships;
2. `sudo systemd-sysusers packaging/systemd/tcn.sysusers`;
3. `packaging/tests/host/spec.sh` (static: unit, nft, sysctl, Ansible render);
4. `packaging/tests/host/attacks.sh` (namespaces: firewall behaviour);
5. **systemd e2e**: install the unit (drop-in only for the test policy path and
   `MemoryMax=512M`), `keygen`, `systemctl start` (Type=notify: returns when ready), assert
   `active`, the `queue_budget_in_use` event reports 128 MiB (= 512 MiB / 4, proves §2(a)-4),
   `systemctl reload` succeeds, a TCP connect to 7443 succeeds, `systemctl stop` drains;
6. **sandbox probe**: the same unit with `ExecStart=`/`ExecPaths=` pointing at the probe
   binary installed as `/usr/local/bin/zt-relay-probe`; the probe tries to `execve("/bin/sh")`
   (expects `EACCES`), connect to 127.0.0.1:22, 169.254.169.254:80 and a host on the runner's
   network (expects refusal from nftables when the ruleset is loaded in that run, otherwise
   documented as N/A), bind 0.0.0.0:8080 (expects `EPERM`/`EACCES` from `SocketBindDeny`), write
   `/etc/tcn/x` (expects `EROFS`), spawn threads until failure (expects failure before 512), and
   prints one JSON line per probe for the script to assert. The probe is safe Rust (std only:
   `Command`, `TcpStream`, `TcpListener`, `fs`, `thread`); no `unsafe`, so it follows the
   workspace lints.

Rust tests run in the existing `build-test` job; the fuzz target joins the existing matrix.

---

## 4. Attack catalogue

Format of `docs/adversary/*.md`. "spec.sh"/"attacks.sh" are `packaging/tests/host/`; Rust test
names are proposals, to be committed RED before the implementation.

### 4.1 Relay code

| # | Attack hypothesis | Expected mitigation | Test that will prove it |
| :-: | :- | :- | :- |
| C-1 | A reconnect wave (512 peers within one second, accept loop busy) overflows the 128-entry accept queue; SYNs are dropped and peers wait 1-3 s per retry | `listen_backlog` 4096 via `TcpSocket::listen` | `the_listen_backlog_holds_a_reconnect_wave` (bind, do not accept, 512 concurrent connects must all complete within 1 s; fails with 128) |
| C-2 | `listen_backlog` 0, 127 or 65536 in `relay.toml` | refused at load (exit 78) | `relay_toml_bounds_the_listen_backlog` |
| C-3 | Per-connection accept errors (e.g. `ECONNABORTED`) each stall the whole accept loop for 100 ms | retried at once; only resource errors back off | `transient_accept_errors_do_not_stall_the_accept_loop` (fake `Acceptor`: 100 `ECONNABORTED` then a real stream, admitted within 50 ms) |
| C-4 | `EMFILE` makes the loop spin or never recover | exponential backoff 10 ms → 1 s, reset on success, counted in `tcn_relay_accept_errors_total{kind="resource"}` | `emfile_backs_off_and_recovers` (fake `Acceptor`, paused time) |
| C-5 | `relay.toml` raises `max_established` above `LimitNOFILE`: `EMFILE` hits before admission and locks everyone out | startup WARN `fd_limit_low` and gauge | `a_low_descriptor_limit_is_reported_at_startup` (spawn `zt-relay run` under `prlimit --nofile=512`) |
| C-6 | Under the shipped unit the queue budget is 1 GiB on a 512 MiB host (meminfo hidden, root cgroup read) | budget from `sysinfo(2)` and the process's own cgroup chain (`memory.max`, `memory.high`) | `the_budget_follows_the_own_cgroup_limit` (pure function over fake `/proc/self/cgroup` and cgroup files), `meminfo_hidden_still_gives_a_bounded_budget`; systemd e2e asserts 128 MiB under `MemoryMax=512M` |
| C-7 | Thread explosion of the blocking pool hits `TasksMax` and aborts the relay | `max_blocking_threads(8)` | systemd e2e (relay stays active for the whole job); sandbox probe for `TasksMax` |
| C-8 | A per-source established cap is missing: one address holds thousands of established connections | accepted by design: established needs a confirmed key; per-identity cap and agent reserve | existing `one_identity_cannot_monopolise_the_established_pool`, `replayed_msg1_does_not_enter_the_established_pool` (documented in the review, no new code) |

### 4.2 PROXY protocol v2

| # | Attack hypothesis | Expected mitigation | Test that will prove it |
| :-: | :- | :- | :- |
| P-1 | An attacker connects directly with a forged header claiming a victim's address (to spend the victim's budget, or to hide) | headers are parsed only from `trusted` sources; with `allow_direct = false` other sources are closed at accept; with `true` the header is just an invalid message 1, attributed to the real TCP source | `a_header_from_an_untrusted_source_is_never_believed` (both settings; the refusal is counted against the attacker's address) |
| P-2 | A trusted source sends no header (raw Noise message 1), or a v1 text header (`PROXY TCP4 …`) | signature mismatch → closed, `proxy_header{reason="signature"}`; no auto-detection, no fallback | `a_trusted_source_without_a_v2_header_is_closed`, `a_v1_header_is_refused` |
| P-3 | Version nibble 0, 1, 3…15 | `Version` | `every_version_but_2_is_refused` (exhaustive over the 16 values) |
| P-4 | Command nibble 2…15 | `Command` | `every_command_but_local_and_proxy_is_refused` (exhaustive) |
| P-5 | Family/transport UDP (`0x12`, `0x22`), UNIX (`0x31`, `0x32`), UNSPEC with PROXY, any other byte | `Family` | `only_tcp4_tcp6_and_local_unspec_are_accepted` (exhaustive over 256 values) |
| P-6 | Length boundaries: IPv4 0…11, IPv6 0…35, exactly 12/36 (accepted), 512 (accepted), 513, `u16::MAX` | `Length` from the 16 fixed bytes, **before** reading the body; nothing buffered | `length_boundaries_per_family`; `a_huge_declared_length_is_refused_without_reading` (loopback: relay closes within 100 ms, sends nothing) |
| P-7 | Slow header: one byte per second, or 15 bytes then silence | closed at `header_timeout` from accept | `a_trickling_header_is_closed_at_its_deadline` (paused time) |
| P-8 | A misbehaving trusted proxy opens `max_preauth + 1` connections and sends nothing | header pool full → closed; established sessions unaffected | `the_header_pool_is_bounded_and_spares_established_sessions` |
| P-9 | TLV framing: length beyond the body, 1 or 2 stray bytes at the end, zero-length TLVs, many NOOP TLVs up to the 512-byte cap | framing errors → `Tlv`; well-framed TLVs of any type ignored | `tlv_framing_is_strict`, `unknown_tlvs_are_ignored` |
| P-10 | LOCAL command (proxy health check), with or without junk address bytes | attributed to the proxy's own address, normal admission; never to an address in the body | `local_uses_the_connection_address` |
| P-11 | Source address unspecified (`0.0.0.0`, `::`), multicast, broadcast; IPv4-mapped in the IPv6 block | refused (`Address`); mapped addresses canonicalised to IPv4, so the admission key equals a direct IPv4 peer | `degenerate_source_addresses_are_refused`, `a_mapped_source_shares_the_ipv4_budget` |
| P-12 | Header and message 1 arrive in one segment: a buffered reader swallows message 1 | exact reads (16, then `len`) | `header_and_msg1_in_one_write_complete_the_handshake` |
| P-13 | Two headers back to back (smuggle a second identity) | the second is an invalid message 1 → handshake failure | `a_second_header_is_not_parsed` |
| P-14 | Admission still keyed on the proxy: 51 slow handshakes from *different* real peers through one proxy block everyone | admission uses the header's source | `per_source_caps_apply_to_the_real_peer` (51 real peers: all admitted; 51 from one real peer: the 51st refused `source_limit`) |
| P-15 | `trusted = ["0.0.0.0/0"]`, `"::/0"`, host bits set (`10.0.0.1/8`), 65 entries, overlap, mapped IPv6 prefix, `header_timeout_secs` 0 or 11, unknown key | refused at load, exit 78, error names the entry index only | `proxy_protocol_config_is_strict` |
| P-16 | Header bytes reach logs or errors (log injection, data leak) | stable reason names only | `proxy_errors_never_echo_received_bytes` (Display of every variant; captured logs of P-2…P-9) |
| P-17 | Parser panics or reads past `16 + len` on arbitrary input | total parser, bounded slices | proptest `parse_never_panics_or_overreads`, round trip `encode_parse_round_trip`; fuzz target `proxy_v2` (60 s per PR) |
| P-18 | A connection in the header phase survives the drain | the header read is bounded by `header_timeout`; the listener is closed first | `draining_closes_connections_still_in_the_header_phase` |
| P-19 | The origin is attacked directly, bypassing the scrubbing proxy | host: relay port only from the proxy prefixes; unit: `IPAddressAllow=` | attacks.sh `proxy_mode_drops_non_proxy_sources`; spec.sh scores the PROXY drop-in at 1.0 |

### 4.3 Host firewall

| # | Attack hypothesis | Expected mitigation | Test that will prove it |
| :-: | :- | :- | :- |
| F-1 | Scan of other TCP and UDP ports finds services | inbound policy drop, no RST and no ICMP unreachable | attacks.sh `other_ports_are_silently_dropped` (listener on 8080 in the relay namespace: connect times out; UDP probe gets no ICMP) |
| F-2 | Spoofed SYN flood to the relay port fills conntrack and blocks SSH | relay port `notrack`; syncookies | attacks.sh `a_syn_flood_to_the_relay_port_creates_no_conntrack_entries` (raw SYNs from random sources; `nf_conntrack_count` unchanged; a legitimate connect still succeeds) |
| F-3 | One source opens connections faster than the meter | SYNs over 50/s burst 500 dropped before conntrack; other sources unaffected | attacks.sh `one_source_over_the_syn_meter_is_throttled_alone` |
| F-4 | An IPv6 attacker rotates addresses inside its /64 to escape the meter | meter keyed on the /64 | attacks.sh `rotating_addresses_in_a_slash64_share_one_meter` |
| F-5 | Tiny-MSS SYN (CVE-2019-11477 class) | dropped; `tcp_min_snd_mss` 536 | attacks.sh `tiny_mss_syns_are_dropped` (raw SYN, MSS 48) |
| F-6 | SSH from outside the admin set; 9 concurrent SSH from one admin address | dropped; 9th reset | attacks.sh `ssh_only_from_admin_networks`, `ssh_connections_per_source_are_capped` |
| F-7 | ACK/NULL/XMAS scans of tracked ports | `ct state new` without SYN dropped, invalid dropped | attacks.sh `non_syn_new_tcp_is_dropped` |
| F-8 | ICMP echo flood; or an attacker exhausts a global ICMP limit to break PMTUD | echo metered per source; errors never globally limited | attacks.sh `echo_is_metered_per_source`; spec.sh asserts (from `nft -j`) that no `limit` applies to `packet-too-big`/`destination-unreachable` |
| F-9 | RCE in the relay dials the metadata service, the internal network or a loopback service | output: `tcn` sockets may only send from the relay port | attacks.sh `the_relay_user_cannot_dial_out` (with a control run without the rule, as done in this analysis) |
| F-10 | The egress rule breaks the relay's own replies | sport 7443 accepted; kernel SYN-ACK/RST have no owner | attacks.sh `relay_replies_still_flow` |
| F-11 | A ruleset reload cuts established relay sessions | relay port untracked; atomic table replace | attacks.sh `a_reload_keeps_established_relay_connections` |
| F-12 | A broken ruleset (missing user, syntax) leaves the host without a firewall | one transaction: the previous table stays; Ansible validates with `nft -c` first | spec.sh `a_ruleset_with_a_missing_user_is_rejected_atomically` |
| F-13 | Bogon or self-spoofed source addresses | `fib saddr . iif oif missing drop` | attacks.sh `unroutable_sources_are_dropped` |
| F-14 | SYN-ACK reflection towards a spoofed victim | ≤ 50 SYN/s per victim address, `synack_retries` 2 | attacks.sh (count SYN-ACKs seen by the "victim" namespace for 2 000 spoofed SYNs) |
| F-15 | Operator locks themselves out of SSH | role asserts a non-empty admin set; rollback timer restores the previous ruleset after 120 s | manual runbook test in RELAY_HARDENING.md; render test asserts the rollback tasks exist |

### 4.4 sysctl and unit

| # | Attack hypothesis | Expected mitigation | Test that will prove it |
| :-: | :- | :- | :- |
| K-1 | A typo in a key silently does nothing | every non-`-` key must exist | spec.sh `every_sysctl_key_exists` |
| K-2 | Conntrack keys are lost at boot (module loaded after systemd-sysctl) | `modules-load.d` file | spec.sh asserts the file and the key's value after `systemd-modules-load` + `systemd-sysctl` |
| K-3 | Host-wide `user.max_user_namespaces=0` breaks `PrivateUsers=yes` | never set | spec.sh `user_namespaces_are_not_disabled_globally` |
| U-1 | The exposure regresses | threshold 1.1 and exact allowlist of unset checks | spec.sh `unit_security_score` (RED today at 1.2) |
| U-2 | RCE runs `/bin/sh` | `NoExecPaths=/` | probe `exec_is_denied` |
| U-3 | RCE opens a backdoor listener | `SocketBindDeny=any` | probe `bind_is_denied` |
| U-4 | RCE writes persistence | `ProtectSystem=strict` | probe `writes_are_denied` |
| U-5 | RCE forks/threads until the host's PID table is full | `TasksMax=512` | probe `tasks_are_bounded` |
| U-6 | RCE uses `io_uring` or the keyring | seccomp `~@aio @keyring` | spec.sh JSON: the unit's `SystemCallFilter` excludes both groups (`systemd-analyze syscall-filter` membership); run-time crash-free relay in the systemd e2e |
| U-7 | A drop-in changes `--listen` but not `SocketBindAllow=` | the relay fails to bind (exit 1, retried with backoff) and the audit log says why; Ansible renders both from one variable | `the_relay_unit_is_hardened` (shipped files agree); render test (drop-in agrees) |
| U-8 | The memory limit kills the relay before the budget sheds | budget = a quarter of the cgroup limit (C-6) | systemd e2e budget assertion |

### 4.5 Deployment

| # | Attack hypothesis | Expected mitigation | Test that will prove it |
| :-: | :- | :- | :- |
| A-1 | A tampered or substituted release binary is deployed | verification on the controller with pinned fingerprints and OpenSSL ≥ 3.5; fail closed while nothing is pinned | render/syntax test asserts no task can skip verification; the verifier itself is covered by `packaging/release/tests/attacks.sh` |
| A-2 | An invalid `policy.toml`/`relay.toml` is pushed and the relay stops | `validate: zt-relay check … %s` before replace; restart only after `check` as `tcn` | CI: `zt-relay check` on a deliberately invalid rendering exits 78 |
| A-3 | All relays restarted at once (outage of every listener for the drain) | `serial: 1` | syntax test greps the example playbook |
| A-4 | The relay key transits the controller or the logs | keygen on the host; `no_log` on key tasks; only `pubkey` output is collected | review + render test (no task references the key's content) |

---

## 5. Priorities: this PR versus later

Commit order follows METHODOLOGY: RED spec tests, RED attack tests, then implementation,
then the review `docs/adversary/0015-relay-hardening.md`.

**In scope (this PR)**, in priority order:

1. **P0 host baseline**: `packaging/nftables/zt-relay.nft`, `packaging/sysctl/90-zt-relay.conf`
   (+ modules-load), unit diff §2(b); tests `spec.sh`, `attacks.sh`, `the_relay_unit_is_hardened`,
   the `host-hardening` CI job with the systemd e2e and the sandbox probe.
2. **P0 code that the host baseline depends on**: queue budget from `sysinfo` and the own cgroup
   (C-6, without it `MemoryMax` is incoherent); `max_blocking_threads(8)` (C-7);
   `listen_backlog` (C-1, C-2); accept-error classification and metric (C-3, C-4);
   `fd_limit_low` (C-5).
3. **P1 PROXY protocol v2** (§3.5, P-rows, fuzz target). Needed for the upstream-scrubbing
   pattern to work at all. It is the largest item; if review finds the PR too big, it is the
   one to split into a follow-up PR, and §2(e) must then say "direct relays only until PROXY v2
   lands".
4. **P1 Ansible role** with syntax, render and drift tests (§3.6).
5. **P1 docs**: `docs/RELAY_HARDENING.md` (install, PROXY mode, under-attack checklist,
   verification commands, lock-out recovery), OPERATIONS §4.1/§9/§17/§18, PROTOCOL §10.1.

**Out of scope**, with reasons:

| Item | Why not now |
| :- | :- |
| XDP/eBPF packet filtering | only pays off at multi-Mpps; needs a privileged loader and a second toolchain; the link saturates first anyway (§2(e)) |
| nftables `synproxy` | fragile (MSS, window scale and timestamps must match the host and path); `notrack` + syncookies + meters cover this workload |
| PROXY protocol v1 | text format, more parsing ambiguity; add only if a needed provider emits v1 only |
| Per-source cap on established connections | needs a confirmed key anyway; would break NATs and controllers (§2(a)-6) |
| Reserved pre-auth slots for known agent networks ("fast lane" during a handshake flood) | needs its own design and review (spoofing is impossible over TCP, but the allowlist becomes an asset); backlog |
| RST on refusal (`SO_LINGER 0`), `TCP_DEFER_ACCEPT` | small gains; the latter has no safe API (§2(a)-8) |
| `RestrictFileSystems=`, `TemporaryFileSystem=/etc`, a strace-derived syscall allow list | portability (BPF LSM) or breakage risk for small gains over the current sandbox |
| AppArmor/SELinux profile | distribution-specific; seccomp + mount namespace + nft egress already contain an RCE |
| Host-wide egress default-drop | breaks updates, NTP and cloud agents; an operator decision. The relay user is already egress-locked |
| Hardening of `zt-agent` and of agent hosts | different exposure (no listener); follow-up phase |
| Molecule/containers converge test of the role | heavy; syntax, render, drift and the namespace tests cover the risky parts |
| Exporting nft counters to Prometheus | monitoring nicety; the runbook shows `nft list` |
| Vendor-specific DDoS configuration | not endorsing a provider; patterns only (§2(e)) |

---

## Appendix A: the ruleset as validated

`nft -c -f` exit 0 (nftables 1.0.9, kernel 6.18, `unshare -rn`); loaded and reloaded for real
in a scratch namespace; the output-chain behaviour verified with and without the reject rule.
The example sets use documentation prefixes (192.0.2.0/24, 2001:db8:1::/48).

```nft
#!/usr/sbin/nft -f
# packaging/nftables/zt-relay.nft: host firewall of an internet-facing zt-relay.
# Loaded atomically (one transaction); only the table inet zt_relay is replaced, other
# tables (cloud agents, container runtimes) are left alone, but a drop here is final.
define RELAY_PORT = 7443
define SSH_PORT = 22

table inet zt_relay
delete table inet zt_relay

table inet zt_relay {
	# Management SSH: only these networks. An empty set means no inbound SSH at all.
	set admin_v4 { type ipv4_addr; flags interval; elements = { 192.0.2.0/24 } }
	set admin_v6 { type ipv6_addr; flags interval; elements = { 2001:db8:1::/48 } }
	# Who may reach the relay port: everyone (direct), or only the upstream proxies (PROXY v2).
	set relay_src_v4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/0 } }
	set relay_src_v6 { type ipv6_addr; flags interval; elements = { ::/0 } }
	# Per-source meters; bounded, so a spoofed flood cannot grow them (a full set stops adding).
	set syn_v4 { type ipv4_addr; size 65536; flags dynamic, timeout; timeout 1m; }
	set syn_v6 { type ipv6_addr; size 65536; flags dynamic, timeout; timeout 1m; }
	set ping_v4 { type ipv4_addr; size 16384; flags dynamic, timeout; timeout 1m; }
	set ping_v6 { type ipv6_addr; size 16384; flags dynamic, timeout; timeout 1m; }
	set ssh_v4 { type ipv4_addr; size 4096; flags dynamic; }
	set ssh_v6 { type ipv6_addr; size 4096; flags dynamic; }

	# Before conntrack: the relay port is stateless (the relay does its own connection
	# accounting), so a SYN flood cannot fill the conntrack table.
	chain raw_pre {
		type filter hook prerouting priority raw; policy accept;
		iif "lo" accept
		fib saddr . iif oif missing counter drop comment "reverse path: spoofed or bogon source"
		tcp dport $RELAY_PORT ip saddr != @relay_src_v4 counter drop
		tcp dport $RELAY_PORT ip6 saddr != @relay_src_v6 counter drop
		tcp dport $RELAY_PORT tcp flags & (fin | syn | rst | ack) == syn tcp option maxseg size 1-535 counter drop comment "tiny MSS"
		# New connections per IPv4 address or IPv6 /64: above the largest legitimate burst
		# behind one address (a NAT, a controller with forks); a dropped SYN is retried.
		tcp dport $RELAY_PORT tcp flags & (fin | syn | rst | ack) == syn add @syn_v4 { ip saddr limit rate over 50/second burst 500 packets } counter drop
		tcp dport $RELAY_PORT tcp flags & (fin | syn | rst | ack) == syn add @syn_v6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 50/second burst 500 packets } counter drop
		tcp dport $RELAY_PORT notrack
	}

	chain raw_out {
		type filter hook output priority raw; policy accept;
		tcp sport $RELAY_PORT notrack
	}

	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		tcp dport $RELAY_PORT ct state untracked accept
		ct state vmap { invalid : drop, established : accept, related : accept }
		tcp flags & (fin | syn | rst | ack) != syn ct state new counter drop
		# ICMP errors are not rate limited: a global limit would let anyone starve PMTUD.
		icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
		icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
		icmp type echo-request add @ping_v4 { ip saddr limit rate 5/second burst 10 packets } accept
		icmpv6 type echo-request add @ping_v6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate 5/second burst 10 packets } accept
		tcp dport $SSH_PORT ip saddr @admin_v4 add @ssh_v4 { ip saddr ct count over 8 } counter reject with tcp reset
		tcp dport $SSH_PORT ip6 saddr @admin_v6 add @ssh_v6 { ip6 saddr ct count over 8 } counter reject with tcp reset
		tcp dport $SSH_PORT ip saddr @admin_v4 accept
		tcp dport $SSH_PORT ip6 saddr @admin_v6 accept
		counter comment "dropped by policy"
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	# Egress: the relay never dials out. Its sockets may only send from the relay port; no
	# loopback, no cloud metadata service, no internal network for a compromised process.
	chain output {
		type filter hook output priority filter; policy accept;
		meta skuid "tcn" tcp sport $RELAY_PORT accept
		meta skuid "tcn" counter reject comment "zt-relay egress"
	}
}
```

Notes for the implementation:

- nft 1.0.9 refuses `$VARIABLES` inside `limit rate` and `ct count`: the numbers are literal
  in the packaged file and rendered by the Ansible template.
- `meta skuid "tcn"` fails to load if the user does not exist (verified): the role runs
  `systemd-sysusers` first, and at boot `systemd-sysusers.service` runs before
  `nftables.service`.
- DHCP and router advertisements: DHCP clients receive offers on packet sockets (before
  netfilter) and renewals as conntrack replies; providers that need more get an
  `zt_relay_nft_extra_input` variable, never a broader default.
