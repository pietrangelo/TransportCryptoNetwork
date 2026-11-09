# TCN: reliability, resilience, self-healing and efficiency (analysis for the next phase)

Status: analysis and design proposal. No code was changed. Baseline: `main` at `dfb3b8b`
(Phases 1–6 merged). A separate analysis covers post-quantum (PQ) cryptography; this document
only notes where PQ handshakes (ML-KEM-768 adds about 1.1 KB per handshake message, an ML-DSA-65
signature is 3.3 KB and its public key 1.9 KB) change the recommendations.

Caveat: `CLAUDE.md` says the project instructions, skills and the adversary agent definition are
stored encrypted (`.claude/private/CLAUDE.md`, `.claude/agents/adversary.md`). They were **not**
decrypted in this session, so this analysis relies only on `docs/` and the code. Any project rule
in those files is not reflected here.

Sources read: `docs/METHODOLOGY.md`, `docs/PROTOCOL.md`, `docs/OPERATIONS.md`,
`docs/phase6-plan.md`, `docs/adversary/0001`–`0006`, `crates/zt-net/src/*`,
`crates/zt-application/src/{relay,ratelimit}.rs`, `crates/zt-crypto/src/noise.rs`, `bins/*/src/main.rs`,
`packaging/systemd/*`.

---

## 1. Summary

TCN already has a solid failure-handling base. Every I/O call has a timeout and every queue is
bounded. The agent connects to all relays at once (active-active) with its own backoff for each
relay. The client fails over in order, and stops at answers that are about access rights. Reloads
check the new files before they apply them and keep the old configuration if a file is bad. The
service sends `Type=notify` readiness only once SIGHUP is handled. Release builds use
`panic = "abort"` with `Restart=always`. What is missing falls into five groups:

1. **Admission under load (highest impact).** The handshake limiter allows a burst of 20 per
   source IPv4 address, then 1 every 3 s, and it cannot be configured. It charges successful
   handshakes the same as failed ones. An Ansible controller with `forks > 20`, or a fleet of
   agents behind a cloud NAT gateway, gets locked out. For example, 300 agents behind one NAT
   need about 14 minutes to re-register after a relay restart. Pre-auth handshakes also share
   the 4 096 connection slots with established peers.
2. **Reconnect storms and dead-peer detection.** The backoff adds jitter on top of the delay
   (`delay + U(0, delay/2)`) instead of drawing the whole delay at random, and it resets to 1 s
   after any session longer than 60 s. So the fleet reconnects in tight waves after a relay
   restart. A half-open path is noticed only after the 90 s idle timeout. Until then, every
   client that tries that relay waits up to 15 s for `OpenAck`.
3. **Lifecycle.** There is no SIGTERM handling, so no graceful drain. A relay restart cuts every
   SSH session that passes through it, including `ControlPersist` masters. There is no systemd
   watchdog. Critical tasks are detached, and if one of them returns, the process stays up but
   degraded and nobody is told. `ExecReload=kill -HUP` returns before the reload result is
   known. A crash loop hits systemd's default start limit (5 starts in 10 s with
   `RestartSec=2s`) and then stops restarting.
4. **Client failover deadline (backlog A5-4).** The relays are tried one after another. One
   attempt can take up to 10 s (connect) + 10 s (handshake) + 15 s (`Open`) = 35 s, so 8
   relays can take up to 280 s. A black-holed first relay adds up to 35 s to every Ansible
   connection.
5. **Observability and test tooling.** There are no metrics and no health signal: only audit
   logs. Unauthenticated traffic can create one WARN line per TCP connection, which can trigger
   journald's rate limit and so lose real audit events. Load-balancer probes look like
   `authentication_failed`. The failover and backoff logic is not sans-IO, and there is no
   deterministic network simulation, so herd, partition and drain behaviour cannot be tested
   under the methodology's RED-first rule.

The recommended phases are R-1 to R-6 (section 6). R-1 to R-3 should ship **before** PQ
handshakes reach production. PQ makes each handshake several times larger and more expensive,
and the PQ rollout itself needs rolling restarts of every relay and agent, which needs drain.
Almost everything proposed here needs **no wire change**. The two items that would change the
wire are listed as decisions, and the recommendation for both is "don't change it".

---

## 2. What exists today

| Area | Mechanism | Evidence |
| :- | :- | :- |
| Agent multi-relay | Active-active: one session per relay (≤ 8), each with its own backoff, in a `JoinSet` | `zt-net/src/agent.rs` `run`, `run_one` |
| Agent backoff | 1 s → 60 s doubling, `+ U(0, delay/2)` jitter, reset when the session lasted > 60 s | `agent.rs:93–110` |
| Keepalive / idle | `Ping` every 30 s from agent and client; idle timeout 90 s on every side; the relay only answers `Pong` (rate 10 burst, 1/5 s) | `lib.rs` `Timeouts`, `relay.rs` (application) `on_frame` |
| Agent registration takeover | A new registration for a node drains the old connection; this self-heals a half-open agent connection seen by the relay | `zt-application/src/relay.rs` `on_register` |
| Client failover | Ordered, sequential; retries only on errors before `OpenAck` that say nothing about access rights | `client.rs` `connect`, `may_try_next_relay` |
| Timeouts | connect = handshake 10 s, open 15 s, write 30 s, ssh connect 5 s, register 10 s | `lib.rs`, `RelayLimits` |
| Admission | Connection semaphore 4 096 (agents, clients and in-progress handshakes together); `HandshakeGate` per IPv4 address or IPv6 /64 (20 burst, 1/3 s) plus a /48 limit on new /64s | `relay.rs:388–395`, `ratelimit.rs` |
| Flow control | 256 KiB initial window, 1 MiB max, `MIN_CHARGE` 512; the relay enforces credit before queueing; queues sized to credit | PROTOCOL §9, `stream.rs`, `relay.rs` `outbound_capacity` |
| Hub | Single sans-IO `RelayCore` owned by one task; never awaits a connection (`try_send`, overflow → disconnect) | `zt-net/src/relay.rs` `hub` |
| Reload | `SIGHUP` → load and check → atomic `watch` swap → applied to open connections; a bad file keeps the previous one, ERROR audit | `reload.rs`, `revocable.rs` |
| Startup | `Type=notify`, `READY=1` only after SIGHUP handler installed; `Restart=always`, `RestartSec=2s` | `systemd.rs`, `packaging/systemd/*.service` |
| Crash behaviour | `panic = "abort"`, no-panic lints in production code | `Cargo.toml` |
| Time | Wall clock only for certificates (`unix_now`), monotonic for all timeouts; `SKEW` 120 s on `not_before` only; agent rechecks expiry ≤ 60 s, relay every 1 s tick | PROTOCOL §15.6–15.7 |
| Tests | `tokio::test(start_paused)` in `keys.rs`; real-socket e2e/HA tests; fuzzing incl. `relay_core`; RSS measurement used ad hoc in review 0005b | `crates/zt-net/tests/*`, `fuzz/` |

---

## 3. Gap analysis

Severity uses the adversary reviews' scale: high blocks a merge, medium, or low.

| # | Gap | Sev. | Evidence / reasoning |
| :-: | :- | :-: | :- |
| G1 | **The handshake limiter penalises legitimate bursts and NAT.** The token is taken at `accept`, before authentication, and is never returned. The defaults are hard-coded (`RelayConfig::default()` in `zt-relay`). Ansible with `forks = 50` against 200 hosts opens about 200 outer connections from a single IP in a few seconds: 20 succeed and the rest fail on every relay, so hosts become UNREACHABLE. Agents behind one NAT IP after a relay restart are admitted at about 20 per minute, because rejected agents back off to 60 s. With N relays restarting during a fleet upgrade, nodes are unreachable for minutes. | **high** | `relay.rs:392`, `ratelimit.rs` `HandshakeGate::admit`, PROTOCOL §10 |
| G2 | **Pre-auth handshakes share slots with established peers.** 4 096 slots cover agents, clients and handshakes together. An attacker from about 205 IPv4 addresses (20 each) can hold every slot by sending msg1 slowly within the 10 s handshake timeout. Established peers keep working, but reconnecting agents and new clients are locked out. The handshake codec also accepts a length prefix up to 65 535, and `LengthDelimitedCodec` reserves the declared length up front (to confirm with a test). That is up to 64 KiB buffered per pre-auth connection (256 MiB total), although a real msg1 is at most `96 + 4 328 + 16` bytes. | medium | `channel.rs` `codec()`, `accept` |
| G3 | **Synchronised reconnects (thundering herd).** The jitter is added on top of the delay, and the first retry after a long session is 1.0–1.5 s for everyone. The relay restarts in about 2 s plus startup, so the fleet arrives in a few waves about 1.5 s wide. The listen backlog is tokio's default of 1 024. Handshake CPU runs on the async workers, so a storm also adds latency to established SSH sessions. This is moderate with classic Noise (4 X25519 per responder handshake, about 0.2 ms). With PQ, bytes per handshake grow 10–40× and CPU 2–4×. | medium (PQ: medium+) | `agent.rs:99–110` |
| G4 | **Slow dead-peer detection.** Idle is 90 s and keepalive 30 s. The relay never probes; the agent treats a `Ping` from the relay as a protocol error, so relay-side probing would be a wire-semantics change. A silent NAT drop or a host crash with no FIN leaves the relay routing `Open`s to a dead agent for up to 90 s. Each client waits the 15 s `open` timeout, then fails over. `TCP_USER_TIMEOUT` and TCP keepalive are not set. | medium | `agent.rs:312–315`, `Timeouts` |
| G5 | **No overall client deadline (A5-4).** Up to 35 s per relay, sequential. Each `zt-client` is a fresh process, so it keeps no memory of a bad relay between invocations. **Closed by R-4** (§5.3). | low→medium for Ansible | `client.rs:61`, review 0005 #4 |
| G6 | **No graceful drain or zero-downtime upgrade.** No SIGTERM handler: the process dies and every SSH session through it drops, including `ControlPersist` masters, and Ansible tasks fail. `CloseReason::Drained` exists but is used only for the session limit. A PQ rollout needs rolling restarts of every relay. | medium | `bins/*/main.rs` |
| G7 | **Detached critical tasks.** The hub, both SIGHUP handlers and the watchers are `tokio::spawn`ed and their handles dropped. If one returns without panicking (for example `Signal::recv` → `None`, or the hub's receiver closing), the process keeps running in a degraded state. The worst case is that SIGHUP is silently ignored, so **revocation stops working without anyone noticing**. In test builds, which unwind, a panicking spawned task is swallowed and the test can still pass. | medium | `zt-relay/src/main.rs`, `agent.rs` `run` |
| G8 | **No watchdog, and the restart policy can give up.** No `WatchdogSec`, so a wedged runtime (deadlock, livelock) stays up forever. With `RestartSec=2s` and the default `StartLimitBurst=5` / `StartLimitIntervalSec=10s`, a fast crash loop puts the unit permanently into `failed`. A crash bug triggered by one frame makes the whole agent fleet crash-loop in step, and each restart reconnects to every relay. | low–medium | `packaging/systemd/*.service` |
| G9 | **Reload is fire-and-forget.** `ExecReload=kill -HUP` returns 0 even when the reload fails, so an Ansible handler reports success while a revocation is **not** in force. The relay reloads keys and policy in two independent tasks; that is on purpose, so a bad key file cannot block a revocation, but a reload can then apply only partly. Events carry no hash of the configuration, so operators compare `sha256sum` by hand (OPERATIONS §2, §10.2). | medium (security-relevant) | `reload.rs`, units |
| G10 | **Unauthenticated traffic is amplified into logs.** Each refused connection logs a WARN (`connection limit reached`, `handshake rate limit`, `authentication_failed`). journald's per-service rate limit (10 000 per 30 s by default) then **drops real audit events** (`access_revoked`, `session_established`). A port scanner or LB health check produces `authentication_failed reason=HandshakeFailed` on every probe, which weakens the security signal. | medium | `relay.rs:389–394, 431` |
| G11 | **No global memory budget on the relay.** Memory per connection is bounded by `streams × MAX_WINDOW` (32 MiB per client connection, 64 MiB per agent connection), but the total over 4 096 connections is far above RAM. Filling it needs authenticated peers (a compromised agent, or an authorised client with SSH access producing output) and a receiver that stops reading. The bound also relies on a subtle invariant: each connection task does its reads and its writes in **one** `select!`, so a blocked write also stops it from reading new `WindowUpdate`s. Splitting reader and writer into separate tasks would quietly remove the bound. | low–medium | `relay.rs` `Connection::serve`, `outbound_capacity` |
| G12 | **Clock handling has no detection.** The relay and agent use the wall clock correctly, but nothing notices a wall-clock step. A backward step makes expired certificates valid again (an accepted residual risk), and an operator alarm would make it visible. The units do not order after `time-sync.target`. | low | PROTOCOL §15.6 |
| G13 | **Efficiency.** On every frame received: `decrypt` allocates a `Vec`, then `BytesMut::from(slice)` copies it again (`channel.rs:183`). On every send: an encode buffer plus another `Vec` from `encrypt`, then a copy into the `Framed` write buffer. The relay therefore copies each payload about 4 times per hop. The fixed 256 KiB window caps throughput per stream at window/RTT (≈ 2.6 MB/s at 100 ms), which is slow for Ansible `copy` / `synchronize` of large artefacts. The 16 KiB `CHUNK` costs 4× more frames and AEAD calls than needed for bulk transfers. | low | `channel.rs`, `stream.rs` |
| G14 | **Untestable resilience logic.** Backoff, failover, keepalive and drain sit inside async loops in `zt-net`, which goes against the spirit of the sans-IO rule. There is no simulated network for partitions, half-open paths, latency or restarts, and no soak or leak test in CI (bug 5b-1 was found by measuring RSS by hand). | medium (methodology) | — |
| G15 | **Capacity limits are implicit.** Agents and clients share one cap of 4 096 connections, so a relay serves fewer than 4 096 agents. `LimitNOFILE=16384`. The listen backlog is not configurable. A duplicate agent (for example a cloned VM with the same key) makes the two copies take the node from each other about once a second, killing that node's SSH sessions each time, and no alarm is raised. | low | `RelayConfig`, `on_register` |
| G16 | **Agent restart during an Ansible run.** Upgrading `zt-agent` *through* TCN with `systemctl restart` kills the session that runs the task. With a drain (G6) this becomes a wait until the drain deadline instead. | low (ops) | OPERATIONS §9 |

Items checked and **not** found to be gaps:

- Cancellation safety: `Established::recv` is cancellation-safe.
- The relay hub never blocks on a peer.
- Per-relay quotas on the agent hold (0005b-1).
- Pre-auth amplification: the relay sends nothing to an unauthenticated peer, so even a bigger
  PQ msg2 cannot be used for amplification. Keep this as an invariant.
- Finding 0001-10 (small `Bytes` pinning large buffers): every message is copied into a buffer
  of its exact size and `MIN_CHARGE` charges small frames, so it appears to be in practice
  mitigated. The backlog should close it explicitly, with a test.

---

## 4. How the PQ handshakes change these recommendations

| Topic | Classic today | With hybrid PQ (indicative) | Consequence here |
| :- | :- | :- | :- |
| Outer msg1 | 96 B + certificate (≤ 4.3 KB) | + ML-KEM ek/ct ≈ 1.1–2.3 KB; ML-DSA-65 certificate ≈ 5.5 KB+ | Pre-auth buffer cap = **computed** `MAX_MSG1_LEN` (a `const`), not 64 KiB (G2); msg1 spans several TCP segments, so loss costs a retransmission (keep the handshake timeout ≥ 5 s) |
| Responder CPU | ≈ 4 X25519 ≈ 0.2 ms | + ML-KEM decaps (≈ 30–60 µs each) + ML-DSA verify (≈ 0.1–0.2 ms) | ≈ 2–4× per handshake: run handshakes in a **bounded worker pool**, not inline on async workers (R-1); the gate should count *cost*, not connections |
| Bytes per reconnect | ≈ 0.3 KB | ≈ 5–12 KB | A 4 000-agent herd is ≈ 20–50 MB in one or two seconds: on small relay VMs the herd becomes bandwidth-bound, so spreading reconnects (R-2) moves from nice-to-have to required |
| Handshake rate limit | 20 burst / 1 per 3 s | same numbers cost 2–4× CPU | Refund on success plus a per-identity bucket (D-1) keeps legitimate traffic away from the limit, so the *unauthenticated* budget can stay tight even as each handshake costs more |
| Amplification | none (silence to unknown peers) | msg2 grows but is sent only to authenticated peers | Keep "no bytes to an unauthenticated peer" as a catalogue row for the PQ design; don't add a pre-auth "busy" reply |
| Session resumption | small gain | large gain (skips KEM + certificate verify) | Still deferred (D-8); a local multiplexer amortises PQ handshakes over many SSH connections without new cryptography |
| Timeouts | 10 s handshake | still adequate; ≈ 1 s extra on 64 kbit/s links | Split "msg1 must arrive within 3–5 s" from "handshake complete within 10 s" |
| Cookies / puzzles | not needed (TCP proves the source address) | still not needed | TCP's handshake (with SYN cookies) already proves return routability, so a WireGuard-style cookie adds nothing, and puzzles hurt small agents more than botnets. Spend the effort on admission accounting instead |

---

## 5. Design proposals (with tradeoffs)

All proposals follow the hexagonal rules. Decisions such as backoff, failover choice, liveness
deadlines, drain progress and budgets become **sans-IO state machines in `zt-application`**:
time and random samples are passed in as parameters, there is no I/O, and they use the no-panic
arithmetic (`checked_*` / `saturating_*`, no indexing). `zt-net` only adapts them to tokio. The
binaries stay composition roots that handle signals and `sd_notify`. Nothing relies on
`catch_unwind`: with `panic = "abort"`, supervision happens at the **process** level
(crash-only design).

### 5.1 Admission and handshake budget (G1, G2, G10, G15)

- **Refund on authenticated success.** `HandshakeGate::refund(addr, now)` gives the token back
  once the policy has admitted the peer *and* msg2 has been sent. Today the gate is owned by
  the accept loop and connection tasks would need to reach it: either use a
  `std::sync::Mutex<HandshakeGate>` (only held briefly, never across an `await`) or send
  refunds back over a bounded channel. The result is that the per-source budget only limits
  **failed or unauthenticated** handshakes, so NAT and Ansible bursts no longer drain it.
- **Per-identity bucket** for authenticated handshakes (keyed by fingerprint, for example burst
  64 and 10/s). This stops a stolen key or a buggy agent loop without affecting neighbours on
  the same IP.
- **Separate pools.** `max_handshakes` (pre-auth, for example 1 024) and `max_connections`
  (authenticated, for example 8 192, with `max_agents` and `max_clients` as sub-limits).
  Handshake slots are released when msg1 is done. Also add a `msg1_deadline` (3 s) separate
  from the 10 s handshake timeout.
- **Handshake buffer cap.** During the handshake phase the codec's `max_frame_length` is set to
  `MAX_MSG1_LEN` (a `const`, so it also covers PQ when that lands), and the transport limit
  applies only after the handshake.
- **Handshake worker pool.** The Noise responder and certificate verification run on a
  bounded `spawn_blocking` pool (a semaphore with about `cores/2` slots), so a storm cannot
  starve the data plane. Tradeoff: a thread hop per handshake (≈ 10 µs), which is negligible.
- **Configurable limits.** Add `[limits]` in an optional `relay.toml`, or CLI flags, with the
  defaults documented in PROTOCOL §10. Defaults to reconsider: per-source unauthenticated
  burst 32 at 1/s (this budget now only meets failures), backlog 4 096.
- **Aggregated pre-auth logging.** Refusals before authentication become counters plus one
  summary event every 10 s (`preauth_refusals {reason → count, distinct_sources}`), never one
  line per connection. `authentication_failed` stays per event **only** once Noise has proven
  an identity (`peer` present). A connection closed before any byte arrives
  (`preauth_aborted`) is counted, not audited. Tradeoff: per-source forensics for anonymous
  scans now come from the firewall or conntrack, not from the audit log.

### 5.2 Reconnect, backoff and liveness (G3, G4)

- **`ReconnectPolicy` (sans-IO):**
  `next(&mut self, outcome: Outcome, lived: Duration, sample: u64) -> Duration`.
  - **Full jitter** on failures: `U(0, min(cap, base·2ⁿ))`, with base 1 s and cap 30 s; a
    lower cap than today shortens recovery for a single relay.
  - **Spread window** after a session that ended once established (the relay restarted or
    drained): the first retry is drawn from `U(0, W)`, with `W = --reconnect-spread` (default
    10 s). Tradeoff: up to W seconds before that relay can serve this node again, which HA
    hides; with a single relay it adds W to the outage, so allow W = 0.
  - An attempt that the relay refused before authentication (a gate drop shows up as EOF
    during the handshake) counts as a failure, which keeps the backoff growing.
- **`Liveness` (sans-IO):** tracks the last inbound frame and outstanding Ping nonces; it
  outputs "send Ping", "dead" and a Ping→Pong round-trip estimate (useful for metrics and for
  window tuning).
  - Agent defaults: keepalive 10 s, dead after 3 unanswered (≈ 30 s). This stays within the
    relay's Ping limit of 1 per 5 s.
  - Relay: idle timeout configurable per role. Default for agents: keep 90 s until the fleet
    runs the new agent, then lower it to 35 s. Old agents ping only every 30 s, so a lower
    relay idle would cut them off (catalogue row R2-L3).
- **Socket options:** `TCP_USER_TIMEOUT` (≈ 20 s) and TCP keepalive on every socket. This
  needs `rustix` with its `net` feature (safe API, crate already used) or `socket2`.
  `TCP_USER_TIMEOUT` catches unacknowledged sends faster than any application timer.
- **No relay-initiated Ping** (D-3): it would change agent semantics (today a `Ping` from the
  relay is a violation) and needs a staged rollout. Agent keepalive plus `TCP_USER_TIMEOUT`
  already bound detection to about 30 s on both sides.
- **Duplicate-agent flapping:** the relay counts registration takeovers per node in a sliding
  window and raises `agent_flapping {node, fingerprints, count}` (WARN). It does not block,
  because whoever holds the key could use a block to deny service.

### 5.3 Client failover deadline (A5-4, G5)

**Implemented (R-4, closes A5-4).** `zt_application::failover::FailoverPlan` with the review
0007 change (AP-10): the hedge fires only while the attempt in flight has not completed connect
and outer handshake; once it has, the client waits for the `OpenAck` up to the open timeout and
never hedges. The events are `Connected(i)`, `OuterReady(i)`, `Acked(i)`, `Failed(i, kind)`
plus `tick(now)`; the actions `Start(i)`, `Cancel(i)`, `TimedOut(i, step)`, `Proceed(i)`,
`GiveUp(Deadline | Exhausted | Refused(i))`. The stagger gets a jitter of at most a quarter of
it (0.5 s) from an injected sample, so a fleet that starts together does not hedge together.
`zt-net` drives it with the attempts as futures of the client's own task (nothing spawned;
dropping the client drops every connection); a cancelled attempt that has sent `Open` sends
`Close Normal` (bounded at 1 s), and one cancelled in its outer handshake completes it and
confirms its key with a `Ping`, so that R-1 refunds the token it charged (review 0011, A11-1).
`require_outer_suite` (A10-9) is carried into `ClientConfig` and enforced before any dial.
`zt-client` exits 75 (`EX_TEMPFAIL`) at the deadline and for every other give-up that says
nothing about the right of access (A11-4). After review 0011 the deadline is 8 s and the
`OpenAck` wait is the time left shared out over the relays left, between 2 s and 4 s (A11-2,
A11-3). PROTOCOL §13 and OPERATIONS §5 have the operator view.

- **`FailoverPlan` (sans-IO):** events `Started(i)`, `Failed(i, kind)`, `Acked(i)`,
  `Tick(now)`; actions `Start(i)`, `Cancel(i)`, `Proceed(i)`, `GiveUp(err)`.
  - **Overall deadline** (`connect_deadline`, default 20 s, settable in `client.toml`; 8 s
    since review 0011, to fit Ansible's default `ConnectTimeout` of 10 s).
  - **Tighter per-step timeouts:** connect 3 s, handshake 5 s, open 10 s (since review 0011:
    the time left ÷ the relays left, between 2 s and 4 s).
  - **Staggered hedge:** start relay *i+1* when relay *i* has failed, or after a stagger of 2 s
    with no `OpenAck` yet; at most 2 attempts in flight. The first `OpenAck` wins and the others
    are closed at once (`Close Normal` on the stream, then EOF).
- **Invariants that must be kept:**
  1. msg1 of the end-to-end channel is sent on **one** relay only, after its `OpenAck`.
  2. A policy answer (`NotAuthorized` / `UnknownNode`) from any relay *before* an `OpenAck`
     aborts every attempt.
  3. After `Proceed`, nothing is retried.

  Accepted change: if relay 1 is slow and relay 2 acknowledges first, a later `NotAuthorized`
  from relay 1 is ignored. Mismatched policies are already a configuration error (finding
  0005-2), and an attacker would use their own client anyway.
- **Cost:** in the worst case each hedge doubles the handshakes, which is why there are at most
  2 in flight and why it ships after R-1. On the agent, the losing `Open` holds a per-relay
  stream slot until its `Close` arrives (milliseconds) or the open timeout. Review 0011 (A11-1)
  found that the losers also spent the client's R-1 per-source budget (cancelled before key
  confirmation, so never refunded); they now confirm their key before they close.
- **Ansible guidance** (OPERATIONS §5):
  - `[ssh_connection] retries = 3`: ssh exits with 255 on a ProxyCommand failure and Ansible
    retries with backoff.
  - `[defaults] timeout` (passed to ssh as `-o ConnectTimeout`, 10 s by default) at least
    `connect_deadline_secs` + 2 s (review 0011, A11-2).
  - `ServerAliveInterval 15` and `ServerAliveCountMax 3`.
  - A longer `ControlPersist` (for example 300 s) is safe: revocation and certificate expiry
    still close multiplexed sessions (PROTOCOL §12, §15.7).

### 5.4 Lifecycle: drain, supervision, watchdog, reload (G6–G9, G16)

- **Relay drain (no wire change).** The first `SIGTERM` starts a drain:
  1. Send `STOPPING=1` to systemd.
  2. Close the listener. New clients get ECONNREFUSED and move to the next relay at once;
     reconnecting agents back off.
  3. Keep established agent connections and existing client streams.
  4. A `DrainController` (sans-IO) waits until there are no client streams or
     `--drain-timeout` has passed (default 60 s), then sends `Close Drained` on the remaining
     streams, closes the agent connections and exits.

  A second `SIGTERM`, or a `SIGINT`, exits immediately. `TimeoutStopSec` must be above
  `--drain-timeout`. `zt-client` already exits 1 on a non-`Normal` `Close`, and
  `ControlMaster auto` makes the next ssh start a fresh master.
- **Agent drain:**
  1. On `SIGTERM`, answer new `Open`s with `Reject NodeOffline`. Clients try the other relays,
     which reach the same agent, so they get an accurate "node offline".
  2. Let existing sessions finish until `--drain-timeout`.
  3. Document `systemctl restart --no-block` (or Ansible `async`) for an agent upgraded
     *through* TCN (G16).
- **Zero-downtime upgrades:** a rolling restart of relays with ≥ 2 relays is the supported
  path (runbook in OPERATIONS §8). `SO_REUSEPORT` blue/green for a single relay is deferred
  (D-6).
- **Supervision.** The composition root keeps every critical task (hub, accept loop, SIGHUP
  handlers, relay session loops) in one `JoinSet`. **If any critical task exits, it is logged
  at ERROR and the process exits with a failure code**, and systemd restarts it. Reminder
  tasks are non-critical: log and respawn. Tests install a panic hook that records panics in
  spawned tasks and fails the test (G7).
- **Watchdog.** `WatchdogSec=60s`, with `WATCHDOG=1` sent every 20 s by a task that checks
  heartbeats: the hub has processed a `Tick` within 5 s, the SIGHUP handlers are alive and the
  runtime is responsive. It does **not** cover connectivity (D-7): restarting an agent because
  a relay is unreachable does not fix anything and makes the herd worse. Also send
  `STATUS=` lines for `systemctl status`, for example
  `relays 2/3 connected, 4 sessions, policy sha256:ab12…`.
- **Restart policy.**
  - Relay: `StartLimitIntervalSec=0`, `RestartSec=2s`, and where systemd ≥ 254 is available
    `RestartSteps=5` with `RestartMaxDelaySec=60s`.
  - Agent: the same, plus `RestartMaxDelaySec`, so a crash-looping fleet spreads out its
    reconnects instead of hitting the relays every 2 s.
  - Configuration errors at startup still fail the unit. There is **no** "last known good"
    fallback, because that could re-admit a revoked key (catalogue R3-C4).
- **Reload safety.**
  - Add `zt-relay check …` and `zt-agent check …`, which run the same loaders and
    infrastructure-key checks as `run` at startup (a pre-flight before a restart).
  - *Superseded by review 0010 (A10-1):* `ExecReload=… check <same args>` repeated
    `ExecStart=`'s arguments, and every drop-in that OPERATIONS prescribes for `ExecStart=`
    (`--revocations` for a pinned CA, key rotation) broke `systemctl reload`. The units now run
    `ExecReload=zt-<bin> reload --pid $MAINPID`: it sends `SIGHUP` and waits for the running
    process's own verdict, which the process publishes in its runtime directory
    (`RuntimeDirectory=`) after validating its files with its own arguments. `systemctl
    reload` fails exactly when the running process rejected the files.
  - The process announces every `SIGHUP` with `RELOADING=1` (and `MONOTONIC_USEC=`) and
    closes it with `READY=1`, which works with `Type=notify` on every systemd. `Type=notify-reload`
    (systemd ≥ 253; RHEL 9 and Debian 12 ship 252) is not used: it has no way to report a
    rejected reload, and `reload --pid` does.
  - Every `*_reloaded`, `*_reload_failed` and `*_in_use` event gains the `sha256` of each file
    and a monotonic `generation`. Fleet comparison then becomes a log query, and the same
    values appear as an info metric.
  - Keep keys and policy reloading independently (the existing rationale stands): since
    review 0010 one `SIGHUP` is one step and one generation; a key file that fails is a
    `relay_keys_reload_failed` and a `warning:` from `reload`, never a blocked policy.
  - Optional `check --diff` against the running process is out of scope: it would need a
    control socket.
- **Clock.**
  - On each relay tick and agent recheck, compare the change in wall-clock time with the change
    in monotonic time. If they differ by more than 5 s, emit `clock_jump {delta_secs}` (WARN;
    backward jumps are security-relevant).
  - At startup, if the wall clock reads before the build's `SOURCE_DATE_EPOCH`, log at ERROR.
    Certificate checks already fail closed in that case.
  - Add `After=time-sync.target` to the units. This only orders startup; it waits for real
    sync only if `systemd-time-wait-sync` or `chrony-wait` is enabled, which the docs
    recommend for certificate deployments.

### 5.5 Observability for self-healing (G10, G14)

- **Counters:** hand-written `AtomicU64` counters, gauges and fixed-bucket histograms in
  `zt-net`, with a ~100-line Prometheus text writer. No new crates, which matches the Phase 6
  no-new-dependencies stance and keeps `cargo deny` unchanged.
- **Relay:** `--metrics-listen 127.0.0.1:9643`, **off by default**. A minimal HTTP/1.0
  responder reads at most 1 KiB of request, applies a timeout and is fuzzed. The same endpoint
  serves `/healthz` (process alive, hub heartbeat fresh) and `/readyz` (listener open and not
  draining) for load balancers. Metrics:
  - connections by role
  - handshakes by outcome and reason
  - gate and limit refusals
  - registered agents
  - active streams
  - `Open` outcomes by `RejectReason`
  - bytes forwarded
  - queue-overflow disconnects
  - reload generation, success and failure timestamps
  - certificate expiries
  - handshake latency histogram
  - hub loop lag
  - drain state
  - `build_info`
- **Agent (no inbound port):** writes a node_exporter **textfile** (`/run/tcn/agent.prom`,
  `RuntimeDirectory=tcn`, atomic rename) every 15 s. It also offers `STATUS=` and
  `zt-agent status` (reads that file). Metrics:
  - per relay *index*: connected, last registration time, consecutive failures, current
    backoff, Ping round-trip
  - sessions
  - sshd connect failures
  - end-to-end authentication failures by check
  - reload generation
  - `clock_jump` count
- **Cardinality and privacy:** no fingerprints, client names or node names as labels (the
  relay would expose its node inventory); only roles, reasons and relay indices. Node names
  could be added later as an opt-in for the relay.

### 5.6 Efficiency (G11, G13)

- **Fewer copies:**
  - Keep the plaintext `Vec` from `decrypt` and decode from `Bytes::from(vec)` with no second
    copy.
  - Encrypt into a per-connection scratch buffer: `snow` already writes into a caller-supplied
    slice, so `Transport::encrypt_into(&mut BytesMut)`.
  - Use `Framed` with a pre-sized write buffer.

  Expected: about 2 fewer allocations and 2 fewer copies per frame per hop. Measure with a
  criterion-style benchmark, kept as a dev-dependency only if approved.
- **Window auto-tuning (no wire change):**
  - The receiver grows its granted window, up to the existing `MAX_WINDOW` (1 MiB), when it
    sees the sender stall within about one Ping round trip.
  - The relay's memory bound is already sized for `MAX_WINDOW`, and old peers still work
    because the rules don't change.
  - Consider a 32 KiB `CHUNK` for bulk transfers. Tradeoff: up to about 32 KiB of
    head-of-line delay for interactive streams that share the agent's connection.
- **Global byte budget on the relay:** count the queued outbound bytes for each connection. If
  the total goes over `--queue-budget` (default min(25 % RAM, 1 GiB)), disconnect the
  connection with the largest backlog (the slow reader) with `Close Drained` on its streams,
  and audit it. Add a regression test for the read/write-in-one-task invariant (G11).
  `MemoryHigh=` / `MemoryMax=` in the unit act as the last resort, and an OOM kill is a
  crash-only restart.
- **Smaller agent footprint:** a `worker_threads(2)` runtime for the agent; it handles few
  streams.

### 5.7 Testing: chaos, simulation, soak (G14)

- **First, extract the logic as sans-IO.** `ReconnectPolicy`, `Liveness`, `FailoverPlan`,
  `DrainController`, the admission budget and the byte budget become pure state machines.
  Each gets unit tests plus `proptest` models: no deadline is ever exceeded, the backoff stays
  inside its bounds, the spread is uniform, and failover never proceeds on two relays.
- **Deterministic network simulation with `turmoil`** (dev-dependency, D-9). Add a narrow
  network port in `zt-net` (`trait Dialer { connect }`, `trait Acceptor { accept }`, with the
  stream generic over `AsyncRead + AsyncWrite`; `channel` already is). Production uses the
  tokio implementation; tests use turmoil's `net` types behind a `sim` cfg or feature.
  Scenarios with a fixed seed:
  - relay restart with N agents, asserting the arrival-rate histogram
  - one-way partition and half-open path
  - latency of 200–500 ms
  - NAT rebinding (the source address changes)
  - drain during an active session
  - a black-holed first relay
  - SIGHUP storm during a herd
- **Fault proxies in CI** for the real binaries: `toxiproxy`, `tc netem` and an iptables DROP
  rule for half-open paths.
- **Nightly soak (≥ 1 h):**
  - processes: 1 000 agent sessions (tasks), 3 relays, Ansible-like client bursts
  - faults injected: random relay SIGTERM and SIGKILL, SIGHUP every 30 s, certificates expiring
    every 2 min
  - assertions: RSS, file descriptors and task counts stay flat (slope near zero); no audit
    loss; recovery time ≤ target

  This turns the manual measurement from review 0005b-1 into a permanent gate.

---

## 6. Phased plan

Every phase follows Adversarial TDD (`docs/METHODOLOGY.md`): RED specification tests and RED
attack tests from the catalogue below are committed first, then GREEN, REFACTOR, and an adversary
review `docs/adversary/00NN-<area>.md`. Wire format: **unchanged** in every phase unless a
decision says otherwise. PROTOCOL §10 and §13 and OPERATIONS §4–§9 are updated with each phase.

| Phase | Scope | Ordering rationale | Before PQ? |
| :- | :- | :- | :-: |
| **R-1 Admission & handshake budget** | 5.1 in full: refund-on-success, per-identity bucket, separate pre-auth and authenticated pools, `msg1_deadline`, handshake buffer cap = `MAX_MSG1_LEN`, bounded handshake worker pool, configurable limits and backlog, aggregated pre-auth logging, `preauth_aborted` | Fixes the only **high** gap (G1). Small and mostly in sans-IO `ratelimit.rs`. It is the prerequisite for hedging (R-4) and for costlier PQ handshakes. Testable with pure tests, no simulator needed | yes |
| **R-2 Simulation harness, reconnect & liveness** | 5.7 network port and turmoil harness; sans-IO `ReconnectPolicy` (full jitter, spread window, 30 s cap), `Liveness` (10 s keepalive, 3 missed), per-role relay idle, `TCP_USER_TIMEOUT` and keepalive, `agent_flapping` | The herd and half-open fixes can only be proven with the simulator, which every later phase reuses. Depends on R-1 so that the herd tests measure the real admission path | yes |
| **R-3 Lifecycle & self-healing** | 5.4: relay and agent drain, critical-task supervision, panic-visibility hook for tests, watchdog with heartbeats, `STATUS=`, restart policy, `check` subcommand + `ExecReload`, config hashes and generations, `clock_jump`, `After=time-sync.target`, rolling-upgrade runbook | Needed for zero-downtime **PQ rollout** (rolling restarts). Uses R-2's simulator for the drain tests. G9 is security-relevant (a reload that silently does not apply) | yes |
| **R-4 Client failover deadline (A5-4)** | 5.3: sans-IO `FailoverPlan`, overall deadline, tighter per-step timeouts, staggered hedge (≤ 2), Ansible guidance (`retries`, `ServerAlive*`, `ControlPersist`) | Low severity on its own. It needs R-1 (hedging doubles handshakes) and R-2 (black-hole simulation). Closes backlog A5-4 | recommended |
| **R-5 Observability** | 5.5: counters, relay localhost exporter with `/healthz` and `/readyz`, agent textfile and `status`, health-cache decision revisited with data | Coming after R-1–R-3 means the metrics describe the final behaviour. If operators need visibility sooner, the counters from R-1 can be exported early (D-10) | parallel |
| **R-6 Efficiency & soak** | 5.6: copy reduction, window auto-tuning, `CHUNK` evaluation, global byte budget, agent runtime size; nightly soak and leak gate in CI; close 0001-10 | Optimisation comes last, measured against the soak baseline. The byte budget is low severity. Copy reduction touches the hot path, so do it once R-2's simulator can catch regressions | no |

Rough sizes (review effort, not calendar): R-1 S–M, R-2 M–L (the harness is most of it), R-3 M,
R-4 S–M, R-5 M, R-6 M.

---

## 7. Attack and failure catalogue for the adversary

The methodology's categories (Parsing, Resources, State, Identity, Side channels, Malleability)
plus failure-mode categories: **Partition**, **Crash/restart**, **Overload**, **Slow peer**,
**Clock**, **Operator**. Every row needs at least one test. Test names are suggestions.

### R-1 Admission

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R1-A1 | Overload | 200 authenticated clients from one IPv4 address within 5 s (Ansible forks) | all admitted; per-source budget unaffected by successes | `authenticated_bursts_from_one_ip_are_not_throttled` |
| R1-A2 | Overload | 300 agents behind one NAT reconnect after relay restart | all registered within the spread window + ε | `a_natted_fleet_reregisters_quickly` (sim) |
| R1-A3 | Resources | unknown keys from one IP in a loop | throttled as today (refund never happens) | `failed_handshakes_still_consume_the_source_budget` |
| R1-A4 | Identity | stolen valid key reconnects in a tight loop from many IPs | per-identity bucket limits it; neighbours unaffected | `one_identity_cannot_monopolise_handshakes` |
| R1-A5 | Resources | 4 096 slow msg1 senders (one byte/s) | pre-auth pool full; **established peers and agents reconnecting through the authenticated pool are unaffected**; slots freed at `msg1_deadline` | `slow_handshakes_cannot_starve_established_or_reconnecting_peers` |
| R1-A6 | Parsing/Resources | handshake length prefix 65 535 / `MAX_MSG1_LEN+1` | rejected before allocation | `oversized_msg1_prefix_is_refused_without_buffering` |
| R1-A7 | State | refund raced with policy reload revoking the peer | no refund for a peer the core rejects; no double refund | `refund_only_after_core_admission` |
| R1-A8 | Side channels | does refund timing or log volume reveal which keys are known? | no per-connection pre-auth output; refusal summary has no identities | `preauth_refusals_are_aggregated_without_identities` |
| R1-A9 | Overload | log flood from a scanner pushes journald rate limit | audit events after the flood still present; pre-auth lines bounded per interval | `scanner_cannot_crowd_out_audit_events` |
| R1-A10 | Overload | handshake storm while SSH sessions are active | data-plane p99 latency bounded (handshakes on worker pool) | `handshake_storm_does_not_stall_established_streams` |
| R1-A11 | Operator | limits set to 0 / absurd values | refused at startup without panic | `admission_limits_are_validated` |
| R1-A12 | Resources | PQ-sized legitimate msg1 (when available) | accepted; cap derived by `const` assertion | `max_legitimate_msg1_fits_the_preauth_cap` |

### R-2 Reconnect and liveness

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R2-L1 | Crash/restart | relay restarts with 2 000 agents, also after 2–30 s of downtime | arrival rate ≤ N/W per second ± tolerance; no wave > X% in any 1 s; ≤ 2.5× N/W with downtime (review 0010, A10-4) | `reconnects_are_spread_after_a_relay_restart` (sim), `reconnects_stay_spread_when_the_relay_is_down_for_a_while` (Monte Carlo of the policy) |
| R2-L2 | Partition | silent drop agent↔relay (no FIN) | both sides detect ≤ 35 s; agent reconnects; relay drops stale registration | `half_open_agent_link_is_detected` (sim, the agent host's arrivals only), `the_agent_alone_detects_a_half_open_link` (sim, relay idle 1 h) |
| R2-L3 | Operator | new relay with short idle, old agent pinging every 30 s | not disconnected while per-role idle default stays ≥ 3× old keepalive | `old_agents_survive_the_default_relay_idle` |
| R2-L4 | State | backoff overflow after days of failures / sample = `u64::MAX` | delay ≤ cap, no overflow, no panic | `backoff_is_bounded_for_any_sample` (proptest) |
| R2-L5 | Crash/restart | relay accepts then closes immediately (crash loop) | backoff grows (does not reset to the spread window) | `a_relay_that_drops_immediately_is_backed_off` |
| R2-L6 | Identity | two agents with the same key flap | `agent_flapping` raised; no registration lockout | `duplicate_agents_are_reported` |
| R2-L7 | Resources | relay floods `Pong` / never answers `Ping` | unsolicited `Pong` still a violation on relay; agent declares dead after 3 misses | `unanswered_pings_end_the_session` |
| R2-L8 | Partition | NAT rebinding (new source port/IP mid-session) | old connection dies (TCP); new one takes over registration | decided (review 0010, A10-6): the takeover is `reconnecting_agent_replaces_the_previous_connection` (core) and `duplicate_agents_are_reported_by_the_relay` (wire); the old connection dies like the half-open link of R2-L2. No separate simulation |
| R2-L9 | Slow peer | relay with a zero TCP window | `TCP_USER_TIMEOUT` / write timeout ends it; other relays unaffected | decided (review 0010, A10-6): one loop per relay with its own timeouts, `an_unreachable_relay_does_not_stop_the_agent_on_the_others` (`ha.rs`); the socket options on both sides, `dialed_sockets_have_user_timeout_and_keepalive` (through the `Acceptor`). A zero window cannot be simulated in turmoil |

### R-3 Lifecycle and self-healing

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R3-C1 | Crash/restart | SIGTERM during active sessions | listener closed at once; sessions continue up to `--drain-timeout`; then `Close Drained`; exit 0 | `sigterm_drains_then_exits` |
| R3-C2 | State | new client during drain; agent reconnect during drain | refused (listener closed); client falls back to next relay immediately | `draining_relay_refuses_new_connections` |
| R3-C3 | State | SIGHUP / revocation during drain | still applied (revocation never waits for drain) | `revocation_applies_while_draining` |
| R3-C4 | Operator | invalid policy at restart | process refuses to start; no last-known-good fallback | `no_fallback_to_a_stale_policy` |
| R3-C5 | Crash/restart | critical task returns (simulated: SIGHUP stream ends, hub receiver closed) | process exits non-zero; never "running without reload" | `a_dead_critical_task_terminates_the_process` |
| R3-C6 | Crash/restart | runtime wedged (hub blocked) | watchdog not kicked → systemd restarts; disconnected relays do **not** stop the kick; no stall at start, a stall only after two checks without progress, `WatchdogSec` ≥ 3 s (review 0010, A10-3) | `a_stalled_hub_stops_the_kicks`, `an_idle_hub_still_makes_progress`, `a_stall_is_reported_after_two_checks_without_progress`, `reloads_are_announced_and_the_watchdog_does_not_stall_at_start`, `a_too_short_watchdog_is_a_configuration_error` |
| R3-C7 | Operator | `systemctl reload` with a bad file, also with `ExecStart=` drop-ins | the running process rejects it; `reload` exits 78 with its reason; running config untouched (review 0010, A10-1) | `a_rejected_reload_fails_the_reload_command`, `reload_works_with_arguments_only_execstart_has`, `reload_is_validated_by_the_running_agent` |
| R3-C8 | Operator | `check` and `run` disagree (different loaders); reload digests name files not in force | same function (`load_startup`, `prepare`) with the same exit codes; reload validated by the running process itself; digests of the bytes parsed, reload digests only of what a reload applies (review 0010, A10-2) | `check_and_run_accept_the_same_files` (five file sets), `a_reload_is_not_blocked_by_files_it_does_not_apply`, `one_reload_is_one_generation` |
| R3-C9 | Side channels | config hash in logs/metrics leaks content | only SHA-256 of whole file; no hash of individual entries | decided (review 0010, A10-6): `Digests` records one SHA-256 per file and nothing else; `check_accepts_a_valid_configuration_and_prints_digests` and `a_reload_is_not_blocked_by_files_it_does_not_apply` compare it with `sha256sum` of the whole file |
| R3-C10 | Clock | wall clock stepped back 1 h | `clock_jump` WARN; certificate decisions use the new clock (documented residual) | `backward_clock_step_is_reported` |
| R3-C11 | Clock | wall clock before build date | ERROR at start (and when the clock steps below it); no certificate valid until it passes the build date (review 0010, A10-7) | `certificates_are_refused_before_the_clock_floor` |
| R3-C12 | Operator | agent upgraded through its own TCN session | with `--no-block` the task completes; documented | ops test in `openssh.rs` |
| R3-C13 | Crash/restart | fleet-wide crash loop | restart delays grow (RestartSteps) or are spread; relays not hammered every 2 s | unit-file review + sim |
| R3-C14 | State | SIGTERM before READY (startup) | exits cleanly, no half-initialised listener | `early_sigterm_is_clean` |

### R-4 Client failover

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R4-F1 | Partition | first relay black-holed | session via relay 2 within stagger + one RTT set; total ≤ deadline | `a_black_holed_first_relay_costs_only_the_stagger` (sim) |
| R4-F2 | State | `OpenAck` from two relays (race) | exactly one proceeds; the other is closed; agent sees one msg1 | `hedged_attempts_never_send_two_msg1` (plan), `hedge_losers_release_agent_slots` (sim: one sshd accept; a second msg1 that never completes would not show) |
| R4-F3 | Identity | relay 1 `NotAuthorized` before relay 2 `OpenAck` | abort all (fail closed) | `a_policy_answer_aborts_all_hedged_attempts` |
| R4-F4 | Identity | relay 2 `OpenAck` before relay 1 `NotAuthorized` | proceeds via relay 2 (accepted, documented) | `late_policy_answer_after_proceed_is_ignored` |
| R4-F5 | Resources | hedged loser's `Open` holds an agent slot | the loser sends `Close Normal` and is closed while the session runs | `hedge_losers_release_agent_slots`, `a_loser_that_sent_open_sends_close_normal`, `the_loser_is_closed_while_the_session_runs` (sim, A11-5) |
| R4-F6 | State | deadline expires mid-handshake / after `OpenAck` | before `OpenAck`: give up; after: session continues (deadline is for establishment only) | `deadline_applies_to_establishment_only` (plan only; the sim sessions after it have no establishment timer left) |
| R4-F7 | Overload | Ansible burst with hedging | at most two in flight, each relay once; the losers confirm their key, so no R-1 refusals for the controller (A11-1) | `hedging_stays_within_the_plans_bounds` (plan), `hedge_losers_do_not_burn_the_controllers_admission_budget`, `a_hedge_cancelled_in_its_handshake_confirms_its_key` (sim, real R-1 admission) |
| R4-F8 | Overload | relay alive but slow to relay `OpenAck` (AP-10) | no hedge: the client waits for the open timeout, then moves on; the second relay sees nobody before; a handshake done at the stagger instant is not hedged (A11-5) | `hedging_does_not_amplify_a_slow_but_alive_relay`, `a_handshake_done_at_the_stagger_instant_is_not_hedged` (sim), `a_slow_open_ack_is_never_hedged` |
| R4-F9 | Identity | `require_outer_suite` with a relay pinned to another suite in a `ClientConfig` built in code (A10-9) | refused before any dial; no hedge onto it | `a_hedge_never_lands_on_a_relay_outside_require_outer_suite` |
| R4-F10 | Resources | client dropped in the middle of a hedge | no connection left open (no spawned task); both attempts were in flight | `dropping_the_client_mid_hedge_leaks_nothing` (sim) |
| R4-F11 | Operator | the client gives up under OpenSSH | `zt-client` exits 75 for every temporary give-up (deadline, unreachable, silent) with a clear stderr line; `ssh` exits 255 (Ansible `retries`) | `the_deadline_exits_with_tempfail_and_a_clear_message`, `a_refusing_relay_exits_with_tempfail`, `a_silent_relay_exits_with_tempfail_with_the_defaults`, `ssh_reports_the_failover_deadline`, `ssh_reports_a_silent_relay_with_the_default_timeouts` (e2e-openssh) |
| R4-F12 | Partition | every relay black-holed / every agent link held | gives up after about 5 s with the last error / at the 8 s deadline | `black_holed_relays_give_up_before_the_deadline`, `all_relays_down_ends_at_the_deadline` (sim) |
| R4-F13 | Operator | first relay handshakes then stalls on `Open`; Ansible's default `ConnectTimeout = 10` (A11-2) | `ssh` gets through the second relay within about 5 s | `one_failed_relay_fits_ansibles_connect_timeout` (plan), `ssh_fails_over_a_stalled_relay_within_ansibles_connect_timeout` (e2e-openssh) |
| R4-F14 | Partition | two or three relays stall on `Open`, a healthy relay comes after them (A11-3) | the healthy relay is reached within the default deadline | `stalling_relays_share_the_deadline` (plan), `two_stalling_relays_leave_time_for_a_healthy_third`, `three_stalling_relays_and_a_healthy_fourth_fit_the_default_deadline` (sim) |
| R4-F15 | Identity | a losing relay refuses the node the winner accepted (partial policy rollout, A11-6) | session kept; WARN `relays disagree on the policy` with both relays | `a_losers_policy_refusal_is_reported` (sim) |

### R-5 Observability

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R5-O1 | Parsing | malformed/huge HTTP request to the metrics port | bounded read (1 KiB), timeout, close; fuzzed | fuzz target `metrics_request` |
| R5-O2 | Side channels | labels expose fingerprints, node names, client names | none by default | `metrics_have_no_identities` |
| R5-O3 | Resources | label cardinality grows with peers | fixed label sets only | `metric_cardinality_is_bounded` |
| R5-O4 | Operator | metrics bound to 0.0.0.0 by mistake | warning at startup; documented | `public_metrics_bind_is_warned` |
| R5-O5 | Resources | textfile write fails (disk full, read-only) | logged once, agent keeps serving | `textfile_failure_is_not_fatal` |
| R5-O6 | State | `/readyz` during drain | not ready; `/healthz` still ok | `readiness_follows_drain` |

### R-6 Efficiency

| ID | Category | Hypothesis | Expected | Test |
| :- | :- | :- | :- | :- |
| R6-E1 | Resources | authenticated slow reader across many connections | global byte budget enforced; largest backlog shed; others unaffected | `queue_budget_sheds_the_slowest_reader` |
| R6-E2 | Resources | refactor splits read/write into separate tasks | bound test fails (guards the invariant) | `relay_queue_never_exceeds_credit_while_writes_block` |
| R6-E3 | Malleability/Parsing | zero-copy decode path differs from current decoder | identical results on fuzz corpus | differential proptest |
| R6-E4 | Resources | receiver auto-tunes window beyond `MAX_WINDOW` | refused by sender and relay (existing rules) | existing `tiny_or_overflowing_window_updates_are_violations` + new grow test |
| R6-E5 | Resources | 1 h soak | RSS/fd/task slope ≈ 0; no audit loss | nightly `soak` job |

---

## 8. Open decisions (recommended option marked)

| # | Decision | Options | Recommendation |
| :-: | :- | :- | :- |
| D-1 | Handshake admission model | (a) only raise/configure limits; (b) **refund on authenticated success + per-identity bucket + separate pre-auth pool**; (c) stateless cookie / client puzzle (protocol change) | **(b)**: fixes Ansible/NAT without loosening unauthenticated protection; TCP already provides return routability, puzzles penalise small agents |
| D-2 | Reconnect spreading | (a) full jitter only; (b) **full jitter + post-session spread window `W` (default 10 s, 0 allowed), cap 30 s**; (c) relay-sent pacing / "retry-after" pre-auth (wire change, oracle) | **(b)**; (c) breaks "silence to unknown peers" |
| D-3 | Dead-peer detection | (a) keep 30 s/90 s; (b) **agent keepalive 10 s, dead after 3 misses, `TCP_USER_TIMEOUT`, per-role relay idle (lowered only after fleet upgrade)**; (c) relay-initiated `Ping` (agent semantics change, staged rollout) | **(b)**, no wire change |
| D-4 | Client failover (A5-4) | (a) overall deadline only; (b) **deadline 20 s + per-step timeouts 3/5/10 s + staggered hedge (≤ 2 in flight, 2 s)**; (c) fully parallel to all relays | **(b)**; (c) multiplies handshakes by N and fights D-1 |
| D-5 | Cross-invocation relay health memory for `zt-client` | (a) **none for now**; (b) hints file in `$XDG_RUNTIME_DIR` (reorders pinned relays only, trust-file rules) | **(a)**: with hedging a bad relay costs ≤ 2 s; revisit with R-5 metrics |
| D-6 | Drain trigger and single-relay zero downtime | (a) **SIGTERM drains with `--drain-timeout` (60 s), second SIGTERM/SIGINT immediate; HA rolling restart is the zero-downtime path**; (b) separate signal (SIGUSR1) for drain; (c) add `SO_REUSEPORT` blue/green instances | **(a)**; (c) deferred: extra moving parts for single-relay setups that the docs already discourage |
| D-7 | Watchdog scope | (a) **internal liveness only (hub tick, critical tasks, runtime)**; (b) also external connectivity | **(a)**: restarts don't fix network problems and amplify herds |
| D-8 | Faster Ansible bursts (connection reuse) | (a) **ControlPersist guidance only now**; (b) local `zt-client` multiplexer daemon (Unix socket, `SO_PEERCRED`, one outer connection, ≤ 32 streams); (c) Noise resumption tickets (`IKpsk2`, per-relay ticket keys) | **(a)** now; re-evaluate **(b)** with PQ measurements (it amortises PQ outer handshakes without new crypto); (c) not recommended (new key-management surface, no shared state between relays) |
| D-9 | Network simulation | (a) **`turmoil` as dev-dependency behind a narrow `Dialer`/`Acceptor` port**; (b) hand-rolled in-memory duplex simulator; (c) only sans-IO unit tests | **(a)** (needs `cargo deny` approval of a dev-only crate); (c) is necessary but not sufficient |
| D-10 | Metrics exposure | (a) **relay: localhost HTTP, off by default; agent: textfile + `STATUS=`**; (b) Unix-socket endpoint for both; (c) logs only | **(a)**: agent keeps zero inbound ports; minimal hand-written HTTP, fuzzed |
| D-11 | Reload feedback | (a) `check` subcommand in `ExecReload` (portable), plus `Type=notify-reload` where systemd ≥ 253; (b) notify-reload only; (c) keep `kill -HUP`; (d) **`reload --pid $MAINPID`: the running process validates and publishes its verdict** | (a), replaced by **(d)** after review 0010 (A10-1) |
| D-12 | Pre-auth logging | (a) **aggregate refusals (10 s summaries + counters); per-event audit only after Noise identity**; (b) keep per-connection lines | **(a)**: avoids journald dropping real audit events |
| D-13 | Global memory protection | (a) **byte budget shedding the largest backlog + `MemoryHigh`/`MemoryMax`**; (b) unit limits only | **(a)** |
| D-14 | Restart policy | (a) **`StartLimitIntervalSec=0` + `RestartSteps`/`RestartMaxDelaySec` where available**; (b) keep defaults | **(a)**: today a fast crash loop ends in permanent `failed` |

---

## 9. Choices the implementation must not revisit without updating the specification

1. The relay sends nothing to an unauthenticated peer. Load shedding is silent, PQ included.
2. The end-to-end msg1 is sent on exactly one relay, after its `OpenAck`. Nothing is retried
   after `OpenAck`.
3. Revocation and reload never wait for drain, backoff or budgets.
4. Supervision is crash-only, at process level (`panic = "abort"`). There is no
   last-known-good fallback for trust files.
5. The watchdog reflects internal liveness only.
6. No new frame types or codes. Drain uses `Close Drained`; failover hedging uses
   `Close Normal`.
7. Resilience decisions live in sans-IO state machines in `zt-application`, with clock and
   randomness passed in.
8. No identities in metric labels or in pre-auth logs.

## 10. Out of scope

- Moving a live session from one relay to another (the SSH TCP state lives on the agent and
  client).
- Shared state or gossip between relays.
- Distributing policy or the denylist automatically.
- An online CA.
- UDP/QUIC transport.
