# Adversary review 0008: Phase 1 (PQ-0 suite and KEM groundwork, R-1 relay admission)

**Surface:** `git diff fef8099..59b02aa` on `claude/project-thread-qi9qrv` (4 commits):
- **PQ-0:** `zt-domain/src/suite.rs` (suite ids, accepted sets per role, msg1/msg2 sizes),
  `zt-crypto/src/noise.rs` (`initiate_suite`, `respond_suites`), `zt-crypto/src/kem.rs` (sans-IO
  `Kem` trait, ML-KEM-768 on `libcrux-ml-kem =0.0.11`), the ACVP/Wycheproof vectors and the
  RustCrypto `ml-kem` oracle, `.cargo/config.toml`, `deny.toml`, `docs/pq-snow.md`;
- **R-1:** `zt-application/src/admission.rs`, `ratelimit.rs` refunds, `zt-net/src/relay.rs`
  (pre-auth pool, key confirmation, deadlines, `preauth_summary`), `zt-net/src/channel.rs`
  (`accept_suites`, pre-auth codec cap), `relay.toml` (`config.rs`), PROTOCOL §7.5/§10.1,
  OPERATIONS §4.1/§6/§11.

It was checked against `docs/pq-resilience-plan.md` and the findings AP-1, AP-2, AP-3, AP-7,
AP-11, AP-16 and AP-20 of review 0007.

**Reviewer:** an independent adversary agent. It did not write the code. The encrypted project
instructions were **not** visible to it.

**Method:**
- The full suite was run at `59b02aa`: `cargo test --workspace --locked --offline` passed 445
  tests, with 0 failures and 7 ignored. `cargo deny check` passed: advisories, bans, licenses and
  sources ok.
- Every hypothesis below marked "reproduced" had a test that **asserted the attackable
  behaviour** and passed at `59b02aa`, in a scratch copy (`adv8_admission.rs` for
  `zt-application`, `adv8_attacks.rs` for `zt-net`). The fix flipped them to assert the safe
  behaviour and committed them before the implementation (RED): they are now
  `crates/zt-application/tests/adversary_0008.rs` and `crates/zt-net/tests/adversary_0008.rs`.
- Cargo behaviour was probed with a throw-away crate.
- The review itself did not modify the repository.

**Attacker models:** these are the models of 0007:
- (a) a remote host with no credentials;
- (b) an on-path recorder that replays handshake messages;
- (c) the holder of one valid or stolen identity;
- (d) one compromised relay;
- (f) operator error.

**Severity:** the 0001–0007 scale. **High** blocks the merge. **Medium** must be fixed in this
phase. **Low** and **info** may be fixed in the phase that next touches the code.

## Verdict

The core of AP-1 holds:
- Refund, the move to the established pool and the per-identity charge all happen only on
  the first authentic transport frame.
- A replayed message 1, or a replayed whole session, earns nothing.
- Slot accounting is RAII-correct on every path the reviewer found.

The suite design meets AP-7 and AP-11:
- one identifier;
- no ordering;
- per-role sets;
- nothing in the clear;
- no fallback.

The KEM wrapper preserves implicit rejection and checks lengths and the modulus.

There is **no high finding**. Three findings are **medium**:
- **A8-1:** the new pre-auth pool is cheap to fill.
- **A8-2:** the AP-3 filter still lets replays of a *known* identity flood the audit log.
- **A8-3:** refund-on-success removes the per-source bound that AP-2 relied on for a stolen
  key.

| # | Sev. | Surface |
| :-: | :-: | :- |
| A8-1 | **medium** | Pre-auth pool: no per-source concurrency cap; one IPv6 /48 or 16 IPv4 addresses fill it |
| A8-2 | **medium** | Per-event `authentication_failed` for replays of a revoked key or an expired certificate |
| A8-3 | **medium** | Refund on success: one stolen/insider key churns unbounded handshakes from one address |
| A8-4 | low | Pre-auth buffer cap lifted to 64 KiB before key confirmation |
| A8-5 | low | Agents and clients share the established pool: clients can starve agent registration |
| A8-6 | low | NEON disable via `.cargo/config.toml` is cwd-dependent, overridable, untracked and unasserted |
| A8-7 | low | `fuzz/Cargo.lock` stale (no libcrux); new parsers and the admission state machine unfuzzed |
| A8-8 | low | `relay.toml` / `AdmissionConfig::validate` gaps |
| A8-9 | low | OPERATIONS §11 `KexAlgorithms` line is a fatal config error on OpenSSH < 9.9 |
| A8-10 | info | Confirmed-identity refusals are anonymous and silent; failure-kind mislabels |
| A8-11 | info | Per-role suite enforcement on the relay is dead code in this build and untested |
| A8-12 | info | KEM wrapper hygiene and vector provenance |

## Outcome

Every medium and low finding is fixed in the PR that carries this review. The full suite went
from 445 to 471 passing tests (7 ignored); `cargo clippy`, `cargo fmt --check` and
`cargo deny check` (workspace and `fuzz/`) are clean, and `zizmor` reports no finding on the
workflows.

| # | Outcome | Regression |
| :-: | :- | :- |
| A8-1 | **Mitigated.** Per-source (`max_pending_per_source = 50`) and per-/48 (`max_pending_per_wide = 100`) caps on unconfirmed handshakes in flight, checked at accept before the budget and released at confirmation or close. Validated: source ≤ /48 ≤ `max_preauth / 2`. Every wide limit, table size and the summary interval are in `relay.toml`. PROTOCOL §10.1 states the remaining global bound (21 IPv4 sources or 11 /48s). The /48 still starts up to `wide_burst` × `source_burst` handshakes over time, at most 100 at once: **accepted**, see below. | `one_ipv6_48_holds_at_most_its_share_of_the_preauth_pool`, `one_source_holds_at_most_max_pending_per_source_slots`, `one_48_and_sixteen_ipv4_addresses_leave_room_for_a_legitimate_agent`, `two_ipv6_48s_cannot_keep_the_pool_full`, `relay_toml_exposes_every_admission_limit` |
| A8-2 | **Mitigated.** `authentication_failed`, `handshake_suite_rejected` and `admission_refused` about a known identity are logged in full once per identity and `summary_interval`, then counted in one `<event>_repeated{peer, …, count}` line; at most 256 identities per interval, the rest in `suppressed_identities`. OPERATIONS §6 calls a repeated revoked key or expired certificate a replay signal. | `per_event_lines_of_a_known_identity_are_rate_limited`, `the_per_identity_line_table_is_bounded`, `replays_of_a_revoked_keys_msg1_are_rate_limited_per_identity`, `replays_of_an_expired_certificate_are_rate_limited_per_identity` |
| A8-3 | **Mitigated.** A per-identity refund bucket (`identity_refund_burst = 512`, one every 100 ms): once it is empty, a confirmation still succeeds but the source token stays spent. PROTOCOL §10.1 states the bound. | `one_key_cannot_churn_unbounded_handshakes_from_one_address`, `a_fleet_controller_with_50_forks_is_still_not_throttled`, `authenticated_bursts_from_one_ip_are_not_throttled`, `confirmed_sessions_do_not_use_up_the_source_budget` |
| A8-4 | **Mitigated.** `channel::MAX_FIRST_MESSAGE_LEN` (87 bytes, compile-time assertions) is the cap from message 1 to key confirmation; `Established::confirmed` lifts it after `on_confirmed` succeeds. An oversized first frame is counted as `oversized`. | `an_unconfirmed_connection_cannot_announce_a_large_first_frame`, `the_first_frame_cap_fits_the_largest_legitimate_first_frames` |
| A8-5 | **Mitigated.** `agent_reserve_percent = 10`: clients fill at most 90 % of `max_established`, agents may use all of it. The role is passed to `on_confirmed`. | `client_identities_cannot_starve_agent_registration`, `agents_are_not_capped_by_the_reserve` |
| A8-6 | **Mitigated.** `force = true` in `.cargo/config.toml`; `crates/zt-crypto/build.rs` refuses an aarch64 build that does not see `LIBCRUX_DISABLE_SIMD128` (any cwd, `rerun-if-env-changed`); `.github/scripts/check-libcrux-backend.sh` fails the release build if a libcrux build-script output contains `simd128`; a new CI job runs the zt-crypto tests (KEM vectors) and the same check on `ubuntu-24.04-arm` on every PR. | CI steps; checked locally by an aarch64 `cargo check` from outside the repository (refused) and from the root (no `simd128`) |
| A8-7 | **Mitigated.** `fuzz/Cargo.lock` updated; CI runs `cargo check --locked --manifest-path fuzz/Cargo.toml --bins` and `cargo metadata --locked` before fuzzing; `config_parsers` covers `parse_relay_settings`; new fuzz target `admission` and property test for the invariants (`Admission::check_invariants`). Both targets ran 45 s each under nightly with no finding. | `admission_bookkeeping_is_consistent`, fuzz targets `admission`, `config_parsers` |
| A8-8 | **Mitigated.** `max_per_identity ≤ max_established`, `source_refill ≥ 3 s`, the pending caps against the pool; every limit in `relay.toml`; `admission_limits_in_use` at startup. | `a_per_identity_cap_above_the_pool_is_refused`, `a_source_refill_under_three_seconds_is_refused`, `pending_caps_are_validated_against_the_pool`, `the_relay_announces_its_admission_limits` |
| A8-9 | **Fixed (docs).** OPERATIONS §11 gives the line per OpenSSH version (9.9+, 8.5–9.8, before 8.5) and how to intersect with `ssh -Q kex`. | none (documentation) |
| A8-10 | **Mitigated.** A confirmed identity refused at `max_per_identity` or a full pool gets a rate-limited `admission_refused{peer, reason}` (the A8-2 mechanism) and `Reject RateLimited` in answer to its `Open`. A timeout while writing message 2 is counted as `timeout`; the OPERATIONS §6 labels are aligned. | `a_confirmed_identity_over_its_limit_is_named_and_answered` |
| A8-11 | **Backlog (PQ-1 RED).** The branch cannot run while only one suite is supported; the network test goes into PQ-1's RED step. The A8-2 rate limit already covers `handshake_suite_rejected`. | (PQ-1) |
| A8-12 | **Partly fixed, rest backlog (PQ-1).** `pq-snow.md` §4 now says libcrux is compiled into every release binary. The zeroization of the by-value copies and a committed vector generator go to PQ-1, see below. | (PQ-1) |

---

### A8-1 (medium): the pre-authentication pool has no per-source concurrency cap. One IPv6 /48, or 16 IPv4 addresses, fill all 1 024 slots at once, and two /48s keep them full

**Surface:** `admission.rs:355–368` (`on_accept`) and the defaults at `admission.rs:56–73`,
`ratelimit.rs:279–287` (`HandshakeGate::admit`), PROTOCOL §10, §10.1; AP-16 ("raise only the
burst").

**Attack hypothesis (a):** R-1 keeps a global pre-auth pool (`max_preauth = 1 024`). The only
per-source control is the token bucket, and its burst rose from 20 to 64 (pq-snow.md §5).
Nothing caps how many **concurrent** pending slots one source holds. For IPv6, the /48 bucket
only limits how fast new /64s appear (wide burst 64, 1 per second). Every new /64 then starts
with a full burst of 64. So:
- **One /48 gives 64 × 64 = 4 096 immediate tokens**, four times the whole pool. The old
  values gave 64 × 20 = 1 280.
- Sixteen IPv4 addresses give 16 × 64 = 1 024.

The attacker needs no keys. Silent TCP connections hold a slot for `msg1_deadline` (5 s). With
a recorded message 1 of any client (model b), a slot is held for 5 s plus the time to message
2. While the pool is full, `on_accept` refuses everyone before the gate (`PreauthPoolFull`).
That includes:
- agents reconnecting after a network blip or a relay restart;
- every new client session.

Established sessions survive, as designed. But the whole fleet's new handshakes are denied,
from one cheap IPv6 allocation.

The existing tests cover this behaviour but do not price it:
- `slow_handshakes_cannot_starve_established_or_reconnecting_peers` asserts that a full pool
  refuses new peers;
- `a_full_preauth_pool_does_not_disturb_established_sessions` uses `max_preauth = 2`.

**Evidence (reproduced, `adv8_admission.rs`):**
- `adv8_one_ipv6_48_fills_the_default_preauth_pool`: with `AdmissionConfig::default()`, 1 024
  accepts from 2001:db8:1::/48 succeed. Then an IPv4 agent gets `Err(PreauthPoolFull)`.
- `adv8_sixteen_ipv4_addresses_fill_the_default_preauth_pool`: the same from 16 addresses.
- `adv8_two_ipv6_48s_keep_the_pool_full_over_time`: two /48s retry every 100 ms over 60 s,
  with 5 s slot lifetime. **Every** legitimate attempt (once a second, from t = 5 s on) is
  refused.
- The `[admission]` section of `relay.toml` does not expose `wide_burst`, `wide_refill` or the
  tracked-table sizes (`config.rs` `AdmissionSection`). So an operator cannot tighten the /48
  budget without a rebuild.

**Required fix:**
- Add a **per-source cap on concurrent pending slots**, enforced in `on_accept` and released in
  `release`/`on_confirmed`. It applies per IPv4 address or IPv6 /64, and also **per /48 in
  aggregate**. Example: at most 16 per source and 64 per /48, both configurable, and both
  validated to be well below `max_preauth`. Keep the burst for *rate* if wanted. A concurrency
  cap is what bounds pool occupancy, and it does not hurt the `forks = 50` case, because
  confirmed connections leave the pending set within an RTT.
- Bound the /48 aggregate: (new /64s per /48) × `source_burst` must not exceed a fixed fraction
  of `max_preauth`, or else charge the /48 bucket on **every** unconfirmed handshake from a
  /64 it created recently, not only on the first one.
- Expose the wide limits in `relay.toml`, with validation.
- Add a regression test with **default** limits: one /48, then 16 IPv4 addresses, then a
  legitimate agent is still admitted.
- Correct PROTOCOL §10.1 to state the remaining global bound honestly (how many sources it
  takes to fill the pool).

**Outcome: mitigated.** The fix follows the first and third options of the required fix:
- `AdmissionConfig::max_pending_per_source` (50) and `max_pending_per_wide` (100), enforced
  in `on_accept` before the pool's budget is spent, and released in `on_confirmed` and
  `release`. The defaults keep `forks = 50` from one address inside the cap (R1-A1).
- `validate` refuses `max_pending_per_source > max_pending_per_wide` and
  `max_pending_per_wide > max_preauth / 2` (`PendingCapsInconsistent`).
- `relay.toml` exposes `max_pending_per_source`, `max_pending_per_wide`, `wide_burst`,
  `wide_refill_secs`, `max_tracked_sources`, `max_tracked_wide` and `summary_interval_secs`
  (OPERATIONS §4.1).
- PROTOCOL §10.1 states the bound: with the defaults, filling the pool takes at least 21 IPv4
  sources or 11 /48s.

The second option (charging the /48 bucket on every unconfirmed handshake) was not taken, and
the residue is **accepted**: in a burst a /48 can still *start* up to `wide_burst` ×
`source_burst` unconfirmed handshakes (one X25519 responder each, about 100 µs), but it holds
at most 100 slots at once, so it cannot deny admission to anyone else. Occupancy, not CPU, was
the finding.

Regression: `one_ipv6_48_holds_at_most_its_share_of_the_preauth_pool`,
`one_source_holds_at_most_max_pending_per_source_slots`,
`one_48_and_sixteen_ipv4_addresses_leave_room_for_a_legitimate_agent` (the test the review
asked for, with default limits), `two_ipv6_48s_cannot_keep_the_pool_full`,
`pending_caps_are_validated_against_the_pool`, `relay_toml_exposes_every_admission_limit`.
`a_full_preauth_pool_does_not_disturb_established_sessions` now fills the pool from two
loopback addresses.

### A8-2 (medium): replays of a recorded message 1 of a **known** identity still write one WARN line each, so the AP-3 flood remains, and it names a real victim

**Surface:** `admission.rs:483–501` (`is_known_identity`), `zt-net/src/relay.rs:577–592`;
OPERATIONS §6, PROTOCOL §15.11; AP-3 ("Replayed msg1s … produce per-event lines that name a real
victim").

**Attack hypothesis (b):** the AP-3 fix logs per event only for identities the configuration
knows. Two kinds of known identity are reachable by a recorder without any key:
1. A key that was later **revoked**: its old msg1 now fails at step 1 (`key_revoked`).
2. Any recorded msg1 that carried a **certificate that has since expired**. With short-lived
   certificates (OPERATIONS §10) that is *every* recorded certificate msg1, a few hours later.
   The rejection happens after the signature check (`expired`, `serial_revoked`,
   `node_out_of_scope`, …), so `is_known_identity` returns `true`. It costs the relay one
   Ed25519 verification per replay.

The replay never reaches message 2, so it is not `unconfirmed`. Each replay is an individual
WARN `authentication_failed{peer=<victim>, ca, serial, cert_name}`.

The budget is per source. With N addresses that is N × 64 lines at once, then N/3 per second.
For example, 500 addresses give 32 000 lines at once, which is above journald's default
10 000 per 30 s. Real audit events are then dropped (G10). The log also falsely suggests that
the victim is active.

**Evidence (reproduced, `adv8_attacks.rs`):**
- `adv8_replays_of_a_revoked_keys_msg1_write_one_line_each`: 60 replays from one address,
  inside the default burst, give 60 `authentication_failed` lines with `peer = victim`.
- `adv8_replays_of_an_expired_certificate_write_one_line_each`: 40 replays of a msg1 whose
  certificate expired an hour ago give 40 lines.
- The same applies to `handshake_suite_rejected` (`relay.rs:600`). That path is unreachable in
  this build (A8-11), but replays will drive it as soon as two suites exist.

**Required fix:**
- Rate-limit the per-event line **per identity** (or per identity + reason, or per serial):
  - the first occurrence is logged in full;
  - later ones go into a per-identity counter, emitted once per summary interval (for example
    `authentication_failed_repeated{peer, reason, count}`);
  - the per-identity table is bounded.
- Apply the same to `handshake_suite_rejected`.
- Regression test: N replays of a revoked key's msg1 and of an expired-certificate msg1 from
  many addresses give at most one per-event line per identity per interval, plus counts.
- In OPERATIONS §6, say that a revoked key or an expired certificate seen repeatedly is a
  *replay signal*, not evidence that the victim is active.

**Outcome: mitigated.** `Admission::note_identity_event` rate-limits the per-event lines about
known identities: the first event of a `(peer, event)` pair in a `summary_interval` is logged
in full, the rest is counted and emitted as one `authentication_failed_repeated`,
`handshake_suite_rejected_repeated` or `admission_refused_repeated` line with `peer`, the
reason fields and `count`. The table holds at most `MAX_LOGGED_IDENTITIES` (256) pairs per
interval; further events only add to `suppressed_identities` in `preauth_summary`. So a
flood of replays gives at most 512 named lines per interval, whatever the number of
addresses. OPERATIONS §6 says that a revoked key or an expired certificate seen repeatedly is
a replay signal, not evidence that the victim is active.

Regression: `per_event_lines_of_a_known_identity_are_rate_limited`,
`the_per_identity_line_table_is_bounded` (sans-IO),
`replays_of_a_revoked_keys_msg1_are_rate_limited_per_identity` and
`replays_of_an_expired_certificate_are_rate_limited_per_identity` (on the wire, from four
loopback addresses: one or two full lines, the rest counted).

### A8-3 (medium): refund on success removes the per-source bound on successful handshakes. One stolen or insider key churns handshakes from one address at any rate

**Surface:** `admission.rs:378–398` (`on_confirmed` → `gate.refund`), PROTOCOL §10.1
"Consequences", AP-2.

**Attack hypothesis (c):** AP-2 replaced the per-identity *rate* with a *concurrency* cap. It
argued that "a stolen key in a tight loop … is already bounded by the per-source gate". With
refund on confirmation, that bound is gone. Connect, handshake, first frame, close: this loop
never spends a token. So one key from one address can drive the relay's full responder cost
(4 DH, certificate verification, and from PQ-1 on an ML-KEM encapsulation, about 300 µs) as
fast as it can loop. The only limit is 512 concurrent sessions, and each session is short.

Each loop that sends `Open` also writes a `session_established` audit line. So an
authenticated principal on a single IP gets an unbounded CPU and log rate. Before R-1 the gate
held this to 1 per 3 s per address after the burst.

**Evidence (reproduced):** `adv8_one_key_churns_unbounded_handshakes_from_one_address` runs
100 000 accept → confirm → release cycles from one IPv4 address at one instant with default
limits. All succeed.

**Required fix:**
- Bound refunds **per identity**: for example, a generous per-identity refund bucket (burst
  ≥ `max_per_identity`, refill 10/s, configurable). Once it is empty, a confirmation still
  succeeds but does not refund the source token. This keeps AP-2's goal (an Ansible controller
  with 50 forks is never throttled) and restores the bound on a loop.
- Alternatively, refund only connections that lived ≥ T (for example 2 s) or carried at least
  one accepted `Open`/`Register`. The bucket is simpler and does not need extra state.
- Correct PROTOCOL §10.1 ("A fleet controller … is not throttled") so that it states the new
  bound.
- Regression test: churn from one address with one identity is bounded, while 4 waves of 50
  forks are still admitted (R1-A1).

**Outcome: mitigated** with the bucket: `identity_refund_burst` (512, at least
`max_per_identity` with the defaults) and `identity_refund_refill` (100 ms), both in
`relay.toml`. `on_confirmed` refunds the source token only if the identity's refund bucket has
a token; otherwise the confirmation succeeds and the token stays spent. The table is bounded
by `max_tracked_sources` and fails closed (no refund) when full. PROTOCOL §10.1 states the new
bound: 512 handshakes at once, then 10 per second plus the source's 1 every 3 s.

Regression: `one_key_cannot_churn_unbounded_handshakes_from_one_address` (512 + 64, then
throttled; 31 more after 3 s), `a_fleet_controller_with_50_forks_is_still_not_throttled`;
the AP-2 tests `authenticated_bursts_from_one_ip_are_not_throttled` and
`confirmed_sessions_do_not_use_up_the_source_budget` still pass.

### A8-4 (low): before key confirmation the codec cap is already the Noise maximum (64 KiB), not the largest legitimate message 1

**Surface:** `zt-net/src/channel.rs:198` (`set_max_frame_length(MAX_MESSAGE_LEN)` right after
message 1), PROTOCOL §10.1 step 2; plan §3 "pre-auth buffer cap = maximum legitimate msg1".

**Attack hypothesis (b):** after a replayed message 1 the connection is still in the
pre-authentication pool for up to `first_frame_deadline` (5 s). The cap has already been
raised to 65 535, so the replayer announces a maximal frame, and the relay waits for it and
buffers it. Its first transport frame can only be `Register`, `Open` or `Ping`, which are a
few hundred bytes. With A8-1 the pool is 1 024 slots, so this is about 64 MiB of attacker-held
memory per relay instead of about 4.5 MiB.

**Evidence (reproduced):** `adv8_unconfirmed_connection_accepts_a_64k_prefix` sends a
replayed msg1, reads msg2, and announces 0xFFFF. The relay does not refuse the prefix on sight
(as it does in the message 1 phase). It holds the connection until the first-frame deadline.

**Required fix:**
- Keep a **first-frame cap** until confirmation: the largest legitimate first frame (Noise tag
  + an encoded `Register` with the longest node name, `Open`, or `Ping`), as a `const` with a
  compile-time assertion.
- Raise the cap to `MAX_MESSAGE_LEN` only after `on_confirmed` succeeds.
- Count an oversized first frame as `oversized`.
- Add a regression test.

**Outcome: mitigated.** `channel::MAX_FIRST_MESSAGE_LEN` is the AEAD tag plus the frame
header plus a 63-byte node name (87 bytes), with compile-time assertions. `accept_suites` sets
it after message 1; `Established::recv` reports a longer prefix as `NetError::Oversized`,
which the relay counts as `oversized`; `Established::confirmed` raises the cap to
`MAX_MESSAGE_LEN`, and the relay calls it only after `on_confirmed` succeeds.
`channel::accept`, which has no admission, confirms at once.

Regression: `an_unconfirmed_connection_cannot_announce_a_large_first_frame` (refused in under
1 s instead of at the 3 s deadline, counted as `oversized`),
`the_first_frame_cap_fits_the_largest_legitimate_first_frames`.

### A8-5 (low): agents and clients share one established pool, so client identities can starve agent registration

**Surface:** `admission.rs` `max_established` (one pool for both roles), PROTOCOL §10.1.

**Attack hypothesis (c):** the established pool (8 192) is shared. Sixteen client identities
at the default `max_per_identity = 512` fill it, and they can stay there indefinitely with a
`Ping` every < 90 s. The identities can be stolen keys, or one rogue operator of a pinned CA
minting certificates. After that, an agent that drops (NAT timeout, agent restart, relay
failover) cannot re-register: its confirmation is refused with `EstablishedPoolFull`. So
clients can take nodes offline. AP-7 already separated roles for suites. Capacity is the same
argument.

**Evidence (reproduced):** `adv8_client_identities_can_starve_agent_registration`: 16 × 512
confirmed client connections, then an agent's `on_confirmed` returns
`Err(EstablishedPoolFull)`.

**Required fix:**
- Reserve established capacity per role. Examples: `max_established_agents` and
  `max_established_clients`, or a reserved floor for agents equal to the number of agents in
  the policy plus a margin. The role is known at confirmation (`initiator_role`).
- Add a regression test.

**Outcome: mitigated.** `agent_reserve_percent` (10 %, at most 50 %, in `relay.toml`):
clients may fill the established pool only up to `max_established` minus the reserve (8 192 −
819 with the defaults); agents may use all of it. `on_confirmed` takes the
`InitiatorRole`, which the relay already knows at confirmation. A floor derived from the
number of agents in the policy was not chosen: the policy changes with `SIGHUP` while the
admission limits are fixed at startup, and a percentage keeps the limits independent of it.
OPERATIONS §4.1 asks to keep the reserve above the number of agents.

Regression: `client_identities_cannot_starve_agent_registration`,
`agents_are_not_capped_by_the_reserve`.

### A8-6 (low): the NEON disable in `.cargo/config.toml` is a fragile control and nothing asserts it

**Surface:** `.cargo/config.toml` (`[env] LIBCRUX_DISABLE_SIMD128 = "1"`), the `build.rs` of
`libcrux-ml-kem`, `libcrux-sha3` and `libcrux-intrinsics` 0.0.x, `release.yml`.

**Evidence:** the three build scripts read the variable but emit **no
`cargo:rerun-if-env-changed`**. The reviewer probed this with a scratch crate on x86_64,
using `LIBCRUX_DISABLE_SIMD256`, which follows the identical code path:
1. Build without the env, then add `[env]`, then build again. libcrux is `Fresh`, and the
   build-script output still has `cfg(feature="simd256")`. A **stale target dir silently keeps
   the SIMD backend**.
2. `LIBCRUX_DISABLE_SIMD256=0` in the shell environment **overrides** `[env]`, because
   `force` is not set. The SIMD backend comes back.
3. `cargo build --manifest-path …/Cargo.toml` from another working directory does **not read**
   the repository's `.cargo/config.toml`. Config discovery follows the cwd. The same holds for
   `cargo install --git`. The SIMD backend comes back.

On aarch64 each of these means the unverified NEON backend
(GHSA-2cgv-28vr-rv6j class) in a production binary, with no signal. The release job builds
fresh from the repository root, so the shipped tarballs are fine today. But:
- distro and self-builds are not covered;
- the guarantee rests on an invisible property;
- no CI job asserts it;
- CI tests only x86_64, so aarch64 vectors run only in `release.yml`.

**Required fix:**
- Set `force = true` on the `[env]` entry.
- In `release.yml`, after the build, fail if any
  `target/$TARGET/release/build/libcrux-*/output` contains `simd128`, or add an equivalent
  check with `cargo build -vv`.
- Add a guard that does not depend on cwd. For example, a `zt-crypto` `build.rs` that, for
  `target_arch = "aarch64"`, fails unless `LIBCRUX_DISABLE_SIMD128` is `1`/`y`/`Y`, and that
  emits `rerun-if-env-changed`. Or document a supported build command.
- Run the KEM vectors on aarch64 in CI, not only at release.

**Outcome: mitigated.**
- `.cargo/config.toml`: `LIBCRUX_DISABLE_SIMD128 = { value = "1", force = true }`, so the
  shell environment no longer overrides it.
- `crates/zt-crypto/build.rs` (cwd-independent): for `target_arch = "aarch64"` it fails the
  build (`cargo::error`) unless the variable is `1`/`y`/`Y`, and emits
  `rerun-if-env-changed`. Checked locally with `cargo check --target
  aarch64-unknown-linux-gnu`: from another directory with `--manifest-path` the build is
  refused; from the repository root it passes and the libcrux build-script outputs contain no
  `simd128`.
- `.github/scripts/check-libcrux-backend.sh` fails if any `libcrux-ml-kem`, `libcrux-sha3` or
  `libcrux-intrinsics` build-script output contains `simd128` (or if they are missing). It
  runs after the release build for both targets.
- A new CI job (`aarch64`, `ubuntu-24.04-arm`) runs the zt-crypto tests, including the KEM
  vectors, and the same check on every PR.

The residue is **accepted**: a stale local `target` directory whose libcrux build scripts ran
before the setting cannot be detected by zt-crypto's build script (the libcrux scripts emit no
`rerun-if-env-changed`); CI and release builds run the output check. `build.rs` documents it.

### A8-7 (low): `fuzz/Cargo.lock` was not updated, and the new parsers and admission are not fuzzed

**Surface:** `fuzz/Cargo.lock`, `ci.yml:99–103` (cargo-deny on `fuzz/Cargo.toml`), the fuzz
targets.

**Evidence:**
- `fuzz/Cargo.lock` contains no `libcrux` entry. `cargo metadata --locked` in `fuzz/` fails
  with "cannot update the lock file".
- In a scratch copy, `cargo deny --manifest-path fuzz/Cargo.toml check` passes only because
  it **silently re-resolves and rewrites** the lock (+16 `libcrux*` entries). So CI checks, and
  `cargo fuzz` builds, a dependency set that is not the committed one.
- `config_parsers` does not call `parse_relay_settings`, and no target or property test drives
  `Admission` with arbitrary event sequences. Invariants that should hold for every sequence of
  `on_accept`/`on_confirmed`/`release`/`record`/`poll_summary`:
  - `preauth + established` matches the live tickets;
  - per-identity counts sum to `established_count`;
  - tokens never exceed the burst;
  - no ticket is confirmed twice.

**Required fix:**
- Commit the updated `fuzz/Cargo.lock`.
- Make CI use `--locked` for the fuzz build. Make cargo-deny fail on a stale lock (run
  `cargo metadata --locked` first).
- Add `parse_relay_settings` to `config_parsers`.
- Add a `proptest` (or a fuzz target) for the `Admission` invariants above.

**Outcome: mitigated.**
- `fuzz/Cargo.lock` regenerated; `cargo metadata --locked` passes in `fuzz/`, and
  `cargo deny --manifest-path fuzz/Cargo.toml check` no longer rewrites it.
- CI: the `build-test` job runs `cargo check --locked --manifest-path fuzz/Cargo.toml --bins`
  (a stale lock or a broken target fails there, on stable), and the fuzz job runs
  `cargo +nightly metadata --locked` before `cargo fuzz run`.
- `config_parsers` calls `parse_relay_settings` and asserts that an accepted file validates.
- New fuzz target `admission` and property test `admission_bookkeeping_is_consistent`: both
  drive `on_accept`/`on_confirmed` (both roles)/`release`/`record`/`note_identity_event`/
  `poll_summary` with clock steps and check `Admission::check_invariants` after every event
  (pending and per-source/per-/48 counters match, per-identity and per-role counters sum to
  the established set, no cap exceeded), that no ticket is confirmed twice, and that releasing
  everything empties both pools. Token bounds are covered by the existing
  `refunds_never_exceed_the_burst`. Locally (nightly, cargo-fuzz 0.13.2) `admission` ran about
  120 000 and `config_parsers` about 220 000 inputs in 45 s each, with no finding.

### A8-8 (low): configuration validation gaps

**Surface:** `AdmissionConfig::validate` (`admission.rs:117–183`), `parse_relay_settings`.

- `max_per_identity > max_established` validates: one identity may then take the whole pool.
  `adv8_per_identity_cap_above_the_pool_validates` shows this.
- `max_preauth` is not checked against `source_burst`. The A8-1 per-source cap, once it
  exists, should be validated to be well below it.
- AP-16 asked to keep the unauthenticated refill at 1 per 3 s. `source_refill_secs = 1` is
  accepted, with only a prose warning ("not recommended").
- `wide_*`, `max_tracked_*` and `summary_interval` are not configurable (see A8-1).

**Required fix:**
- Require `max_per_identity ≤ max_established`, and ideally ≤ a fraction of it.
- Refuse, or WARN at startup (`admission_limits_in_use`), a refill under 3 s. Log the effective
  admission limits at startup, as `handshake_suites_in_use` already does.
- Expose the wide limits.

**Outcome: mitigated.** `validate` now refuses `max_per_identity > max_established`
(`PerIdentityAbovePool`), `source_refill < 3 s` (`SourceRefillTooFast`, so AP-16 is enforced,
not only documented) and inconsistent pending caps (`PendingCapsInconsistent`, A8-1). The
wide limits, table sizes and summary interval are in `relay.toml`, and the relay logs every
limit in force at startup (`admission_limits_in_use`). The per-identity cap is checked against
the whole pool, not a fraction: a deployment with one controller may legitimately need most of
it, and the default is 1/16.

Regression: `a_per_identity_cap_above_the_pool_is_refused`,
`a_source_refill_under_three_seconds_is_refused`, `pending_caps_are_validated_against_the_pool`,
`relay_toml_exposes_every_admission_limit`, `the_relay_announces_its_admission_limits`.

### A8-9 (low, docs): the OPERATIONS §11 `KexAlgorithms` line breaks ssh/sshd before 9.9

**Surface:** OPERATIONS §11.

**Evidence:** OpenSSH validates every name in `KexAlgorithms` (`kex_names_valid`), and an
unknown name is fatal ("Bad SSH2 KexAlgorithms") in both `ssh_config` and `sshd_config`. The
recommended line lists `mlkem768x25519-sha256` and the alias `sntrup761x25519-sha512`, and
both exist only from **9.9**. On 8.5–9.8 the line kills the client with a config error, and on
the server `sshd -t` refuses it. Those versions support `sntrup761x25519-sha512@openssh.com`.
Examples: Ubuntu 22.04 has 8.9, Ubuntu 24.04 has 9.6, EL9 has 8.7. So users who could get a
hybrid key exchange do not. The text says "an old `ssh` … fails to connect", but the failure
is a parse error, even on versions that support a hybrid.

**Required fix:** give per-version lines:
- 9.9+: all three names;
- 8.5–9.8: `sntrup761x25519-sha512@openssh.com` only;
- < 8.5: no hybrid.

Also tell users to intersect with `ssh -Q kex`.

**Outcome: fixed (documentation).** OPERATIONS §11 explains that the line depends on the
OpenSSH that reads the file, gives a table per version (9.9 and later: all three names; 8.5 to
9.8: the `@openssh.com` name only; before 8.5: no hybrid, upgrade), with distribution
examples, and a one-liner that builds the line from `ssh -Q kex`. The failure of a peer that
supports no listed hybrid is now described as a negotiation failure, separate from the parse
error.

### A8-10 (info): refusals of confirmed identities are anonymous and silent; failure-kind labels

- `identity_limit` and `established_pool_full` are refused **after** the key is confirmed, so
  the identity is authentic. Even so, they go only into the anonymous summary
  (`relay.rs:616–618`), and the client gets a bare close after its `Open`. An Ansible run that
  hits `max_per_identity` fails as "connection closed" on every relay, and the operator cannot
  tell which key.
  **Fix:**
  - emit a per-identity, rate-limited audit line (the A8-2 mechanism);
  - answer the first `Open` with `Reject RateLimited`, which `may_try_next_relay` already
    handles.
- `PreauthFailure::Timeout` is documented as covering "the handshake not within
  `handshake_timeout`", but a timeout while writing message 2 is recorded as `Aborted`
  (`relay.rs:603–607`). OPERATIONS §6 describes `aborted` as message 1 "cut off". Align the
  labels.

**Outcome: mitigated.**
- A confirmed identity refused at `identity_limit` or `established_pool_full` gets an
  `admission_refused{peer, reason}` WARN line, rate-limited per identity with the A8-2
  mechanism, and, if its first frame was an `Open`, a `Reject RateLimited`, which
  `may_try_next_relay` already handles. Regression:
  `a_confirmed_identity_over_its_limit_is_named_and_answered`.
- A timeout while writing message 2 is now counted as `timeout`, other errors there as
  `aborted`; `PreauthFailure` and OPERATIONS §6 describe both. No test: a 48-byte message 2
  always fits the socket buffer on loopback, so the write timeout cannot be provoked
  reliably; **accepted**, the change is a label.

### A8-11 (info): per-role suite enforcement on the relay is dead code in this build and untested

**Surface:** `relay.rs:593–602` (`initiator_role`, `suites.check`, `HandshakeSuiteRejected`).

Only the classical suite is supported, and `RelayServer::bind` refuses unsupported sets. So
both sets are always `{classical}`, and the per-role branch cannot run. No test exercises it:
`suite_attacks.rs` tests only `SuitePolicy::check` in `zt-domain`.

When PQ-1 flips `is_supported`, the following become live at once:
- the role mapping (anything that is not an agent counts as a client);
- the WARN path (A8-2);
- `max_msg1_len` computed over the union of the two roles' sets.

**Fix:** in PQ-1's RED step, add a network test: an agent with a client-only suite gets no
message 2, no session and one rate-limited `handshake_suite_rejected`, and vice versa.

**Outcome: backlog (PQ-1).** The branch cannot be reached while only the classical suite is
supported, so the network test is added in PQ-1's RED step, as the review recommends. The
A8-2 rate limit already applies to `handshake_suite_rejected`.

### A8-12 (info): KEM wrapper hygiene and vector provenance

- Secrets cross into libcrux **by value**, and the stack copies are not wiped:
  - `*seed.as_bytes()` in `generate`;
  - `*randomness` in `encapsulate`;
  - the `ss` returned by libcrux;
  - the 2 400-byte decapsulation key in `decapsulate`, rebuilt on every call
    (`kem.rs:163, 180, 192–195`).

  The comment admits it. In PQ-1 these are ephemeral keys, so the residue matters for the
  forward secrecy against HNDL that IKhfs exists to provide.
  **Fix:** in PQ-1, keep a single libcrux value per handshake and wipe it on drop. Put
  `Zeroizing` around the by-value arrays before the call and wipe the local `ss`. Bound
  `Kem::DecapsulationKey` by `ZeroizeOnDrop` or an equivalent marker.
- `tests/vectors/mlkem768.txt` says "Generated" and records the SHA-256 of its JSON sources,
  but the generator script is not committed. The vectors cannot be re-derived from ACVP or
  Wycheproof. The oracle passing the same file mitigates circularity.
  **Fix:** commit the script under `tests/vectors/` or `xtask`.
- `pq-snow.md` §4 says "until PQ-1, nothing ships". In fact libcrux is a normal dependency of
  every release binary: its build scripts run and its code is compiled, although LTO removes
  it. State this precisely, since it is why A8-6 matters now.

**Outcome: partly fixed, rest in the backlog (PQ-1).**
- `pq-snow.md` §4 now says precisely that libcrux is a normal dependency of every release
  binary (build scripts run, code compiled, LTO removes it while unused), and why A8-6
  matters now.
- The zeroization of the by-value copies (`Zeroizing` around the arrays passed to libcrux, one
  libcrux value per handshake wiped on drop, a `ZeroizeOnDrop` bound on
  `Kem::DecapsulationKey`) goes to PQ-1: before PQ-1 no handshake creates a KEM key, so there
  is no ephemeral secret to leave behind.
- The vector generator script goes to PQ-1 as well. Until then the file records the SHA-256 of
  its ACVP and Wycheproof sources, and the independent `ml-kem` oracle passes the same file.

## Refuted or confirmed-correct hypotheses

| # | Hypothesis | Outcome |
| :-: | :- | :- |
| 13 | Replay msg1 to earn a refund, to enter the established pool, or to charge or lock out the victim's identity (AP-1) | **Refuted.** Refund and charge happen only in `on_confirmed`, after `ch.recv()` decrypts an authentic frame. Covered by the existing tests `replayed_msg1_is_not_refunded_and_names_no_one` and `replayed_msg1_does_not_enter_the_established_pool`. |
| 14 | Replay a **whole** recorded session (msg1 + first transport frame) to confirm | **Refuted.** The responder's ephemeral is fresh, and the transport keys depend on `ee`/`se`, so the recorded frame fails AEAD and is counted as `unconfirmed`. |
| 15 | Identity claimed before authentication, or a revoked identity charged | **Refuted.** `peer` is charged only after key confirmation. A revocation is refused at `admit` (step 1). A revoked established connection is closed by the core, and `Admitted::drop` releases it. |
| 16 | Counter leak or underflow on error, timeout or cancellation paths | **Refuted by inspection.** `Admitted` is owned by the task future and released in `Drop` on every return. `on_confirmed` removes the pending entry before any refusal. `release` is idempotent and saturating. Mutex guards are statement temporaries, never held across `.await`. Poisoning is tolerated, and `panic = "abort"` applies in release. |
| 17 | Double refund, or refund above the burst | **Refuted.** `refunds_never_exceed_the_burst`, `refund_only_after_a_successful_confirmation_and_only_once`. |
| 18 | Downgrade or suite confusion | **Refuted.** The protocol name is hashed into `h`, so a message of one suite never decrypts as another. The initiator pins one suite with no retry. The responder tries only suites that are both accepted and supported, within each suite's length bounds. Configuration refuses unsupported suites and aliases. |
| 19 | Oversized or trickled msg1 (AP-20, G2) | **Refuted.** The length prefix is refused on sight. `msg1_deadline` is at least 5 s and holds against a trickle. `msg1_deadline ≤ handshake_timeout` is validated. |
| 20 | `preauth_summary` leaks addresses or keys, or floods | **Refuted.** It emits counts and bounded distinct counts only, one line per interval. |
| 21 | KEM misuse: lengths, modulus check, implicit rejection, constant-time `SharedSecret` equality | **Refuted.** Length and FIPS 203 §7.2 checks run before use. Decapsulation never errors on a correct length. The ACVP/Wycheproof vectors pass, and the differential test also covers tampered ciphertexts. `SharedSecret` uses `ct_eq`. |
| 22 | `snow` `hfs` or `hax-lib` reach release builds | **Refuted.** `hfs` is a dev-dependency feature only, under resolver 3, and `cargo tree -e normal,features` shows no `hfs`. `hax-lib` and `proc-macro-error2` sit under `cfg(hax)` only. `cargo deny check` is clean. |
| 23 | `pq-snow.md` facts (three `unwrap()`s in the `E1`/`Ekem1` paths, `e1` after `es`, sizes 1 296 / 1 152) | **Confirmed** against the `snow-0.10.0` source (`handshakestate.rs:275–308`, `409–438`) and the spike test. |
| 24 | AP-7 / AP-11 / AP-16 / AP-20 compliance | **Met**: one identifier, no ordering, per-role sets, a startup audit, no magic, refill kept at 3 s, `msg1_deadline` at least 5 s. Two gaps remain: the burst increase has a side effect at the /48 level (A8-1), and AP-20's netem test was not added. |
