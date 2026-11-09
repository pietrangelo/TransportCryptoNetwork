# Adversary review 0011: Phase 4 (R-4 client failover deadline and limited hedge)

**Surface:** `git diff 784a77c..7043bfa` on `claude/project-thread-qi9qrv` (5 commits):
- `zt-application/src/failover.rs` (sans-IO `FailoverPlan`, `FailoverConfig`, `MAX_IN_FLIGHT`,
  `MAX_DEADLINE`).
- `zt-net/src/client.rs` (`establish`, `attempt`, `Losers`, `close_politely`), `config.rs`
  (`connect_deadline_secs`, `require_outer_suite` carried into `ClientConfig`), `error.rs`
  (`NetError::Deadline`).
- `bins/zt-client/src/main.rs` (exit 75).
- Tests: `zt-application/tests/failover{,_attacks}.rs`, `zt-net/tests/failover{,_attacks}.rs`,
  `failover_harness`, `zt-client/tests/{cli,openssh}.rs`.
- Docs: PROTOCOL §13, OPERATIONS §5, resilience §5.3 and catalogue R4-F1..F12, 0005 #4.

Checked against `docs/pq-resilience-plan.md`, `docs/analysis/resilience.md` §5.3, review 0005
(A5-4), 0007 (AP-10, D-4, D-8) and 0010 (A10-9).

**Reviewer:** an independent adversary agent. It did not write the code. The encrypted project
instructions (CLAUDE.md: decrypted by a SessionStart hook) were **not** visible to it.

**Method:**
- `cargo test --workspace --offline` at `7043bfa`: exit 0, 646 passed, 11 ignored. The two
  R-4 OpenSSH tests (`--ignored`) also pass (OpenSSH 9.6p1, ansible-core 2.16.3 on the host).
- Mutation testing: 11 hand-written mutants applied one at a time to a `git archive 7043bfa`
  copy (never to the repository), each run against every R-4 test
  (`adv11-tests/mutate.py`). 3 survive (table in A11-5).
- Reproducers in a throw-away crate `adv11-tests/` (path dependencies on the workspace,
  `CARGO_TARGET_DIR` = the repository's `target/`):
  - `tests/a11_admission_burn.rs`: the real `FailoverPlan` driving two real R-1 `Admission`
    instances for an Ansible controller behind one address (sans-IO, 1 ms steps).
  - `tests/a11_sim.rs`: turmoil 0.7.2 with the real relays, agent and client (harness copied
    from `crates/zt-net/tests/failover_harness`).
  - `a11_ansible_tail.rs`: appended to a copy of `bins/zt-client/tests/openssh.rs`; real
    `ssh` + `sshd` + `zt-client` binary, two real relays, a freezable TCP proxy on one agent
    link.
- Ansible's own source (`ansible/plugins/connection/ssh.py`, `config/base.yml`) read for the
  options it passes to `ssh` and its retry loop.
- Every hypothesis marked "reproduced" has a reproducer that asserts the attackable behaviour
  and passes at `7043bfa`. The repository was not modified.

**Attacker models (0007):** (a) remote, no credentials; (b) on-path recorder / active
on-path; (c) holder of one valid identity; (d) one compromised relay; (e) HNDL quantum
adversary; (f) operator error. Plus non-malicious failure: overload, half-open links (G4).

**Severity:** the 0001–0010 scale. **High** blocks the merge. **Medium** must be fixed in this
phase. **Low** and **info** may be fixed in the phase that next touches the code.

## Verdict

The core of R-4 is **correct**. The invariants of §5.3 hold under every attack tried: message 1
of the end-to-end channel is sent on one relay only, a policy answer before any `OpenAck` aborts
every attempt, nothing is retried after `Proceed`, at most two attempts are in flight, the plan
never hedges an attempt that has completed its handshake, `require_outer_suite` is enforced
before any dial, nothing is spawned and dropping the client closes every connection. No high
finding.

The weak part is the interaction with the **rest of the system**: the admission budget of R-1,
Ansible's own connect timeout, and the deadline arithmetic with more than two relays. The
operator documentation promises things the code does not deliver there, and the catalogue rows
that should prove them are tested at the plan level only.

| # | Sev. | Surface |
| :-: | :-: | :- |
| A11-1 | **medium** | Hedge losers cancelled before key confirmation keep their R-1 source token spent. A slow relay plus a controller behind one address burns the controller's budget on the *other* relay. A restart of the slow relay then leaves hosts UNREACHABLE (138–162 of 800 in the model; 0 without the hedge). R4-F7 "no gate refusals with R-1" is false, and its test never touches R-1 |
| A11-2 | **medium** | Ansible always passes `-o ConnectTimeout=<timeout>` (default **10 s**), and OpenSSH applies it to the banner exchange through a `ProxyCommand`. The no-hedge wait for `OpenAck` is also 10 s, so one relay that handshakes but cannot answer `Open` makes every Ansible connection fail before failover, although another relay is healthy. The 20 s deadline and exit 75 are unreachable under Ansible's defaults. OPERATIONS §5 recommends a `ConnectTimeout` "unset, or above 20 s" but never says that Ansible sets it |
| A11-3 | low | The deadline is not shared fairly across relays. Two relays that complete the handshake and sit on `Open` (half-open agent links G4, overload, or model (d)) use up the 20 s, and a healthy third relay is **never dialed**. The sequential client got through after about 30 s, so this is a regression for deployments with three or more relays |
| A11-4 | low | Exit 75 is rare in practice. Black-holed, refusing or silent relays end as `Exhausted` with the last error (exit 1) after about 5–7 s. OPERATIONS §5 presents 75 as *the* failure status. `ssh_reports_the_failover_deadline` reaches the deadline only because it sets it to 2 s |
| A11-5 | low | Tests that do not test what they claim. Mutants M1 (no `Close Normal`), M2 (losers kept open for the whole session) and M3 (`select!` not biased) survive. `dropping_the_client_mid_hedge_leaks_nothing` passes with the hedge disabled. R4-F2, R4-F6 and R4-F7 are plan-only |
| A11-6 | low | Hedging makes the relay's security telemetry misleading. Losers appear as `unconfirmed`/`aborted` from one source, which OPERATIONS §6 calls "the signature of someone replaying recorded handshakes". A loser that reached `OpenAck` logs a phantom `session_established`. A `NotAuthorized` after `Proceed`, the only symptom of a partial policy rollout, is dropped silently |
| A11-7 | info | Downgrade during the rollout: with mixed pins, an on-path **delay** of the hybrid relay (no reset, nothing logged at that relay) or simply a slower hybrid handshake hands the session to a classical relay. A10-9's warning is still printed. `require_outer_suite` is `None` by default, which is necessary while pins are mixed |
| A11-8 | info | Documentation drift: "at most two outer handshakes" (it is two *at once*, up to 8 in total, ×4 with `retries = 3`); `connect_deadline_secs` placed inside the commented `[[relays]]` block; `Close Normal` is not guaranteed for an `Open` already written (unbiased `select!` in `attempt`); a misleading "relay unavailable" line for a refusal that the plan has ignored |

## Outcome

Both mediums and every low finding are fixed in the PR that carries this review; A11-7 is
documented (no code change), A11-8 is fixed item by item. Commits: RED `41f8105`, GREEN
`8b1f312`; the documentation and this record follow in one commit. The full suite
(`--all-features`) has 664 passing tests, 14 of them new, and 13 ignored (OpenSSH, Ansible and
timing baselines, 2 of them new); the 10 `e2e-openssh` tests pass; `cargo clippy`
(all targets and features), `cargo fmt --check` and `cargo deny check` (workspace and `fuzz/`)
are clean.

**The design of A11-1.** Of the two fixes the review proposed, the hedge keeps its trigger
("connect and outer handshake not complete after the stagger") and the losers **finish their
handshake and confirm their key** before they close:
- cancelled before TCP connect: dropped; the relay has not accepted, so it charged nothing;
- cancelled in the outer handshake: the handshake is completed, bounded by the plan's
  handshake step timeout counted from the connect, and one authentic transport frame is sent,
  a `Ping` (it opens nothing, the relay answers it with a `Pong` and keeps no state), then EOF.
  That is the key confirmation of PROTOCOL §10.1, for which `Admission::on_confirmed` gives the
  per-source token back;
- cancelled after `Open`: `Close Normal` for the stream, as before. `Open` is no longer
  cancellable once started, so the race of A11-8 (an `Open` written, then dropped without its
  `Close`) is gone.

**AP-1 still holds.** The refund is still tied to an authentic frame under the session keys,
which only the holder of the client key can produce: a replayed message 1 never gets past
message 2, so it never gets a refund; the identity's refund rate (A8-3) still caps what one
key can give back. Nothing changes on the relay or on the wire. The alternative, hedging only
while TCP connect is incomplete, was rejected: it would drop the hedge for the case R-4 was
built for (a relay that accepts and stays silent under a PQ reconnect storm, G3) and leave the
5 s handshake timeout as the only answer. The cost of the chosen design is one more round trip
on a relay that has already done its share of the handshake, in the background of the
session; a loser whose relay cannot finish its own handshake in time still keeps its token
spent, which is exactly what the budget is for ("handshakes that never complete").

**The defaults of A11-2 and A11-3.** `connect_deadline_secs` 8 s (was 20 s); the `OpenAck`
wait is now the time left before the deadline divided by the relays not yet started plus one,
at least the stagger (2 s) and at most `open` (4 s, was 10 s). Connect 3 s, handshake 5 s and
the 2 s stagger are unchanged. With two relays, one failed relay of any kind followed by a
healthy one gives `Proceed` within 6.5 s in the worst case (relay 1 handshakes just before the
stagger and then stalls: 2 s + 3 s + the healthy relay), which leaves room for the end-to-end
handshake and the SSH banner inside Ansible's default 10 s. Three relays that stall on `Open`
and a healthy fourth fit in the 8 s (2 s each). The floor keeps a long list from turning a
merely slow `OpenAck` into a failure (AP-10 asks for no hedge there, and there is none: the
attempt is cancelled before the next one starts). The defaults were preferred to an
"`ConnectTimeout` ≥ deadline" rule, which every Ansible setup would have to apply; OPERATIONS
§5 still tells operators who raise `connect_deadline_secs` to raise `[defaults] timeout` with
it, and how (`timeout`, `ANSIBLE_TIMEOUT`, or `-o ConnectTimeout` in `ssh_args`, which come
before Ansible's own option: the first one wins). The lab's `ansible.cfg` sets it explicitly.

| # | Outcome | Regression |
| :-: | :- | :- |
| A11-1 | **Fixed** (design above). OPERATIONS §5 and PROTOCOL §13 no longer say "absorbs": they describe the confirmation and what the budget still counts; R4-F7 is tested against the real `Admission` of real relays. | `hedge_losers_do_not_burn_the_controllers_admission_budget` (simulator, real relays with a 3-token per-source budget that does not refill: four hedged sessions in which the hedge to relay 2 is cancelled mid-handshake, then relay 1 black-holed: relay 2 must still admit the controller; it fails at `7043bfa` with `Closed`), `a_hedge_cancelled_in_its_handshake_confirms_its_key` (scripted relay: the loser's only frame is a `Ping`) |
| A11-2 | **Fixed** (defaults above). OPERATIONS §5: the `ansible.cfg` example sets `[defaults] timeout`, the settings table explains that Ansible always passes it as `ConnectTimeout`. | `ssh_fails_over_a_stalled_relay_within_ansibles_connect_timeout` (e2e-openssh, the reproducer flipped: `ConnectTimeout=10`, first relay with a frozen agent link, success in about 4 s), `one_failed_relay_fits_ansibles_connect_timeout` (plan, every failure mode of relay 1 and three jitters), `hedging_does_not_amplify_a_slow_but_alive_relay` (now 4 s), `connect_deadline_is_read_from_client_toml` |
| A11-3 | **Fixed:** the shared `OpenAck` wait. PROTOCOL §13 states the bound (with more than four relays, those after the fourth are reached only if earlier ones fail faster). | `two_stalling_relays_leave_time_for_a_healthy_third` (the reproducer flipped: echo through relay 3 at about 5.3 s), `three_stalling_relays_and_a_healthy_fourth_fit_the_default_deadline` (about 6 s), `stalling_relays_share_the_deadline`, `the_shared_wait_is_bounded` (plan) |
| A11-4 | **Fixed.** `zt-client` exits 75 for the deadline and for every give-up whose error says nothing about the right of access: I/O, timeout, connection closed, `NodeOffline`, `RateLimited`, `Close Drained`. A policy refusal, a handshake that fails with a pinned key, a protocol or configuration error stay 1. A relay that drops an unknown client key cannot be told apart from one under admission pressure, so it is 75 too; OPERATIONS §5 says so. The OpenSSH test now also covers the default path. | `a_refusing_relay_exits_with_tempfail`, `a_silent_relay_exits_with_tempfail_with_the_defaults` (cli), `temporary_failures_exit_with_tempfail` (unit), `ssh_reports_a_silent_relay_with_the_default_timeouts` (e2e-openssh) |
| A11-5 | **Fixed.** M1 and M2 are killed by new simulator tests; `during == 2` is asserted (and the test was wrong: it measured "during" after the drop; it now spawns the client and aborts it). M3 was more than a test gap: at `7043bfa` a handshake completing at the very instant of the stagger **was** hedged on every round, because the attempt reports its step while it is polled, after the `biased` select has checked the progress queue. The timer arm now drains the reported steps before it ticks; removing either the drain or the `biased` makes the test fail. Mutation re-run on the new code: M1, M2, M3, "no drain", "no key confirmation" and "no policy warning" are all killed. Catalogue: R4-F2 and R4-F6 say what their tests do and do not show; R4-F7 points to the real test; the plan-only proptest is renamed `hedging_stays_within_the_plans_bounds`. | `a_loser_that_sent_open_sends_close_normal` (M1), `the_loser_is_closed_while_the_session_runs` (M2, the reviewer's `a11_6`), `a_handshake_done_at_the_stagger_instant_is_not_hedged` (M3: a 3 ms stagger has no jitter and is exactly the handshake time on 1 ms links), `dropping_the_client_mid_hedge_leaks_nothing` |
| A11-6 | **Fixed.** Losers now confirm and leave, so they are no longer `unconfirmed`; OPERATIONS §6 explains what a hedge still looks like at a relay (`aborted`/`timeout` for one cut off before its handshake completed, a `session_established` immediately drained for one that had sent `Open`). A loser in `Step::Open` listens 1 s after its `Close` for a `Reject` that crossed it; a policy refusal from a loser is logged as WARN `relays disagree on the policy` with `relay` and `used_relay`. | `a_losers_policy_refusal_is_reported` |
| A11-7 | **Documented.** OPERATIONS §13 (step 4) and PROTOCOL §13 say that a hedge, like failover, can hand the session to a classical hop during the rollout without any reset, and recommend a short window, hybrid relays first and `require_outer_suite` at the end of it. No code change: the hedge to "a relay pinned like the first" would make the hedge useless exactly when the hybrid relays are down. | (A10-9's `a_required_outer_suite_refuses_relays_pinned_to_another_suite`, `a_hedge_never_lands_on_a_relay_outside_require_outer_suite`) |
| A11-8 | **Fixed item by item:** "at most two outer handshakes" now reads two **at once**, every relay at most once, ×4 with `retries = 3`; `connect_deadline_secs` moved above the first `[[relays]]` in the OPERATIONS example and to 8 in the `config.rs` example; the `Close Normal` promise holds (`Open` is not cancellable once started); an outcome the plan ignored no longer logs "relay unavailable" or replaces the final error (`FailoverPlan::is_in_flight`), and neither WARN says "trying the next one" any more (it was printed for the last relay too); a failing RNG for the jitter is logged. | `the_deadline_exits_with_tempfail_and_a_clear_message` (unchanged), the A11-5 tests |

---

### A11-1 (medium): hedge losers spend the controller's R-1 budget; a relay restart then makes hosts UNREACHABLE

**Surface:** `crates/zt-net/src/client.rs:329-370` (an attempt cancelled in the handshake drops
the connection), `crates/zt-application/src/admission.rs:513` (`gate.admit` takes the token at
accept), `:583-585` (refund only in `on_confirmed`), `:590-593` (`release` of a pending ticket:
no refund); OPERATIONS §5 lines 317-319 ("which their admission budget (§4.1) absorbs"),
PROTOCOL §13 line 579 ("absorbs"), resilience catalogue R4-F7 line 504 ("no gate refusals with
R-1").

**Hypothesis:** R-1 refunds a source's token only when the connection confirms its key, that is,
when the client sends its first transport frame, the `Open`. A hedge loser is cancelled when the
other relay's `OpenAck` arrives. That is often while the loser is still in its outer handshake,
so its token is never refunded. OPERATIONS §4.1 sizes `source_burst` (64, then 1 per 3 s) on the
promise that it "limits only handshakes that never complete: scanners, replays, broken
clients". With R-4, hedge losers count against it too. Take an Ansible controller behind one
address whose first relay handshakes in a little over the 2 s stagger. That relay can be
overloaded (G3: a PQ reconnect storm), on a slow path, or delayed by an on-path attacker
(model b). Nearly every connection is then hedged, and the loser, on either relay, burns a token.
The controller's budget at the second relay is gone after a few dozen connections. If the first
relay then dies, which is likely for an overloaded relay, everything needs the second relay, and
it drops the controller without a reply until its bucket refills.

**Evidence (reproduced):** `adv11-tests/tests/a11_admission_burn.rs`. The real `FailoverPlan` and
two real `Admission`s with default limits. Ansible `forks = 50`, one address, 4 s sessions,
`retries = 3` with Ansible's real pauses (0, 1, 3 s: `ssh.py:560`).

| relay 1 / relay 2 handshake | client | relay 2 refusals | tokens burnt (r1/r2) | UNREACHABLE |
| :- | :- | -: | -: | -: |
| 2.4 s / 0.3 s, 400 hosts | sequential (pre-R-4) | 0 | 0 / 0 | 0 |
| 2.4 s / 0.3 s, 400 hosts | R-4 | 208 | 30 / 79 | 0 |
| 3.0 s / 2.3 s, 400 hosts | R-4 | 320 | 0 / 80 | 0 |
| 2.4 s / 0.3 s, relay 1 dies at 30 s, 800 hosts | sequential | 0 | 0 / 0 | **0** |
| same | R-4 | 863 | 13 / 72 | **138** |
| same, relay 1 dies at 45 s | R-4 | 1 054 | 16 / 77 | **162** |

The proptest named in R4-F7 (`hedging_stays_within_admission_budget`) only counts actions of the
plan. It never instantiates `Admission`, so "no gate refusals with R-1" was never tested. The
same losers also fill the `unconfirmed`/`aborted` counters (A11-6).

The on-path variant is an amplification. An attacker on the path to relay 1 only, who cannot
touch relay 2, delays relay 1 by about 2.3 s for a minute and then resets it. Before R-4 a reset
just moved the controller to relay 2. Now relay 2 drops the controller.

**Required fix (one of):**
- Let a loser that is past message 1 **finish its handshake and confirm** before it closes.
  Send `Close Normal` (or any authentic frame) instead of dropping the connection, bounded by the
  step timeout or `CLOSE_GRACE`. The relay refunds the token. The relay's CPU for message 1 is
  already spent, so this costs one more round trip at most. Only a loser cancelled before TCP
  accept or before message 1 is sent may be dropped.
- Or narrow the hedge to "TCP connect incomplete". A black-holed relay never accepts, so it never
  charges a token. Keep the 5 s handshake timeout for accept-and-silence.

In both cases, fix OPERATIONS §5 and PROTOCOL §13 ("absorbs"), and size `source_burst` against
`forks` × (1 + hedge losers). Add a test of R4-F7 that drives `FailoverPlan` against real
`Admission`s, like the reproducer, and asserts zero `RateLimited` refusals for a controller with
`forks = 50`.

**Outcome: fixed** (table above, the design of A11-1).

### A11-2 (medium): under Ansible's defaults, `ConnectTimeout = 10` ends `ssh` before failover

**Surface:** `crates/zt-application/src/failover.rs:51` (`open: 10 s`), `:292` (no hedge in
`Step::Open`); OPERATIONS §5 lines 294-320 (ansible.cfg, the recommended settings table, line
315: "`ConnectTimeout` (ssh) | unset, or above 20 s"); Ansible
`plugins/connection/ssh.py:792-797` (always `-o ConnectTimeout=<timeout>`), `config/base.yml:1079-1086`
(`[defaults] timeout`, default **10**).

**Hypothesis:** Ansible's ssh connection plugin always adds `-o ConnectTimeout=<timeout>`, with
`timeout = 10` unless it is configured. With a `ProxyCommand`, OpenSSH applies `ConnectTimeout`
to the banner exchange ("Connection timed out during banner exchange", exit 255). After AP-10,
`zt-client` waits up to 10 s for the `OpenAck` of a relay that has completed the handshake,
without hedging. A relay with a half-open agent link (G4 lasts up to the 90 s agent idle), an
overloaded hub, or a compromised relay (model d) that sits on `Open` therefore makes **every**
Ansible connection fail at 10 s. Every retry starts on the same first relay again. So the host
is UNREACHABLE after 4 attempts, although the second relay is healthy. The 20 s deadline,
exit 75 and the deadline message on stderr are never seen under Ansible, which is the audience
R-4 was built for (A5-4: "adds a timeout to every Ansible connection").

**Evidence (reproduced):** `adv11-tests/a11_ansible_tail.rs`, appended to a copy of
`openssh.rs`. Relay B (real, production timeouts) is listed first, with a second `web-01` agent
registered through a TCP proxy that is then frozen. Relay A (the lab's relay) is healthy.
- `ssh -o ConnectTimeout=10` (Ansible's default): `status Some(255) after 10.01 s, stderr:
  Connection timed out during banner exchange`.
- Control with `ConnectTimeout=30`: success after 10.35 s through relay A, with `zt-client`
  logging `relay timed out, trying the next one step="open"`.

The OPERATIONS table tells the operator to keep `ConnectTimeout` unset or above 20 s. It does not
say that Ansible sets it, or how to override it: `[defaults] timeout` or `ANSIBLE_TIMEOUT`, or
`-o ConnectTimeout=30` placed first in `ssh_args`, because the first `-o` wins in OpenSSH. Its
example `ansible.cfg` leaves it at 10. Before R-4 the open timeout was 15 s, so this is not a
regression, but R-4 closes A5-4 without closing it for the default Ansible setup.

**Required fix:**
- Add `[defaults] timeout = 30` (≥ `connect_deadline_secs` + margin) to the OPERATIONS §5
  `ansible.cfg`, and explain why in the table. Do the same in the `ansible_playbook_runs_through_tcn`
  lab.
- Bring the worst single-relay failover path under 10 s, which is what Ansible gives by default.
  For example, lower the `OpenAck` timeout to about 5 s once the outer handshake is complete:
  AP-10 asks for no **hedge** there, not for a long wait. Or allow one replacement attempt after
  `open/2` with no overlap: cancel first, then start.
- Add an e2e-openssh test with `ConnectTimeout=10` and a stalled first relay, like the
  reproducer.

**Outcome: fixed** (table above, the defaults paragraph).

### A11-3 (low): two stalling relays use up the deadline, and a healthy third relay is never tried

**Surface:** `crates/zt-application/src/failover.rs:290-296,300-305`; PROTOCOL §13 (the timing
table), resilience R4-F12.

**Hypothesis:** each relay that completes the handshake but cannot answer `Open` costs the full
10 s open timeout, by design (AP-10). The deadline is a flat 20 s, so after two such relays
nothing is left for relay 3. Before R-4 the client reached relay 3 after about 30 s, which is
slow but works. Now it fails with `Deadline` (exit 75). With 8 relays the deadline caps the
useful list at 2 "alive but stuck" relays. The same holds for the half-open agent links of G4
when one agent's links to two relays break together (a NAT or site event).

**Evidence (reproduced):** `adv11-tests/tests/a11_sim.rs::a11_1_two_stalling_relays_hide_a_healthy_third`.
Three real relays, with the agent's links to relays 1 and 2 held. Result: `Failed(20s,
Deadline(20s))`, client arrivals `relay1 [1.001s] relay2 [11.004s] relay3 []`. Control
(`a11_1_control_longer_deadline_reaches_relay3`): with a deadline of 40 s, the echo comes
through relay 3 at 20.02 s.

**Required fix:** document the bound ("about two relays that accept and stall can use up the
deadline") and choose one of these:
- Give each later attempt a shorter `OpenAck` timeout, from `min(open, remaining / relays_left)`.
- Or compute the default deadline from the number of relays.
- Or, once A11-2 lowers the open timeout, check that 3 stalling relays plus a healthy fourth fit
  within the default.

Add a three-relay simulator test to R4-F12.

**Outcome: fixed** (table above, the defaults paragraph).

### A11-4 (low): exit 75 is the exception, not "the" failure status

**Surface:** `crates/zt-net/src/client.rs:249-252` (`Deadline` → `NetError::Deadline`, every
other give-up → `last`), `bins/zt-client/src/main.rs:326-333`; OPERATIONS §5 lines 238-245;
resilience R4-F11, R4-F12; `bins/zt-client/tests/openssh.rs:406-431`.

**Hypothesis:** with the default timeouts, the most common outages end as `Exhausted`:
- every relay refused (connection refused, relay restart): at once;
- black-holed relays: about 5 s;
- relays that accept and stay silent: about 7.3 s.

`zt-client` then exits **1** with the last error, not 75. Only "handshake completes, `Open`
never answered" reaches the deadline. OPERATIONS §5 presents 75 and the deadline line as what
happens when the relays fail. `ssh_reports_the_failover_deadline` claims "with no relay
answering, `ssh` fails after `connect_deadline_secs`". It reaches the deadline only because it
lowers it to 2 s, under the 5 s handshake timeout of its single silent relay. With the defaults
the same lab prints `timeout: handshake` and `zt-client` exits 1. For `ssh` both give 255, so
Ansible is not affected. Scripts or monitoring that call `zt-client` and treat 75 as "temporary,
retry" and 1 as "configuration error" are misled.

**Evidence (reproduced):** `a11_sim.rs::a11_4_black_holed_relays_exit_1_not_75` gives
`Failed(7.319s, Timeout("handshake"))` for two silent relays with the default configuration.

**Required fix:** exit 75 for every `GiveUp` that is not a policy refusal (`Exhausted` with
only `Unavailable` failures is just as temporary), or document the two statuses. Make the
OpenSSH test cover the default path.

**Outcome: fixed** (table above).

### A11-5 (low): tests that do not test what they claim

**Surface:** `crates/zt-net/tests/failover_attacks.rs:200-272` (`hedge_losers_release_agent_slots`),
`:327-352` (`dropping_the_client_mid_hedge_leaks_nothing`),
`crates/zt-application/tests/failover_attacks.rs:170-262` (proptest); catalogue R4-F2, R4-F5,
R4-F6, R4-F7, R4-F10.

**Evidence (reproduced):** mutation run (`adv11-tests/mutate.py`, 11 mutants on a copy, all
R-4 tests including the two OpenSSH ones):

| Mutant | Result |
| :- | :- |
| M1 `close_politely` does nothing: no `Close Normal`, EOF only | **survived** |
| M2 losers are not polled; they stay open until the session ends | **survived** |
| M3 `select!` in `establish` not `biased` | **survived** |
| M4 a policy refusal treated as `Unavailable` (fail open) | killed (`a_policy_answer_aborts_all_hedged_attempts`) |
| M5 hedge on a slow `OpenAck` (the plan before AP-10) | killed (4 tests) |
| M6 never hedge | killed (6 tests), but **not** `dropping_the_client_mid_hedge_leaks_nothing` |
| M7 hedge only before TCP connect | killed (2 tests) |
| M8 exit 1 at the deadline | killed (`the_deadline_exits_with_tempfail_…`) |
| M9 `require_outer_suite` not enforced in `connect_with` | killed |
| M10 three attempts in flight | killed (proptest only) |
| M11 no jitter | killed |

- **R4-F5** promises that the loser is "released ≤ one RTT after the client closes it". The test
  starts the second client at 15 s, after the first session has ended. So it passes when the
  loser stays open for the whole session (M2): with `ControlPersist = 300s` that is minutes. It
  is bounded only by the agent's 15 s message-1 timeout, which is what actually frees the slot
  in the test. `a11_sim.rs::a11_6_the_loser_is_closed_while_the_session_runs` passes at
  `7043bfa` (1 TCP stream 3.5 s after the echo) and **kills M2** (2 streams). Nothing checks that
  `Close Normal` is sent (M1).
- **R4-F10** binds the number of streams in flight to `_` and never asserts it, so the test is
  vacuous without a hedge (M6). Assert `during == 2`.
- **R4-F2** ("agent sees one msg1"): the plan-level test checks for a single `Proceed`, and the
  sim counts sshd accepts. There is no test that would see a second message 1 that never
  completes. Acceptable, but say so.
- **R4-F6** ("after the `OpenAck` the session continues past the deadline") and **R4-F7** (A11-1)
  are plan-only. No test runs a session past 20 s.
- M3: the `biased` ordering is the only thing that stops a hedge when a handshake completes in
  the same instant as the stagger. Accept with a review note, as 0010 did for AP-4, or add a sim
  test with a handshake latency equal to the stagger.

**Required fix:** add `a11_6`, a `Close Normal` assertion (a relay-side counter in the harness),
`during == 2`, and the tests named in A11-1..A11-3. Correct the catalogue's test column for the
plan-only rows.

**Outcome: fixed** (table above).

### A11-6 (low): hedging makes the relay's security telemetry misleading

**Surface:** `crates/zt-net/src/relay.rs:664-670` (a connection closed mid-handshake →
`aborted`), `:935` (message 2 sent, no authentic frame → `unconfirmed`), `crates/zt-application/src/relay.rs:747-770`
(`session_established` at `OpenAck`); OPERATIONS §6 lines 397, 415; `client.rs:191-198`
(`Losers::close` ignores everything but `Acked`).

**Hypothesis:**
- An Ansible controller with a slow first relay produces a steady stream of `unconfirmed` (loser
  cancelled after message 2 was sent) and `aborted` from **one** `distinct_source`. OPERATIONS §6
  says that is "the signature of someone replaying recorded handshakes".
- A loser that already got its `OpenAck` (the case `hedge_losers_release_agent_slots` builds)
  logs `session_established` then `connection_drained` on the losing relay. That is a phantom
  session in the audit trail.
- When relay 1's `NotAuthorized` arrives after relay 2's `OpenAck` (R4-F4, accepted), the client
  drops it silently. That refusal is the only signal that the relays' policies differ (0005-2:
  revocation is complete only when every relay has reloaded).

**Required fix:**
- Document the hedge in OPERATIONS §6: losers count as `aborted`/`unconfirmed`, and a short
  session on a second relay is a hedge, not a login. A11-1's "confirm before close" also removes
  most of the `unconfirmed` noise.
- Have `Losers::close` log a WARN with both relay addresses when a loser answers with a policy
  `Reject`: "relays disagree on the policy".

**Outcome: fixed** (table above).

### A11-7 (info): a hedge picks the classical hop on timing alone during the rollout

**Surface:** `client.rs:114-126` (warning only); PROTOCOL §7.5.2, §13; A10-9.

**Hypothesis:** with mixed pins and `require_outer_suite` unset (the default, which the
rollout of OPERATIONS §13 needs), an on-path attacker no longer has to *reset* the hybrid relay.
Delaying its handshake past the stagger (about 2.3 s) is enough: the classical relay wins the
race, and the hybrid relay records only an `aborted`. The same happens with no attacker when the
hybrid handshake (larger messages) is naturally slower than the stagger. A10-9's warning is
still printed on stderr, but Ansible hides it.

**Required fix (optional):** while pins are mixed, hedge only to a relay pinned like the first
one when there is one. Or document that a hedge, like failover, can lower the per-session suite.

**Outcome: documented** (table above).

### A11-8 (info): documentation drift

- OPERATIONS §5 lines 317-318: "each `zt-client` performs at most two outer handshakes". It is
  two **at once**. With *n* relays failing quickly, up to *n* (≤ 8), and with `retries = 3`, up
  to 4 *n* per host.
- OPERATIONS §5 line 207: the commented `connect_deadline_secs` sits inside the commented
  `[[relays]]` block. Uncommented there, `RelayEntry`'s `deny_unknown_fields` rejects the file.
  Move it above the first `[[relays]]`.
- PROTOCOL §13 step 4: "after `Open` it sends `Close Normal`". `attempt`'s `select!`
  (`client.rs:347-370`) is unbiased. A cancel that races a completed `send(Open)` returns
  `Cancelled` and drops the connection (EOF only). That is harmless, because EOF releases the
  stream, but the text promises more.
- `client.rs:292-299`: a `Failed` that the plan ignored (the attempt had already timed out or
  been cancelled) still logs "relay unavailable, trying the next one", even for a policy
  refusal. It also overwrites `last`, so the final error of an `Exhausted` give-up can be a
  `NotAuthorized` the plan never acted on.
- `getrandom::u64().unwrap_or(0)` (`client.rs:209`): if the RNG fails, the jitter is 0 and the
  fleet hedges in step. Same as A10-4. Log it.

**Outcome: fixed item by item** (table above).

## Verified correct

- **One message 1:** `Proceed` is emitted once (`end()` sets `finished`). `establish` returns on
  the first `Proceed`, and the end-to-end `initiate_suite` runs only on the winner. A late
  `Acked` (a loser, or an attempt the plan has timed out) is closed with `Close Normal`
  (`client.rs:280-281`, `Losers::close`). Two attempts can both reach `Open` (two agent stream slots,
  each on its own relay session, `StreamId` 1 on separate connections), but only one gets a
  message 1. A compromised losing relay has nothing to replay.
- **`OpenAck` A vs `Reject` B:** `FuturesUnordered` delivers one outcome at a time, and the plan
  decides on the first. A `Refused` first → `GiveUp(Refused)` and every attempt is dropped. An
  `Acked` first → `Proceed`, and the later refusal is ignored (R4-F4, accepted). A `Refused` for
  an attempt the plan already timed out is ignored, as a timeout was before R-4.
- **Fail closed:** only `NodeOffline`/`RateLimited` and transport errors are `Unavailable`
  (`may_try_next_relay`). Every other `Reject` stops everything (M4 is killed).
- **Deadline arithmetic:** every `Duration` sum saturates. `MAX_DEADLINE` is 300 s, so
  `Instant::checked_add` cannot fail. The clock is tokio's monotonic `Instant` (no wall-clock
  jumps, and it does not count suspend). The deadline is checked before every event and timer,
  and nothing runs after it. A zero duration is refused before any dial.
- **Cancellation and RAII:** the attempts are futures of the caller's task. Dropping the
  `oneshot` senders cancels them, and each select arm returns at once, or after a
  `CLOSE_GRACE`-bounded `Close`. `Losers::close` is joined with the session and bounded by about
  1 s. The progress queue (16) cannot overflow: at most 2 events per attempt × at most 8
  attempts. No socket, task or agent slot outlives the client (sim, `a11_6`).
- **AP-10:** `hedge_at` is `None` once the only attempt is in `Step::Open`. A failure of the
  hedge does not start a "replacement hedge" against a slow `OpenAck` (M5 is killed).
- **`require_outer_suite`:** enforced both in `parse_client_settings` and in `connect_with`
  before any dial (M9 is killed). A hedge cannot land on another suite.
- **Error text:** `NetError::Deadline` and the WARN lines carry only configuration values
  (relay address, step name) and static strings. No bytes from the network reach stderr.
- **Jitter:** `jitter mod (stagger/4 + 1 ms)`, so 0–500 ms. It is deterministic for a sample,
  and the modulo bias is negligible.

## Reproducers

The reviewer's reproducers asserted the **attackable** behaviour (they passed at `7043bfa`).
They are now regression tests that assert the safe behaviour:

| Reproducer | Finding | Now |
| :- | :- | :- |
| `tests/a11_admission_burn.rs` (sans-IO model of the adapter) | A11-1 | `crates/zt-net/tests/failover_attacks.rs`: `hedge_losers_do_not_burn_the_controllers_admission_budget` with the real relays and their real admission, `a_hedge_cancelled_in_its_handshake_confirms_its_key` |
| `a11_ansible_tail.rs` | A11-2 | `bins/zt-client/tests/openssh.rs`: `ssh_fails_over_a_stalled_relay_within_ansibles_connect_timeout` |
| `tests/a11_sim.rs::a11_1_two_stalling_relays_hide_a_healthy_third` | A11-3 | `two_stalling_relays_leave_time_for_a_healthy_third`, `three_stalling_relays_and_a_healthy_fourth_fit_the_default_deadline` |
| `tests/a11_sim.rs::a11_4_black_holed_relays_exit_1_not_75` | A11-4 | `bins/zt-client/tests/cli.rs`: `a_refusing_relay_exits_with_tempfail`, `a_silent_relay_exits_with_tempfail_with_the_defaults` |
| `tests/a11_sim.rs::a11_6_the_loser_is_closed_while_the_session_runs` | A11-5 | `the_loser_is_closed_while_the_session_runs` |
| `mutate.py` (M1–M3) | A11-5 | `a_loser_that_sent_open_sends_close_normal`, `the_loser_is_closed_while_the_session_runs`, `a_handshake_done_at_the_stagger_instant_is_not_hedged` |

The reviewer's originals, run against the throw-away copy described in the method, are not in
the repository.
