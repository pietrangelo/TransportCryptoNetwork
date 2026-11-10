# Adversary review 0010: Phase 3 (PQ-1 on the outer hops, R-2, R-3)

**Surface:** `git diff 08724db..5de3a84` on `claude/project-thread-qi9qrv` (11 commits):
- PQ-1 outer: `zt-domain/src/suite.rs` (`is_supported` for `Outer`), `zt-net/src/channel.rs`
  (first-frame cap moved after message 2), `zt-net/src/relay.rs` (per-role check,
  `ConfirmedSuites` / `outer_suites_confirmed`), `zt-net/src/agent.rs` (`relay_registered`),
  the agent's `--relay-suite`, fuzz `noise_responder`, PROTOCOL §7.5.2, OPERATIONS §13.
- R-2: `zt-net/src/net.rs` (`Dialer`/`Acceptor`, socket options), `zt-application`
  `reconnect.rs`, `liveness.rs`, `flapping.rs`, the relay's per-role idle, `tests/sim.rs`
  (turmoil 0.7.2).
- R-3: `zt-application/src/lifecycle.rs`, `zt-net/src/lifecycle.rs`, `systemd.rs`, `reload.rs`,
  the relay hub (`run_until`, `drain`, tick order, `Progress`), the agent's `run_until`, both
  binaries (`check`, exit 78, `harden_process`), `packaging/systemd/*.service`, OPERATIONS
  §4, §6, §9, §14, PROTOCOL §8, §10, §13.

Checked against `docs/pq-resilience-plan.md`, `docs/analysis/resilience.md` (catalogue
R2-L*, R3-C*), review 0007 (AP-4, AP-10, AP-17, AP-18, AP-21), 0008 and 0009.

**Reviewer:** an independent adversary agent. It did not write the code. The encrypted project
instructions (CLAUDE.md: decrypted by a SessionStart hook) were **not** visible to it.

**Method:**
- `cargo test --workspace --offline` at `5de3a84`: exit 0, no failure.
- Shell reproducers against the repository's debug binaries (`target/debug/zt-relay`,
  `zt-agent`, `zt-ca`), a fake `NOTIFY_SOCKET` (abstract unix socket) with `WATCHDOG_USEC`.
- Rust reproducers in a throw-away crate (path dependencies on the workspace,
  `CARGO_TARGET_DIR` = the repository's `target/`): one on real TCP (relay drain), two in
  turmoil (the half-open scenario with other parameters). Every hypothesis marked
  "reproduced" had a reproducer that asserted the attackable behaviour and passed at
  `5de3a84`; the fix flipped them to assert the safe behaviour and committed them before the
  implementation (RED, `0754ec3`).
- A Monte Carlo of `ReconnectPolicy` with relay downtime.
- `PR_SET_DUMPABLE` checked on a live relay run as uid 65534 (`/proc/<pid>/mem` and
  `environ` owned by root).
- The repository was not modified.

**Attacker models (0007):** (a) remote, no credentials; (b) on-path recorder / active
on-path; (c) holder of one valid identity; (d) one compromised relay; (e) HNDL quantum
adversary; (f) operator error.

**Severity:** the 0001–0009 scale. **High** blocks the merge. **Medium** must be fixed in this
phase. **Low** and **info** may be fixed in the phase that next touches the code.

## Verdict

The PQ-1 outer-hop crypto is **correct**: no downgrade, suite confusion or cross-channel replay
was found (see "Verified correct"). The R-2 sans-IO pieces are sound. The weak part is R-3's
operational surface: the `ExecReload=check` design breaks the documented revocation path.

| # | Sev. | Surface |
| :-: | :-: | :- |
| A10-1 | **high** | `ExecReload=check` runs the unit's literal arguments. Every drop-in that OPERATIONS prescribes for `ExecStart` (`--revocations` for a pinned CA, key rotation) makes `systemctl reload`, and with it hot revocation, fail |
| A10-2 | **medium** | `check` checks other things than the reload reads (`relay.toml`, key files on disk). Digests are re-reads and name files that are not in force. A passing `check` does not mean the reload succeeded |
| A10-3 | low | Watchdog: `watchdog_stalled` (ERROR, audit) at every start of both services; a false restart when `WatchdogSec` is under about 1.5 s; blocking `sd_notify` from the hub |
| A10-4 | low | Reconnect herd: with a few seconds of relay downtime the peak reaches 2.3–3.7× the ideal; the simulator tests only zero downtime; RNG failure gives zero delay |
| A10-5 | low | The relay drain still routes **new streams** on existing connections. One client holds the drain open until its deadline. The agent drain ignores streams in mid-handshake |
| A10-6 | low | The simulator test does not prove what it says: `half_open_agent_link_is_detected` also passes with the old 30 s keepalive. Catalogue rows have no tests |
| A10-7 | low | R3-C11 is not implemented as specified: a clock before the build only logs, and certificates are still evaluated |
| A10-8 | low | Exit 78 is used for every load failure, transient I/O included, so a provisioning race leaves the unit permanently dead |
| A10-9 | low | Cross-relay failover picks the weakest outer pin: an active attacker forces the classical hop. "failover never lowers a pin" is misleading |
| A10-10 | info | Generations, `relay_registered` timing, idle bounds, `panic = "abort"` vs the supervisor, documentation drift |


## Outcome

The high, the medium and every low finding are fixed or decided in the PR that carries this
review; A10-10 is fixed or recorded item by item. Commits: RED `0754ec3`, GREEN `78b08d5`,
REFACTOR `cf7b5bb`. The full suite went from 588 to 612 passing tests (9 ignored: OpenSSH,
ansible and timing baselines); the `e2e-openssh` tests pass; `cargo clippy` (all targets and
features), `cargo fmt --check` and `cargo deny check` (workspace and `fuzz/`) are clean.

**The design of A10-1 and A10-2.** The running process is the only judge of a reload.
`ExecReload=` is now `zt-<bin> --log-format json reload --pid $MAINPID`, with no file
arguments. `reload` reads the reload state that the service publishes in its runtime directory
(`RuntimeDirectory=zt-<bin>`, mode 0700, `$RUNTIME_DIRECTORY`), sends `SIGHUP`, and waits for
the first attempt that **started after** its read (an attempt already in flight may have read
the files before the edit). The service announces every `SIGHUP` to systemd with `RELOADING=1`
and `MONOTONIC_USEC=`, validates its files with the arguments it was started with and the
keys in force, applies them or keeps the previous ones, publishes the outcome (atomic write
and rename) and sends `READY=1`. `reload` exits 0 (applied; relay warnings on stderr), 78
(rejected; the service's own reason) or 1 (no state, the process ended, or no answer within
`--timeout`, 30 s). The alternatives were rejected: an environment variable shared by both
lines still lets a drop-in on `ExecStart=` diverge and still validates in another process;
`check --pid` reading `/proc/$MAINPID/cmdline` still runs a different process against
different key material (A10-2 item 3); `Type=notify-reload` (systemd ≥ 253) cannot report a
rejected reload. Signalling uses rustix's safe `kill_process` (`forbid(unsafe_code)` intact)
under the same user and sandbox as the old `/bin/kill`. `check` stays a pre-flight before a
**restart**: it runs the same function as `run` at startup (`load_startup` in the relay,
`prepare` in the agent), with the same exit codes.

| # | Outcome | Regression |
| :-: | :- | :- |
| A10-1 | **Fixed.** `reload --pid $MAINPID` and the in-process validation above; both units carry `RuntimeDirectory=` and one `ExecReload=` line without arguments. A relay with `--revocations` for a pinned CA, or an agent with `--revocations` and `--relay-suite`, only in `ExecStart=`, reloads; a rejected file fails the command with the service's reason and leaves the service running. OPERATIONS §4, §7, §9, §10.5, §14; resilience.md D-11 and §5.4. | `reload_works_with_arguments_only_execstart_has`, `a_rejected_reload_fails_the_reload_command`, `reload_is_validated_by_the_running_agent`, `reloads_are_announced_and_the_watchdog_does_not_stall_at_start` (`RELOADING=1` + `MONOTONIC_USEC`, then `READY=1`), `reload_without_a_relay_fails`, `the_units_carry_the_lifecycle_directives` (exact `ExecReload=`, `RuntimeDirectory=`), `the_state_round_trips` |
| A10-2 | **Fixed.** (1) A reload validates exactly what `SIGHUP` applies, in the process that applies it: the relay's policy and denylist against the keys in force, and its keys against the policy in force and the new one; `relay.toml` is not read; a key file that fails is `relay_keys_reload_failed` plus a `warning:` from `reload`, never a blocked policy. (2) Digests come from the bytes parsed (`config::Digests`, `load_*_digested`); the reload lines name only the policy (or authorized clients) and the denylist. (3) No window between a separate check and the `SIGHUP`. R3-C7 and R3-C8 now hold and have their tests. | `a_reload_is_not_blocked_by_files_it_does_not_apply` (broken `relay.toml` and key file, policy applied, digest equals `sha256sum`, no `relay.toml`), `check_and_run_accept_the_same_files` (five file sets, same exit code), `configuration_generations_and_digests_are_logged` |
| A10-3 | **Fixed.** `ProgressWatchdog::observe`: the first observation is a baseline and kicks; a stall is reported after two checks in a row without progress, once per stall. A `WatchdogSec` below 3 s (three hub ticks) is refused at startup with exit 78 and a message naming `WatchdogSec`. The notification socket is non-blocking (a lost notification instead of a blocked hub); the first failure is a warning, later ones debug; the doc says so. The scope of the progress signal (hub only; agent runtime heartbeat) is in OPERATIONS §6. | `the_first_observation_is_a_baseline`, `a_stall_is_reported_after_two_checks_without_progress`, `a_stalled_hub_stops_the_kicks`, `a_watchdog_shorter_than_three_hub_ticks_is_refused`, `a_too_short_watchdog_is_a_configuration_error`, `reloads_are_announced_and_the_watchdog_does_not_stall_at_start` (fake `NOTIFY_SOCKET`: a kick right after `READY=1`, no `watchdog_stalled`) |
| A10-4 | **Fixed.** After a lived session the spread is the floor of the failure ceiling, `max(spread, min(cap, base·2ⁿ⁻¹))` (the reviewer's proposal); a fleet that boots keeps the base. A failing RNG gives `u64::MAX`, the longest delay. With 4 000 agents the peak is 1.1–2.3 times the ideal for 0–30 s of downtime (it was up to 3.7). The Monte Carlo is deterministic (splitmix64) on the sans-IO policy: a turmoil row with downtime and 40 agents uses the OS RNG and was too noisy for a 2× bound. When the spread is above the cap, the spread wins (R2-L4's bound is `max(cap, spread)`). | `the_spread_stays_the_floor_after_a_lived_session`, `reconnects_stay_spread_when_the_relay_is_down_for_a_while` (bound 2.5×), `a_session_that_lived_is_followed_by_a_spread_retry`, `backoff_is_bounded_for_any_sample` |
| A10-5 | **Fixed.** `Input::DrainStarted`: from the start of the drain the relay core answers a new `Open` with `Reject NodeOffline` after the rate and authorization checks (no new oracle), also on connections opened before the drain; open streams continue. The agent counts streams that were acknowledged and are still in their end-to-end handshake, and closes them with `Close Drained` at the permit instead of opening a session; sshd is never reached. The `relay_core` fuzz target drives `DrainStarted`. PROTOCOL §8.5, OPERATIONS §14. | `a_draining_core_rejects_new_streams_and_keeps_the_open_ones`, `a_draining_relay_rejects_new_streams_on_existing_connections` (the reproducer, flipped: every new stream rejected, the drain ends with the last pre-drain stream, well before its deadline), `a_draining_agent_counts_and_refuses_streams_in_mid_handshake` |
| A10-6 | **Fixed, three rows decided.** The half-open simulation counts only the agent host's arrivals; the control is committed (relay idle 1 h: the agent must be back within 30 s of the repair, which the 30 s keepalive of before R-2 cannot do). The socket-option test goes through `Acceptor::accept`. R3-C8 has its test (A10-2), R3-C11 too (A10-7). R2-L8, R2-L9 and R3-C9 are marked decided in resilience.md with the tests that cover them. AP-4's saturation test: **accepted**, see below. `an_early_sigterm_is_clean` accepting signal 15: **accepted**, see below. | `half_open_agent_link_is_detected`, `the_agent_alone_detects_a_half_open_link`, `dialed_sockets_have_user_timeout_and_keepalive` |
| A10-7 | **Fixed.** `lifecycle::certificate_time`: while the wall clock is before the build (`clock_floor`), certificates are evaluated at time zero, so none is valid (the same fail-closed rule as a clock before 1970). Used for the relay's admission and core and for the agent's admission and expiry recheck; key-pinned peers are unaffected, so the host stays reachable. `clock_unsynchronised` at start and whenever the clock steps below the floor, `clock_synchronised` when it passes it again. OPERATIONS §6, §10.7. | `certificates_are_refused_before_the_clock_floor` |
| A10-8 | **Fixed.** `ConfigError::is_transient` (I/O: missing, unreadable): exit 1, restarted with the backoff; a file that was read and is invalid stays 78. Chosen over `ConditionPathExists=`, which would turn a missing file into a silently skipped unit. Units and OPERATIONS §4, §9, §14 say which. | `a_missing_file_is_restarted_not_ex_config`, `a_missing_key_is_restarted_not_ex_config`, `check_and_run_accept_the_same_files` (missing key) |
| A10-9 | **Fixed.** `require_outer_suite` in `client.toml`: any relay pinned to another suite is a configuration error, so failover cannot land on a weaker hop. It is an explicit set of one suite, consistent with AP-7 (no ordering of suites). During the rollout, when pins are mixed by design, `zt-client` warns `failover to a relay pinned to another outer suite` on stderr. PROTOCOL §7.5.2 and OPERATIONS §5, §13 state the per-session downgrade instead of "failover never lowers a pin". | `a_required_outer_suite_refuses_relays_pinned_to_another_suite` |
| A10-10 | **Fixed or recorded per item**, see below. | `one_reload_is_one_generation` |

**A10-10, item by item.**
- *Generations:* fixed. One `SIGHUP` is one attempt and at most one generation, shared by
  `policy_reloaded` and `relay_keys_reloaded`, in a fixed order (keys, then policy).
- *`relay_registered`:* documented (code comment, PROTOCOL §7.5.2): it is logged once
  `Register` is sent; the relay can still refuse the registration. Not renamed: dashboards
  use the name.
- *Idle bounds:* the comment of `MIN_RELAY_IDLE_SECS` now says what 15 s is (one keepalive
  plus slack); OPERATIONS §4.1 recommends 30 s or more instead of saying it is needed.
- *`panic = "abort"`:* recorded. In release builds a panic ends the process, so the
  supervisor's "panicked" branch and the hub's `JoinError` path exist only in debug builds and
  tests; systemd restarts the process either way, which is the intended outcome.
- *Agent startup:* the `Terminate` doc now says that the agent reads its files before the
  runtime exists, so a `SIGTERM` during that read still has its default action (nothing is
  open to drain yet).
- *Shutdown:* the last interval's `outer_suites_confirmed` is flushed after the drain.
- *Hub tick:* `MissedTickBehavior::Delay`.
- *Fuzz header:* `noise_responder`'s header no longer says that the outer channel never
  accepts a hybrid message 1.
- *`TCP_USER_TIMEOUT`:* PROTOCOL §10 says that 20–25 s of path loss now ends an interactive
  session.
- *`configure()` before admission:* accepted (five `setsockopt` calls).
- *Clock watch:* OPERATIONS §6 says that a VM suspend and resume looks like a forward
  `clock_jumped`.
- Also fixed: OPERATIONS §5 still said that a relay cannot be pinned to the hybrid suite.

**Accepted.**
- *AP-4 saturation test (A10-6).* The ordering fix (tick before events in a `biased` select)
  is in place and `an_idle_hub_still_makes_progress` covers the progress counter. Saturating
  the real hub's 4 096-entry queue from a test needs a test-only hook into the hub; the
  ordering is a single `select!` and is reviewed, not tested.
- *Early `SIGTERM` (A10-6).* A `SIGTERM` that arrives before the handler is installed (the
  first milliseconds of `main`) still kills the process with signal 15. Blocking it earlier
  needs `sigprocmask` before the runtime, which is `unsafe` or a new dependency; nothing is
  open at that point, and `Restart=always` treats it as a clean exit.
- *Reload state file.* It lives in a 0700 directory of the service user and only decides the
  exit status of `reload`; it never feeds a security decision. A process running as the
  service user could forge it, but such a process can already signal the service and read
  its keys; it is the same trust boundary as the old `/bin/kill`.

---

### A10-1 (high): `ExecReload=check` and the drop-ins prescribed by OPERATIONS disagree, and hot revocation via `systemctl reload` breaks

**Surface:** `packaging/systemd/zt-relay.service:24,28-29`, `zt-agent.service:27,30-31`;
OPERATIONS §8 (relay key rotation, step 2: "a drop-in … an empty `ExecStart=` line, then the
full `ExecStart=`") and §10.2 ("Startup (or a drop-in for the systemd unit) … `--revocations`").

**Hypothesis:** `ExecReload=` repeats `ExecStart=`'s arguments literally. A drop-in that
replaces `ExecStart=` leaves `ExecReload=` unchanged. `check` then validates a command line that
is not the one running:
- With a pinned CA, `--revocations` is mandatory. A `check` without it fails with 78. `systemd`
  stops at the first failing `ExecReload=`, so `kill -HUP` is never sent and **no reload
  happens**. That includes the revocation the operator just wrote into `revoked.toml` or
  `policy.toml`. This hits every deployment that follows §10, which are exactly the ones that
  revoke certificates.
- Before Phase 3 the same `systemctl reload` worked. This is a regression of the security
  function that R-3 meant to make *more* visible.
- The reverse also happens. An agent drop-in with `--relay-suite` or `--previous-key` makes
  `check` pass on a command line that differs from `run`.

**Evidence (reproduced):** `adv10-tests/a10-1_execreload_check.sh`. A relay runs with
`--revocations` and a policy that has `[[authorities]]`. The unit's `ExecReload` check line
prints `policy.toml: [[authorities]] require a revocation list (--revocations, may be empty)`
and exits **78**. A plain `kill -HUP` with the same files gives `policy_reloaded`.
`the_units_carry_the_lifecycle_directives` checks only that `ExecReload=` contains `check`. It
does not check that both lines take the same arguments.

**Required fix:** one source of truth for the arguments. Either:
- `check` reads them from the running process (for example `check --pid $MAINPID`, which
  reads `/proc/$MAINPID/cmdline` under the same sandbox); or
- both units use `Environment=TCN_RELAY_ARGS=…` / `EnvironmentFile=` with
  `ExecStart=… run $TCN_RELAY_ARGS` and `ExecReload=… check $TCN_RELAY_ARGS`, and
  OPERATIONS §8 and §10.2 change the variable, not `ExecStart=`.

Add a unit test that both lines expand to the same arguments. Add an ops test: a drop-in with
`--revocations`, then `systemctl reload` succeeds. Until this is fixed, OPERATIONS §10.2 must
say to override `ExecReload=` too.

**Outcome: fixed** (table above, the design paragraph).

### A10-2 (medium): `check` and the reload read different things; digests do not identify the configuration in force

**Surface:** `bins/zt-relay/src/main.rs:155` (design: "a wrong key file does not block an
urgent revocation"), `:211-225` (`check`), `:71-75` (`digested` includes `--config`);
`crates/zt-net/src/lifecycle.rs:241-256` (`digests` re-reads the files);
`crates/zt-net/src/reload.rs:73-80`.

**Hypothesis:**
1. The relay's `check` fails on `relay.toml`, which `SIGHUP` never reads (OPERATIONS §4.1),
   and on the key files (`load_keyring` from disk). The running relay reloads keys and policy in
   **separate** tasks precisely so that a bad key file does not block an urgent revocation.
   `check` turns either problem into a blocked `systemctl reload`. The agent is the same: its
   `check` loads `--key` and validates `--relay`/`--relay-key`, none of which `SIGHUP` reloads.
2. `policy_reloaded` and `configuration_loaded` carry `files=` digests computed by **reading the
   files again** after `load()`, not from the bytes parsed. They include `relay.toml`, whose
   content is never reloaded. An edited `relay.toml` plus a `SIGHUP` logs the new digest while
   the old suites stay in force. A file that changes between `load()` and `digests()` is logged
   with content that was never loaded.
3. `ExecReload=check; kill -HUP` is asynchronous. A file that changes between `check` and the
   reload, or a reload-only check (the relay validates the CA against the keys **in force**,
   `check` against the keys on disk), gives a successful `systemctl reload` followed by
   `policy_reload_failed`. Catalogue R3-C7 ("reload exits non-zero") and R3-C8 ("impossible
   by construction: same function") do not hold: `check` is a separate function, and the
   promised property test `check_and_run_accept_the_same_files` does not exist.

**Evidence (reproduced):** `a10-1_execreload_check.sh`:
- (2a) An invalid `relay.toml` makes `check` exit 78 with the full arguments, while the
  running relay is unaffected.
- (2b) A valid edit of `relay.toml` adds the hybrid suite for agents. After `SIGHUP`,
  `policy_reloaded files=… relay.toml=sha256:ee559c4d…` equals the on-disk digest, while
  `handshake_suites_in_use` still says `agent_suites = Noise_IK_25519…`.

**Required fix:**
- `check` validates exactly the files that `SIGHUP` reloads, through the same closures. Keys
  and `relay.toml` produce warnings at most, never exit 78 from a reload.
- Compute digests from the bytes the loader parsed (return them from `load_*`).
- Drop `relay.toml` from the reload `files`, or log it as `startup_only`.
- Document that a successful `systemctl reload` means only "`check` passed". The reload
  outcome is `*_reloaded` or `*_reload_failed`.

**Outcome: fixed** (table above, the design paragraph).

### A10-3 (low): the watchdog reports a stall at every start; small `WatchdogSec` causes a false restart

**Surface:** `crates/zt-net/src/lifecycle.rs:136-165` (`watchdog`),
`zt-application/src/lifecycle.rs` (`ProgressWatchdog::should_kick`),
`crates/zt-net/src/relay.rs:1111-1120` (`STATUS=` from the hub), `systemd.rs:20-26,47-66`.

**Hypothesis / evidence (reproduced, `adv10-tests/a10-wd_notify.py`):**
- `interval` fires immediately. At t≈0 the counter is still 0, so `should_kick(0)` is false
  and `watchdog_stalled` (ERROR, `zt_audit`) is logged **on every start of the relay and of the
  agent** (3/3 runs each). The first `WATCHDOG=1` comes only at `WatchdogSec/3` (20.01 s).
  Operators will learn to ignore the one alarm that predicts a watchdog restart.
- There is no lower bound on `WATCHDOG_USEC`. With `WatchdogSec=1s` the check period is 333 ms
  but progress moves once per second at idle: kicks at 0.34, 1.01, 2.34, … (a gap of 1.33 s
  > 1 s), so systemd would kill a healthy relay. A `watchdog_stalled`/`resumed` pair is logged
  every second.
- `STATUS=` (every 10 ticks) and `STOPPING=1` call a **blocking** `UnixDatagram::send_to`
  from the hub task. If PID 1 stops draining its notify queue, the hub blocks. The
  `notify` doc says errors are logged at debug level; the code logs `warn!` (every 10 s when
  the socket is gone).
- Scope (info): the relay's progress covers only the hub, not the accept loop or admission.
  The agent's is a 1 s runtime heartbeat that keeps kicking when every relay loop is dead.
  OPERATIONS says this; R3-C6 `watchdog_reflects_internal_liveness_only` has no test on the
  real hub.

**Required fix:**
- Treat the first observation as a baseline, or start the watchdog after the hub's first tick.
  Report a stall only after one full missed period.
- Refuse, or raise to at least 3 s, a `WatchdogSec` below 3 × the hub tick (log it).
- Send notifications from a non-blocking socket, or outside the hub, through a channel.
- Fix the `notify` doc or the log level.

**Outcome: fixed** (table above).

### A10-4 (low): reconnect herd math holds only for a relay that is back instantly

**Surface:** `zt-application/src/reconnect.rs:96-125`, `zt-net/src/agent.rs:318`,
`tests/sim.rs:158-231` (R2-L1).

**Hypothesis:** after a session that lived, the first retry is `U(0, spread)`. If the relay is
still down (drain, then restart, `RestartSec=2s`, crash, slow start), every agent whose draw
fell inside the downtime fails and drops to `U(0, 1 s)`, `U(0, 2 s)`, …. Those agents pile up
just after the relay returns. R2-L1 uses `sim.bounce` (zero downtime) and a 3× tolerance
(12/s for 40 agents with an ideal of 4/s), so it can't see this.

**Evidence (Monte Carlo of the exact policy, `adv10-tests/a10_herd.py`, N=2000, ideal
200/s):**

| relay down | 0 s | 2 s | 3 s | 5 s | 8 s | 10 s | 15 s | 30 s |
| :- | -: | -: | -: | -: | -: | -: | -: | -: |
| peak per second | 228 (1.1×) | 466 (2.3×) | 521 (2.6×) | 667 (3.3×) | 732 (3.7×) | 624 (3.1×) | 304 (1.5×) | 129 |

In addition, `getrandom::u64().unwrap_or(0)` gives **zero** delay on every attempt if the RNG
fails: a hot reconnect loop. It should fail towards the ceiling.

**Required fix:**
- After a lived session, keep `spread` as the floor of the jitter ceiling for the following
  failures, for example `max(spread, base·2ⁿ⁻¹)` until the next success. Another option is
  decorrelated jitter.
- `unwrap_or(u64::MAX)`.
- Add a simulator row with 2–10 s of downtime (`crash`, step, `bounce`) and a 2× tolerance.

**Outcome: fixed** (table above).

### A10-5 (low): the relay drain accepts new sessions on existing connections; the agent drain ignores streams in mid-handshake

**Surface:** `zt-application/src/relay.rs` (no draining state; `client_stream_count` counts
every route), `zt-net/src/relay.rs:1107-1150` (hub drain), `zt-net/src/agent.rs:248-276,
455-464, 747`.

**Hypothesis / evidence (reproduced, `adv10-tests/tests/adv10_drain.rs`, real TCP):**
- An authorized client is established before `SIGTERM`. After the drain starts, the listener
  is closed (control), but `Open` on the existing connection is still routed and acknowledged:
  **16 new streams acked** during an 8 s drain. Opening one every 500 ms holds the drain until
  its **deadline (8.36 s)**, instead of ending when the pre-drain session ends.
- Connections that were accepted but not yet confirmed when the drain started also complete
  and join.
- PROTOCOL §8.5 and OPERATIONS §14 promise "open sessions continue". The agent rejects new
  ones with `NodeOffline`; the relay does not.
- On the agent, `active()` counts only semaphore permits, which are taken **after** end-to-end
  authorization (`agent.rs:747`). Streams that were acknowledged just before the drain are
  neither counted nor rejected: the drain can end at once and abort them, or they become new
  sessions during the drain.

The impact is bounded by `--drain-timeout`, and attacker model (c) is needed.

**Required fix:**
- Give `RelayCore` an `Input::DrainStarted`: a new `Open` gets `Reject NodeOffline` (or a new
  `Draining` reason). Test it on the core and on the wire (flip this reproducer).
- In the agent, count streams that are acknowledged but not yet authorized, and reject their
  permit after the drain starts.

**Outcome: fixed** (table above).

### A10-6 (low): simulator and catalogue tests that do not prove their claim

**Surface:** `crates/zt-net/tests/sim.rs:233-343`, `tests/liveness.rs:142-160`, resilience.md
§7 catalogue.

**Evidence (reproduced, `adv10-tests/tests/adv10_sim.rs`):**
- `half_open_agent_link_is_detected` claims "the agent declares the link dead after three
  unanswered keepalives". The same scenario with the agent's keepalive at the pre-R-2 **30 s**
  (dead after 90 s) **passes all its assertions**. The relay's 35 s idle and a later ping that
  meets the reset socket do the work: the agent re-registered at 68.18 s, 26 s after the repair.
- Its final `assert!(agent_arrivals >= 2)` counts **every** accepted connection, Alice's
  included (5.02 s and 42.39 s), so it holds even if the agent never returned.
- The agent-side detection does work: with relay idle at 3600 s the agent re-registered 0.7 s
  after the repair (control test). No committed test shows it.
- turmoil has no `TCP_USER_TIMEOUT`. `dialed_sockets_have_user_timeout_and_keepalive` checks the
  accepted side by calling `configure()` by hand, not through `Acceptor::accept`.
- Catalogue rows with no test of that name or an equivalent:
  - R2-L8 `nat_rebinding_heals_via_registration_takeover`;
  - R2-L9 `a_stalled_relay_does_not_block_the_others`;
  - R3-C8 `check_and_run_accept_the_same_files`;
  - R3-C9 `config_hashes_reveal_no_entries`;
  - R3-C11 `clock_before_release_fails_closed`;
  - AP-4 `tick_is_not_starved_by_a_saturated_event_queue` (the ordering fix is there, but no
    test saturates the real hub).
- `an_early_sigterm_is_clean` accepts death by signal 15.

**Required fix:**
- Commit the control above (relay idle ≫ 30 s, assert the agent's own reconnect within
  30–45 s).
- Count only the agent host's arrivals.
- Add the missing rows, or mark them as decided in resilience.md.

**Outcome: fixed; R2-L8, R2-L9, R3-C9 decided; AP-4 saturation and early `SIGTERM` accepted** (table above).

### A10-7 (low): R3-C11 "clock before release fails closed" is implemented as a log line

**Surface:** `crates/zt-net/src/lifecycle.rs:209-225`, resilience.md R3-C11 ("ERROR at start;
no certificate valid"), OPERATIONS §6 `clock_unsynchronised`.

**Hypothesis:** with the wall clock before the build date, the services log once and go on
evaluating certificates against that clock. A certificate issued and **expired before the
build** (and therefore not on the denylist, because expiry was relied on) becomes valid again.
Attacker models (b)+(c): spoofed NTP at boot, or a dead RTC with time-sync not waited for.
`After=time-sync.target` does not wait for synchronization unless
`systemd-time-wait-sync.service` is enabled.

**Required fix:** while `now < clock_floor()`, refuse certificate credentials (key-pinned
clients still work, so the host stays reachable). Re-check on every `clock_jumped`. Or record
the decision in resilience.md and drop the catalogue promise.

**Outcome: fixed** (table above).

### A10-8 (low): exit 78 for transient load failures disables the restart

**Surface:** `bins/zt-agent/src/main.rs:253-298,338`, `bins/zt-relay/src/main.rs:230,259,275`.

**Hypothesis:** every error from `load_keyring`, `load_*` and `relay_endpoints` maps to
`EX_CONFIG`, including `ENOENT`/`EIO`/`EACCES` when a file is not there **yet** (first-boot
provisioning by cloud-init or Ansible after the enabled unit starts, or a late mount). With
`RestartPreventExitStatus=78` the unit stays dead until an operator acts. Before R-3,
`Restart=always` healed this, and the unit says "Restarts are never given up on".

**Required fix:** use 78 only for parse and validation errors. Missing or unreadable files exit 1
(restarted with the backoff), or use `ConditionPathExists=` in the unit. Document which.

**Outcome: fixed** (table above).

### A10-9 (low): failover goes to the weakest outer pin

**Surface:** `crates/zt-net/src/client.rs:79-96,170-186`, PROTOCOL §7.5.2 (line 282: "failover
never lowers a pin"), OPERATIONS §13 step 4 (line 850).

**Hypothesis:** during the rollout of §13, pins are mixed by design (hybrid only towards
upgraded relays). An active on-path attacker resets the TCP connection to each hybrid-pinned
relay (`Io` and `Timeout` allow the next relay), and the client completes on a classical-pinned
relay. The recorded hop then carries the client's certificate in later transport frames and
the routing metadata, which is what §13 is meant to protect. This is not a pin downgrade per
relay, but it is a suite downgrade per session, and the client logs nothing about it.

**Required fix:**
- Document it in §7.5.2 and §13.
- Have the client log (or print) the suite of the hop it used.
- Offer `require_outer_suite` (or refuse a mixed-pin `client.toml` once rollout is done) so
  that failover never lands on a weaker suite.

**Outcome: fixed** (table above).

### A10-10 (info)

- **Generations:** one relay `SIGHUP` takes **two** generations (`policy_reloaded` and
  `relay_keys_reloaded`), in nondeterministic order (observed 2,3 then 4,5 with the order
  swapped). The key line has `files=""`. OPERATIONS says "one more per successful reload".
  The test accepts `>= 2`.
- **`relay_registered`** (`agent.rs:356-365`) is logged after `Register` is *sent*. A relay
  that then refuses (admission, wrong node) has still produced the line. Message 2 does prove
  that the relay accepted the suite for the role, so §13 step 3 holds. Rename it or document
  this.
- **Idle bounds:** `MIN_RELAY_IDLE_SECS = 15` contradicts its own comment ("above … 3 × 10 s
  plus one keepalive") and OPERATIONS §4.1 ("need at least 30 s").
- **`panic = "abort"`** (`Cargo.toml:110`): `Supervisor`'s "panicked" branch, the hub
  `JoinError` path and the agent `JoinSet` comment ("if one panicked the others would keep
  going") exist only in debug builds. The tests exercise behaviour that release builds do not
  have. That is harmless, but it is worth saying.
- **Agent startup:** `Terminate::listen` comes after `prepare()` has read the files (the doc
  says "before the files are read").
- **Shutdown:** `outer_suites_confirmed` of the last interval is lost at shutdown.
- **Hub tick:** the tick `Interval` keeps `MissedTickBehavior::Burst`.
- **Fuzz header:** `noise_responder`'s header still says "the outer channel never accepts a
  hybrid msg1".
- **`TCP_USER_TIMEOUT`:** 20 s on client sockets cuts an interactive SSH session after about
  20–25 s of path loss (Wi-Fi roaming), where the old limit was the 90 s idle. Say so in
  OPERATIONS.
- **`configure()`** runs five `setsockopt` calls on every accepted socket before the
  admission gate (negligible).
- **Clock watch:** a VM suspend and resume is reported as a forward `clock_jumped`.

**Outcome: fixed or recorded item by item** (above).

## Verified correct

- **No outer downgrade.** Each initiator sends exactly one suite (`connect_suite` with the pin).
  The responder's message 2 completes only that `HandshakeState`. The tests
  `a_hybrid_pinned_{client,agent}_never_falls_back` hold. A relay cannot make an agent accept an
  outer suite outside its pin, nor an end-to-end suite outside `--accept-client-suites`
  (0009's `respond_or_identify` is unchanged).
- **Per-role sets.** The relay checks the role's set (`suites.check(role, suite)`) after
  `admit` and **before** message 2; the union is used only to parse message 1. Policy roles
  are mutually exclusive (`ensure_new_peer`).
- **Domain separation.** The prologues `TCN/1 outer`, `TCN/1 end-to-end`, `TCN/2 outer‖01`
  and `TCN/2 end-to-end‖01` are distinct, and the protocol names differ too. Both outer hops
  share one prologue; the role comes from the policy, and a key has one role. The end-to-end
  confirmations do not decode as frames (tested).
- **First-frame cap fix.** Nothing is read between `respond_suites` and `establish`; the
  87-byte cap is set right after message 2 is written. Pre-auth bounds are unchanged.
- **Confirmed counts.** `outer_suites_confirmed` counts only after key confirmation and
  admission, so replays cannot inflate it.
- **No new remotely reachable panic.** The lints deny `unwrap`, indexing and plain arithmetic.
  The new code saturates or checks (`uniform`, `later`, `DrainController::new`, the watchdog
  `max(100ms)`).
- **Keepalive abuse.** Pre-auth peers cannot send `Ping`, and TCP keepalive does not extend any
  application deadline. Relay idle resets only on authentic frames. The agent's `Liveness`
  counts any inbound frame (busy links never die), and R2-L7 is meaningful (idle 600 s).
- **Revocation during the relay drain** is applied (`revocation_still_applies_while_draining`).
  The hub keeps `policy.changed()` first.
- **AP-4.** The tick is ordered before events; progress counts every processed input.
- **AP-17/18.** Exit 78 and `RestartPreventExitStatus=78` (but see A10-1 and A10-8).
  `PR_SET_DUMPABLE` 0 goes through rustix's safe `set_dumpable_behavior`
  (`forbid(unsafe_code)` intact) and is effective: `/proc/<pid>/{mem,environ}` were root-owned
  for a relay running as uid 65534. Both units set `LimitCORE=0`.
- **Flapping detector.** Bounded per node (`threshold × 64`) and keyed by registered nodes
  only; it reports and never blocks.

## Reproducers

The reviewer's reproducers asserted the **attackable** behaviour (they passed at `5de3a84`).
They are now regression tests that assert the safe behaviour:

| Reproducer | Finding | Now |
| :- | :- | :- |
| `a10-1_execreload_check.sh` | A10-1, A10-2 | `bins/zt-relay/tests/lifecycle.rs` (`reload_works_with_arguments_only_execstart_has`, `a_reload_is_not_blocked_by_files_it_does_not_apply`, `check_and_run_accept_the_same_files`), `bins/zt-agent/tests/lifecycle.rs` |
| `a10-wd_notify.py` | A10-3 | `reloads_are_announced_and_the_watchdog_does_not_stall_at_start`, `a_too_short_watchdog_is_a_configuration_error` (a fake `NOTIFY_SOCKET` in the test) |
| `a10_herd.py` | A10-4 | `crates/zt-application/tests/adversary_0010.rs` (the same Monte Carlo, in Rust, deterministic) |
| `tests/adv10_drain.rs` | A10-5 | `crates/zt-net/tests/adversary_0010.rs` |
| `tests/adv10_sim.rs` | A10-6 | `crates/zt-net/tests/sim.rs` |
