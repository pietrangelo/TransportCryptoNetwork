# Adversary review 0014: Phase 7, PQ-SUNSET (the pq-only profile) and the final cross-phase pass

- **Scope:** `git diff de47ea9..f3d90a5` on `claude/project-thread-qi9qrv`. This covers:
  - the `pq_only` profile of the relay (`[handshake] pq_only` in `relay.toml`), the agent
    (`--pq-only`, `TCN_PQ_ONLY`) and the client (`pq_only` in `client.toml`);
  - the `check` report of the classical paths still accepted (`crates/zt-net/src/sunset.rs`);
  - OPERATIONS §19 (end state, runbook, rollback).

  A short pass over the whole roadmap followed (`git diff dfb3b8b..f3d90a5 --stat`,
  docs/pq-resilience-plan.md).
- **Requirements checked against:** pq-resilience-plan §4 row 7 and analysis/pq.md PQ-5.
- **Reviewer:** independent adversary (step 5 of METHODOLOGY). I did not write this code.
- **Note:** CLAUDE.md says the project's own instructions are encrypted and decrypted by a
  SessionStart hook. They were not visible in the reviewer's context, nor in the context of the
  fixes. This review and its outcome rely only on `docs/`, `CONTRIBUTING.md` and the code.

## Verdict

**No high-severity finding.** The **wire** is sound. I found no channel on which a correctly
configured pq-only fleet still accepts a classical suite, a v1 identity or a v1 certificate.
The profile is a load-time guard over the Phase 5/6 machinery, and that machinery holds:

- the agent's end-to-end set and its relay pins (`check_agent_suites`, after the merge of
  `TCN_ACCEPT_CLIENT_SUITES` and the CLI: CLI precedence cannot bypass it);
- both relay sets, which must be written out explicitly (a missing set is refused);
- `IKhfs` (classical authentication), refused everywhere because it does not need a hybrid
  identity;
- previous keys in the keyring. Every key file derives the static ML-KEM key, so a rotation
  stays hybrid;
- `[[agents]] public_keys` during a rotation: `require_hybrid_identity` checks every key;
- `[[authorities]]` v1 keys, also inside a `public_keys` rotation pair;
- a composite pin never verifies a v1 certificate (AP-13), and a hybrid-bound v2 certificate is
  `key_mismatch` over any non-hybrid handshake (`zt-crypto/src/cert.rs:231-237`), even after
  rollback step 4;
- the denylist, whose v1 forms reduce to the X25519 fingerprint and keep revoking v2 peers;
- the reload paths: the agent's single `load` closure, and the relay's `Reloader.pq_only`;
- client failover: every relay must be pinned to the hybrid IK suite, so failover cannot land on
  a weaker hop;
- an unknown key in any section (`deny_unknown_fields`) fails closed.

There is **no date logic**: the sunset is event-driven, so I found no clock-skew or date-format
surface. The defaults stay classical (`the_defaults_stay_compatible_with_a_mixed_fleet`).

The findings concern **the signal the sunset is decided on**, the **operability of the agent
setting**, and **test strength**: two medium, three low, one informational.

### Checks run

| Check | Result |
| :- | :- |
| `cargo test --workspace --all-features` on f3d90a5 | green (exit 0, no failure) |
| Mutations (each reverted, tree restored) | 4 run; 1 survives the whole suite (M1), 2 survive every network test (M2, M3). Table under A14-5 |
| Reproducers | `scratchpad/adv14-tests/`: `adv14_audit.rs` (red on f3d90a5), `adv14_relay_reload.rs` (green, red under M1), `adv14_agent_env.sh` (exit 2 for `1`, `yes`, `on`, `True` and the empty value) |

### Cross-phase pass (dfb3b8b..f3d90a5)

Coverage: 14 phases and fixes, about 248 files, +110 006/−1 206 lines. I found no integration
gap beyond A14-1.

- **R-1 admission vs hybrid IK message 1.** The hybrid message 1 is capped by the codec at
  `max_msg1_len()` (≤ `MAX_PAYLOAD_LEN`, compile-time asserted in suite.rs:180-195). Its cost
  was budgeted in 0012 (A12-6, ≤ 2.5×). Under pq-only one suite is accepted, so an invalid
  message 1 costs one trial per key: the profile lowers the cost.
- **R-6 byte budgets and windows.** The largest end-to-end message 1 (about 11.2 KB with a v2
  certificate) is one `Data` frame, far below `INITIAL_WINDOW` (256 KiB) and the 128 MiB
  minimum queue budget, so no handshake is cut or stalled by flow control.
- **Metrics.** The Prometheus labels iterate `HandshakeSuite::ALL` (metrics.rs:222), so all
  three suites are labelled. The **audit** line is not (A14-1).
- **Failover.** `require_outer_suite` and `pq_only` compose: the profile forces every relay pin
  to the hybrid IK suite, so `require_outer_suite` is redundant but consistent. A mismatching
  value is a load error, so failover cannot reach a weaker hop.
- **Rotation.** Keyring previous keys are hybrid. Agent rotation pairs must both be v2 under
  `require_hybrid_identity`, and a CA rotation pair with a v1 half is refused by the profile.
- **Docs.** The plan's status and table match the code. The OPERATIONS §16 and §19 orders are
  coherent. Forward order: agents, relays, then clients (optional). The hop sets were already
  hybrid-only since §16 Phase 6, so no step cuts a peer off, unless A14-1 misled the operator.
  Rollback: §19.3 has no unauthenticated-downgrade window, because `require_hybrid_identity`
  stays until the last step and hybrid-bound certificates are `key_mismatch` over classical
  handshakes regardless.

## Outcome

Every finding is fixed in the PR that carries this review. Commits: RED `a73fd21`, GREEN
`75611e2`, REFACTOR `5c1aa39`; the documentation and this record follow in one commit.

The full suite (`cargo test --workspace --all-features`) has 874 passing tests and 17 ignored
(OpenSSH, Ansible, timing baselines and the long soak). The 10 `e2e-openssh` tests pass. These
checks are clean:

- `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
- `cargo fmt --check`;
- `cargo deny check` (root, `fuzz/` and `vendor/upstream-snow-advisories`);
- `check-vendored-snow.sh` (snow is not modified).

Mutations after the fix (each file restored from a copy, tree clean at the end):

| Mutant | Killed by |
| :- | :- |
| M1: the relay's reload loads the policy with `pq_only = false` | `a_pq_only_relay_rejects_a_reload_that_readmits_v1_identities` (zt-relay `lifecycle`, the reproducer) |
| M2: `sunset::check_trust` always `Ok` | the 2 unit tests, and now `the_profile_refuses_every_file_that_keeps_a_classical_path` (through the loading code) |
| M3: `classical_suites` keeps only `NoiseIk25519` (forgets `IKhfs`) | the 2 unit tests, and now `the_profile_refuses_every_file_that_keeps_a_classical_path` |
| M5 (new): `load_relay_policy_checked` skips `check_policy` | `a_reload_that_readmits_v1_identities_is_refused_under_the_profile` (on the wire) and `the_profile_refuses_every_file_that_keeps_a_classical_path` |

**The design of A14-1.** `outer_suites_confirmed` has one field per role and suite, named after
the suite and absent when zero:

| Field | Suite |
| :- | :- |
| `agents_ik`, `clients_ik` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` (classical) |
| `agents_ikhfs`, `clients_ikhfs` | `Noise_IKhfs_25519+MLKEM768_…` (hybrid key exchange, classical authentication) |
| `agents_hybrid_ik`, `clients_hybrid_ik` | `Noise_IKhfs+psk0+psk2_25519+MLKEM768_…` (hybrid IK) |

The old `*_classical` and `*_hybrid` fields are **removed**, not kept as aliases. `*_hybrid`
counted `IKhfs`, so keeping that name with any meaning would keep the trap. A saved search on
the old names now finds nothing, which is visible, instead of a wrong count. A compile-time
assertion ties the field list to `HandshakeSuite::ALL`, so a fourth suite cannot be added without
its field. PROTOCOL §7.5.2, the OPERATIONS §6 event table, §13 steps 4–5, §16 Phase 4 and the
§19.2 prerequisites use the new names. The prerequisite now asks for only `*_hybrid_ik` counts,
and for `suite=` the hybrid IK name in `relay_registered` and `e2e_session_started`; the old
instruction pointed at a `suite` field the event never had.

**The design of A14-2.** The agent setting stays a command-line flag, now with an optional
value; there is no agent configuration file:

- `--pq-only` alone turns the profile on. `--pq-only=BOOL` and `TCN_PQ_ONLY` take `true`/`false`,
  `1`/`0`, `yes`/`no`, `on`/`off` in any case. The flag wins over the variable.
- Clap no longer parses the value. `sunset::parse_pq_only` does, and any other value (the empty
  one included) is a `pq_only:` configuration error naming `--pq-only (TCN_PQ_ONLY)`, exit 78.
  The unit does not restart on 78, so a typo stops one agent with a clear message instead of a
  restart loop. The value is never guessed: an empty `TCN_PQ_ONLY=` is not "off".
- OPERATIONS §19.1 puts `--pq-only` in a drop-in for `ExecStart=`, not in `agent.env`. An agent
  older than Phase 7 refuses the unknown flag and does not start, while it silently ignores the
  variable.
- `check` sees only its command line and the process environment. §19.2 therefore gives the
  exact command that runs `check` with `agent.env` and the unit's arguments, and requires it to
  print `pq-only profile in force` (an older release never prints it).
- The prerequisites require the Phase 7 release on every relay and agent.

Detection of an older agent. Nothing on the wire tells the relay which release an agent runs,
and adding a version or profile field to `Register` would be a protocol change for a
configuration phase. The signals are therefore these:

- the older agent refuses the flag and stops registering, so its node goes offline;
- it never writes `pq_only_profile` (A14-4) or prints `pq-only profile in force`;
- if it was left with classical pins, the relay's audit line shows it under its own name
  (`agents_ik`, `agents_ikhfs`, A14-1), and a pq-only relay refuses it
  (`a_pq_only_relay_refuses_agents_outside_the_profile`).

A configuration file for the agent was considered and not added. It would be a fourth file for
one boolean, it would be just as invisible to a shell `check` without its option, and the flag
already gives the fail-closed behaviour of an unknown key.

**The design of A14-3.** The relay's and the agent's loaders move into zt-net:

- `config::load_relay_policy_checked` is the policy, the denylist, the CA-is-not-a-relay-key
  check and, under the profile, `check_policy`;
- `config::load_agent_clients_checked` is the same for the agent's `clients.toml`.

`zt-relay` uses one function for startup, `check` and every reload. Its `Reloader` keeps the
`relay.toml` read at startup and loads every reloaded policy against its `pq_only`. The tests
use the same functions.

**The design of A14-4.** The relay and the agent write two audit lines, at startup and after
every applied reload:

- `pq_only_profile` with `role`, `pq_only` and `classical_paths` (a count);
- one `classical_paths_accepted` line per path, with `role` and `path`, the text of `check`'s
  `classical still accepted:` lines. Under the profile there are none.

Both lines are INFO, not the WARN the review proposed. The classical defaults are the supported
state of every installation that has not chosen the sunset, and a WARN on every start and
reload of every default relay and agent would be noise. OPERATIONS §19 tells operators to alert
on `pq_only_profile pq_only=false` from a host that should be in the end state; that is the
case of the review (a unit without `--config`). The optional `tcn_pq_only` gauge was not added:
the audit line carries the same bit, and the textfile already has the generation and reload
counters that say when it changed.

**The design of A14-5.** The fleet tests no longer apply the profile by hand. They write the
operator's files and load them through the zt-net loaders above with the relay's `pq_only` and
the agent's `--pq-only`. Three tests are new:

- `the_profile_refuses_every_file_that_keeps_a_classical_path` writes eight files, each with one
  classical path left next to the end state:
  - `IKhfs` for agents, or the classical suite for clients, in `relay.toml`;
  - v1 clients, or a v1 CA key in a rotation pair, in the relay policy;
  - a v1 CA key, or v1 clients, in `clients.toml`;
  - `IKhfs` end to end, or towards the relay, on the agent.

  The test checks that the profile refuses each one, and that the same files load without the
  profile.
- `a_reload_that_readmits_v1_identities_is_refused_under_the_profile` checks the wire. Under
  the profile, a reload that re-admits a v1 client is refused by both loaders and the client
  stays out. Without the profile, the same reload is applied and the client gets in. The outcome
  on the wire therefore depends on the profile.
- `the_rollback_follows_the_documented_order_without_a_downgrade_window` follows §19.3 step by
  step. After step 2, a client pinned by its v2 key is refused over the classical outer suite
  with `identity_downgrade` (by the relay). After step 3, the same holds end to end (by the
  agent). After step 4, a v1 client gets in, and a hybrid-bound certificate is still refused over
  the classical suite. That certificate's client is not listed, so its `key_mismatch` is counted
  in `preauth_summary` as `unverified_certificate` rather than logged per event. The test
  checks that count.

The end-state network tests are renamed `the_end_state_fleet_…`. The agent test with classical
pins is now `a_pq_only_relay_refuses_agents_outside_the_profile`: the agent is loaded without
the profile, as an older agent would run.

| # | Outcome | Regression |
| :-: | :- | :- |
| A14-1 | **Fixed** (design above). PROTOCOL §7.5.2 and OPERATIONS §6, §13, §16 and §19.2 updated. | `the_sunset_audit_counts_hybrid_ik_handshakes` (the reproducer, with the new names; zt-net `pq_sunset`), `the_relay_reports_confirmed_handshakes_per_role_and_suite` (now asserts `agents_ikhfs`, `clients_ik` and that no old field remains) |
| A14-2 | **Fixed** (design above). OPERATIONS §4, §19.1–19.3 and the agent unit's header. | `the_pq_only_setting_is_parsed_leniently_and_an_invalid_value_is_ex_config` (zt-agent `lifecycle`, the reproducer: every spelling through the variable and the flag, invalid values for `check` and `run`, the flag over the variable) |
| A14-3 | **Fixed.** | `a_pq_only_relay_rejects_a_reload_that_readmits_v1_identities` (zt-relay `lifecycle`, the reproducer; kills M1) |
| A14-4 | **Fixed** (design above). OPERATIONS §6 and §19. | `the_relay_logs_its_profile_and_classical_paths_at_startup_and_on_reload`, `the_agent_logs_its_profile_and_classical_paths_at_startup_and_on_reload`, `a_pq_only_agent_logs_the_profile_and_no_classical_path` |
| A14-5 | **Fixed** (design above). | `the_profile_refuses_every_file_that_keeps_a_classical_path` (kills M2, M3), `a_reload_that_readmits_v1_identities_is_refused_under_the_profile` (kills M5), `the_rollback_follows_the_documented_order_without_a_downgrade_window` |
| A14-6 | **Fixed item by item.** OPERATIONS §19 gives the exit codes per binary: 78 for `zt-relay` and `zt-agent`, 1 for `zt-client`, which has neither `check` nor reload. PROTOCOL §7.5.2 lists the new fields and points at §19. pq.md PQ-5 says that the catalogue reuse was not done as written, and what replaces it. | documentation |

## Findings

| ID | Severity | Surface | Title |
| :- | :- | :- | :- |
| A14-1 | Medium | relay audit `outer_suites_confirmed` (Phase 3 ↔ 5 ↔ 7) | the sunset signal never counts the hybrid IK suite and calls `IKhfs` "hybrid" |
| A14-2 | Medium | agent `TCN_PQ_ONLY` / runbook §19.2 step 2 | env-only setting: ignored by older agents, invisible to a shell `check`, non-`true` values exit 2 (restart loop) |
| A14-3 | Low | relay reload under the profile | the reload enforcement is untested: a mutant that drops it survives the whole suite |
| A14-4 | Low | runtime observability | the running relay or agent never says whether the profile is in force or which classical paths remain |
| A14-5 | Low | tests `pq_sunset.rs` (fleet and rollback) | the network tests do not depend on the profile, and the rollback test skips the documented order |
| A14-6 | Info | docs | §19 "exit 78" also for the client (exits 1); PROTOCOL §7.5.2 audit fields stale; PQ-5 catalogue reuse not done |

---

### A14-1 (medium): `outer_suites_confirmed` omits the hybrid IK suite and mislabels `IKhfs`

**Surface:** the relay's sunset audit (`ConfirmedSuites::flush`), as used by the runbook
prerequisite of OPERATIONS §19.2 and by §16 Phase 4 step 3 and Phase 6.

**Hypothesis:** the audit was written in Phase 3, when only two suites existed. Phase 5 added
`NoiseIkHybrid25519MlKem768`, and Phase 7 makes the audit the go/no-go signal for the sunset. If
the audit was not updated, operators decide the sunset on wrong data.

**Evidence:**

- `crates/zt-net/src/relay.rs:878-890`: `flush` emits only
  `(NoiseIk25519 → *_classical, NoiseIkhfs25519MlKem768 → *_hybrid)`. `note()` (`:864`) counts
  hybrid IK handshakes in the map, but no field ever prints them.
- In the end-state pq-only fleet every confirmed handshake is hybrid IK, so the event is
  emitted with **no count at all**.
- During §16 Phase 4–6, `agents_hybrid` / `clients_hybrid` count `IKhfs`, which is the suite
  with classical **authentication** that the sunset removes. An operator who reads
  "`*_classical` absent, `*_hybrid` > 0" concludes the role is ready. When pq_only is turned on,
  every `IKhfs` peer is locked out.
- §19.2 asks for "no `outer_suites_confirmed` … with another `suite`", but the event has no
  `suite` field, so the instruction cannot be followed.
- The documentation repeats the stale field set: PROTOCOL.md:296-297 and OPERATIONS.md:390.
- The Prometheus counters (`metrics.rs:222`, `SUITES = HandshakeSuite::ALL`) are correct, so
  only the audit log is wrong.
- Reproducer `adv14-tests/adv14_audit.rs` is **red**: after one agent and one client hybrid IK
  handshake were key-confirmed on f3d90a5, the only `outer_suites_confirmed` line carries
  `event_kind` and `message` and no count.

**Required fix:**

- Emit one count per `(role, suite)` for all of `HandshakeSuite::ALL`, either as fields named
  after the suite id (`agents_ik`, `agents_ikhfs`, `agents_hybrid_ik`, …) or as one line per
  suite with a `suite = protocol_name` field.
- Rename or keep the old fields, and document the change.
- Update PROTOCOL §7.5.2, the OPERATIONS event table and the §19.2 prerequisite.
- Add a test asserting the hybrid IK counts, which the existing test
  `the_relay_reports_confirmed_handshakes_per_role_and_suite` does not cover.

### A14-2 (medium): the agent profile is an env-only setting that can be silently absent or crash-loop

**Surface:** `bins/zt-agent/src/main.rs:72-73` (`#[arg(long, env = "TCN_PQ_ONLY")]`), and
OPERATIONS §19.1 and §19.2 step 2 ("Set `TCN_PQ_ONLY=true` in `agent.env`, run
`zt-agent check`").

**Hypothesis:** the profile can be partly applied, so that it enforces nothing without any
error, or a typo can take a node off TCN.

**Evidence:**

1. **Silently ignored.** A pre-Phase-7 `zt-agent` ignores an unknown environment variable. The
   §19.2 prerequisite does not require the Phase 7 release on agents. The relay fails closed on
   `pq_only` in `relay.toml` (`deny_unknown_fields`), and the client does too. Only the agent
   can run with "the profile on" while enforcing nothing. This is the same trap OPERATIONS
   already describes for `TCN_ACCEPT_CLIENT_SUITES`.
2. **`check` vs running.** `agent.env` is read only by systemd (`EnvironmentFile=`,
   packaging/systemd/zt-agent.service:31). A `zt-agent check` typed in a shell after editing
   `agent.env` sees neither `TCN_PQ_ONLY` nor `TCN_ACCEPT_CLIENT_SUITES`. It then validates a
   different configuration and exits 0. Unlike step 3 for relays, step 2 does not ask to see
   `pq-only profile in force`.
3. **Exit 2.** clap's bool parser accepts only `true` or `false`. `TCN_PQ_ONLY=1`, `yes`, `on`,
   `True` or an empty value exits **2** (usage), not 78 (`adv14-tests/adv14_agent_env.sh`).
   With `Restart=always` and `RestartPreventExitStatus=78` the unit crash-loops and the host is
   unreachable through TCN. When the agent is the SSH path, that is a lockout of the node (or of
   the fleet, if pushed by configuration management).

```
TCN_PQ_ONLY='true' -> exit 78 | 'false' -> exit 1 | '1','yes','on','True','' -> exit 2
```

**Required fix:**

- Parse the value leniently with `BoolishValueParser`, or map clap's error on this argument to
  exit 78.
- In §19.2 step 2, require that `check` runs with the unit's environment, for example
  `systemd-run --pipe -p EnvironmentFile=/etc/tcn/agent.env …` or `set -a; . /etc/tcn/agent.env`.
- Require that `check` prints `pq-only profile in force`, which an old binary never prints.
- Add the Phase 7 agent release to the prerequisite, or prefer `--pq-only` in a drop-in, which
  an old binary refuses.

### A14-3 (low): relay reload under the profile is untested

**Surface:** `bins/zt-relay/src/main.rs:284-300,514`: the relay `Reloader` has its own
`pq_only` field. The agent shares its `load` closure between startup and reload, so its reload
is covered; the relay's is a separate path.

**Hypothesis:** a regression that forgets to propagate the flag to the reloader would let a
`SIGHUP` bring v1 identities and v1 CAs back under a "pq-only" relay. No test would notice,
because `check` and startup still pass.

**Evidence:**

- Mutation `pq_only: settings.pq_only` → `pq_only: false` at main.rs:514 **survives** every
  existing `zt-relay` test (`lifecycle` 20/20, `operations` 12/12) and
  `zt-net --test pq_sunset` 12/12. Only the reproducer kills it.
- `grep` finds no reload test under `pq_only` in any `tests/` directory.
- Reproducer `adv14-tests/adv14_relay_reload.rs`: green on f3d90a5 and red under M1.

**Required fix:** add the reproducer, or an equivalent, to `bins/zt-relay/tests/lifecycle.rs`.
It writes a policy without `require_hybrid_identity` (or with a v1 CA), runs `reload`, and
expects exit 78, `pq_only` in the message, and `policy_reload_failed`.

### A14-4 (low): the running process never shows the profile or the classical paths left

**Surface:** `relay.rs:721-727` and `agent.rs:178-192` (`handshake_suites_in_use`), and the
R-5 metrics.

**Hypothesis:** the "sunset warning or audit" of the plan exists only as a hand-run `check`.
Nothing in the journal, the SIEM or the metrics shows whether a running unit enforces the
profile or still accepts classical paths.

**Evidence:**

- `grep pq_only crates/zt-net/src bins/*/src` finds no log or metric.
- `sunset::relay_report` and `sunset::agent_report` are called only from `check`
  (zt-relay main.rs:448, zt-agent main.rs:444).
- A relay whose unit lacks `--config` (the shipped unit has none,
  packaging/systemd/zt-relay.service:32) runs classical, while a hand-run
  `zt-relay check --config …` prints `pq-only profile in force`.

**Required fix:**

- Add `pq_only = true|false` to `handshake_suites_in_use` (relay and agent), and the
  `relay_report` / `agent_report` lines at startup and on each reload, as one WARN audit line
  `classical_paths_accepted` (absent under the profile).
- Optionally add a `tcn_pq_only` gauge to the textfile.

### A14-5 (low): the tests prove less than their names say

**Surface:** `crates/zt-net/tests/pq_sunset.rs:310-517`.

**Evidence:**

- `pq_only_fleet` uses only `settings.suites` from the parsed `relay.toml` and calls the
  `sunset::check_*` functions by hand. The fleet then runs the Phase 5/6 machinery with
  hybrid-only sets. The four network attack tests therefore pass identically with
  `pq_only = false` and the same sets: they show the end state works, not that the profile
  enforces anything.
- The mutations below confirm that the profile's guarantees rest on the parse-level unit tests
  and the two binary tests, which do kill them.
- `the_rollback_is_a_configuration_change` (`:471-517`) jumps directly to an all-v1 fleet
  without `require_hybrid_identity`. It skips the documented §19.3 order (clients → relays →
  agents → only then §16 rollback). In particular it never tests the intermediate state where
  classical suites are back but `require_hybrid_identity` is still set. That state must refuse
  a classical handshake of a hybrid-pinned peer (`identity_downgrade`) and is the "no
  downgrade window" claim.

The analysis holds: `require_bound` (policy.rs:119-137) and `verify_v2` (cert.rs:231-237) give
no window, but nothing tests it as a rollback.

Mutations run (each reverted):

| Mutant | Result |
| :- | :- |
| M1: relay `Reloader { pq_only: false }` | **survives** (only `adv14_relay_reload.rs` kills it) |
| M2: `sunset::check_trust` always `Ok` | killed by 2 unit tests (`…policy_requires…`, `…agent_pins…`); the 4 network tests stay green |
| M3: `classical_suites` filter `== NoiseIk25519` (forgets IKhfs) | killed by 2 unit tests (`…relay_accepts_only…`, `…agent_pins…`); the 4 network tests stay green |
| M4: `check_client` skips the node loop | killed by `a_pq_only_client_pins_only_the_hybrid_ik_suite` |

**Required fix:**

- Add a rollback test for each §19.3 step. After step 2, assert that a classical handshake by a
  hybrid-pinned client is `identity_downgrade`, and that a hybrid-bound certificate is
  `key_mismatch` over the classical suite after step 4.
- Rename the network tests "end-state fleet …" or make them start the relay through the
  binary's loading path.

### A14-6 (info): documentation consistency

- OPERATIONS §19 says the profile refuses "at startup, in `check` and on every reload (exit
  78, `EX_CONFIG`)". `zt-client` has neither `check` nor reload, and exits **1** on a `pq_only`
  refusal (`bins/zt-client/src/main.rs:418,427-430`, `Failure::from(String)`). Say so.
- PROTOCOL.md never mentions the profile. That is acceptable for a config-only phase, but
  §7.5.2's audit field list is stale (A14-1).
- analysis/pq.md PQ-5 asked to reuse the catalogue's Parsing/State rows as negative tests. The
  "As implemented" note does not say this was dropped.
- docs/pq-resilience-plan.md row 7 and the status line match the code ("opt-in", defaults
  unchanged).

## Reproducers

Kept in the reviewer's scratchpad (`adv14-tests/`), not committed as such; each one is now a
regression test in the tree:

| Reproducer | Regression test |
| :- | :- |
| `adv14_audit.rs` | `the_sunset_audit_counts_hybrid_ik_handshakes` (`crates/zt-net/tests/pq_sunset.rs`), with the new field names |
| `adv14_relay_reload.rs` | `a_pq_only_relay_rejects_a_reload_that_readmits_v1_identities` (`bins/zt-relay/tests/lifecycle.rs`) |
| `adv14_agent_env.sh` | `the_pq_only_setting_is_parsed_leniently_and_an_invalid_value_is_ex_config` (`bins/zt-agent/tests/lifecycle.rs`) |
