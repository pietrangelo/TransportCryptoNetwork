# Adversary review 0009: Phase 2 (PQ-1, hybrid end-to-end suite)

**Surface:** `git diff dc979e5..d2db0c2` on `claude/project-thread-qi9qrv` (5 commits):
- `vendor/snow` (snow 0.10.0, imported unmodified in `f67c431`, then patched in `7090452`) and
  `vendor/snow/PATCHES.md`;
- `zt-crypto`: `resolver.rs` (ML-KEM-768 from libcrux in snow's shape), `noise.rs` (prologues
  per channel and suite, `Builder::with_resolver`), `kem.rs` (decapsulation key wiped in place);
- `zt-domain/src/suite.rs` (`HandshakeChannel`, `is_supported(channel)`, `confirmation()`,
  `AcceptedSuites::supported/without`);
- `zt-net`: `agent.rs` (`read_msg1`, the unaccepted-suite fallback `respond`, the per-suite
  check before message 2, `handshake_suites_in_use`, `suite` in `e2e_session_started`),
  `client.rs` (per-node pin, suite confirmation), `config.rs` (per-channel validation);
- `zt-agent` (`--accept-client-suites` / `TCN_ACCEPT_CLIENT_SUITES`), the systemd unit;
- fuzz targets `noise_responder` (hybrid mode) and `noise_initiator` (new), CI matrix;
- PROTOCOL §7.3, §7.5, §7.5.1, §15.3; OPERATIONS §4, §6, §9, §11, §12; `docs/pq-snow.md`.

It was checked against `docs/pq-resilience-plan.md`, `docs/analysis/pq.md` (§7, PQ-1 attack
catalogue), `docs/pq-snow.md`, review 0007 (AP-7, AP-11, AP-14, AP-23) and review 0008 (A8-2,
A8-11, A8-12).

**Reviewer:** an independent adversary agent. It did not write the code. The encrypted project
instructions were **not** visible to it.

**Method:**
- The full suite was run at `d2db0c2`: `cargo test --workspace --all-features --no-fail-fast`
  passed 516 tests, with 0 failures and 9 ignored (6 need OpenSSH or ansible, 3 are timing
  baselines). `cargo deny check` passed.
- The vendored crate: `snow-0.10.0.crate` was fetched from `static.crates.io`; its SHA-256
  `599b506c…6ad02d82` equals `PATCHES.md` and the local cargo cache. `diff -r` of the tarball
  against `f67c431:vendor/snow` and against `vendor/snow` at `d2db0c2`.
- An **independent transcript implementation** (Noise revision 34 §5 and HFS revision 1 §5,
  written from the specification with RustCrypto BLAKE2s, ChaCha20-Poly1305 and dalek X25519,
  **without snow**) interoperates with TCN in both directions. Its negative controls (no
  `MixKey(ss_kem)`, `MixKey` before `EncryptAndHash(ct)`, `e1` before `es`, a prologue without
  the suite id, the Kyber name) are all refused by TCN.
- Reproducers on the wire used the repository's `zt-net/tests/common` harness (`FakeRelay`, a
  compromised relay talking to a real agent). Every hypothesis marked "reproduced" had a test
  that **asserted the attackable behaviour** and passed at `d2db0c2`. The fix flipped them to
  assert the safe behaviour and committed them before the implementation (RED): they are now
  `crates/zt-net/tests/adversary_0009.rs`, `crates/zt-crypto/tests/adversary_0009.rs` and
  `crates/zt-application/tests/adversary_0009.rs`.
- Fuzzing: `noise_initiator` and `noise_responder` ran 150 s each (28 063 and 52 336
  executions) with no crash.
- The vendored snow's own test suite passed from a scratch copy with
  `--features "hfs pqclean_kyber1024"` (upstream ships **no** HFS vectors).
- `cargo-deny`'s behaviour on path crates was probed with a throw-away workspace.
- The review itself did not modify the repository.

**Attacker models (0007):** (a) a remote host with no credentials; (b) an on-path recorder that
replays; (c) the holder of one valid or stolen identity; (d) one compromised relay (it sits in
the middle of the end-to-end channel); (e) a future quantum computer on recorded traffic
(HNDL); (f) operator error.

**Severity:** the 0001–0008 scale. **High** blocks the merge. **Medium** must be fixed in this
phase. **Low** and **info** may be fixed in the phase that next touches the code.

## Verdict

There is **no high finding**, and **the cryptographic core is correct** (see "Verified
correct"). Two findings are **medium**:
- **A9-1:** the vendored snow is invisible to RustSec, and nothing re-checks that `vendor/snow`
  is upstream plus the listed patches.
- **A9-2:** a compromised relay forges unlimited `handshake_suite_rejected` lines naming a real
  client, and those lines were the rollback signal of OPERATIONS §12.

| # | Sev. | Surface |
| :-: | :-: | :- |
| A9-1 | **medium** | Vendored snow outside RustSec; `vendor/snow` never re-verified; its tests never run in CI |
| A9-2 | **medium** | Agent `handshake_suite_rejected` replayable by the relay, unthrottled, and the §12 rollback signal |
| A9-3 | low | The unaccepted-suite fallback runs on every upgraded agent; an `AuthorizationPending` of an unaccepted suite is one `if` away from `accept()` |
| A9-4 | low | A failed `accept()` (invalid `e1`, RNG failure) closes with no audit line and no log |
| A9-5 | low | A hybrid message 1 with a certificate over 3 128 bytes to a classical-only agent is an anonymous `certificate malformed` |
| A9-6 | low | The client says "client key not authorized" for a suite mismatch |
| A9-7 | low | Catalogue gaps: no dudect test, the KEM parsers on chosen input and the fallback not fuzzed, binary growth not recorded |
| A9-8 | info | Rollback and downgrade notes, inert vendored `.github`, KEM randomness outside the resolver RNG |

## Outcome

Every medium and low finding is fixed or decided in the PR that carries this review; A9-8 is
recorded. The full suite went from 516 to 530 passing tests (9 ignored); `cargo clippy`
(all targets and features), `cargo fmt --check` and `cargo deny check` (workspace and `fuzz/`)
are clean, `zizmor` reports no finding on the workflows, and the new `vendor` workflow's
checks pass locally.

| # | Outcome | Regression |
| :-: | :- | :- |
| A9-1 | **Mitigated.** The patches are a series in `vendor/patches/snow/` (three files, mapped to patches 1–5 in `PATCHES.md`). The new workflow `vendor` runs `.github/scripts/check-vendored-snow.sh --test`: it downloads the release, checks the SHA-256 (pinned in the script, `PATCHES.md` and the advisory lock file), applies the series with no fuzz, fails unless the result plus `PATCHES.md` equals the files git tracks under `vendor/snow` byte for byte, then runs upstream's tests with `hfs pqclean_kyber1024`. `vendor/upstream-advisories` locks `snow =0.10.0` from crates.io and is checked with `cargo deny check advisories` on every PR and **daily**. The script fails if a new directory appears under `vendor/`. `pq-snow.md` §4 and `PATCHES.md` say what `cargo deny` on the workspace does not cover. | CI job `vendor / snow-identity`, `vendor / snow-advisories`; checked locally, including a negative control (one appended line in `vendor/snow/src/lib.rs` fails the check; `snow =0.9.4` in the advisory package fails with RUSTSEC-2024-0011) |
| A9-2 | **Mitigated.** The A8-2 limiter is now a sans-IO value, `zt_application::identity_lines::IdentityLines`, used by the relay's `Admission` and by the agent. The agent writes `authentication_failed` with a peer and `handshake_suite_rejected` in full once per identity and `identity_log_interval` (10 s), across all relays, then one `<event>_repeated{peer, …, count}` line; beyond 256 identities, one `identity_events_suppressed{count}`. `handshake_suite_rejected` (and its `_repeated`) carry `confirmed = false` on the relay and the agent. OPERATIONS §6 and §12: the line is unconfirmed, sunset and rollback decisions rest on `e2e_session_started` and the client inventory, and a repeated identical rejection is a replay signal. PROTOCOL §7.5.1 says so too. | `replayed_suite_rejections_on_the_agent_are_rate_limited_per_identity` (the reviewer's reproducer, flipped), `replayed_authentication_failures_on_the_agent_are_rate_limited_per_identity`, `made_up_keys_cannot_grow_the_agents_line_table`, `suite_rejections_of_one_identity_are_logged_once_then_counted`, `the_agents_identity_table_is_bounded` |
| A9-3 | **Mitigated (by type).** `noise::respond_or_identify` replaces the agent's `respond`: it returns `Responded::Pending(AuthorizationPending)` only for an accepted suite and `Responded::Unaccepted(Identified)` otherwise; `Identified` has `peer`, `suite`, `payload` and no `accept`, so no refactor of the agent can send message 2 for a suite outside the set. The fallback stays for every agent whose set is not both suites (it is what names a client in §12 step 2); PROTOCOL §7.5.1 and `pq-snow.md` §5 now state its cost per key and per suite, for every such agent. | `a_suite_outside_the_accepted_set_is_identified_but_never_pending`, `a_suite_inside_the_accepted_set_is_pending`, `an_invalid_message_1_is_an_error_for_every_set`, `the_outer_channel_has_no_fallback`; fuzz `noise_responder` (fallback mode) |
| A9-4 | **Mitigated.** A failed `accept()` writes `authentication_failed{peer, reason = HandshakeFailed}` (rate-limited, A9-2) and closes with `ProtocolViolation`; if the system RNG also fails, an ERROR line says so. | `an_invalid_e1_from_a_known_client_is_audited` (the reproducer, flipped) |
| A9-5 | **Mitigated.** The agent's bound before Noise is the largest message 1 of any end-to-end suite this build runs (5 624), not of the accepted set; the per-suite bounds apply inside. A hybrid message 1 with a large certificate at a classical-only agent is now `handshake_suite_rejected` with the client's identity. A message 1 valid for no suite and longer than any accepted one is still reported as a malformed certificate. | `a_large_certificate_hybrid_msg1_to_a_classical_agent_is_a_suite_rejection` (with a real 3 600-byte certificate), `a_hybrid_message_1_with_the_largest_certificate_is_identified_by_a_classical_responder`; `an_oversized_message_1_is_refused_before_parsing` updated |
| A9-6 | **Fixed.** With a non-classical pin, `Unauthorized` and `ProtocolViolation` from the agent add "or the agent does not accept the pinned suite `<name>` (OPERATIONS §12)". | `a_refusal_names_the_pinned_hybrid_suite`, `a_classical_refusal_does_not_mention_suites` (zt-client unit tests) |
| A9-7 | **Mitigated, one item decided.** New fuzz target `kem_inputs` (in the CI matrix): the ML-KEM-768 encapsulation and decapsulation on arbitrary and mutated keys and ciphertexts, as an authorized malicious peer hands them after AEAD. `noise_responder` has a fallback mode (classical-only responder, `respond_or_identify`). Both ran 30 s locally with no finding (134 798 and 12 535 executions). The binary-growth row is in `pq-snow.md` §5 (+326 / +321 KiB, gate passed on x86_64 glibc). **Dudect test: not added, decided** in `pq-snow.md` §5 (single-use ephemeral key, decapsulation only after the AEAD tag, no repeated-query oracle). **CPU per replay: accepted**, see below. | fuzz `kem_inputs`, `noise_responder` |
| A9-8 | **Recorded; two notes fixed in docs.** OPERATIONS §12 now says that a pre-PQ-1 `zt-client` refuses a whole configuration with a hybrid pin, and that a pre-PQ-1 agent ignores `TCN_ACCEPT_CLIENT_SUITES`. `resolver.rs` documents that the encapsulation randomness comes from the OS. The inert `vendor/snow/.github` is kept: it is upstream content, and removing it would be one more deviation for the A9-1 check to carry. | none (documentation) |

---

### A9-1 (medium): the vendored snow is outside RustSec, and nothing re-checks that `vendor/snow` is upstream plus the five patches

**Surface:** `Cargo.toml` (`[patch.crates-io] snow = { path = "vendor/snow" }`),
`fuzz/Cargo.toml`, `Cargo.lock` (the `snow` entry has no `source` or `checksum` any more),
`docs/pq-snow.md` §4, `vendor/snow/PATCHES.md`, `.github/workflows/ci.yml`, the root
`exclude = ["fuzz", "vendor"]`.

**Hypothesis:** snow is the TCB of every handshake. As a path crate:
1. `cargo deny check advisories` no longer matches it against RustSec, whose queries are
   scoped to the crates.io source. snow already had RUSTSEC-2024-0011 (unauthenticated nonce
   increment); a future advisory against snow 0.10.0 would pass CI silently.
2. The only guarantee that the unpatched 98 % of `vendor/snow` is upstream was a manual
   `diff -ru`. `Cargo.lock` carries no checksum, so a later commit could change
   `vendor/snow/src/*` without a lock or CI signal.
3. `vendor/` is outside the workspace: snow's own tests, including the `hfs` unit tests of the
   patched paths, never ran in CI.

`docs/pq-snow.md` said "`cargo deny` keeps checking the vendored crate"; true for licences,
false for advisories.

**Evidence (reproduced with a probe):** a path crate named `snow` at the vulnerable 0.9.4 gave
`advisories ok`; the same workspace with the registry crate `snow = "=0.9.4"` gave
`error[vulnerability] RUSTSEC-2024-0011`. At `d2db0c2` the vendored copy was clean; the gap was
that nothing kept it so.

**Outcome: mitigated** (table above). Two choices:
- The series is three files, not five: patches 2, 3 and 4 interleave in the same hunks of
  `handshakestate.rs`, so they share one file; patch 5 is its own file and also carries the
  one-line change to the published `Cargo.lock` (`zeroize` among snow's dependencies), so that
  upstream's tests run with `--locked` against the published lock.
- Advisory coverage uses `cargo deny` on a package that depends on the upstream release
  (`vendor/upstream-advisories`), through the action already pinned in `ci.yml`, rather than a
  script over the advisory database: the same tool, configuration format and matching rules
  as the workspace check. An advisory against the release fails CI; whether it applies to the
  patched copy is decided by hand, as `PATCHES.md` says.

### A9-2 (medium): a compromised relay forges unlimited `handshake_suite_rejected` lines that name a real client, and they are exactly the signal §12 tells operators to act on

**Surface:** `zt-net/src/agent.rs` (suite check after `admit_client`, plain `audit()`), the
`respond` fallback, OPERATIONS §6 and §12, PROTOCOL §7.5.1; review 0008 A8-2 (fixed on the
relay only).

**Hypothesis (d):** IK message 1 is replayable (PROTOCOL §7.3). After PQ-SUNSET, a compromised
relay replays a classical end-to-end message 1 it recorded before. The agent's fallback reads
it as a known client with an unaccepted suite and writes a full WARN
`handshake_suite_rejected{peer = <victim>}` once per replay, without the per-identity limiter
A8-2 added on the relay. Consequences: a log flood with a real victim's name, and an
**operator-mediated downgrade**: §12 said "Classical clients then fail with
`handshake_suite_rejected`" and rollback step 1 is "accept both suites again", so the relay can
manufacture "client X is still classical and is being cut off" for any client it ever recorded,
pushing the operator to re-enable the classical suite. The event cannot be authenticated
(there is no message 2), and nothing said so. The same holds in the other direction.

**Evidence (reproduced):** with an agent accepting only `IKhfs`, 40 replays of one recorded
classical message 1 gave 40 full `handshake_suite_rejected` lines with `peer = alice` and no
`_repeated` line.

**Outcome: mitigated** (table above). The interval is a field of `AgentConfig`
(`identity_log_interval`, at least 1 s, default 10 s like the relay's `summary_interval`); it
is not a CLI flag, since nothing in operation needs another value. Only the identity's *line*
is limited: the stream is closed exactly as before.

### A9-3 (low): the unaccepted-suite fallback runs on every upgraded agent and hands out an `AuthorizationPending` for a suite outside the set

**Surface:** `agent.rs` `respond` and `if !client_suites.contains(suite)`, `noise.rs` `accept`,
PROTOCOL §7.5 and §7.5.1.

**Hypothesis (code):** `AcceptedSuites::supported(EndToEnd).without(accepted)` is non-empty for
every agent that does not accept both suites, including the default classical-only one, so the
HFS read path of the vendored snow runs on remote input on agents whose operator never opted
in (read-only, no KEM operation). An invalid message 1 of a length both suites allow costs up
to four trials during a key rotation on every upgraded agent; PROTOCOL §7.5.1 said "at most one
extra hybrid trial", and only for agents that accept both. Safety rested on one `if` after
`admit_client`: `accept()` on the returned value would run the KEM and send message 2.

**Outcome: mitigated** (table above). The fallback is kept on purpose: it is the only way a
classical-only agent can name a client that pins the hybrid suite during rollout, and with
A9-2 its line is bounded and marked unconfirmed. The extra parsed surface is the HFS read path
that the fuzz targets cover, now including a classical-only responder.

### A9-4 (low): a failed `accept()` is silent

**Surface:** `agent.rs` (`pending.accept()`), `resolver.rs` `encapsulate` (FIPS 203 §7.2
check, `getrandom` failure).

**Hypothesis (c):** message 1 is authenticated by `ss`, so an invalid `e1` comes from the
client's key holder (a buggy or malicious client, or a stolen key). The agent closed with
`ProtocolViolation` and wrote nothing. An RNG failure on the agent, which breaks every hybrid
session, was equally silent.

**Evidence (reproduced):** an authenticated message 1 whose `e1` is 1 184 × `0xff` got
`Close(ProtocolViolation)` and no log line beyond startup.

**Outcome: mitigated** (table above). The two causes cannot be told apart from snow's error, so
the agent probes the RNG once on this (rare) path and logs an ERROR if it fails.

### A9-5 (low): a hybrid message 1 with a large certificate to a classical-only agent is an anonymous `certificate malformed`

**Surface:** `agent.rs` `read_msg1` (`msg1.len() > client_suites.max_msg1_len()` before Noise),
OPERATIONS §12 rollout step 2, PROTOCOL §7.5.1 step 1.

**Hypothesis (f):** the bound was the *accepted* set's maximum, 4 424 bytes for a classical-only
agent. A hybrid message 1 is 1 296 + payload, so any certificate over 3 128 bytes (legitimate up
to 4 328) was refused before Noise as `authentication_failed{cert_check = malformed}` with no
peer, contrary to §12.

**Evidence (reproduced):** a 3 200-byte payload gave one anonymous `certificate malformed` line
and no `handshake_suite_rejected`.

**Outcome: mitigated** (table above), with the first option of the required fix.

### A9-6 (low): the client blames the key for a suite mismatch

**Surface:** `bins/zt-client/src/main.rs` `describe`.

**Hypothesis:** a hybrid-pinned client at an agent that does not accept the hybrid suite (the
normal failure during §12 step 2) printed "client key not authorized there"; at an older agent,
"session closed: ProtocolViolation". Fail-closed is right and the agent must not leak more, but
the client knows its own pin.

**Outcome: fixed** (table above). The agent's answer is unchanged.

### A9-7 (low): attack-catalogue and gate items of pq.md §7 PQ-1 not covered

**Evidence (code and docs):**
- **Side channels:** no dudect-style smoke test for decapsulation. Impact small: the
  initiator's decapsulation key is ephemeral and used once, and `ct` is decapsulated only after
  its AEAD tag verifies.
- **Fuzzing:** both PQ targets mutate bytes under AEAD, so a mutated `e1` or `ct` never reaches
  `encapsulate` or `decapsulate`; the fallback was not fuzzed (`noise_responder` accepted both
  suites).
- **Resources:** each replay of an authorized client's hybrid message 1 costs the agent a
  certificate check, an encapsulation and three DH, bounded only in concurrency
  (`max_streams`).
- **Perf gate "release binary growth ≤ 400 KB per binary"** was not recorded.

**Outcome: mitigated, with two decisions** (table above). The new target feeds the KEM directly
rather than re-encrypting a fuzzed field under a re-implemented Noise: the bytes snow hands the
resolver after decryption are exactly the target's input, so the parsers see the same inputs
without a second Noise implementation in `fuzz/`.

**CPU per replay: accepted.** A replay is possible only through a relay the client used (or a
compromised one), costs the agent about 0.5 ms (pq-snow.md §5, "read message 1 and write
message 2"), reaches sshd never (the confirmation is missing), and is bounded by the per-relay
`max_streams` in flight. A compromised relay can already make the agent do classical
handshakes at the same rate; the hybrid suite adds about +112 µs p99 to each. With A9-2 such a
loop no longer floods the log.

### A9-8 (info): rollback, downgrade and housekeeping notes

- **Client downgrade:** a pre-PQ-1 `zt-client` refuses a configuration that pins the hybrid
  suite on any node, so *all* nodes become unreachable. Now explicit in OPERATIONS §12.
- **Agent downgrade:** a pre-PQ-1 `zt-agent` ignores `TCN_ACCEPT_CLIENT_SUITES` and runs
  classical-only, failing closed for hybrid-pinned clients. Now in rollback step 3.
- `TCN_ACCEPT_CLIENT_SUITES=` (empty, a space or a trailing comma) stops the agent at startup:
  fail-safe, verified.
- `vendor/snow/.github/{workflows/rust.yml,dependabot.yml}` are inert (GitHub reads only the
  root `.github`). Kept as upstream content (see the table).
- `resolver.rs` `encapsulate` draws `m` from `getrandom`, not snow's RNG: documented in the
  code.

## CodeQL: "hard-coded cryptographic value" in `vendor/snow` (false positives)

After the PR was opened, GitHub's CodeQL (default setup) raised three critical alerts, "Hard-coded
cryptographic value", at `vendor/snow/src/symmetricstate.rs:64` and `:93` and
`vendor/snow/src/cipherstate.rs:18`. They are **false positives** in upstream code that the
patches do not touch (the A9-1 check proves it is byte for byte snow 0.10.0):

- `cipherstate.rs:18` is Noise's `InitializeKey(k)`: it sets the key and resets the nonce
  counter `n = 0`. The zero is the specified initial nonce of a fresh key, not a constant key
  or IV.
- `symmetricstate.rs:64` and `:93` are `MixKey` and `MixKeyAndHash`: they call
  `InitializeKey` with the output of HKDF over the chaining key and fresh DH (or KEM) output.
  Every key is new, and each `(key, nonce)` pair is used once (snow refuses a nonce overflow,
  RUSTSEC-2024-0011 fixed in 0.9.5).

Upstream code is not changed for them. A `.github/codeql/codeql-config.yml` with
`paths-ignore: [vendor/**]` would **not** take effect: CodeQL default setup does not read a
configuration file, only an advanced-setup workflow does. No workflow is added in this PR.
**Maintainer action:** dismiss the three alerts as "False positive" with a link to this
section, or switch CodeQL to advanced setup with `paths-ignore: [vendor/**]` (the vendored
crate is then covered by the `vendor` workflow and the patch review instead).

## Verified correct

- **Vendored crate identity.** The tarball's SHA-256 is
  `599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82`; `f67c431:vendor/snow`
  equals it except the published `Cargo.lock`; at `d2db0c2` the diff touches exactly
  `Cargo.toml`, `src/params/mod.rs`, `src/resolvers/default.rs`, `src/handshakestate.rs` and
  `PATCHES.md`. No unlisted change. The vendored test suite passes.
- **Patch correctness.** `kem_sizes` rejects 0 and anything over the buffers before any slice;
  the write-side bounds include `byte_index` and the tag; patch 3 refuses a short `e1` after an
  RNG failure; the three `unwrap()`s are `Error::Kem`; `kem_output_buf` is `Zeroizing` on both
  sides. No new panic path.
- **HFS transcript.** `e1` after the first DH of message 1 (`e, es, e1, s, ss`), `ekem1` after
  `ee` (`e, ee, ekem1, se`), `EncryptAndHash(ct)` then `MixKey(ss_kem)`. The independent
  implementation derives the same transport keys both ways, and every deviation is refused.
- **Hybrid property.** The transport keys depend on es, ss, ee, ss_kem and se: with every X25519
  secret but not ss_kem the confirmation does not decrypt; ss_kem alone gives nothing.
- **Binding and downgrade.** The protocol name (with `MLKEM768`) and the prologue
  `TCN/2 end-to-end ‖ 0x01` are hashed into `h`; a message 1 of one suite is never valid as the
  other; a relay cannot strip or rewrite the suite (nothing on the wire names it); a
  hybrid-pinned client never retries classical; an agent never sends message 2 for a suite
  outside its set (now by type, A9-3).
- **Implicit rejection, no oracle.** A wrong `ct` with a valid tag and a bad tag both end in
  `CryptoError::Handshake`; only a party that already holds the handshake key could observe the
  timing difference, and the decapsulation key is used once.
- **Sizes before allocation**, **zeroization** (KEM seed, decapsulation key, encapsulation
  randomness, shared secrets, snow's KEM output buffer; residuals as PROTOCOL §7.5.1 lists),
  **no panics** found by reading or fuzzing, **licensing** (Apache-2.0 OR MIT, notices kept,
  modified files marked), **AP-7 / AP-23** and the **§12 order** (subject to A9-2, A9-5, A9-8).

## Note: binary growth (A9-7, perf gate)

Release builds (`cargo build --release --locked -p zt-agent -p zt-client`,
`x86_64-unknown-linux-gnu`, fat LTO, stripped) of `git archive dc979e5` and `git archive
d2db0c2`:

| Binary | `dc979e5` | `d2db0c2` | Growth |
| :- | -: | -: | -: |
| `zt-agent` | 2 362 104 B | 2 695 552 B | +333 448 B (326 KiB) |
| `zt-client` | 1 957 616 B | 2 285 984 B | +328 368 B (321 KiB) |

Both are within the ≤ 400 KB gate on this target; musl and aarch64 were not measured. The row is
now in `docs/pq-snow.md` §5.
