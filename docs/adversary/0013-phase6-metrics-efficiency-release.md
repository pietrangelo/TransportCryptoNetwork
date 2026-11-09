# Adversary review 0013: Phase 6 (R-5 metrics, R-6 budgets and soak, PQ-REL release signatures)

- **Scope:** `git diff 8b2a005..df5e2f0` on `claude/project-thread-qi9qrv` (48 files, +6 305/−65).
  This covers:
  - R-5: the Prometheus textfile writer (`crates/zt-net/src/metrics.rs`) for the relay, the agent and
    the client, and the `status` subcommand;
  - R-6: the global byte budgets (`budget.rs`), shedding (`relay.rs`), window auto-tuning
    (`efficiency.rs`, `stream.rs`), fewer copies per frame (`channel.rs`, `noise.rs`), and the
    nightly soak (`soak.yml`, `tests/soak*.rs`);
  - PQ-REL: `packaging/release/tcn-release.sh` and its tests, `release-publish.yml`, `release.yml`,
    `build-openssl.sh`, and the verification steps in SECURITY.md, OPERATIONS §9/§17/§18 and
    REPOSITORY_SECURITY.
- **Requirements checked against:**
  - pq-resilience-plan;
  - resilience.md §5.5–5.7 and the R-5/R-6 catalogue;
  - pq.md (PQ-4 release signing);
  - review 0007 AP-19, AP-21, AP-22 and D-13;
  - reviews 0008–0012.
- **Reviewer:** independent adversary (step 5 of METHODOLOGY). I did not write this code.
- **Note:** CLAUDE.md says the project's own instructions are encrypted and that a SessionStart
  hook decrypts them. They were **not** visible in this reviewer's context. This review relies
  only on `docs/`.

## Verdict

**No high-severity finding.** The requirements set by review 0007 are met as written:

| Requirement | Status |
| :- | :- |
| AP-21: no new listening socket; a textfile for both services | Met. No listener or `bind` was added; the only new dependency is `proptest`, as a dev-dependency |
| AP-22 / D-13: the byte budget ships with auto-tuning | Met. The budget is in the same change |
| AP-19: the private key never reaches CI | Met. No secret appears in any workflow |
| AP-19: two standard detached signatures, both required | Met |

The release tool holds against every stripping, swapping and tampering attack I tried.

There is **one medium** finding:

- **A13-1:** the relay sheds the *connection* with the largest backlog. An authorized client can
  spread its backlog over many connections, so that the relay sheds honest users first, again and
  again.

There are **eight low** findings and **two informational** findings. The most relevant low
findings are:

- **A13-3:** the relay, agent and client metrics files export identical series. On a host that
  runs more than one of them, node_exporter sees duplicates, and the `TcnReloadRejected` alert
  (revocation not in force) can be lost.
- **A13-4:** the release trust anchor is not pinned. Keys and fingerprints come from the same
  tag, so the AP-19 circularity is still there.
- **A13-7:** the soak gate cannot see any R-6 accounting.

### Checks run

| Check | Result |
| :- | :- |
| `cargo test --workspace --all-features` | **830 passed, 0 failed, 17 ignored** (the OpenSSH/Ansible tests need tools that are not installed) |
| `cargo fmt --all --check` | clean |
| `cargo clippy` | not run: the disk had about 2.5 GB free |
| `build-openssl.sh` into the scratchpad | the pinned SHA-256 matches the downloaded `openssl-3.5.9.tar.gz`; the build works. The build was deleted afterwards |
| `packaging/release/tests/spec.sh`, `attacks.sh` (OpenSSL 3.5.9) | 18/18 and 29/29. With `VERBOSE=1`, every refusal is for the stated reason |
| `zizmor 1.32.0 --offline` on ci, release, release-publish and soak | no findings (6 suppressed). The auditor persona reports one info, `superfluous-actions`, at soak.yml:33 |
| Mutations (repository `target/`; each file restored with `git checkout`, tree clean at the end) | 5 run, 4 killed reliably, 1 weak (A13-10). Details in the table below |
| Reproducers | `scratchpad/adv13-tests/`: `release_probes.sh`, `adv13_shed.rs`, `adv13_status.rs`, `adv13_collide.rs`. All of them reproduce |

### What was tried and held (no finding)

**Metrics: label and value injection, and cardinality**

- Every label value is compiled in: roles, reasons from closed vocabularies, suites, and relay
  indices below `MAX_RELAYS = 8`.
- `ByLabel::inc` folds any unknown value into `other` (`metrics.rs` `ByLabel`).
- `escape_label_value` is applied anyway.
- No fingerprint, node name, address or certificate field is ever passed. Node ids, reasons and
  suites from peers never reach a label as a string.
- The number of lines is fixed.

**Metrics: atomic writes**

- The temporary file is created with `O_CREAT|O_EXCL` and mode 0644 (`set_permissions` makes it
  0644 whatever the umask), then `sync_data`, then `rename`.
- A symlink planted at the target is replaced, not followed.
- A symlink planted at a predictable temporary name causes `AlreadyExists` and a retry.
- The temporary name does not end in `.prom`.
- A failed write is not fatal. It is logged once.

**Budgets: accounting**

- `try_reserve` and `try_grow` are CAS loops with a checked ceiling, so they never go past the
  limit (or ¾ of it).
- Every `Charge` and `QueueCharge` is released on drop on every path I traced:
  - a failed `try_send`;
  - a shed;
  - the end of the task;
  - `drop(rx)`, which also drains tokio's buffered values.
- The hub never awaits a peer (`try_send`).
- Auto-tuning cannot go past `MAX_WINDOW`: `WindowTuner::grew` uses `min(MAX_WINDOW)`, and
  `Window::grant` refuses more than `MAX_WINDOW`.
- The client has its own standalone budget, which is sized so that ¾ of it is at least
  `MAX_WINDOW`.

**Budgets: liveness**

- A shed wakes the victim's task even in the middle of a write. Mutation 1 below kills the
  regression test.
- The G11 rule (read and write in one task) is guarded by
  `relay_queue_never_exceeds_credit_while_writes_block`.

**Copy reduction**

- `recv` rejects trailing bytes after the frame (`channel.rs:351`), so a small payload cannot
  carry a large padded message.
- A payload pins only its own decrypted message, as `a_small_payload_pins_only_its_own_message`
  shows.
- Payload `Bytes` are never mutated, and `send` copies into its own scratch buffer, so no buffer
  is aliased across streams.
- Encryption happens before the flush. A cancelled flush leaves a whole frame in the write buffer,
  and that frame is still sent in order.

**Release signatures**

- Each of the following is refused by `tcn-release.sh verify` and by the OpenSSL commands in
  SECURITY.md (exit 1):
  - a stripped, empty, truncated, bit-flipped or swapped signature;
  - a signature by another key;
  - a signature with another context string, or with no context;
  - a pure Ed25519 signature (no ctx);
  - a signature over another artefact.
- OpenSSL 3.0 cannot load the SLH-DSA key and rejects `instance:Ed25519ctx`, so it fails closed.
- A fake "3.0 that verifies anything" is refused by the version check.

**Workflows**

- The tag is validated (semver regex, through `env`) before it is used.
- `inputs.tag` appears in `with: ref:` and in `concurrency`, never in a `run:` script.
- Actions are pinned to SHAs, `persist-credentials: false` is set everywhere, and the soak job has
  read-only permissions and a 75-minute timeout.
- `build-openssl.sh` pins the SHA-256, uses `--proto '=https'`, and its trap deletes the build
  tree.

**Soak gate**

- The gate fails on the injected leak. In that run fds grew by 255 (limit 8), tasks by 255
  (limit 16) and RSS by 68 MB (limit 24 MiB).

## Outcome

The medium finding and every low finding are fixed in the PR that carries this review; A13-7 is
fixed except for shedding in the soak, and A13-10 and A13-11 are fixed item by item. Commits:
RED `72a7600`, GREEN `a65179b`; the documentation and this record follow in one commit. The
full suite (`--all-features`) has 851 passing tests and 17 ignored (OpenSSH,
Ansible, timing baselines and the long soak). The 10 `e2e-openssh` tests pass. The release tests
pass with OpenSSL 3.5.9 built by `build-openssl.sh` (`spec.sh` 26/26, `attacks.sh`
53/53, every refusal checked for its reason). These checks are clean:

- `cargo clippy` (all targets and features);
- `cargo fmt --check`;
- `cargo deny check` (workspace, `fuzz/` and `vendor/upstream-snow-advisories`);
- `check-vendored-snow.sh` (snow is not modified);
- `zizmor` on the workflows.

**The design of A13-1.** Shedding is fair per authenticated identity (the peer fingerprint), in
`zt_application::efficiency::shed_victim`:

- **Aggregation.** The relay counts every queued frame per connection and per identity (one
  shared counter per fingerprint). The decision sums the backlogs per identity, so 512
  connections of one key weigh as one identity.
- **The share.** No identity may hold more than a quarter of the budget, never less than one
  connection's full credit (its streams × 1 MiB, so a single well-behaved connection is never
  over it). Past it, the identity loses its largest connection, even while the budget as a whole
  has room. The cheap test runs on every queued frame (the identity's counter against the cap);
  the full scan runs only when it fires or when the budget is exceeded.
- **Past the budget.** The identity with the largest *excess* loses its largest connection. An
  agent's normal credit (`max_streams_per_agent × 1 MiB`) is not counted as excess, so an agent
  within its credit is never shed for a client. When nobody has an excess, the largest identity
  is shed anyway (the last resort: the budget still holds). Ties go to the newest connection.
- **The minimum budget.** `MIN_QUEUE_BUDGET` is now 128 MiB, two agents' full credit with the
  default 64 streams. A smaller `--queue-budget-mib` is reported at startup
  (`queue_budget_below_agent_credit`, WARN).
- **The audit line.** `queue_budget_exceeded` names `peer` (the fingerprint), `role`, `cause`
  (`identity_cap` or `budget`), `backlog`, `identity_backlog`, `budget` and `identity_cap`.
- **Not done.** "Prefer a stalled connection over a slow but progressing one": with the
  per-identity rule an abuser can no longer pick its victim, and a progress history per
  connection adds state to the hot path for a second-order gain. Backlog item.

**The design of A13-2.** The agent no longer reserves anything from the global budget on
`Open`. The stream task reserves the initial window after key confirmation, next to the
session permit; a session that finds no room is closed with `Close Drained` (there is no
`ResourceExhausted` close reason, and `Drained` is what "too many sessions" already sends) and
counted in `tcn_agent_buffer_refusals_total`. Before authentication, a stream is bounded by the
per-relay quota (`--max-streams`, its initial window each), which restores the 0005-1 isolation:
one relay cannot touch the budget that the other relays' streams share. The startup warning the
review proposed for `relays × max_streams × INITIAL_WINDOW` is therefore not needed.

**The design of A13-4.** The keys are trusted only through pinned fingerprints, in three places
that the release tests check against each other: `PINNED_FINGERPRINTS` in `tcn-release.sh`,
`packaging/release/release-keys.fingerprints` and the "Pinned release keys" block of
SECURITY.md. `verify` refuses a key that is not pinned before it looks at any signature;
`--pins FILE` replaces the built-in pins (a user's saved copy, an old rotation). No release key
exists yet, so all three pin nothing and every verification fails closed until the maintainer's
key ceremony pins the first pair (REPOSITORY_SECURITY). `release-publish.yml` runs the script
and its pins from the default branch, against the keys at the tag. Rotation continuity: the old
pair signs the announcement of the new fingerprints, and both pairs stay pinned during the
overlap; a dedicated `endorse` subcommand was not added.

| # | Outcome | Regression |
| :-: | :- | :- |
| A13-1 | **Fixed** (design above). OPERATIONS §18 and resilience.md §5.6 describe the rules. | `a_split_backlog_sheds_the_abusing_identity_not_the_honest_connection` (the reproducer, flipped), `an_identity_over_its_share_is_shed_within_the_budget`, `an_agent_within_its_normal_credit_is_not_shed_for_a_client`, `agents_alone_over_the_budget_are_shed_as_a_last_resort` and 3 more (zt-application); `a_split_backlog_sheds_the_abusing_identity_and_the_audit_names_it` (zt-net, on the network: it fails with the per-connection rule), `the_minimum_budget_is_consistent_with_the_agent_windows`, `the_relay_warns_about_a_budget_below_two_agents_credit` |
| A13-2 | **Fixed** (design above). | `streams_without_message_1_take_nothing_from_the_global_budget`; `streams_beyond_the_agent_budget_are_rejected_then_admitted_again` (now closed after authentication) |
| A13-3 | **Fixed.** Every process series carries `role` (`tcn_process_start_time_seconds`, the interval and write time, `tcn_config_generation`, `tcn_reloads_total`, `tcn_watchdog_progress_total`, `tcn_draining`), and so does the client's write time. The exporter's stamp keeps the labels; `status` reads the role's series and still reads an older, unlabelled file. The OPERATIONS §17 table and the `TcnMetricsStale` alert match. | `relay_agent_and_client_series_are_pairwise_disjoint`, `the_process_series_carry_the_role`, `the_stamp_keeps_the_role` |
| A13-4 | **Fixed** (design above). SECURITY.md, OPERATIONS §9 and REPOSITORY_SECURITY say to take the fingerprints out of band once and to pin them. | `attacks.sh`: a self-consistent attacker key set refused against the pins (A13-R3), no `--pins` and nothing built in, a half-pinned pair, a malformed and an empty pin file; `spec.sh`: pinned keys verify, a rotation's two pairs, the three places agree |
| A13-5 | **Fixed.** `sign` runs `check_sums` first. `check_sums` checks bytes before lines: only `[0-9A-Za-z._+ -]` and LF, so a NUL, a CR, a tab or a `/` is refused before bash's `read` can drop or split anything. `verify --tag vX.Y.Z` requires every name to start with `tcn-vX.Y.Z-`. | `attacks.sh`: for each malformed case, `sign` refuses and a raw-signed copy is refused by `verify`, for the stated reason; the NUL duplicate (A13-R2), CRLF with a path (A13-R1), a tab, another tag |
| A13-6 | **Fixed.** (a) No input: the run must start from a release tag (`github.ref_type`), its commit must be on `main`, and the `release` environment (v* tags only) now agrees with how the workflow is started; REPOSITORY_SECURITY step 4 says *Use workflow from → Tags*. (b) OpenSSL is built in its own job with a read-only token, from the default branch's script, and passed as an artifact; `GH_TOKEN` is set only on the steps that call `gh`. (c) Just before publishing, the draft must hold exactly `SHA256SUMS`, its two signatures and the listed archives, and a second download must be byte for byte what was verified. Residual: an asset replaced between that download and `gh release edit` (seconds, and it needs write access to the repository). | `workflow_check.py` (run by `spec.sh`): 20 structural checks; `zizmor` clean |
| A13-7 | **Fixed**, except shedding. The soak runs the agent through `run_observed` and the relay with its metrics; after the load, `tcn_agent_buffer_bytes`, `tcn_agent_sessions`, `tcn_relay_queue_bytes`, `tcn_relay_streams` and the client connections must be 0. One more client loop moves 4 MiB per session, and `soak_short` asserts that windows grew. A slow reader is not part of the soak: on localhost TCP the kernel buffers absorb its backlog before the relay's queue fills (the shedding paths are covered by `budget_attacks.rs` and `adversary_0013.rs`). R6-E5 now says 30 minutes, as the workflow runs, and says that audit loss is not checked. | `the_gate_fails_when_the_budget_is_still_held_after_the_load`, `soak_short` (counters and window growth) |
| A13-8 | **Fixed.** `status` opens with `O_NONBLOCK` and requires a regular file (a FIFO is refused at once), refuses a write time more than 60 s in the future, caps the file's interval at 3600 s, and prints only printable ASCII (format characters such as bidi overrides become `?`). OPERATIONS §17 recommends a sticky directory (`root:tcn 1775`) or a directory of TCN's own, and documents the client file's 0644. The path is still followed if it is a symlink (an operator may link it); the file is never written through one. | `a_future_timestamp_is_refused`, `a_huge_interval_does_not_keep_a_file_fresh`, `status_does_not_block_on_a_fifo`, `status_filters_format_characters` |
| A13-9 | **Fixed.** After a send, a scratch buffer above `SCRATCH_KEEP` (two `Data` chunks and their headers, about 32 KiB) is dropped; the usual 16 KiB frames keep reusing it. | `the_scratch_buffer_does_not_keep_its_high_water_mark` |
| A13-10 | **Fixed item by item.** `one_bulk_stream_cannot_starve_new_streams` waits until the hog's window grew and hit the ceiling (or grew twice) instead of sleeping. `the_gate_catches_an_injected_leak` asserts `rss` too. The round-trip proptest adds frames within 64 bytes of `MAX_PAYLOAD_LEN`, and `the_largest_frame_fits_the_length_prefix` sends the largest frame; one byte more cannot be built (`FramePayload`). Every refusal in `attacks.sh` is checked for a stable part of its message (`expect_refused`). | as listed |
| A13-11 | **Fixed item by item.** resilience.md has an "As implemented (R-5)" block, voids R5-O1/O4/O6 and records D-10 as decided by AP-21. Window growth refusals have their own counter (`tcn_agent_window_growth_refusals_total`), so `TcnAgentBufferExhausted` alerts on refused sessions only. SECURITY.md chains the OpenSSL commands with `&&`, names the archive instead of `--ignore-missing`, and states what the offline signatures add and what they do not. Encrypted backups of the release keys are documented (`openssl pkey -aes-256-cbc`); `keygen` still writes them unencrypted on the offline machine. `count_sent` now counts a frame only once it is queued. | `without_budget_room_the_window_stays_and_the_transfer_completes` (the new counter) |

## Findings

| ID | Severity | Title |
| :-: | :-: | :- |
| A13-1 | **medium** | Per-connection shedding can be evaded and turned against honest users; the audit line does not name the abuser |
| A13-2 | low | The agent reserves the initial window before end-to-end authentication, so a relay can drain the *global* budget (regresses 0005-1 per-relay isolation) |
| A13-3 | low | Relay, agent and client textfiles export identical series; on a shared host node_exporter sees duplicates, including `tcn_reloads_total{result="rejected"}` |
| A13-4 | low | The release trust anchor is not pinned: `verify` trusts any key pair and only prints fingerprints; keys and fingerprints come from the same tag (AP-19 residual) |
| A13-5 | low | `sign` signs a malformed `SHA256SUMS`, and `check_sums` can be bypassed with a NUL byte |
| A13-6 | low | `release-publish.yml`: environment and ref mismatch, write token exposed to the OpenSSL build, verify-then-publish TOCTOU, unverified extra assets |
| A13-7 | low | The soak gate cannot see R-6 accounting, and the soak never exercises growth or shedding |
| A13-8 | low | `status` trusts the file (a future timestamp is fresh forever, a FIFO hangs it), and the documented `root:tcn 0775` directory lets the relay rewrite other collectors' files |
| A13-9 | low | The send-side scratch buffer keeps its high-water capacity per connection, outside every budget |
| A13-10 | info | Tests that claim more than they check |
| A13-11 | info | Divergences between docs and code, and cosmetics |

---

### A13-1 (medium): per-connection shedding can be evaded and turned against honest users

**Surface:** R-6 / D-13, relay byte budget.

**Hypothesis:**

- `shed_victim` picks the single connection with the largest backlog.
- An authorized client controls the credit it grants, and so the relay-side backlog of each of
  its connections:
  - up to 32 streams × 1 MiB per client connection (`max_streams_per_client = 32`);
  - up to `max_per_identity = 512` connections per identity.
- Such a client keeps each of its connections slightly below the backlog of an honest
  slow-link download, and keeps the sum above the budget (64 MiB on small relays).
- The relay then sheds the honest connection first. The next `Send` sheds the next largest
  connection, and the attacker simply reconnects.
- The honest victim can be an agent connection: its legitimate credit is 64 streams × 1 MiB =
  64 MiB, which equals the smallest default budget. Shedding it drops every session of that node
  on this relay.
- The audit line identifies neither the victim nor the cause.

**Evidence:**

- `crates/zt-application/src/efficiency.rs:89–100` (`max_by_key(|(id, b)| (b, id))`, per
  connection).
- `crates/zt-net/src/relay.rs:452–473` (`Queues::shed`).
- `relay.rs:1418–1428`: the `queue_budget_exceeded` audit has `conn`, `backlog` and `budget`, and
  no fingerprint or role.
- `zt-application/src/admission.rs:84` (`max_per_identity: 512`) and `relay.rs:133–134` (32 and
  64 streams).
- OPERATIONS §18 says "keep the budget well above streams per connection × 1 MiB, which the
  default does on any real host". On a host with ≤ 256 MiB of memory, the 64 MiB minimum equals
  one agent connection's credit.
- Reproducer `adv13-tests/adv13_shed.rs`:
  - setup: one honest connection with a 2 MiB backlog, and 40 attacker connections of 1.9 MiB
    each, under a 64 MiB budget;
  - result: `shed_victim` returns the honest connection.

**Required fix:**

- Aggregate the backlog per **peer identity** (fingerprint) and shed the identity with the largest
  aggregate (all of its connections). Alternatively, cap each identity's share of the budget.
- Prefer connections whose backlog has not gone down since the last check (stalled) over
  slow-but-progressing ones.
- Put the fingerprint and role into `queue_budget_exceeded`.
- Either raise `MIN_QUEUE_BUDGET`, or warn at startup when the budget is below 2 ×
  `max_streams_per_agent × MAX_WINDOW`.
- Regression test: an identity with N connections, each below the honest backlog, never gets the
  honest connection shed.

### A13-2 (low): the initial window is reserved before end-to-end authentication

**Surface:** R-6 agent budget; 0005-1 / 0005b-1 per-relay quota isolation.

**Hypothesis:**

- On `Open` the agent reserves `INITIAL_WINDOW` (256 KiB) from the **global** budget before
  `StreamTask::serve` reads and authenticates msg1.
- A compromised relay needs no client key. It can open `max_streams` streams, hold them until the
  handshake timeout, and repeat.
- Before R-6 this cost only that relay's own quota. Now the budget is shared by every relay. Once
  `--max-streams` (allowed up to 4096) × 256 KiB reaches the budget, one relay causes
  `ResourceExhausted` for streams arriving through **all** the other relays.
- With the default of 16 streams this is 4 MiB per relay, which is harmless.
- Separately, authenticated growth may take ¾ of the budget. The remaining ¼ (64 initial windows
  with 64 MiB) is shared by every relay.

**Evidence:**

- `crates/zt-net/src/agent.rs:587`: `try_reserve(INITIAL_WINDOW)` in `on_relay_frame`, before the
  task is spawned.
- `read_msg1` runs later, in `StreamTask::serve`.
- `bins/zt-agent/src/main.rs:96`: default 16, and `parse_max_streams` accepts up to
  `agent::MAX_STREAMS = 4096`.

**Required fix:**

- Before msg1 is authenticated, reserve only a small handshake allowance, or charge pre-auth
  windows to a per-relay sub-budget of `budget / relays`.
- Take the full window after key confirmation.
- Warn at startup when `relays × max_streams × INITIAL_WINDOW > budget / 4`.
- Test: a relay that opens `max_streams` streams and never sends msg1 does not stop a session
  arriving through another relay.

### A13-3 (low): the three textfiles export identical series

**Surface:** R-5, node_exporter textfile (OPERATIONS §17 tells operators to use "a different file
name for each service on the host", so co-location is supported).

**Hypothesis:**

- `Process::render` writes the following series without any `role` label:
  - `tcn_process_start_time_seconds`;
  - `tcn_metrics_interval_seconds`;
  - `tcn_metrics_last_write_timestamp_seconds`;
  - `tcn_config_generation`;
  - `tcn_reloads_total{result}`;
  - `tcn_watchdog_progress_total`;
  - `tcn_draining`.
- The client file also writes `tcn_metrics_last_write_timestamp_seconds` without a label.
- The textfile collector merges every `*.prom` file into one registry. Two files with the same
  name and the same label set produce a duplicate, which the gather reports as an error. Depending
  on the node_exporter version and its error handling, one sample is dropped or the textfile
  scrape fails. I did not run node_exporter.
- Either way, `TcnMetricsStale`, `TcnWatchdogStalled` and **`TcnReloadRejected`** ("revocation
  not in force", G9) are evaluated for one of the two services only, or for neither.

**Evidence:**

- `crates/zt-net/src/metrics.rs:384–452` (`Process::render`) and `metrics.rs:975–990` (client `render`).
- Reproducer `adv13-tests/adv13_collide.rs`. Relay ∩ agent gives 8 identical series, and agent ∩
  client gives 1.

**Required fix:**

- Add `role` to every process-level series, or prefix the names (`tcn_relay_…`, `tcn_agent_…`,
  `tcn_client_…`).
- Add a test that the three sets of series are pairwise disjoint.
- Update the alerts in OPERATIONS §17 to match.

### A13-4 (low): the release trust anchor is not pinned (AP-19 residual)

**Surface:** PQ-REL. AP-19 says "verification must not be circular".

**Hypothesis:**

- `tcn-release.sh verify DIR` accepts any SLH-DSA + Ed25519 pair found in `DIR`. It prints the
  fingerprints only **after** "OK" and never compares them with anything.
- SECURITY.md and OPERATIONS §9 tell users to take the keys from `packaging/release/keys/` **at
  the release tag** and to compare them with the fingerprints "published here" (SECURITY.md,
  which is in the same tree).
- `release-publish.yml` verifies against the keys committed at the tag being published, and it
  does not check that the tag is on `main`.
- An attacker who controls what a user downloads, or the repository content at a tag, supplies a
  consistent set: keys, fingerprints and signatures.
- The documented rotation ("commit the new public key, publish the new fingerprint") has no
  continuity: nothing makes the new key be endorsed by the old one.

**Evidence:**

- `packaging/release/tcn-release.sh:139–161`.
- SECURITY.md:62–64 and :80–81.
- `release-publish.yml:43–46,60–63`.
- Reproducer `release_probes.sh`, section A13-R3: an attacker-generated key pair verifies "OK",
  exit 0.

**Required fix:**

- Add `verify --expect-fingerprints FILE`, or a pinned `release-keys.sha256` that the
  **previously installed** release ships (`/usr/local/share/tcn/`). Fail closed on a mismatch.
- `release-publish.yml` should read the pinned fingerprints from the default branch (or hard-code
  them in the workflow) and reject keys at the tag that differ.
- On rotation, the new public keys must be signed by the old pair.
- The docs should say to get the fingerprints out of band **once** and to pin them.

### A13-5 (low): `sign` signs malformed files; NUL bypass of `check_sums`

**Surface:** PQ-REL, `SHA256SUMS` parsing and "signing the wrong bytes".

**Hypothesis:**

- `cmd_sign` never calls `check_sums`, so the maintainer can sign a file that `verify` would
  refuse. The plain-OpenSSL procedure in SECURITY.md has no format check of its own, so it
  accepts those signatures.
- Bash `read` silently drops NUL bytes. The line `HASH  tcn-v1.tar.gz\0.tar.gz` reaches
  `check_sums` as a distinct, valid name. `sha256sum` reads it as a second entry for
  `tcn-v1.tar.gz`, so the duplicate check is bypassed.
- In this case `sha256sum -c` fails because the hashes differ, so it still fails closed. The claim
  "no duplicates" in `tcn-release.sh:56–57` is still false.

**Evidence:**

- `tcn-release.sh:58–72` (`check_sums`) and `:101–121` (`cmd_sign`, no `check_sums`).
- `release_probes.sh` A13-R1: a CRLF file with `../../etc/evil.tar.gz` is signed (exit 0) and both
  documented `openssl pkeyutl -verify` commands exit 0.
- A13-R2: `verify` exits 0 on the NUL file, and `sha256sum` reports `OK` and then `FAILED` for the
  same name.

**Required fix:**

- Run `check_sums` in `cmd_sign` and refuse to sign on failure.
- Reject any byte outside `[0-9a-zA-Z._+ \n-]`, for example with
  `LC_ALL=C grep -q '[^[:print:]]'`, or `tr -d '\0' | cmp`.
- Optionally require every name to start with `tcn-$TAG-`, given the tag.
- Add tests for both cases.

### A13-6 (low): `release-publish.yml` hardening

**Surface:** PQ-REL workflow and the `release` environment.

**(a) Ref mismatch.**
- REPOSITORY_SECURITY §4 restricts the `release` environment to `v*` **tags**.
- `release-publish` is `workflow_dispatch` with a `tag` input. Dispatched from `main` (the
  default, and the documented "Actions → release-publish → vX.Y.Z"), the environment refuses the
  job.
- Dispatched from a tag, nothing ties `inputs.tag` to `github.ref`, so the workflow and the
  verifier of one tag can publish another tag's draft.

**(b) Token exposure.**
- `GH_TOKEN` (`contents: write`) is in the **job** env.
- So it is present while `build-openssl.sh` runs OpenSSL's `Configure`/`make`, which is
  third-party code. The tarball is hash-pinned, but the principle of least privilege still
  applies.

**(c) Verify-then-publish TOCTOU, and extra assets.**
- The workflow downloads, verifies, and then runs `gh release edit --draft=false`, which
  publishes whatever the draft holds **at that moment**.
- Assets that are not `*.tar.gz` (anything uploaded to the draft) are published without being
  checked.

**Evidence:** `release-publish.yml:9–15,30–35,54,57–59,74–75`; REPOSITORY_SECURITY.md:89–93,143–146.

**Required fix:**

- Drop the input. Use `github.ref_name`, and require `github.ref_type == 'tag'` and the tag on
  `main` (as `verify-tag` does).
- Build OpenSSL in a separate job with no token, or set `GH_TOKEN` only on the `gh` steps.
- Just before publishing, compare the draft's asset list and digests
  (`gh release view --json assets`) with what was verified. Refuse unknown assets.
- Fix step 4 of the docs.

### A13-7 (low): the soak gate cannot see R-6 accounting

**Surface:** R6-E5, `soak.yml`, `tests/soak_support/mod.rs`.

**Hypothesis:**

- The gate samples fds, RSS and tasks only.
- It never reads the following, and never checks that they return to 0 once the load stops:
  - `tcn_agent_buffer_bytes`;
  - `tcn_relay_queue_bytes`;
  - the stream, session and connection gauges.
- A leaked `Reservation` costs no memory, but it shrinks the budget until every stream is
  rejected. That is a slow denial of service.
- Each session moves 4 KiB, so windows never grow and the budget is never approached: the soak
  never runs the new R-6 paths.
- Sensitivity is 24 MiB over 30 minutes, which is a few hundred bytes per session.
- R6-E5 asked for 1 hour and "no audit loss". The workflow runs 30 minutes and checks no audit
  output.

**Evidence:**

- `soak_support/mod.rs:43–56,95–141,331–348`. The soak uses `agent::run`, so the metrics are
  never observed.
- Mutation: forget a 4 KiB `try_reserve` per stream in `agent.rs`. `soak_short` **passed**. It is
  killed only by `budget.rs::streams_beyond_the_agent_budget…`, which uses a tiny budget.

**Required fix:**

- Run the soak through `run_observed` and the relay metrics.
- At quiescence, assert:
  - budget used == 0;
  - streams, sessions and connections == 0.
- Add bulk sessions (≥ 4 MiB, so windows grow) and one slow reader (so the relay sheds).
- Either align R6-E5 with the workflow, or the workflow with R6-E5.

### A13-8 (low): `status` trusts the file; the shared textfile directory

**Surface:** R-5 `status`, OPERATIONS §17.

**Hypothesis:**

- `status` opens the path with `File::open`, which follows symlinks and blocks.
- It takes `written` and `interval` from the file. A timestamp in the future makes
  `age < 0 ⇒ fresh` forever. The same happens after a backward clock step. A huge interval is
  never stale.
- A FIFO at the path blocks `status` forever.
- Unicode format characters (bidi overrides, category Cf) are not filtered. Only `is_control`
  characters are.
- OPERATIONS §17 tells operators to make the shared node_exporter textfile directory
  `root:tcn 0775` and to add `ReadWritePaths=` for it. With no sticky bit, the `tcn` user can
  then rename over or delete **other collectors'** `*.prom` files: a compromised relay can forge
  or hide host metrics. It can also plant the FIFO or the future timestamp for root's `status`.
- The client file is forced to 0644 whatever the user's umask, so other local users can read the
  timing and byte counts of the last session. This part is informational.

**Evidence:**

- `metrics.rs:1355–1386` and `:1084–1117`.
- OPERATIONS.md:1287–1292.
- Reproducer `adv13_status.rs`: a future timestamp gives `stale == false`; `status` on a FIFO is
  still blocked after 3 s.

**Required fix:**

- In `status`, open with `O_NONBLOCK | O_NOFOLLOW`, `fstat` and require a regular file. Treat
  `age < −skew` as invalid or stale. Clamp the interval to at most 3600. Filter category Cf.
- Recommend a sticky directory (`root:tcn 1775`) or a directory dedicated to TCN files.
- For the client file, keep the umask (`0644 & !umask`), or document it.

### A13-9 (low): the scratch buffer keeps its high-water capacity

**Surface:** R-6 copy reduction.

**Hypothesis:**

- `Established::scratch` is cleared but never shrunk. Each connection keeps the capacity of the
  largest frame it ever sent, for its whole life:
  - typically one 16 KiB `Data` chunk plus the header;
  - at most the largest message (about 64 KiB).
- Previously the encode buffer was transient. Over `max_established = 8192` connections this is
  about 135 MiB typically and about 512 MiB at most.
- None of it is counted by any budget or by the soak.

**Evidence:** `crates/zt-net/src/channel.rs:148,296,311,362`.

**Required fix:**

- Either use a thread-local scratch (encoding and encryption happen before the first `.await`), or
  `shrink_to(CHUNK + header)` when the capacity is above about 2 × CHUNK after a send.
- Add a test that the capacity is bounded after a large frame.

### A13-10 (info): tests that claim more than they check

- **`one_bulk_stream_cannot_starve_new_streams`** depends on timing. With the ¾ ceiling removed it
  **passed once** when run with the rest of `budget_attacks.rs` (CPU contention: the second
  doubling did not happen within the fixed `sleep(2 s)`). Run alone, it failed 6/6. The reliable
  guard is the unit test `growth_stops_at_three_quarters_of_the_budget`.
  - Fix: wait until `window_grows_total ≥ 2`, or until a growth refusal, instead of sleeping.
- **`soak_leak`** asserts only `fds` and `tasks`. The RSS gate does catch the injected leak (68 MB
  against 24 MiB), but nothing would notice if it stopped doing so.
  - Fix: also assert `rss`.
- **R6-E3** asked for a *differential* proptest on the fuzz corpus. `frames_survive_the_channel…`
  is a round-trip test with payloads ≤ 20 000 bytes. It never reaches the hand-written two-byte
  length prefix near 65 535 (`channel.rs:366–369`), which is where the new code differs from the
  codec's encoder.
  - Fix: add frames up to the maximum message length, and one just over it.
- The release `expect_fail` helper does not check *why* a command failed. With `VERBOSE=1` every
  refusal in this run was for the stated reason.
  - Fix: assert on a stable prefix of the error message.

### A13-11 (info): divergences between docs and code, and cosmetics

**resilience.md is out of date for R-5:**

- §5.5 still specifies:
  - `--metrics-listen`, `/healthz` and `/readyz`;
  - a handshake latency histogram and hub loop lag;
  - the Ping round trip and the current backoff;
  - `clock_jump`;
  - certificate expiries;
  - `/run/tcn/agent.prom`.
- Catalogue rows R5-O1, O4 and O6 still name HTTP tests.
- D-10 still recommends "(a) localhost HTTP".
- There is no "As implemented (R-5)" block, unlike R-6.

**OPERATIONS §17:**

- `tcn_agent_buffer_refusals_total` counts both stream rejections and refused window growth. The
  second kind is benign. Use two counters, so that the `TcnAgentBufferExhausted` alert is not
  needed as a workaround.

**SECURITY.md:**

- The verification commands are not chained with `&&` or `set -e`. When they are pasted into a
  shell, a failed `pkeyutl` scrolls away and is followed by "OK" lines from `sha256sum` and
  `gh attestation`.
- Prefer naming the archive (`grep ' tcn-vX.Y.Z-…tar.gz$' SHA256SUMS | sha256sum -c -`) over
  `--ignore-missing`.

**Release keys:**

- `keygen` writes the private keys unencrypted (`genpkey` without a cipher; A13-R4). The docs say
  to keep backups "in two places", so offer passphrase-protected PEM.

**Relay metrics:**

- `count_sent` counts forwarded bytes before the enqueue, so it also counts frames that were
  dropped on overflow or for a missing peer.

**Value of the offline signatures:**

- The signer cannot check what CI built (there is no reproducible build).
- The signatures add PQ authenticity and independence from GitHub. They add nothing to build
  integrity beyond SLSA.
- State this in SECURITY.md so that it is not over-read.

## Mutation testing (repository `target/`; every file restored, `git status` clean at the end)

| # | Mutation | Result |
| :-: | :- | :- |
| 1 | `relay.rs`: both `shed.notified()` arms removed | killed: `queue_budget_sheds_the_slowest_reader` |
| 2 | `budget.rs`: growth ceiling = limit (no ¾ rule) | killed: `growth_stops_at_three_quarters_of_the_budget` (unit). `one_bulk_stream_cannot_starve_new_streams` survived once, under contention (A13-10) |
| 3 | `agent.rs`: forget a 4 KiB reservation per stream | killed by `budget.rs::streams_beyond_the_agent_budget…`; **survived `soak_short`** (A13-7) |
| 4 | `soak_leak.rs`: require `rss` in the gate's verdict | holds (the RSS gate does fire); the test just does not assert it |
| 5 | `release_probes.sh` against `tcn-release.sh` (no code change) | A13-R1, R2 and R3 reproduce; the controls fail closed |

## Reproducers

All are under `scratchpad/adv13-tests/`, with no target directory there. Each Rust file was copied
into the crate's `tests/` folder, run, and removed.

- `release_probes.sh` (`OPENSSL=… REPO=…`): A13-4 (R3), A13-5 (R1, R2), A13-11 (R4), and the
  fail-closed controls.
- `adv13_shed.rs` (zt-application): A13-1.
- `adv13_status.rs` (zt-net): A13-8.
- `adv13_collide.rs` (zt-net): A13-3.
