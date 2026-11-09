# Adversary review 0012: Phase 5, PQ-AUTH (certificate v2, hybrid identities, hybrid IK)

- **Scope:** `git diff a8f216e..7839eb6` on `claude/project-thread-qi9qrv` (9 commits, 99 files).
  This covers:
  - certificate v2 with a composite ML-DSA-65 + Ed25519 CA (PROTOCOL §15.14, OPERATIONS §10.8);
  - hybrid static identities (the ML-KEM-768 key derived from the seed, fingerprint v2);
  - the hybrid IK suite 0x02 (PROTOCOL §7.5.3);
  - denylist forms, the `pubkey` subcommand, the PQ-AUTH runbook (OPERATIONS §15–16) and the
    three new fuzz targets.
- **Requirements checked against:**
  - pq-resilience-plan §2;
  - pq.md §4, §7 (PQ-2/PQ-3);
  - 0007 AP-5, AP-6, AP-9, AP-12, AP-13, AP-15 and D11;
  - pq-snow.md, and the vendored snow patch policy;
  - reviews 0008–0011.
- **Reviewer:** independent adversary (step 5 of METHODOLOGY). I did not write this code.
- **Note:** CLAUDE.md says the project's own instructions are encrypted and decrypted by a
  SessionStart hook. They were not visible in this reviewer's context. This review relies only
  on the docs in `docs/`.

## Verdict

**No high-severity finding.** The cryptographic core holds up against every attack I tried:

- composite verification;
- algorithm binding;
- the hybrid IK transcript;
- the denylist and the fingerprint units.

There are three **medium** findings. All three concern whether the PQ-AUTH guarantee can actually
be *reached and enforced* in a real fleet:

- A12-1: nothing enforces PQ authentication fleet-wide, and certificate-only clients cannot be
  pinned at all.
- A12-2: Phase 5 of the runbook cannot complete above about 420 pinned peers per file.
- A12-6: the unauthenticated message 1 cost during the migration is 3.4–6.8× the classical
  baseline, against a 2.5× budget.

There are also six low and one informational findings. Medium findings do not block the merge
under METHODOLOGY §2. A12-1 and A12-2 should be fixed before PQ-AUTH is announced as closing A3,
or before the runbook is used on a fleet larger than about 400 peers.

### Checks run

| Check | Result |
| :- | :- |
| `cargo test --workspace --all-features` | **751 passed, 0 failed**, 14 ignored |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | clean |
| `cargo fmt --all --check` | clean |
| `cargo deny check` | advisories, bans, licenses and sources ok (advisory DB of 2026-11-09). `ml-dsa =0.1.2` (RUSTSEC-2025-0144 patched ≥ 0.1.0-rc.3; CVE-2026-24850 and GHSA-h37v fixed). `libcrux-ml-dsa =0.0.11` (RUSTSEC-2026-0076/0077 patched ≥ 0.0.8, 0125/0126 patched ≥ 0.0.9) is a dev-dependency only. `shake =0.1.0` has the `zeroize` feature. The fuzz lockfile has the same versions |
| `.github/scripts/check-vendored-snow.sh` | ok: snow 0.10.0 plus the same 3 patch files. `vendor/` is unchanged by the phase |
| Mutation testing (14 mutants, scratch copy, repo `target/`) | 13 killed, **1 survived (A12-3)**; table below |
| Reproducers | `scratchpad/adv12-tests/adversary_0012.rs` (zt-crypto) and `adversary_0012_net.rs` (zt-net): all reproduce |

### What was tried and held (no finding)

**Stripping or swapping one signature component.**

- A zero, foreign or swapped `sig_M` or `sig_E` fails.
- Both components sign `CTX2 ‖ TBS`, which contains `version = 0x02` and `sig_alg`.
- The v1 context differs, so a v2 component never verifies as v1 (`cert.rs:269–291`).

**Algorithm confusion.**

- `CaKeyRef` makes the pin, not the certificate, choose the algorithm. `TrustedCaKey::matches`
  (`trust.rs`) never matches Ed25519 against a composite pin, or the reverse.
- `ca_fp` covers `sig_alg ‖ ed25519 ‖ mldsa`. The reserved codes 0x03 and 0x04 are refused.
- A v2 certificate under a v1-only pin is `unknown_authority`, and so is the reverse.
- The relay core's recheck uses the same `authority_for(claims.authority_key())`.

**Malleability.**

- The v2 TBS is canonical: fixed fields, length-prefixed labels, nodes strictly increasing. The
  `cert_v2_decoder` fuzz target asserts re-encoding identity.
- Ed25519 uses `verify_strict`, which rejects non-canonical S and R and small-order points.
- `ml-dsa 0.1.2` `Hint::bit_unpack` enforces monotonic cuts, strictly increasing indices and zero
  padding, and `Signature::decode` enforces the norm of z. So a third party cannot produce a
  second valid encoding.
- `decode_certificate_text` accepts one textual form, with a prefix that must match the version
  byte.

**ML-DSA reachability (AP-5).**

- `mldsa::verify` has one call site, after the binding (step 4), the pinned `ca_fp` and Ed25519
  `verify_strict`.
- An outsider needs a CA-signed TBS bound to its *own* authenticated X25519 key to reach the
  ML-DSA code.
- Verify-after-sign in `zt-ca` uses the fleet's `verify_composite` and decoder.

**Size before allocation.**

- The v2 bounds are checked before any field.
- Key texts are length-checked before `hex::decode`.
- A hybrid message 1 is capped by the codec (`accepted.max_msg1_len()`, 11 238 bytes) before it
  is buffered.
- `respond_hybrid` allocates `rest.len()`, which is at most 64 447.

**Panics from remote input.** None found. Specifically:

- `split_at` is only called on fixed-length data.
- `.get()` is used for `ct1`, `ct2` and `ek_i`.
- libcrux decapsulation does implicit rejection.
- The one `expect` in `ml-dsa`'s `bit_unpack` (`cuts.max()`, K > 0) is unreachable.

**KDF.**

- The ML-KEM key is `SHAKE256("TCN ML-KEM-768 seed v1\0" ‖ seed)`. Ed25519 and X25519 come from
  SHA-512(seed), so the inputs are distinct and domain-separated.
- A CRQC that recovers the X25519/Ed25519 *scalar* still cannot reach the seed (a preimage) and
  therefore cannot reach `dk`.
- The derivation is deterministic, has one purpose, and is tested (mutant M7 killed).

**Hybrid IK transcript.**

- *Authentication of the responder:* `psk0` keys `s`, `ek_i` and the payload, and message 2
  decrypts only with `ss1`.
- *Authentication of the initiator:* the transport keys depend on `psk2(ss2)`, which is
  encapsulated to the `ek_i` that the fingerprint v2 binds (mutants M4 and M4b killed).
- *KCI:*
  - Compromise of R does not let an attacker impersonate I, who still needs `se` and `dk_i`.
  - Compromise of I does not let an attacker impersonate R, who still needs `es` and `dk_r`.
- *Identity hiding:* `s`, `ek_i` and the certificate are under `psk0` (PQ).
- *Replay:* no key confirmation is possible without `dk_i`. `Connected` reaches the core only
  after key confirmation (`relay.rs:944–978`), so AP-12 is met.
- *Downgrade:* the protocol names and prologues differ (`TCN/3 <channel>\x02 ‖ H(ek_r) ‖ ct1`).
  A v2 pin refuses a classical or IKhfs handshake with `identity_downgrade` before message 2.
- *Cross-channel:* the prologues already differ at byte 6.

**Fingerprints (AP-6).**

- Every denylist form reduces to the X25519-level fingerprint, and `SHA256v2:` is a load error.
- Roles, pins and audit `peer` use v1. `peer_v2` is extra. The CA is named by its Ed25519-half
  fingerprint.
- A v1 entry and a v2 entry for one key are a duplicate.

**AP-15.** There is one Noise stack: the composition is at the TCN layer and no new snow patch was
added.

**zt-ca.**

- `keygen --v2` draws 64 fresh bytes.
- The key file is `create_new` with mode 0600, and is loaded through `open_trusted(private)`.
- The log refuses a CA-key prefix of either version.
- The `is_ca_secret` check covers both 32-byte halves.

## Outcome

The three mediums and every low finding are fixed in the PR that carries this review. A12-8 is
fixed except the snow PSK slots, which are documented as a residual. A12-10 is fixed item by
item. Commits: RED `51d3eda`, GREEN `e9d2f92`; the documentation and this record follow in one
commit. The full suite (`--all-features`) has 769 passing tests and 15 ignored (OpenSSH,
Ansible and timing baselines). The 10 `e2e-openssh` tests pass. These checks are clean:
- `cargo clippy` (all targets and features);
- `cargo fmt --check`;
- `cargo deny check` (workspace, `fuzz/` and `vendor/upstream-advisories`);
- `check-vendored-snow.sh` (snow is not modified).

**The design of A12-1.** The setting is `require_hybrid_identity`, an explicit list of roles,
in the style of AP-7. In the relay policy the roles are `agents` and `clients`; in
`clients.toml` the only role is `clients`. It is not a version number. Once a role is listed:
- **Loading.** Every key entry of that role must be v2, or the file is refused with the entry
  named (`DomainError::HybridIdentityRequired`).
- **Admission.** A peer of that role is admitted only if it proved a fingerprint v2 that the
  policy binds to it. For a key entry or an agent, that is the pinned v2. For a
  certificate-only client, it is the v2 that a **hybrid-bound certificate** (`subject_kind`
  0x02) names.
- **Refusal.** Anything else is refused as `IdentityDowngrade`, an `authentication_failed`
  event that names the identity. This includes a classical-kind certificate, which is the CRQC
  impostor's path, and a classical or IKhfs handshake.
- **Reload.** `still_admits_hybrid` applies the same rule, so a reload that adds the
  requirement cuts the sessions that no longer meet it.

`zt-ca` no longer signs a classical-kind certificate with a composite CA by default. A 64-hex
subject needs `--classical-subject`; a `tcn-pub-v2:` subject gives a hybrid-bound certificate,
and the output says which (`subject_kind`). OPERATIONS §16 ends Phase 5 with the requirement;
Phase 6 (drop the unused suites) is now recommended.

**The design of A12-2.** The caps are derived from the entries:
- **Files.** A trust file (policy, `clients.toml`, `known_nodes`, client configuration) may be
  up to 8 MiB (`MAX_TRUST_FILE_LEN`) and hold at most 32 768 entries (`MAX_PEER_ENTRIES`),
  counted before any key is parsed. Key files keep the 1 MiB cap.
- **The compact pin.** It is a responder-side form, `tcn-pin-v2:<fingerprint>:<fingerprint
  v2>` (138 bytes). It pins both fingerprints. It is accepted in the policy, `clients.toml` and
  the denylist, and is refused where the full key is needed to initiate (`known_nodes`, the
  client's node keys).
- **Where the pin comes from.** `keygen` and `pubkey` print it as `pin_v2`.

A policy of 1 000 v2 clients now loads in either form, and so do 4 000 agents in pins. The
policy grows to about 2.4 MB with full keys and about 0.15 MB with pins.

**The design of A12-6.** The responder now runs a pre-filter (`zt-crypto/src/prefilter.rs`).
It replays snow's steps up to the first authenticated decryption of message 1, with snow's own
primitives, and the keys are those snow would derive. A message 1 that fails it would fail snow
at the same step, so the filter only saves work. One X25519 multiplication per key serves both
pre-PQ-AUTH suites. The hybrid IK suite adds one decapsulation and one multiplication per key,
and only if its length bound fits and the suite is accepted (A12-4). Snow then runs in full on
the first suite and key that pass, in a fixed order, so there is exactly one trial.

Measured in release against the classical responder of the release before PQ-AUTH:
- the union of the three suites costs 1.28–1.39× with one key and 1.29–1.32× with two;
- it was 3.4× and 6.8× before the fix;
- against the classical responder of this release, which got cheaper too, the union costs
  2.4–2.8×. pq-snow.md §6 gives both numbers.

The counted operations are a unit test that runs in every build.

| # | Outcome | Regression |
| :-: | :- | :- |
| A12-1 | **Fixed** (design above). PROTOCOL §7.5.3 and OPERATIONS §15–16 describe the setting, the hybrid-bound certificate and what "Gives" means without it. | `a_crqc_impostor_with_a_classical_kind_certificate_is_refused_when_hybrid_is_required`, `a_certificate_only_client_is_pq_authenticated_only_by_a_hybrid_bound_certificate`, `a_v1_entry_of_a_required_role_is_refused` (zt-crypto); `require_hybrid_identity_refuses_v1_entries_of_required_roles`, `a_classical_kind_certificate_is_refused_when_hybrid_is_required` (zt-net, end to end over hybrid IK with the relay audit); `a_composite_ca_needs_an_explicit_choice_for_a_classical_subject` (zt-ca) |
| A12-2 | **Fixed** (design above). OPERATIONS §15 gives the sizes and the pin. | `a_policy_of_a_thousand_v2_clients_loads`, `a_client_configuration_with_a_thousand_v2_nodes_loads`, `the_bounds_of_a_policy_file_are_derived_from_its_entries`, `the_compact_pin_is_a_responder_side_form` |
| A12-3 | **Fixed** for the unit tests. A test-only counter records each ML-DSA verification. A certificate with a bad Ed25519 signature must be refused with no ML-DSA call, which kills M1. The fuzz target cannot see the counter, so the order is not a fuzz property. | `ml_dsa_is_verified_only_after_ed25519` |
| A12-4 | **Fixed.** The identify pass of `respond_or_identify` tries the accepted suites and the unaccepted pre-PQ-AUTH suites, in one pre-filter pass. An unaccepted hybrid IK message 1 is never decapsulated: it is an error, as an unknown suite is. The doc comment is corrected. | `an_unaccepted_hybrid_ik_message_1_is_never_decapsulated`, `no_suite_is_read_as_another` (updated) |
| A12-5 | **Fixed.** Two CA keys are refused if they share a component: an Ed25519 key, or the ML-DSA key of two composites. This holds within an entry and across entries. | `a_shared_ml_dsa_component_is_refused` |
| A12-6 | **Fixed** (design above): within the budget of 2.5×. PROTOCOL §7.5.3, OPERATIONS §15 and pq-snow.md §6 give the cost. | `an_invalid_message_1_costs_a_bounded_number_of_operations` and `a_valid_message_1_runs_one_noise_trial` (counted operations, every build), `the_union_of_suites_stays_within_the_unauthenticated_msg1_budget` (release timing, ignored) |
| A12-7 | **Fixed.** `zt-client` refuses at startup, and in `certificate`, a hybrid-bound certificate whose fingerprint v2 is not its own. With such a certificate, `connect` refuses if the node suite is not hybrid IK or if no relay is; it warns about the relays that are not on hybrid IK, by name. | `a_hybrid_bound_certificate_needs_hybrid_hops_and_the_clients_own_key` |
| A12-8 | **Fixed**, with one residual. `StaticKem::derive` fills the seed in place (`KemSeed::filled_by`). `MlDsa65SigningKey::from_seed` copies into a buffer that is wiped. The snow PSK slots are documented as a residual in pq-snow.md §6: they are short-lived and protect nothing after the split. The vendored patch series is left unchanged in this PR. | (code review; `check-vendored-snow.sh`) |
| A12-9 | **Fixed.** The impostor now derives `psk2` exactly as the product does, from a decapsulation with a key that is not the victim's, which kills M4. AP-12 is now covered on the network: the impostor fails at key confirmation, with no session and no identity-named success event. `fuzz/cert_v2_verify` has a hybrid-bound fixture and checks rejection for `None` and for another fingerprint v2. The repeated-hint check loops until a signature repeats a hint. | `a_crqc_impostor_without_the_static_key_shares_no_transport_key`, `a_crqc_impostor_fails_at_key_confirmation_on_the_network` |
| A12-10 | **Fixed item by item.** Message 1 sizes: OPERATIONS §10.8 gives 11.2 KB for hybrid IK, and PROTOCOL §15.3 lists the 11 238 cap. The PQ-AUTH text says `IKhfs` and "hybrid IK" explicitly; the older sections keep their established "hybrid suite" (IKhfs), which §7.5.3 defines. The identify-path doc comment is corrected. The `emit!` blocks are re-indented. The `keygen` output, now with `pin_v2`, is noted in OPERATIONS §15 for scripts. | — |

## Findings

| ID | Severity | Surface | Status |
| :- | :- | :- | :- |
| A12-1 | medium | policy / certificates: enforcement of PQ authentication | fixed |
| A12-2 | medium | config / runbook Phase 5: file cap vs v2 key size | fixed |
| A12-3 | low | tests: AP-5 verification order unprotected (mutant survives) | fixed |
| A12-4 | low | agent identify path: static-key decapsulation for an unaccepted suite | fixed |
| A12-5 | low | trust load: ML-DSA component reuse (AP-13) | fixed |
| A12-6 | medium | relay/agent pre-auth CPU: union of suites | fixed |
| A12-7 | low | zt-client: hybrid-bound certificate lockout | fixed |
| A12-8 | low | zeroization of the new secrets | fixed (snow PSK residual documented) |
| A12-9 | low | tests and fuzz targets that claim more than they check | fixed |
| A12-10 | info | docs and cosmetics | fixed |

---

### A12-1 (medium): PQ authentication cannot be enforced fleet-wide, and certificate-only clients cannot be v2-pinned

**Surface:**

- `AccessPolicy::pin_hybrid` (`crates/zt-domain/src/policy.rs:215–225`);
- `ClassicalIdentityMatch`, which is only an audit (`crates/zt-application/src/relay.rs:423–432`,
  `crates/zt-net/src/agent.rs:803–816`);
- `zt-ca sign` with a v2 CA (`bins/zt-ca/src/main.rs:243–256`);
- pq.md §4.6 and the PQ-3 scope (`min_identity_version`).

**Hypothesis.**

A live CRQC recovers a client's X25519 secret from its public key and connects over the hybrid IK
suite. It pairs that secret with the victim's X25519 key and **its own** ML-KEM key. The relay
admits the connection whenever the entry that matches is not a v2 pin. Such entries are:

- a v1 whitelist entry;
- a v1 certificate;
- a v2 certificate with `subject_kind = 0x01`.

The only consequence is a WARN, `classical_identity_match`.

pq.md §4.6 and the PQ-3 scope require `min_identity_version = 2` to forbid this. It is **not
implemented**, and the gap is not documented as deferred.

**Evidence:**

- The PQ-AUTH docs state the guarantee as unconditional. PROTOCOL §7.5.3 says "Gives:
  authentication of both parties against an adversary with a quantum computer". Plan §2 says that
  PQ-2 + PQ-3 ship together "so that" a CRQC cannot reuse a client's own certificate (AP-9).
- In practice the guarantee holds only per peer, and only if the operator completes Phase 5 for
  every entry and every certificate.
- **Certificate-only clients cannot be pinned at all.** `pin_hybrid` returns `UnknownPeer` for a
  key without a role (reproducer `a12_1_…`, part a). The only protection for them is that the CA
  issues hybrid-bound certificates. But `zt-ca sign --ca <v2>` silently issues a
  `subject_kind = 0x01` certificate when it is given the 64-hex key (`main.rs:254`), and no
  relay or agent setting refuses such certificates.
- `verify_certificate_hybrid` accepts a `subject_kind = 0x01` v2 certificate with *any* claimed
  hybrid fingerprint, including the victim's X25519 key paired with the attacker's `ek`
  (reproducer, part b).
- The runbook has no completion check that operators could run ("no classical match left")
  other than watching a WARN.

**Required fix:**

1. Implement the planned switch as an explicit, per-role responder setting, in line with AP-7
   (no ordering): for example `require_hybrid_identity = ["agent", "client"]` on the relay and
   `--require-hybrid-identity` on the agent. When it is set, a peer that does not prove a pinned
   or certificate-bound fingerprint v2 is **refused** (`identity_downgrade`), not warned about.
2. Add a per-authority `require_hybrid_subject = true` that refuses `subject_kind = 0x01` and v1
   certificates from that CA.
3. In `zt-ca sign` with a v2 CA, refuse a 64-hex subject unless `--classical-subject` is given,
   and log the choice.
4. Make the runbook's Phase 5 end with turning these settings on. State in PROTOCOL §7.5.3 that
   the guarantee holds only with them.
5. Add catalogue tests: `a_crqc_impostor_with_a_classical_kind_certificate_is_refused_when_hybrid_is_required`
   and `a_certificate_only_client_is_pq_authenticated_only_by_a_hybrid_bound_certificate`.

---

### A12-2 (medium): Phase 5 cannot complete above about 420 pinned peers per file (1 MiB cap vs 2.4 KB keys)

**Surface:**

- `MAX_FILE_LEN = 1 MiB` (`crates/zt-net/src/config.rs:29`), which applies to the relay policy,
  `clients.toml` and `client.toml` / known nodes;
- OPERATIONS §16 Phase 5 ("Replace v1 keys with `tcn-pub-v2:` keys in the relay policy and in
  `clients.toml`").

**Hypothesis.**

- A `tcn-pub-v2:` key is 2 443 characters, against 64 before. A `[[clients]]` or `[[agents]]`
  entry grows from about 130 bytes to about 2 510 bytes.
- So the 1 MiB file cap is reached at about 417 pinned peers.
- A relay policy for a fleet of the size the plans assume (a 4 000-agent herd, pq.md and 0007
  AP-8) **cannot be loaded** once Phase 5 is applied.
- The same applies to an agent's `clients.toml` with more than about 420 v2 clients, and to a
  `client.toml` with that many v2 node pins.

**Evidence:** reproducer `a12_2_phase5_policy_exceeds_the_file_cap`. With the same 1 000 clients:

- in v1 form the file is 131 998 bytes and `load_policy` returns ok;
- in v2 form it is 2 510 998 bytes and `load_policy` fails with "file too large".
  `load_authorized_clients_digested` fails the same way.

No test or doc mentions this ceiling.

**Required fix.**

A responder never needs `ek_i` from its configuration: it receives `ek_i` in message 1 and only
compares `H(x25519 ‖ ek_i)` with the pin. So responder-side pins should be the compact typed
form, for example:

```toml
public_key = "<64 hex>"
fingerprint_v2 = "SHA256v2:<64 hex>"
```

That is about 80 extra bytes per entry, and it keeps AP-6's typed prefixes. Keep the full
`tcn-pub-v2:` form for **initiator** pins only: `client.toml` relays and nodes, and
`--relay-key`.

If the full form is kept anyway:

- raise the cap for these files to a bounded value derived from the entry limits;
- document the ceiling;
- add a load test at the documented fleet size.

---

### A12-3 (low): the AP-5 order (Ed25519 before ML-DSA) is not protected by any test

**Surface:** `verify_composite` (`crates/zt-crypto/src/cert.rs:269–291`) and
`tests/cert_v2.rs:309` (`ed25519_is_checked_first_and_garbage_ml_dsa_never_panics`).

**Hypothesis.** A refactor that verifies ML-DSA first would reopen AP-5: the RustCrypto or libcrux
class of ML-DSA verifier bugs would become reachable by any host that can write a well-formed
certificate for its own key. Nothing would notice.

**Evidence.** Mutant **M1** (ML-DSA verified first, then Ed25519) **survives the entire zt-crypto
suite**. The test named "…is_checked_first…" only asserts that both orders return
`BadSignature`, which they do either way.

**Required fix.** Make the ML-DSA check observable in tests. Options:

- inject the verifier (a `fn` parameter or a crate-private trait) and use a counting fake in a
  unit test;
- add a `#[cfg(test)]` call counter.

Then assert that the ML-DSA check is *not* invoked when `sig_E` is invalid. Add the same property
to `fuzz/cert_v2_verify`.

---

### A12-4 (low): the agent decapsulates with its static ML-KEM key for a suite it does not accept

**Surface:** `noise::respond_or_identify` (`crates/zt-crypto/src/noise.rs:362–391`), used by
`agent.rs:670`; `respond_hybrid` (`noise.rs:451–461`).

**Hypothesis.**

- The doc comment says the identification attempts are "read-only: no KEM operation".
- For suite 0x02 that is false. To identify the initiator, `respond_hybrid` must first run
  `MlKem768::decapsulate(dk_static, ct1)`, because `s` is encrypted under `psk0`.
- So **every** agent on the PQ-AUTH release decapsulates every relayed end-to-end message 1 of
  hybrid length with its long-term key. That includes an agent in runbook Phase 0 ("Nothing
  changes on the wire") that never added the suite.
- The constant-time property of that decapsulation is still an **open** item (pq-snow.md: no
  dudect test yet).

Reachability is limited to clients the relay has admitted, which makes them insiders, so the
severity is low.

**Evidence:** reproducer `a12_4_identify_path_decapsulates_with_the_static_key`. With
`AcceptedSuites::only(classical)`, a hybrid message 1 comes back as `Unaccepted` with
`hybrid_peer() == Some(client's fingerprint v2)`. That value is only computable after the static
decapsulation.

**Required fix:**

- Drop suites that `requires_hybrid_identity()` from the identify pass unless they are accepted.
  The unaccepted hybrid initiator then gets the generic `handshake_failed`.
- Alternatively, document and budget the decapsulation.
- In either case, correct the doc comment.

---

### A12-5 (low): AP-13 "component keys are never reused" is enforced for Ed25519 only

**Surface:** `CertTrust::add_authority` (`crates/zt-domain/src/trust.rs:230–262`) and plan §2
("component keys are never reused (AP-13)").

**Hypothesis.** Two composite CA keys can share the ML-DSA-65 half and differ only in Ed25519. The
loader accepts them in one entry (`[v2a, v2b]`) and across entries.

There is little practical risk: each `ca_fp` still names a distinct composite, and both halves are
mandatory. But it contradicts the stated invariant and the composite-signature guidance, and a
"rotation" that keeps the ML-DSA key gives no rotation of the PQ half.

**Evidence:** reproducer `a12_5_mldsa_component_reuse_is_accepted`. CA seeds `(0x01, 0x77)` and
`(0x02, 0x77)` load in both layouts.

**Required fix:** in `add_authority`, compare the ML-DSA halves of composite pins, within the
entry and against every pinned key, in addition to the Ed25519 bytes and fingerprints. Add a test.

---

### A12-6 (medium): unauthenticated message 1 cost of the suite union is 3.4× (6.8× in rotation), over the PQ-3 budget of 2.5×

**Surface:**

- `respond_suites` trial loop (`crates/zt-crypto/src/noise.rs:292–310`);
- R-1 admission (PROTOCOL §10.1), whose per-source tokens count connections and not CPU;
- OPERATIONS §15 (`OPERATIONS.md:1131`);
- runbook Phases 3–6, which keep classical, IKhfs and hybrid IK accepted together, potentially
  for good (Phase 6 is "optional").

**Hypothesis.**

- A message 1 of 3 568 to 7 766 bytes fits the length bounds of all three suites.
- The responder therefore runs a classical trial, an IKhfs trial and a hybrid trial
  (decapsulation plus DH) **per key**.
- Garbage message 1s cost the attacker nothing. The per-source budgets throttle the *count* of
  attempts, not their cost.
- PQ-AUTH raised the CPU per invalid message 1 by about 1.7× over the PQ-1 union, and by 3.4×
  over the classical baseline, without re-deriving the R-1 budgets.

**Evidence:** reproducer `a12_6_…`, release build, 300 rounds, three runs. Against the classical
baseline (one key, about 95 µs):

| Responder | Ratio | Time |
| :- | -: | -: |
| hybrid IK alone | 1.34–1.45× | — |
| all suites, 1 key | **3.40–3.53×** | 323–507 µs |
| all suites, 2 keys (rotation) | **6.74–8.0×** | 644–1 002 µs |

- pq.md PQ-3 sets the budget at "unauthenticated-msg1 cost ≤ 2.5× baseline".
- OPERATIONS §15 says only "costs one decapsulation per key". The pq-snow §6 table measures each
  suite alone, never the union.

**Required fix:**

1. Cut the trial cost:
   - classical and IKhfs carry `e` at offset 0, so compute `DH(s_r, e)` once per key and share it
     across both trials;
   - try hybrid IK last, and only when `len ≥ 3 568`.
2. Charge the per-source token in proportion to the trials actually run (CPU-weighted admission).
   Alternatively, size `max_pending` and the refill rates for the union cost.
3. Measure the union in pq-snow §6. Document that the union is the expensive state, and make
   Phase 6 a recommended step rather than an optional one.
4. Add a gate test, ignored by default and run in CI release mode, asserting the configured
   budget.

---

### A12-7 (low): a hybrid-bound certificate locks the client out of any hop that is not on hybrid IK, with no local diagnostic

**Surface:**

- `zt-client` `load_own_certificate` (`bins/zt-client/src/main.rs:214–245`);
- `client.rs:104–112` (the same certificate goes into message 1 of **both** channels);
- runbook Phase 2 and rollback step 3.

**Hypothesis.**

- A `subject_kind = 0x02` certificate passes only over a hybrid IK handshake that proves exactly
  that fingerprint v2.
- The client sends it to the relay *and* to the agent. Every `[[relays]]` and `[[nodes]]` entry
  therefore has to be pinned to hybrid IK with a v2 key.
- Any node whose agent is not yet in Phase 3.2, and any classical failover relay, refuses the
  client with `key_mismatch`.
- The client config parses and runs anyway. The certificate check at load time compares only the
  X25519-level `subject`.

This is a half-migrated lockout that the operator learns about only from refusals.

**Evidence:**

- `load_own_certificate` checks `body.subject().classical()` only.
- No check ties a hybrid-bound certificate to the pinned suites, or ties `subject_v2` to
  `identity.hybrid_fingerprint()`.
- The runbook mentions the constraint only in prose ("distribute it … together with its Phase 4
  pin").

**Required fix.** At load, for a hybrid-bound certificate:

- require `subject_v2 == identity.hybrid_fingerprint()`;
- make it an error, or at least a loud warning that names the entries, when any relay or node
  pin is not hybrid IK.

Add a test for both checks.

---

### A12-8 (low): zeroization gaps for the new secrets

**Surface:** `StaticKem::derive` (`crates/zt-crypto/src/hybrid.rs:42–53`), the snow PSK slots
(`noise.rs:263, 467, 553, 637`), and `MlDsa65SigningKey::from_seed` (`mldsa.rs`).

**Evidence:**

- **`StaticKem::derive`.** `KemSeed::from_bytes(*dz)` copies the 64-byte `d ‖ z` by value onto
  the stack before boxing it. `kem.rs` documents this explicitly: "the caller's array is a copy:
  wipe it". That temporary, which is the node's long-term ML-KEM secret, is never wiped. It is
  also re-derived on **every** hybrid initiation (`Identity::static_decapsulation_key`).
- **snow PSK slots.** `psk0` and `psk2` (functions of `ss1` and `ss2`) are copied into
  `Builder.psks` and `HandshakeState.psks`. snow never zeroizes these: there is no `Drop`, and
  patch 5 covers only the KEM output buffer.
- **`MlDsa65SigningKey::from_seed`.** `ml_dsa::B32::from(*seed)` makes the same kind of copy.
  This is on the offline CA, so the impact is minor.

**Required fix:**

- Use `KemSeed::filled_by(|b| { xof.finalize_xof().read(b); Ok(()) })`.
- Either add a reviewed snow patch that wipes `psks` (and ideally the symmetric state) on drop,
  or document the residual in pq-snow.md next to patch 5.

---

### A12-9 (low): tests and fuzz targets that claim more than they check

**`a_crqc_impostor_fails_at_key_confirmation`** (`tests/pq_hybrid_ik.rs:488`):

- The impostor uses the test's *own* `psk2` derivation with a random `ss2`. A `zt-crypto`
  responder whose `psk2` ignores `ss2` (mutant **M4**) still passes it.
- Only the interop test kills M4.
- Required fix: let the impostor derive `psk2` *exactly as the product does*, from a guessed
  `ss2`, and assert that the transport fails.

**Missing network-level test for the AP-12 catalogue row:** "CRQC impostor passes the pre-msg2
check, fails at key confirmation, leaves no session and no identity-named success event". Add it
in `zt-net`, with a hand-built initiator and the relay audit captured.

**`fuzz/cert_v2_verify`:**

- Its header claims that the certificate is rejected "with another hybrid fingerprint". The
  fixture is `CertSubject::Classical` and never calls `verify_certificate_hybrid`.
- Required fix: add a hybrid-bound fixture, and assert rejection for `None` and for a wrong
  fingerprint v2.

**`cert_v2.rs`:** the repeated-hint check is under `if count >= 2`, so on some random signatures
it silently checks nothing. Use a deterministic signature, or loop until `count ≥ 2`.

---

### A12-10 (info): docs and cosmetics

**Message 1 size statements:**

- OPERATIONS §10.8 (`OPERATIONS.md:886`) says "8.9 KB at most under the hybrid suite". That is
  IKhfs. The hybrid IK maximum is 11 238 bytes.
- PROTOCOL §15 (around line 883) lists the 7 766 and 8 966 caps as "the relay's pre-authentication
  caps" without the 11 238 cap.
- "Hybrid suite" (IKhfs) next to "hybrid IK suite" invites exactly this confusion. Rename the
  former "HFS suite" in the PQ-AUTH text.

**Identify-path doc comment:** `noise.rs:365` says "no KEM operation". This is false; see A12-4.

**Audit macros:** the `emit!` blocks in `zt-net/src/relay.rs` `audit()` are mis-indented, and
rustfmt does not format macro bodies.

**`keygen` output:** the alignment changed from `public_key  =` to `public_key     =`. Note it in
the changelog for scripts that parse it.

## Mutation testing (scratch copy; the repository was not modified)

| Mutant | Change | Result |
| :- | :- | :- |
| M1 | ML-DSA verified before Ed25519 | **survived** (A12-3) |
| M2 | hybrid subject binding removed | killed (`a_hybrid_subject_needs_the_hybrid_handshake`) |
| M3 | prologue drops `SHA-256(ek_r)` | killed |
| M4 | `psk2` ignores `ss2` | killed only by the interop test (A12-9) |
| M4b | `psk0` ignores `ss1` | killed |
| M5 | v2 pin check always Ok | killed (6 tests) |
| M7 | no KEM-seed domain string | killed |
| M8 | no FIPS 203 check of `ek_i` | killed |
| M11 | file prefix vs version byte not checked | killed |
| M13 | reload adding a v2 pin does not cut sessions (agent) | killed |
| M14 | v2 self-certification check removed | killed |
| M15 | `classical_identity_match` never emitted (relay core) | killed |

## Open items carried forward

- dudect-style constant-time test of the **static-key** ML-KEM decapsulation. The authors list it
  as open in pq-snow.md. It matters more because of A12-4 and A12-6.
- Re-measure the per-side p99 gate on an idle machine before hybrid IK becomes a default
  (pq-snow.md §6).

## Reproducers

The reviewer's reproducers asserted the **attackable** behaviour. They are now regression tests
that assert the safe behaviour:

| Reproducer | Finding | Now |
| :- | :- | :- |
| `adversary_0012.rs` | A12-1, A12-4, A12-5, A12-6 | `crates/zt-crypto/tests/adversary_0012.rs` (A12-6 is the ignored release timing test, with the pre-PQ-AUTH responder as its baseline) |
| `adversary_0012_net.rs` | A12-2 | `crates/zt-net/tests/adversary_0012.rs`, with the A12-1 and AP-12 tests on the network |
| `mutate.py` (M1, M4) | A12-3, A12-9 | `ml_dsa_is_verified_only_after_ed25519` (M1), `a_crqc_impostor_without_the_static_key_shares_no_transport_key` (M4) |

The reviewer's originals, which ran against a throw-away copy, are not in the repository.
