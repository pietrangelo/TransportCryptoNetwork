# Post-quantum and resilience roadmap (pre-implementation plan)

Status: phases 1–4 implemented (PQ-0, R-1, PQ-1 end to end and on the outer hops, R-2, R-3,
R-4 failover deadline and limited hedge, which closes backlog A5-4); phases 5–7 pending. Serial restarts are documented guidance (OPERATIONS §14), not enforced.

This plan merges two independent design analyses and the adversary review of both:

| Document | Content |
| :- | :- |
| [`analysis/pq.md`](analysis/pq.md) | threat model, handshake and signature options, crate maturity, migration |
| [`analysis/resilience.md`](analysis/resilience.md) | gaps G1–G16, admission, reconnect, drain, watchdog, failover, metrics, efficiency |
| [`adversary/0007-pq-resilience-plan.md`](adversary/0007-pq-resilience-plan.md) | 24 findings against the two analyses (1 high, 9 medium, 12 low, 2 info) |

Where the adversary review changed a recommendation, this document carries the **corrected**
version and cites the finding (AP-n). Each phase still follows `docs/METHODOLOGY.md`: spec and
attack tests first, then green, refactor, adversary review.

## 1. Threat model in one table

| Layer | Protected today by | Breaks with a CRQC as | Urgency |
| :- | :- | :- | :- |
| Hop handshakes client↔relay, relay↔agent | Noise IK, X25519 | recorded traffic decrypted later (metadata: who talks to which node, when) | **high** (harvest-now-decrypt-later) |
| E2E handshake client↔agent | Noise IK, X25519 | recorded SSH stream decrypted later, if SSH's own KEX is classical | **highest** |
| Client certificates, CA | Ed25519 | live forgery of certificates (access to every node in `allow`) | medium (needs a CRQC at attack time) |
| Static identities and pins | X25519 keys, SHA-256 fingerprints | live impersonation of relays, agents, clients | medium |
| Release signing | SLSA attestation (classical) | forged releases | low–medium |
| SSH inside the tunnel | OpenSSH KEX | OpenSSH ≥ 10.0 defaults to `mlkem768x25519`; 8.x (EL8/EL9) and Paramiko do not | depends on the fleet |

Confidentiality lost later cannot be recovered; authentication can be upgraded before a CRQC
exists. So **key agreement first, authentication second**.

## 2. Target design

**Handshake (PQ-1):** `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`. An ephemeral ML-KEM-768
key travels in msg1 and its ciphertext in msg2, mixed after `ee`. This gives hybrid
forward secrecy with no new keys, pins or certificates and no extra round trip. It adds about
2.3 KB per handshake, far inside the 61 440 / 65 535 limits.
What it does **not** give (AP-23, to be written into PROTOCOL): PQ authentication and PQ
identity hiding of the static keys. Those come with PQ-AUTH.

**Versioning (AP-7, AP-11):** one **suite id** inside the authenticated handshake, mixed into
the prologue; each role has an explicit **accepted set** of suites (no numeric minimum). The
initiator pins the suite per peer and never falls back on its own. No plaintext magic that
would let passive observers fingerprint TCN or its classical flows.

**Certificates and identities (PQ-AUTH, merged PQ-2 + PQ-3 per AP-9):**
- Certificate v2 signed with a **composite ML-DSA-65 + Ed25519** (AND: both must verify).
  Verify **Ed25519 first**, so ML-DSA parser bugs are reachable only by holders of a valid
  classical CA signature (AP-5). The signature algorithm is bound to the pinned CA key, and
  component keys are never reused (AP-13).
- Hybrid static identities: each node gets an ML-KEM-768 static key **derived from its
  existing seed** (no new secret file), and a PQNoise-style hybrid IK with KEM authentication
  in both directions, so node keys still never sign.
- Revocation and pins use one **X25519-level fingerprint everywhere**, with a distinct prefix for
  v2 display, so a v1 handshake cannot bypass a v2 denylist entry (AP-6).
- PQ-2 alone is not claimed to stop a live CRQC: an attacker who recovers a client's X25519
  key could reuse that client's own valid certificate. That is why the two ship together.

**Crates:**
| Need | Choice | Guard rails |
| :- | :- | :- |
| ML-KEM | `libcrux-ml-kem`, exact pin | portable backend on aarch64 until NEON is verified; RustCrypto `ml-kem` as a test-only differential oracle |
| ML-DSA | RustCrypto `ml-dsa` ≥ 0.1.2, exact pin | Wycheproof/ACVP vectors, libcrux differential, verify-after-sign in `zt-ca` with the fleet verifier (both crates had 2026 advisories, e.g. RUSTSEC-2026-0076) |
| Noise | vendored minimal `snow` patch as the primary path, upstream PR opportunistic (AP-14) | `snow` has had no release since 2025-07; stock snow only knows round-3 Kyber |
| Excluded | `pqcrypto*` (RustSec: unmaintained, `cargo deny` fails), `aws-lc-rs` (C TCB, FIPS buys nothing inside a non-FIPS Noise suite), a second Noise stack such as `clatter` (AP-15) | |

None of the PQ crates has an independent audit. Formal verification, differential testing and
fuzzing are the controls TCN owns.

**Release signing (PQ-REL):** an offline SLH-DSA key over `SHA256SUMS`, signed with OpenSSL
offline. Verification uses an independently installed tool, not the downloaded binary (AP-19).

## 3. Resilience, corrected

| Area | Corrected design |
| :- | :- |
| Admission (G1, high) | "Success" = **key confirmation** (first authentic transport frame from the initiator), not "msg2 sent", so a replayed msg1 earns nothing (AP-1). Add a first-frame deadline for clients. Per-identity limit is a **concurrency** cap charged after confirmation, so one Ansible controller with many forks is not throttled (AP-2). Unauthenticated refill stays 1 per 3 s until measured (AP-16). `msg1_deadline` ≥ 5 s or derived from the suite (AP-20). Separate pre-auth pool; pre-auth buffer cap = maximum legitimate msg1. |
| Logging | Aggregate pre-auth failures **and** unknown identities; per-event lines only for known identities (AP-3). |
| Reconnect | Full jitter with a spread window, 30 s cap; dead peer = no inbound frame for 3 × 10 s; `TCP_USER_TIMEOUT`. |
| Failover (A5-4) | Overall deadline of about 20 s (8 s since review 0011, A11-2); hedge only while connect and outer handshake are incomplete, never after `OpenAck` delays (AP-10). |
| Lifecycle | SIGTERM drain with serial-restart enforcement; supervised critical tasks; watchdog driven by a **progress counter** on a non-starvable tick (AP-4); `check` subcommand in `ExecReload`; `RestartPreventExitStatus` for config errors and `LimitCORE=0` so crashes never dump keys (AP-17, AP-18). |
| Metrics | Textfile exporter for relay **and** agent: no new listening socket anywhere (AP-21). |
| Efficiency | Global byte budget **before** window auto-tuning (AP-22); copy reduction once the simulator can catch regressions; nightly soak. |
| Testing | `turmoil` deterministic network simulator behind a network port (dev-dependency). |

## 4. Phases and order

The adversary rejected "all resilience first, then PQ" (AP-8): it delays the harvest-now fix,
and the PQ cost estimates behind it were inflated. The E2E upgrade needs no relay restart,
because the relay is blind.

| # | Phase | Scope | Wire change |
| :-: | :- | :- | :-: |
| 1 | **PQ-0 ∥ R-1** | Suite id type, accepted sets, KEM trait, test vectors, baselines on x86_64/aarch64 musl, vendored snow patch, SSH KEX guidance. In parallel: admission fixes (AP-1/AP-2) | no |
| 2 | **PQ-1 E2E** | IKhfs on the client↔agent channel only. Upgrades clients and agents, not relays | E2E handshake only |
| 3 | **PQ-1 outer ∥ R-2 + R-3** | IKhfs on both hops, rolled out with the new drain and rolling-restart tooling; simulator, reconnect, liveness, lifecycle | hop handshakes |
| 4 | **R-4** | Failover deadline and limited hedge (closes A5-4; implemented) | no |
| 5 | **PQ-AUTH** | Cert v2 composite, hybrid identities, hybrid IK, unified fingerprints | yes |
| 6 | **R-5, R-6, PQ-REL** | Metrics, efficiency + soak, SLH-DSA release signing | no |
| 7 | **PQ-SUNSET** | Remove classical-only suites from accepted sets, event-driven | config |

## 5. Decisions for the user

The recommendation is marked. Defaults already agreed by both analyses and the adversary are
not repeated here (ML-KEM-768 rather than X-Wing, no FIPS track, KEM derived from the seed,
KEM-based initiator authentication, SLH-DSA only for releases, ControlPersist guidance only,
`turmoil`).

| # | Question | Options | Recommended |
| :-: | :- | :- | :- |
| P1 | Hybrid construction for PQ-1 | IKhfs · PSK from out-of-band KEM · TLS 1.3 + rustls X25519MLKEM768 · straight to hybrid IK | **IKhfs** |
| P2 | Rollout | hard cutover · negotiated suites with pinned, never-downgrading initiator | **negotiated, pinned** |
| P3 | Order | PQ first (as in §4) · resilience first | **as in §4** (E2E PQ first, in parallel with admission fixes) |
| P4 | Signature level | ML-DSA-44 · **ML-DSA-65** · ML-DSA-87 | **ML-DSA-65 composite with Ed25519** |
| P5 | CNSA 2.0 compliance needed? | no (ML-KEM-768) · yes (ML-KEM-1024, ML-DSA-87; ciphertext +480 B) | **no**, unless a customer requires it |
| P6 | Snow strategy | vendored patch · wait for upstream · replace snow | **vendored patch**, upstream PR in parallel |
| R1 | Client metrics | textfile only · relay HTTP on localhost | **textfile only** |

## 6. Side finding

`limits.rs` and PROTOCOL §15.3 count the 16-byte AEAD tag twice in the msg1 size bound, while
`MAX_MSG1_LEN` in `agent.rs` has the exact value. It is harmless but inconsistent; fix it in PQ-0
when the per-suite msg1 sizes are introduced.
