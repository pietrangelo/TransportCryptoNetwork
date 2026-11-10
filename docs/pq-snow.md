# PQ-0: the `snow` decision for IKhfs

Status: **decided** (PQ-0), **landed** in PQ-1 (Phase 2): `vendor/snow`, described patch by
patch in `vendor/snow/PATCHES.md`. Finding AP-14 of review 0007 asked
for this decision, and for a spike test that backs it, before any PQ code.

## 1. Question

PQ-1 adds the suite `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` (PROTOCOL §7.5). TCN builds
its handshakes with `snow` 0.10.0, the latest release (2025-07). Can PQ-1 run on stock snow, or
does it need a patch? If it needs one, how big is it?

## 2. Options

| Option | What it is | Verdict |
| :- | :- | :- |
| (a) stock snow, honest name | `KemChoice` is a closed enum with only `Kyber1024`, so `"…+MLKEM768…".parse()` fails | **impossible** (spike test `stock_snow_does_not_know_ml_kem_768`) |
| (b) stock snow, borrowed label | run ML-KEM-768 through `resolve_kem` under the `Kyber1024` name | **rejected**: the name is hashed into the transcript, so the protocol would lie about itself and interoperate with nothing honest (pq.md §3.2b) |
| (c) stock snow plus a post-handshake ratchet | after IK, encapsulate in transport messages and feed the secret into `rekey_manually` / `get_handshake_hash` | **rejected**: it is a homemade construction rather than IKhfs and has no published analysis. It needs a new framing state on the outer channel, plus a round trip before the channel is PQ |
| (d) vendored minimal patch | `vendor/snow` with `[patch.crates-io]`: one `KemChoice::MlKem768` variant, its name and its sizes; `unwrap()` → `Err` in the `E1`/`Ekem1` paths | **chosen** |
| (e) upstream PR | the same patch, proposed upstream | worth trying, but not on the critical path: snow has not released since 2025-07 |

## 3. What the spike shows

(Historical: the spike was `crates/zt-crypto/tests/snow_hfs_spike.rs` in PQ-0. PQ-1 replaced it
with `snow_patch.rs`, which tests each patch, and `pq_handshake.rs`, which runs the real
handshake.) The spike built the IKhfs handshake on stock snow (feature
`hfs`, which pulls no `pqcrypto`). It plugs `zt_crypto::kem::MlKem768` (libcrux) in through a
`CryptoResolver`, under the borrowed label of option (b), **in a test only**:

1. stock snow refuses the honest name, so option (a) is closed;
2. the HFS token path of stock snow already works with an ML-KEM-768 provider: the handshake
   completes, and both sides derive the same transport keys;
3. the sizes are those of PROTOCOL §7.5: message 1 is **1 296** bytes plus the payload, and
   message 2 is **1 152** bytes;
4. any change to `e1` (including its tag) is rejected by the responder.

Point 3 corrects the analysis. pq.md §3.2b had `e1` in clear after `e` (1 280 bytes). The HFS
specification (§5) and snow both place `e1` directly after the first DH token of the message,
which in IK is `es`. So `e1` is encrypted, and costs 16 bytes more. `HandshakeSuite::msg1_overhead`
and the domain tests use 1 296.

So the patch touches only the parameter enum, its name and the size constants. Nothing in the
state machine changes, and that state machine is the code the spike exercised.

## 4. Decision

- **Vendored minimal patch, option (d)**, in PQ-1:
  - `vendor/snow` (0.10.0, with its checksum recorded) and `[patch.crates-io] snow = { path = "vendor/snow" }`;
  - changes, each covered by a test: `KemChoice::MlKem768` and `"MLKEM768"` in the parser;
    `MAXKEMPUBLEN` / `MAXKEMCTLEN` stay at 4 096 (ML-KEM-768 fits); the three `unwrap()` calls in
    `Token::E1`/`Token::Ekem1` (`handshakestate.rs`) become errors (AP-14: the
    least-exercised code in the TCB, under `panic = "abort"`);
  - no KEM inside snow: the resolver hands it `zt_crypto::kem::MlKem768`, so snow never sees
    a KEM implementation other than the one the test vectors cover;
  - `cargo deny` keeps checking the vendored crate's licence and sources, but **not** its
    advisories: a path crate is outside RustSec matching (review 0009, A9-1). The `vendor` CI
    workflow closes the gap: it checks the upstream release (`vendor/upstream-advisories`) on
    every pull request and daily, verifies that `vendor/snow` is that release plus the patch
    series in `vendor/patches/snow`, and runs upstream's tests on it (`vendor/snow/PATCHES.md`).
- **Upstream PR**, opportunistic: if a release with ML-KEM-768 appears, the vendored copy goes.
- **Until PQ-1**, no hybrid handshake ships: the `hfs` feature is enabled only in zt-crypto's
  dev-dependencies (the spike), and `HandshakeSuite::NoiseIkhfs25519MlKem768.is_supported()` is
  `false`. Configuration refuses the suite (`SuiteError::Unsupported`), and so does the handshake
  API (`CryptoError::UnsupportedSuite`). `libcrux-ml-kem` itself, however, is already a normal
  dependency of every release binary: its build scripts run and its code is compiled, even if
  fat LTO removes it as unused (review 0008, finding A8-12). This is why the backend selection
  of `.cargo/config.toml` is guarded now (`crates/zt-crypto/build.rs`, the release check of the
  libcrux build-script output, finding A8-6), not only from PQ-1 on.
- PQ-1 inverts the spike test `stock_snow_does_not_know_ml_kem_768` and replaces the borrowed
  label with the honest name.

What PQ-1 actually landed (`vendor/snow/PATCHES.md`): patches 1 (`MLKEM768`) and 4 (no
`unwrap()`, as `Error::Kem`) as decided, plus three found while writing them: 2, KEM sizes
checked against snow's buffers (the declared sizes indexed fixed stack arrays); 3, a public key
of the wrong length after `generate` is an error (an RNG failure would otherwise send a short
`e1`); 5, the KEM shared secret buffer is `Zeroizing` (A8-12). In TCN the hybrid suite ran on the
end-to-end channel only in Phase 2; Phase 3 enables it on the outer channel too (PROTOCOL §7.5.2).

## 5. Baseline (classical and hybrid suites, ML-KEM-768)

`crates/zt-crypto/tests/baseline.rs`, ignored by default:

```sh
cargo test --release -p zt-crypto --test baseline -- --ignored --nocapture --test-threads 1
```

The machine: Intel Xeon at 2.10 GHz, 4 vCPU, a shared cloud VM (so expect noise in the p99),
`x86_64`, release build, libcrux portable and AVX2 code paths, 2 000 rounds after warm-up, a
400-byte certificate in message 1. Figures of PQ-1 (2026-11-09), median / p99 in µs:

| Operation | classical, end to end | hybrid, end to end | Δ p99 |
| :- | -: | -: | -: |
| initiator: write message 1 | 251 / 395 | 312 / 460 | +65 |
| responder: read message 1 (unauthenticated cost) | 209 / 325 | 214 / 333 | +8 |
| responder: reject an invalid message 1 | 122 / 203 | 149 / 256 | +53 |
| responder: read message 1 and write message 2 | 306 / 569 | 522 / 681 | +112 |
| initiator: read message 2 | 114 / 225 | 217 / 315 | +90 |
| full handshake, both sides | 618 / 1 039 | 900 / 1 285 | +246 |

| Other | median / p99 |
| :- | -: |
| both suites accepted: reject an invalid hybrid-length message 1 | 299 / 360 |
| classical, outer channel: full handshake | 636 / 1 145 |
| ML-KEM-768 keygen (libcrux) | 32.7 / 50.8 |
| ML-KEM-768 encapsulate | 35.9 / 57.6 |
| ML-KEM-768 decapsulate | 36.1 / 56.0 |

PQ-0's figures (same VM type, another day) were 21.6 / 41.5, 22.8 / 40.4 and 23.4 / 60.7 µs
for the three KEM operations and 1 010 / 1 232 µs for a full classical handshake: the VM is
noisy, so compare rows of one run only.

Reading it:

- **Perf gate (pq.md §7: at most +200 µs p99 per side on `x86_64`): passed.** The responder
  adds +112 µs p99 (read message 1 and write message 2); the initiator +65 µs (write
  message 1) and +90 µs (read message 2), +155 µs in all. The "full handshake" row adds
  both sides.
- IKhfs adds one keygen on the initiator, one encapsulation on the responder (after the
  authorization decision, in `accept`) and one decapsulation on the initiator, plus the AEAD
  and hashing of about 2.3 KiB more transcript.
- Before authentication, the responder's cost barely changes with IKhfs (+8 µs median): `e1`
  adds one AEAD decryption of 1 200 bytes, and the KEM work happens only after the decision.
  An agent that accepts both suites tries both on an invalid message 1 of a length both can
  have, about 300 µs. So the per-source budget of R-1 needs no tightening for PQ (AP-16), and
  the relay is not involved at all in this release (the hybrid suite runs end to end only).
- aarch64 figures (NEON backend disabled, see `.cargo/config.toml`) are still to be recorded on
  real hardware before the gate is evaluated there.
- From review 0009 (A9-3) the fallback of PROTOCOL §7.5.1 step 3 runs on **every** upgraded
  agent whose set is not both suites, including the classical-only default: the "both suites"
  row is then also the cost of an invalid hybrid-length message 1 at such an agent, per key
  (up to four trials during a key rotation).

Release binary growth (perf gate of pq.md §7 PQ-1: at most 400 KB per binary), measured by
review 0009 (`cargo build --release --locked -p zt-agent -p zt-client`,
`x86_64-unknown-linux-gnu`, fat LTO, stripped), `dc979e5` (before PQ-1) vs `d2db0c2`:

| Binary | before | PQ-1 | Growth |
| :- | -: | -: | -: |
| `zt-agent` | 2 362 104 B | 2 695 552 B | +333 448 B (326 KiB) |
| `zt-client` | 1 957 616 B | 2 285 984 B | +328 368 B (321 KiB) |

**Passed** on this target. The musl and aarch64 release targets are not measured yet.

Side channels of decapsulation (pq.md §7 PQ-1 asks for "libcrux claim plus a dudect-style smoke
test"): **decided not to add the dudect test** (review 0009, A9-7). The initiator's
decapsulation key is ephemeral and used exactly once, and the ciphertext is decapsulated only
after its AEAD tag verifies, so an attacker gets at most one timing sample per key, with no
repeated-query oracle to amplify a leak; the constant-time claim rests on libcrux's verified
portable and AVX2 code. The decision is revisited if the KEM is ever used with a static key
(for example a post-quantum authenticated suite).

**Revisited by PQ-AUTH** (§6): the hybrid IK suite decapsulates `ct1` with the responder's
**static** key, before authentication, as often as anyone opens a connection. That is the
repeated-query setting the decision above excluded. Mitigations in this release: libcrux's
verified constant-time decapsulation (portable and AVX2), implicit rejection (FIPS 203: an
invalid `ct1` yields a pseudo-random secret, and every failure is the same `handshake_failed`
after Noise runs), and the relay's per-source admission budget (PROTOCOL §10.1), which bounds
the sample rate. A dudect-style test of the static-key decapsulation is still **open** and
listed for the next adversary review.

## 6. PQ-AUTH: the hybrid IK suite without a new snow patch

Decision (PQ-AUTH, D12): suite `0x02`,
`Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s` (PROTOCOL §7.5.3), is **composed at the
TCN layer** on the vendored snow, with patches 1–5 only. `vendor/snow` and
`vendor/patches/snow` are unchanged, and `check-vendored-snow.sh` still verifies the same
series.

| Option | Verdict |
| :- | :- |
| (a) new snow tokens `skem` / `ekem` for static KEM (a "KEM-IK" pattern, as in PQNoise) | **rejected**: a new state-machine patch in the least-exercised code of the TCB, with no Noise spec revision to follow |
| (b) TCN-layer composition: encapsulate outside snow, feed the secrets as Noise PSKs, bind the ciphertexts in the prologue | **chosen** |
| (c) sign with ML-DSA node keys | **rejected**: node keys never sign (D12); signatures are 3.3 KB and the verifier is the riskiest PQ code |

How (b) works: the initiator encapsulates to the responder's pinned static key before Noise
(`ct1`, sent in clear in front of message 1) and uses `psk0 = SHA-256("TCN/3 skem-i\0" ‖ ct1 ‖
ss1)`; the responder encapsulates to the initiator's static key, which message 1 carries
encrypted (`ct2` in front of message 2), and both set `psk2 = SHA-256("TCN/3 skem-r\0" ‖ ct2 ‖
ss2)` before the `psk` token at the end of message 2. The prologue `TCN/3 <channel>` ‖ `0x02` ‖
`SHA-256(ek_r)` ‖ `ct1` binds the suite, the channel, the responder's KEM key and `ct1`. snow
only parses the modifiers `psk0+psk2` of its existing grammar and runs its own PSK code; the
protocol name carries them, so the transcript names the construction. Everything snow does not
see (`ct1`, `ct2`, the PSK derivation, `ek_i` in the payload) is in `zt-crypto/src/noise.rs` and
covered by `tests/pq_hybrid_ik.rs` and the `hybrid_ik` fuzz target.

What it costs, on the machine of §5 (another day, release build, 2 000 rounds; median / p99
in µs; compare rows of one run only):

| Operation | classical, end to end | IKhfs, end to end | hybrid IK, end to end | hybrid IK, outer |
| :- | -: | -: | -: | -: |
| initiator: write message 1 | 196 / 261 | 229 / 580 | 290 / 515 | 438 / 582 |
| responder: read message 1 | 152 / 292 | 151 / 440 | 278 / 383 | 299 / 437 |
| responder: reject an invalid message 1 | 92 / 174 | 92 / 174 | 124 / 204 | 193 / 266 |
| responder: read message 1 and write message 2 | 306 / 559 | 339 / 1 199 | 407 / 702 | 407 / 709 |
| initiator: read message 2 | 110 / 229 | 148 / 302 | 170 / 329 | 171 / 323 |
| full handshake, both sides | 665 / 1 199 | 720 / 1 269 | 871 / 1 515 | 899 / 1 825 |

Deriving the static ML-KEM key when a key file is loaded: 59 / 96 µs. ML-KEM-768 in that run:
keygen 20.9 / 42.9, encapsulate 22.5 / 44.3, decapsulate 22.5 / 55.5 µs. Against IKhfs the hybrid
IK suite adds one encapsulation and one decapsulation per side and about 3.4 KB on the wire;
the responder's unauthenticated cost grows by one decapsulation per key tried. The VM is noisy
(the IKhfs p99 of this run is an outlier): the per-side p99 gate of pq.md §7 should be checked
again on an idle machine before the suite becomes a default.

**The union of suites (finding A12-6 of review 0012).** The rows above measure each suite
alone. During the migration (OPERATIONS §16, Phases 3–5) a responder accepts all three suites,
and nothing on the wire names the suite or the key, so the attacker picks a length that fits
all of them. Before review 0012 the responder ran a full snow trial per suite and key whose
length bounds fit: 3.4–3.5× the classical responder with one key, 6.7–8× with two keys in
rotation, against the PQ-3 budget of 2.5×. The responder now runs a pre-filter first
(`zt-crypto/src/prefilter.rs`): it replays snow's steps up to the first authenticated decryption
of message 1 with snow's own primitives (one X25519 multiplication per key serves the
classical and IKhfs suites, which both carry `e` at offset 0; the hybrid IK suite adds one
decapsulation and one multiplication per key), and snow runs in full on the one suite and key
that pass, the first in a fixed order. Measured with
`cargo test --release -p zt-crypto --test adversary_0012 -- --ignored --nocapture` (an invalid
4 000-byte message 1, best of three runs of 1 000; the baseline is the classical responder of
the release before PQ-AUTH, one snow trial per key):

| Keys | Baseline (pre-PQ-AUTH, classical) | All three suites | Ratio | Classical only, this release |
| :-: | -: | -: | -: | -: |
| 1 | 116–122 µs | 148–170 µs | 1.28–1.39× | 61 µs |
| 2 (rotation) | 227–265 µs | 293–343 µs | 1.29–1.32× | 106 µs |

The union is now within the budget against the same keyring; the rotation costs about 2.8× the
single-key baseline (it was 6.7–8×). The classical responder alone got cheaper too, so against
it the union is about 2.4–2.8×: Phase 6 of the runbook (drop the suites a role no longer uses)
is recommended, not optional. The operation counts are a unit test in every build
(`an_invalid_message_1_costs_a_bounded_number_of_operations`): per key, 2 multiplications and 1
decapsulation for the union, 1 multiplication for the classical suite, no Noise state.

**Residual: the PSK slots (finding A12-8).** `psk0` and `psk2` are copied into snow's
`Builder` and `HandshakeState`, which do not wipe them on drop (patch 5 covers only the KEM
output buffer). They are functions of `ss1` and `ss2` and of the handshake only, live for the
duration of one handshake, and protect nothing once the transport keys are derived; the snow
symmetric state (chaining key, handshake hash) has the same property and has never been wiped
by snow. A sixth patch that adds `Drop` + `zeroize` to these fields is deferred to the next
change of the vendored series, so that the series is reviewed once. TCN's own copies
(`kem_psk`, the decapsulated secrets, the static key seed) are `Zeroizing`.
