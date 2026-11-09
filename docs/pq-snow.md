# PQ-0: the `snow` decision for IKhfs

Status: **decided** (PQ-0). The patch lands in PQ-1 (Phase 2). Finding AP-14 of review 0007 asked
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

`crates/zt-crypto/tests/snow_hfs_spike.rs` builds the IKhfs handshake on stock snow (feature
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
    `Token::E1`/`Token::Ekem1` (`handshakestate.rs`) become `Err(Error::Input)` (AP-14: the
    least-exercised code in the TCB, under `panic = "abort"`);
  - no KEM inside snow: the resolver hands it `zt_crypto::kem::MlKem768`, so snow never sees
    a KEM implementation other than the one the test vectors cover;
  - `cargo deny` keeps checking the vendored crate (its license and sources do not change).
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

## 5. Baseline (classical suite and ML-KEM-768)

`crates/zt-crypto/tests/baseline.rs`, ignored by default:

```sh
cargo test --release -p zt-crypto --test baseline -- --ignored --nocapture
```

The machine: Intel Xeon at 2.10 GHz, 4 vCPU, a shared cloud VM (so expect noise in the p99),
`x86_64`, release build, libcrux portable and AVX2 code paths, 2 000 rounds after warm-up.

| Operation | median | p99 |
| :- | -: | -: |
| ML-KEM-768 keygen (libcrux) | 21.6 µs | 41.5 µs |
| ML-KEM-768 encapsulate | 22.8 µs | 40.4 µs |
| ML-KEM-768 decapsulate | 23.4 µs | 60.7 µs |
| initiator: write message 1 | 202.1 µs | 343.1 µs |
| responder: read message 1 (unauthenticated cost) | 148.7 µs | 270.3 µs |
| responder: reject an invalid message 1 | 93.0 µs | 174.0 µs |
| responder: read message 1 and write message 2 | 297.2 µs | 499.5 µs |
| full handshake, both sides | 1 010.3 µs | 1 231.6 µs |

Reading it:

- IKhfs adds one keygen on the initiator, one encapsulation on the responder (after the
  authorization decision, in `accept`) and one decapsulation on the initiator. That is about
  25 µs per side at the median, well within the PQ-1 performance gate (pq.md §7: at most
  +200 µs p99 per side on `x86_64`).
- Before authentication, the responder's cost barely changes with IKhfs: `e1` adds one AEAD
  decryption of 1 200 bytes, and the KEM work happens only after the decision. So the per-source budget
  of R-1 needs no tightening for PQ (AP-16). The unauthenticated refill stays one handshake
  every 3 s per source. Only the burst rose (20 → 64), for fleets that open 50 sessions at
  once (`forks = 50`). At about 150 µs of responder CPU per unauthenticated message 1, a full
  burst costs one core under 10 ms.
- aarch64 figures (NEON backend disabled, see `.cargo/config.toml`) are still to be recorded on
  real hardware; PQ-1 must add them before the gate is evaluated there.
