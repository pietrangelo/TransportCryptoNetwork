# TCN patches to snow 0.10.0

This directory is `snow` 0.10.0 from crates.io, vendored by TCN for PQ-1 (docs/pq-snow.md,
decision PQ-0) and wired into the workspace and `fuzz/` with `[patch.crates-io]`. The upstream
license (`LICENSE-APACHE`, `LICENSE-MIT`: Apache-2.0 OR MIT) is unchanged and applies to the whole crate, patches
included.

## Upstream identity

| | |
| :- | :- |
| crate | `snow` 0.10.0 (crates.io) |
| `.crate` SHA-256 | `599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82` |
| upstream commit (`.cargo_vcs_info.json`) | `4bb43f50370bdb3e8b1b57814ac662864db2704f` |
| unmodified import | TCN commit `f67c431` ("chore: vendor snow 0.10.0, unmodified") |

`Cargo.toml.orig` is kept as published and is not edited: the build reads `Cargo.toml`. The
published `Cargo.lock` is not committed (upstream's own `.gitignore` excludes it); the workspace
and `fuzz/` lock files pin the dependencies.

To review the patch against upstream:

```sh
git diff f67c431 -- vendor/snow
# or, from a fresh download:
curl -sSfL https://static.crates.io/crates/snow/snow-0.10.0.crate -o snow.crate
echo "599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82  snow.crate" | sha256sum -c
mkdir upstream && tar -xzf snow.crate -C upstream
diff -ru upstream/snow-0.10.0 vendor/snow
```

The diff touches only `Cargo.toml`, `src/params/mod.rs`, `src/resolvers/default.rs` and
`src/handshakestate.rs`, plus this file. Each change carries a
`TCN patch N` comment in the code.

## Patches

All changes are behind the `hfs` feature: a build without it is upstream snow.

1. **`KemChoice::MlKem768`, spelled `MLKEM768`.** The protocol name
   `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` parses, so the transcript hashes the honest
   name. The default resolver returns `None` for it: snow ships no ML-KEM, and TCN's resolver
   (`crates/zt-crypto/src/resolver.rs`) provides `libcrux-ml-kem`. `Kyber1024` still parses.
   Test: `the_vendored_snow_knows_ml_kem_768` (`crates/zt-crypto/tests/snow_patch.rs`).
2. **KEM sizes are checked.** The sizes a provider declares must be non-zero and within
   `MAXKEMPUBLEN`, `MAXKEMCTLEN` (4 096) and `MAXKEMSSLEN` (32); otherwise `Error::Kem`. The
   write paths also check that the encrypted field, with its tag, fits the output buffer from
   the current offset (upstream compared the field with the whole buffer). Upstream indexed its
   stack buffers with the declared sizes: a panic, an abort under TCN's `panic = "abort"`.
   Test: `kem_sizes_beyond_snows_buffers_are_errors_not_panics`.
3. **A short public key is not sent.** `Kem::generate` cannot report a failure (an RNG error in
   TCN's provider leaves no key), so after it snow checks that the public key has the declared
   length, or fails with `Error::Kem`. Test:
   `a_key_generation_without_a_full_public_key_fails_the_handshake`.
4. **No `unwrap()` in the `Ekem1` paths.** The three calls (missing KEM, missing remote KEM
   key) are `Error::Kem`. They cannot be reached through the public API (the builder refuses a
   hybrid pattern without a KEM, test `a_hybrid_pattern_without_a_kem_is_a_build_error`); the
   fuzz targets `noise_responder` and `noise_initiator` exercise the paths around them.
5. **The KEM shared secret is wiped.** `kem_output_buf` is a `zeroize::Zeroizing` buffer on
   both sides (finding A8-12). This adds the optional dependency `zeroize` 1.8, enabled by
   `hfs`; it is already in TCN's dependency tree and under `cargo deny`.

Not changed: the handshake state machine, the token order (`e1` after the first DH token,
`ekem1` after `ee`), the constants, and the cipher, hash and DH code. snow's internal HKDF and
DH temporaries are not wiped (PROTOCOL §7.5.1).

## Upstream

Patches 1 to 5 are meant for an upstream pull request. When a snow release contains an
equivalent, TCN drops this directory and the `[patch.crates-io]` entries.
