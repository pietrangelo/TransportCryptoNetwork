# Fuzzing TCN

[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets on the surfaces
that read untrusted input. They require nightly; the crate is excluded from the workspace.

| Target | Surface | Verified properties |
| :- | :- | :- |
| `frame_decoder` | frame decoder, arbitrary bytes in arbitrary chunks | no panic; canonical encoding (an accepted frame re-encodes to the same bytes); no bytes consumed without a frame; decoder poisoned after an error |
| `noise_responder` | first IK message from an unauthenticated network, outer and end-to-end channel; half of the inputs are a modified authentic msg1, including with a payload (certificate) | no panic; an accepted msg1 reveals only the true identity of the initiator; the intact msg1 is accepted; the returned payload is the one sent; a payload beyond `MAX_CERT_LEN` is never accepted; with mode bit 3, the same with the hybrid suite end to end (PQ-1: `e1` read, `ekem1` written by `accept`), against an agent that accepts both suites, and the outer channel never accepts an end-to-end hybrid msg1; with bits 3 and 5, the hybrid suite on the outer channel (PQ-1, Phase 3) against a relay that accepts both suites, never valid end to end |
| `noise_initiator` | message 2 as the initiator receives it, classical or hybrid suite end to end (PQ-1: `ekem1` decrypted and decapsulated by the vendored snow); arbitrary bytes or a modified genuine msg2 | no panic; a msg2 that differs from the genuine one is never accepted; the genuine one is, with the responder's keys |
| `transport_decrypt` | forged transport messages interleaved with authentic ones, including across a rekey | no forgery accepted; a forgery does not desynchronise the channel |
| `config_parsers` | policy and authorized clients (with `[[authorities]]`), known nodes, client configuration, `revoked.toml` denylist, certificate file, `relay.toml` | no panic; an error does not echo long hexadecimal sequences from the file (keys pasted by mistake); an accepted `relay.toml` gives admission limits that validate |
| `relay_core` | sequences of connections (including with certificate claims), frames, disconnections, jumps of the monotonic clock and of the Unix clock (which advances and jumps), policy reloads with CA and denylist | no panic; nothing sent to a closed connection; after a reload no peer without a role stays connected; no connection with a certificate survives beyond `not_after`, a revoked serial or key, or the removal of the CA |
| `cert_decoder` | client certificate decoder (PROTOCOL §15.1), arbitrary bytes | no panic; an accepted certificate re-encodes identically (`encode_tbs` + signature); no error echoes bytes of the input |
| `cert_verify` | `verify_certificate` with fixed trust and peer; half of the inputs are a modified authentic certificate | no panic; an accepted input is byte for byte the authentic certificate, and the claims are its own; never accepted for another peer |
| `admission` | relay admission (PROTOCOL §10.1): accepts from few IPv4 addresses and IPv6 /48s, key confirmations of both roles, releases, failures, identity events, clock steps, summaries | no panic; `Admission::check_invariants` after every event (counters match the live connections, no cap exceeded); no ticket confirmed twice; releasing everything empties both pools |

```bash
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run frame_decoder -- -max_total_time=600
```

CI runs each target for 60 seconds on every pull request (job `fuzz`). A crash must be
turned into a regression test in the affected crate before the fix, as
Adversarial TDD requires (`docs/METHODOLOGY.md`). The dependencies in `fuzz/Cargo.lock` also go
through `cargo deny` (job `deny`), and the `build-test` job checks that the targets build with
the committed lock (`cargo check --locked --manifest-path fuzz/Cargo.toml --bins`, review 0008
finding A8-7): after a dependency change, run `cargo check` in `fuzz/` and commit the lock.
