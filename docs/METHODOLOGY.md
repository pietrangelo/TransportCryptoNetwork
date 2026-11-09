# Development methodology

TCN is a network-exposed security component: every line of code is written on the assumption that
there is an attacker on the other end of the socket. The methodology combines three practices.

## 1. Architecture: hexagonal DDD

| Crate | Layer | Rule |
| :- | :- | :- |
| `zt-domain` | Domain core | pure: no async, no I/O, no clock, no randomness |
| `zt-application` | Application layer | sans-IO use cases (relay core); time and randomness come in as parameters or ports |
| `zt-proto` | Adapter (wire format) | sans-IO; tokio integration is behind the `codec` feature |
| `zt-crypto` | Adapter (cryptography) | sans-IO; typestate handshake |
| `zt-net` | Adapter (network, files) | tokio; every I/O has a timeout, every queue is bounded |
| `zt-relay`, `zt-agent`, `zt-client` | Composition root | CLI and wiring |

**Invalid states are unrepresentable**: value objects can only be built through validating
`TryFrom`/factories; an existing `Frame` is valid by construction, so the encoder is infallible
and the decoder is the only place where input is rejected.

## 2. Development cycle: Adversarial TDD

Every feature follows five steps. The first two produce failing tests, which must be committed
**before** the implementation (the git history proves it).

```
 1. RED (specification)  tests of the expected behaviour
 2. RED (adversary)      attack tests: input an attacker would use
 3. GREEN                minimal implementation that makes them all pass
 4. REFACTOR             clean-up with tests green
 5. ADVERSARY REVIEW     independent review that tries to break the code;
                         every finding becomes a regression test or a backlog item
```

### The adversary pattern

The adversary's role is separate from the implementer's: whoever writes the attack tests or the
review must not start from the assumptions of whoever wrote the code.

**Step 2: attack catalogue.** For every surface that accepts external input, the adversary
fills in a table and writes at least one test per row:

| Category | Guiding questions |
| :- | :- |
| Parsing | boundary lengths (0, 1, max, max+1, `u16::MAX`), unknown types, versions, mutually inconsistent fields |
| Resources | can I make it allocate, buffer or keep alive more than I send? can I keep it open without sending? |
| State | can I send a message in the wrong state, twice, or after close? |
| Identity | can I claim to be someone else, reuse a session, confuse two similar names? |
| Side channels | comparison timing, error messages, logs: do they reveal anything? |
| Malleability | does the same message have more than one valid encoding? |

**Step 5: adversary review.** With tests green, an independent review (a different person or a
separate agent given the code, not the author's conclusions) tries to violate the stated
guarantees. The outcome is recorded in `docs/adversary/NNNN-<area>.md` with: surface, attack
hypothesis, outcome (*mitigated by test X*, *accepted with rationale*, *open → backlog*). An open
finding blocks the merge if its severity is high.

**Continuous fuzzing.** Property tests (`proptest`) are the automated version of the adversary:
they generate arbitrary input and structured input that gets past the first filters.
`cargo-fuzz` (in `fuzz/`) covers decoder, handshake, transport and configuration parser; CI runs
it on every pull request. A crash first becomes a regression test, then a fix.

## 3. Code rules

- `#![forbid(unsafe_code)]` in every crate and `unsafe_code = "forbid"` at workspace level.
- Forbidden in production: `unwrap`, `expect`, `panic!`, `todo!`, indexing with `[]`,
  arithmetic that can overflow, truncating casts (clippy lints at `deny` level).
  Tests re-enable them locally.
- Release: `panic = "abort"`, `overflow-checks = true`, fat LTO, a single codegen unit, symbols
  stripped.
- Secrets: no `Clone`, `ZeroizeOnDrop`, redacted `Debug`, comparisons with `subtle`.
- Logs: metadata only. No payload, no secret, no received byte in an error message. All logs go
  to stderr (`zt-client`'s stdout is the SSH channel).

## 4. Definition of done

- [ ] specification and attack tests committed before the implementation
- [ ] `cargo test --workspace --all-features` green
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] adversary review recorded in `docs/adversary/`
- [ ] `cargo deny check` clean (advisories, licences, sources)
- [ ] protocol documentation updated if the format changes
- [ ] comments, docs, commit message and PR description in English (see `CONTRIBUTING.md`)
