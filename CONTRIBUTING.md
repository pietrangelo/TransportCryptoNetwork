# Contributing

## Language: English only

Everything committed to this repository is written in English:

- code comments, doc comments (`///`, `//!`) and CLI help text;
- `README.md`, `SECURITY.md`, everything under `docs/` (including adversary reviews in
  `docs/adversary/`) and any other Markdown file;
- comments in configuration files (Cargo, CI workflows, systemd units);
- error and log messages, commit messages and pull request descriptions.

This applies to new and edited text alike. When you touch a file that still contains text in
another language, translate it in the same change.

## Methodology

Development follows the adversarial TDD cycle described in
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md): failing spec and attack tests first, then the
implementation, then an independent adversary review logged in `docs/adversary/`.

Before opening a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

Security issues are reported privately, as described in [`SECURITY.md`](SECURITY.md).
