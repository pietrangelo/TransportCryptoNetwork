//! Build guard for the ML-KEM backend (finding A8-6 of review 0008).
//!
//! `libcrux-ml-kem` enables its NEON backend on every aarch64 build unless
//! `LIBCRUX_DISABLE_SIMD128` is `1`, `y` or `Y`. That backend is not covered by the formal
//! verification (docs/analysis/pq.md §5), so TCN sets the variable in `.cargo/config.toml`
//! (`force = true`). That file is only read when cargo runs from inside the repository: this
//! script refuses an aarch64 build that does not see the variable (for example
//! `cargo build --manifest-path …` from elsewhere, or `cargo install --git`), whatever the
//! working directory.
//!
//! It cannot fix a stale `target` directory whose libcrux build scripts already ran without
//! the variable (they emit no `rerun-if-env-changed`); the release workflow checks their
//! output.
#![allow(clippy::print_stdout)]

fn main() {
    println!("cargo::rerun-if-env-changed=LIBCRUX_DISABLE_SIMD128");
    println!("cargo::rerun-if-env-changed=LIBCRUX_ENABLE_SIMD128");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let disabled = matches!(
        std::env::var("LIBCRUX_DISABLE_SIMD128").as_deref(),
        Ok("1" | "y" | "Y")
    );
    if arch == "aarch64" && !disabled {
        println!(
            "cargo::error=aarch64 builds of TCN need LIBCRUX_DISABLE_SIMD128=1 (the unverified \
             NEON backend of libcrux-ml-kem must stay off): build from the repository root, \
             which reads .cargo/config.toml, or export the variable"
        );
    }
}
