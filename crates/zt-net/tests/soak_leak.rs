//! R-6 soak, attack on the gate itself (R6-E5): a leak injected in every session (a descriptor,
//! a task and 256 KiB) must make the gate fail, or the nightly soak proves nothing. A separate
//! test binary, so the injected leak never pollutes another test's process.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;
mod soak_support;

use std::time::Duration;

use soak_support::{Limits, Plan, check, report, run};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gate_catches_an_injected_leak() {
    let r = run(Plan {
        duration: Duration::from_secs(10),
        clients: 4,
        reload_every: Duration::from_secs(3),
        restart_every: Duration::from_secs(60),
        sample_every: Duration::from_millis(250),
        inject_leak: true,
        bulk: false,
    })
    .await;
    assert!(
        r.sessions >= 20,
        "only {} sessions ({} failed)",
        r.sessions,
        r.failures
    );
    let verdict = check(&r.under_load, &r.baseline, &r.quiescent, Limits::default());
    let err = verdict.expect_err(&format!("the gate missed the leak:\n{}", report(&r)));
    // Every resource the gate watches must fire: one that stopped firing would go unnoticed
    // (review 0013, A13-10).
    assert!(
        err.contains("fds") && err.contains("tasks") && err.contains("rss"),
        "{err}"
    );
}
