//! R-6 soak (resilience.md §5.7, R6-E5): the leak gate on synthetic series, a short soak run in
//! every CI build, and the long soak the nightly workflow runs (`--ignored`, `TCN_SOAK_SECS`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::cast_precision_loss
)]

mod common;
mod soak_support;

use std::time::Duration;

use soak_support::{
    Counters, Limits, Plan, Sample, check, check_counters, duration_from_env, report, run,
};

fn series(n: usize, f: impl Fn(usize) -> (usize, usize, usize)) -> Vec<Sample> {
    (0..n)
        .map(|i| {
            let (fds, rss, tasks) = f(i);
            Sample {
                at: i as f64,
                fds,
                rss,
                tasks,
            }
        })
        .collect()
}

fn flat() -> Sample {
    Sample {
        at: 0.0,
        fds: 40,
        rss: 20 << 20,
        tasks: 12,
    }
}

/// A process that churns (sessions open and close, memory moves up and down) but does not grow
/// passes the gate.
#[test]
fn the_gate_passes_a_steady_process() {
    let load = series(60, |i| {
        (40 + i % 7, (20 << 20) + (i % 5) * (1 << 20), 12 + i % 9)
    });
    assert_eq!(check(&load, &flat(), &flat(), Limits::default()), Ok(()));
}

/// Memory that settles after warm-up (allocator arenas, caches filling) is not a leak.
#[test]
fn the_gate_ignores_the_warm_up() {
    let load = series(60, |i| {
        (40, if i < 10 { (20 + i * 4) << 20 } else { 60 << 20 }, 12)
    });
    assert_eq!(check(&load, &flat(), &flat(), Limits::default()), Ok(()));
}

/// One descriptor more per sample, steadily: a descriptor leak.
#[test]
fn the_gate_fails_on_a_descriptor_leak() {
    let load = series(60, |i| (40 + i, 20 << 20, 12));
    let err = check(&load, &flat(), &flat(), Limits::default()).unwrap_err();
    assert!(err.contains("fds"), "{err}");
}

/// Tasks that pile up: a task leak.
#[test]
fn the_gate_fails_on_a_task_leak() {
    let load = series(60, |i| (40, 20 << 20, 12 + i));
    let err = check(&load, &flat(), &flat(), Limits::default()).unwrap_err();
    assert!(err.contains("tasks"), "{err}");
}

/// Resident memory growing steadily past the limit: a memory leak.
#[test]
fn the_gate_fails_on_memory_growth() {
    let load = series(60, |i| (40, (20 << 20) + i * (1 << 20), 12));
    let err = check(&load, &flat(), &flat(), Limits::default()).unwrap_err();
    assert!(err.contains("rss"), "{err}");
}

/// Descriptors or tasks that stay after the load stopped are leaks even without a trend.
#[test]
fn the_gate_fails_when_resources_stay_after_the_load() {
    let load = series(60, |_| (40, 20 << 20, 12));
    let after = Sample {
        fds: 80,
        tasks: 50,
        ..flat()
    };
    let err = check(&load, &flat(), &after, Limits::default()).unwrap_err();
    assert!(
        err.contains("fds after") && err.contains("tasks after"),
        "{err}"
    );
}

/// Review 0013, A13-7: the R-6 accounting must be back to zero once the load stops. A leaked
/// reservation costs no memory, so only the counters can show it: it shrinks the budget until
/// every stream is refused.
#[test]
fn the_gate_fails_when_the_budget_is_still_held_after_the_load() {
    assert_eq!(check_counters(&Counters::default()), Ok(()));
    let held = Counters {
        agent_buffer_bytes: 4096.0,
        ..Counters::default()
    };
    let err = check_counters(&held).unwrap_err();
    assert!(err.contains("tcn_agent_buffer_bytes"), "{err}");
    let queued = Counters {
        relay_queue_bytes: 1.0,
        relay_streams: 1.0,
        ..Counters::default()
    };
    let err = check_counters(&queued).unwrap_err();
    assert!(
        err.contains("tcn_relay_queue_bytes") && err.contains("tcn_relay_streams"),
        "{err}"
    );
    for c in [
        Counters {
            agent_sessions: 1.0,
            ..Counters::default()
        },
        Counters {
            relay_client_connections: 1.0,
            ..Counters::default()
        },
    ] {
        assert!(check_counters(&c).is_err());
    }
}

/// The short soak, in every CI build: sessions in a loop for about fifteen seconds, the relay
/// restarted and the policy reloaded meanwhile; no leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn soak_short() {
    let r = run(Plan {
        duration: Duration::from_secs(15),
        clients: 4,
        reload_every: Duration::from_secs(2),
        restart_every: Duration::from_secs(5),
        sample_every: Duration::from_millis(500),
        inject_leak: false,
        bulk: true,
    })
    .await;
    eprintln!("{}", report(&r));
    assert!(
        r.sessions >= 20,
        "only {} sessions ({} failed)",
        r.sessions,
        r.failures
    );
    check(&r.under_load, &r.baseline, &r.quiescent, Limits::default()).unwrap();
    // A13-7: the budgets are back to zero, and the bulk sessions made windows grow (the R-6
    // paths ran).
    check_counters(&r.counters).unwrap();
    assert!(r.bulk_sessions >= 1, "no bulk session completed");
    assert!(
        r.window_grows >= 1.0,
        "no window grew: the R-6 paths never ran"
    );
}

/// The nightly soak: `TCN_SOAK_SECS` long (default 30 minutes), bounded by the workflow's
/// timeout; the CSV goes to `TCN_SOAK_REPORT` when set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long soak, run by the nightly workflow"]
async fn soak_long() {
    let duration = duration_from_env(Duration::from_secs(30 * 60));
    let r = run(Plan {
        duration,
        clients: 8,
        reload_every: Duration::from_secs(10),
        restart_every: Duration::from_secs(60),
        sample_every: Duration::from_secs(5),
        inject_leak: false,
        bulk: true,
    })
    .await;
    let csv = report(&r);
    if let Ok(path) = std::env::var("TCN_SOAK_REPORT") {
        std::fs::write(path, &csv).unwrap();
    }
    eprintln!("{} sessions, {} failures", r.sessions, r.failures);
    // Restarts cost a few sessions each, never most of them.
    assert!(
        r.sessions > 0 && r.failures * 10 <= r.sessions,
        "{} sessions, {} failures",
        r.sessions,
        r.failures
    );
    check(&r.under_load, &r.baseline, &r.quiescent, Limits::default()).unwrap();
    check_counters(&r.counters).unwrap();
}
