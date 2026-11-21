//! Relay code hardening (docs/analysis/relay-hardening.md §2(a), attack catalogue §4.1):
//! listen backlog (C-1, C-2), accept-error classification (C-3, C-4), descriptor budget (C-5),
//! queue budget under the shipped sandbox (C-6) and the blocking pool cap (C-7).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::single_match_else,
    missing_docs
)]

mod common;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::DuplexStream;
use zt_application::admission::AdmissionConfig;
use zt_crypto::Identity;
use zt_domain::trust::CertTrust;
use zt_net::budget::{
    MAX_QUEUE_BUDGET, MIN_QUEUE_BUDGET, cgroup_memory_limit, effective_memory, queue_budget_for,
    sysinfo_memory,
};
use zt_net::config::{ConfigError, parse_relay_settings};
use zt_net::metrics::{RelayMetrics, Snapshot};
use zt_net::net::{AcceptBackoff, AcceptErrorKind, Acceptor, classify_accept_error};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::{Revocable, lifecycle};

const MIB: u64 = 1024 * 1024;

fn metric(metrics: &RelayMetrics, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    Snapshot::parse(&metrics.render())
        .unwrap()
        .get(name, labels)
}

// ---------------------------------------------------------------------------------------------
// C-1, C-2: listen backlog
// ---------------------------------------------------------------------------------------------

/// C-1: a reconnect wave of 512 peers while the accept loop is not accepting: every connect
/// completes within one second (with mio's fixed 128 the kernel drops SYNs and peers wait
/// for the 1 s retransmission).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_listen_backlog_holds_a_reconnect_wave() {
    let policy = common::relay_policy(
        &Identity::generate().unwrap().fingerprint(),
        &[],
        CertTrust::new(),
    );
    let (rx, _updater) = Revocable::new(policy);
    let config = common::relay_config();
    assert_eq!(config.listen_backlog, 4096);
    // Bound but never run: nothing accepts, so only the kernel's accept queue holds them.
    let server = RelayServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::generate().unwrap(),
        rx,
        config,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let started = std::time::Instant::now();
    let connects: Vec<_> = (0..512)
        .map(|_| tokio::spawn(tokio::net::TcpStream::connect(addr)))
        .collect();
    let mut held = Vec::new();
    for c in connects {
        let stream = tokio::time::timeout(Duration::from_secs(5), c)
            .await
            .expect("connect hung")
            .unwrap()
            .unwrap();
        held.push(stream);
    }
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(900),
        "512 connects took {took:?}: SYNs were dropped"
    );
    drop(server);
}

/// C-2: `[network] listen_backlog` is bounded; refused values are configuration errors.
#[test]
fn relay_toml_bounds_the_listen_backlog() {
    assert_eq!(
        parse_relay_settings("relay.toml", "")
            .unwrap()
            .listen_backlog,
        4096
    );
    for ok in [128_u32, 4096, 65_535] {
        let text = format!("[network]\nlisten_backlog = {ok}\n");
        assert_eq!(
            parse_relay_settings("relay.toml", &text)
                .unwrap()
                .listen_backlog,
            ok
        );
    }
    for bad in ["0", "127", "65536", "-1", "4294967296", "\"4096\""] {
        let text = format!("[network]\nlisten_backlog = {bad}\n");
        let err = parse_relay_settings("relay.toml", &text).unwrap_err();
        assert!(matches!(err, ConfigError::Syntax { .. }), "{bad}: {err}");
    }
    let err = parse_relay_settings("relay.toml", "[network]\nbacklog = 4096\n").unwrap_err();
    assert!(matches!(err, ConfigError::Syntax { .. }), "{err}");
}

#[test]
fn the_relay_config_carries_the_backlog_of_relay_toml() {
    let s = parse_relay_settings("relay.toml", "[network]\nlisten_backlog = 1024\n").unwrap();
    assert_eq!(s.listen_backlog, 1024);
    assert_eq!(RelayConfig::default().listen_backlog, 4096);
}

// ---------------------------------------------------------------------------------------------
// C-3, C-4: accept errors
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
fn errno(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

#[cfg(unix)]
#[test]
fn accept_errors_are_classified() {
    use rustix::io::Errno;
    for e in [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM] {
        assert_eq!(
            classify_accept_error(&errno(e)),
            AcceptErrorKind::Resource,
            "{e:?}"
        );
    }
    for e in [
        Errno::CONNABORTED,
        Errno::PROTO,
        Errno::PERM,
        Errno::NETDOWN,
        Errno::NOPROTOOPT,
        Errno::HOSTDOWN,
        Errno::NONET,
        Errno::HOSTUNREACH,
        Errno::OPNOTSUPP,
        Errno::NETUNREACH,
        Errno::TIMEDOUT,
        Errno::CONNRESET,
        Errno::INTR,
    ] {
        assert_eq!(
            classify_accept_error(&errno(e)),
            AcceptErrorKind::Connection,
            "{e:?}"
        );
    }
    assert_eq!(
        classify_accept_error(&std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
        AcceptErrorKind::Resource
    );
}

#[test]
fn the_accept_backoff_doubles_to_one_second_and_resets() {
    let mut b = AcceptBackoff::new();
    let delays: Vec<_> = (0..9).map(|_| b.failed().as_millis()).collect();
    assert_eq!(delays, [10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
    b.succeeded();
    assert_eq!(b.failed(), Duration::from_millis(10));
    assert_eq!(b.failed(), Duration::from_millis(20));
}

enum Step {
    Fail(std::io::Error),
    Accept(DuplexStream),
}

/// An acceptor that plays a script, then waits forever; it records when each `accept` is
/// called, on the runtime's clock.
struct Scripted {
    steps: VecDeque<Step>,
    calls: Arc<Mutex<Vec<tokio::time::Instant>>>,
    /// The peers' ends of the accepted streams, kept open.
    _peers: Vec<DuplexStream>,
}

impl Scripted {
    fn new(
        script: impl IntoIterator<Item = Option<std::io::Error>>,
    ) -> (Self, Arc<Mutex<Vec<tokio::time::Instant>>>) {
        let mut peers = Vec::new();
        let steps = script
            .into_iter()
            .map(|s| match s {
                Some(err) => Step::Fail(err),
                None => {
                    let (ours, theirs) = tokio::io::duplex(1024);
                    peers.push(theirs);
                    Step::Accept(ours)
                }
            })
            .collect();
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                steps,
                calls: Arc::clone(&calls),
                _peers: peers,
            },
            calls,
        )
    }
}

impl Acceptor for Scripted {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> std::io::Result<(DuplexStream, SocketAddr)> {
        self.calls.lock().unwrap().push(tokio::time::Instant::now());
        match self.steps.pop_front() {
            Some(Step::Fail(err)) => Err(err),
            Some(Step::Accept(stream)) => Ok((stream, "192.0.2.10:40000".parse().unwrap())),
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:7443".parse().unwrap())
    }
}

fn scripted_relay(acceptor: Scripted) -> Arc<RelayMetrics> {
    let policy = common::relay_policy(
        &Identity::generate().unwrap().fingerprint(),
        &[],
        CertTrust::new(),
    );
    let (rx, updater) = Revocable::new(policy);
    std::mem::forget(updater);
    let config = common::relay_config();
    let metrics = Arc::clone(&config.metrics);
    let server =
        RelayServer::with_acceptor(acceptor, Identity::generate().unwrap(), rx, config).unwrap();
    tokio::spawn(server.run());
    metrics
}

/// C-3: per-connection errors are retried at once: 100 `ECONNABORTED` do not delay the next
/// connection.
#[cfg(unix)]
#[tokio::test]
async fn transient_accept_errors_do_not_stall_the_accept_loop() {
    let script = (0..100)
        .map(|_| Some(errno(rustix::io::Errno::CONNABORTED)))
        .chain([None]);
    let (acceptor, calls) = Scripted::new(script);
    let metrics = scripted_relay(acceptor);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while calls.lock().unwrap().len() < 102 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        102,
        "the accept loop stalled on transient errors"
    );
    let took = calls[100] - calls[0];
    assert!(took < Duration::from_millis(100), "{took:?}");
    assert_eq!(
        metric(
            &metrics,
            "tcn_relay_accept_errors_total",
            &[("kind", "connection")]
        ),
        Some(100.0)
    );
    assert_eq!(
        metric(
            &metrics,
            "tcn_relay_accept_errors_total",
            &[("kind", "resource")]
        ),
        Some(0.0)
    );
}

/// C-4: `EMFILE` backs off exponentially (10 ms to 1 s), an accepted connection resets the
/// back-off, and the loop recovers.
#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn emfile_backs_off_and_recovers() {
    let emfile = || Some(errno(rustix::io::Errno::MFILE));
    let script = (0..8)
        .map(|_| emfile())
        .chain([None])
        .chain([emfile(), emfile()]);
    let (acceptor, calls) = Scripted::new(script);
    let metrics = scripted_relay(acceptor);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 12, "the loop did not recover");
    let gaps: Vec<u128> = calls
        .windows(2)
        .map(|w| (w[1] - w[0]).as_millis())
        .collect();
    // Eight failures, the accepted connection (no wait after it), then two failures again
    // starting from 10 ms.
    assert_eq!(gaps, [10, 20, 40, 80, 160, 320, 640, 1000, 0, 10, 20]);
    assert_eq!(
        metric(
            &metrics,
            "tcn_relay_accept_errors_total",
            &[("kind", "resource")]
        ),
        Some(10.0)
    );
}

// ---------------------------------------------------------------------------------------------
// C-5: descriptors
// ---------------------------------------------------------------------------------------------

#[test]
fn the_descriptor_budget_covers_both_pools_and_the_header_pool() {
    let a = AdmissionConfig::default();
    let direct = (a.max_preauth + a.max_established + 64) as u64;
    let proxy = (2 * a.max_preauth + a.max_established + 64) as u64;
    assert_eq!(lifecycle::descriptors_needed(&a, false), direct);
    assert_eq!(lifecycle::descriptors_needed(&a, true), proxy);
    // The shipped unit's LimitNOFILE covers the defaults in both modes.
    assert!(proxy <= 16_384);
    let big = AdmissionConfig {
        max_preauth: 1_048_576,
        max_established: 1_048_576,
        ..AdmissionConfig::default()
    };
    assert_eq!(
        lifecycle::descriptors_needed(&big, true),
        3 * 1_048_576 + 64
    );
}

#[cfg(unix)]
#[test]
fn the_descriptor_limit_is_the_soft_rlimit() {
    let soft = rustix::process::getrlimit(rustix::process::Resource::Nofile).current;
    assert_eq!(lifecycle::descriptor_limit(), soft);
}

// ---------------------------------------------------------------------------------------------
// C-6: queue budget under the sandbox
// ---------------------------------------------------------------------------------------------

fn files(entries: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
    let map: HashMap<String, String> = entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |p: &Path| map.get(p.to_str()?).cloned()
}

const UNIT: &str = "0::/system.slice/zt-relay.service\n";

#[test]
fn the_budget_follows_the_own_cgroup_limit() {
    // MemoryMax=512M on the unit: the root cgroup's memory.max does not exist.
    let read = files(&[
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
            "536870912\n",
        ),
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.high",
            "max\n",
        ),
        ("/sys/fs/cgroup/system.slice/memory.max", "max\n"),
        ("/sys/fs/cgroup/system.slice/memory.high", "max\n"),
    ]);
    let limit = cgroup_memory_limit(UNIT, read);
    assert_eq!(limit, Some(512 * MIB));
    let memory = effective_memory(Some(8 * 1024 * MIB), limit);
    assert_eq!(memory, Some(512 * MIB));
    assert_eq!(queue_budget_for(memory), 128 * 1024 * 1024);
}

#[test]
fn memory_high_and_ancestors_lower_the_limit() {
    // MemoryHigh=70% below MemoryMax=80%.
    let read = files(&[
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
            "4294967296\n",
        ),
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.high",
            "3758096384\n",
        ),
    ]);
    assert_eq!(cgroup_memory_limit(UNIT, read), Some(3_758_096_384));
    // A slice limit above the unit.
    let read = files(&[
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
            "max\n",
        ),
        ("/sys/fs/cgroup/system.slice/memory.max", "1073741824\n"),
    ]);
    assert_eq!(cgroup_memory_limit(UNIT, read), Some(1024 * MIB));
    // Inside a cgroup namespace (a container) the own cgroup is "/" and the limit is at the
    // mount point itself.
    let read = files(&[("/sys/fs/cgroup/memory.max", "268435456\n")]);
    assert_eq!(cgroup_memory_limit("0::/\n", read), Some(256 * MIB));
}

#[test]
fn no_limit_unreadable_or_odd_cgroups_give_none() {
    let none = files(&[]);
    assert_eq!(cgroup_memory_limit(UNIT, &none), None);
    let unlimited = files(&[(
        "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
        "max\n",
    )]);
    assert_eq!(cgroup_memory_limit(UNIT, unlimited), None);
    // cgroup v1 only: not supported, no limit.
    let v1 = files(&[(
        "/sys/fs/cgroup/memory/foo/memory.limit_in_bytes",
        "1048576\n",
    )]);
    assert_eq!(
        cgroup_memory_limit("4:memory:/foo\n1:name=systemd:/foo\n", v1),
        None
    );
    // Garbage values are ignored, not trusted.
    let garbage = files(&[
        (
            "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
            "-1\n",
        ),
        ("/sys/fs/cgroup/system.slice/memory.max", "lots\n"),
    ]);
    assert_eq!(cgroup_memory_limit(UNIT, garbage), None);
    // A path that tries to leave the hierarchy is not followed.
    let escape = files(&[
        ("/sys/fs/memory.max", "1048576\n"),
        ("/etc/memory.max", "1\n"),
    ]);
    assert_eq!(cgroup_memory_limit("0::/../..\n", &escape), None);
    assert_eq!(cgroup_memory_limit("0::relative/path\n", &escape), None);
    assert_eq!(cgroup_memory_limit("", &escape), None);
}

#[test]
fn a_hybrid_hierarchy_uses_the_v2_line() {
    let read = files(&[(
        "/sys/fs/cgroup/system.slice/zt-relay.service/memory.max",
        "536870912\n",
    )]);
    let text = "12:memory:/system.slice/zt-relay.service\n0::/system.slice/zt-relay.service\n";
    assert_eq!(cgroup_memory_limit(text, read), Some(512 * MIB));
}

/// C-6: with `/proc/meminfo` hidden (`ProcSubset=pid`) the physical memory still comes from
/// `sysinfo(2)`, so the budget is bounded by the host and never the 1 GiB fallback.
#[test]
fn meminfo_hidden_still_gives_a_bounded_budget() {
    let physical = sysinfo_memory().expect("sysinfo(2) gives the physical memory");
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        let kb: u64 = meminfo
            .lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .unwrap()
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .unwrap();
        let from_meminfo = kb * 1024;
        let diff = physical.abs_diff(from_meminfo);
        assert!(diff <= from_meminfo / 100, "{physical} vs {from_meminfo}");
    }
    // A 512 MiB VPS without any cgroup limit: 128 MiB, not 1 GiB.
    assert_eq!(
        queue_budget_for(effective_memory(Some(512 * MIB), None)),
        128 * 1024 * 1024
    );
    // Neither known: the documented fallback.
    assert_eq!(
        queue_budget_for(effective_memory(None, None)),
        MAX_QUEUE_BUDGET
    );
    assert_eq!(effective_memory(None, Some(512 * MIB)), Some(512 * MIB));
    assert!(MIN_QUEUE_BUDGET <= zt_net::budget::default_queue_budget());
}

// ---------------------------------------------------------------------------------------------
// C-7: blocking pool
// ---------------------------------------------------------------------------------------------

#[test]
fn the_relay_runtime_caps_its_blocking_pool() {
    assert_eq!(lifecycle::MAX_BLOCKING_THREADS, 8);
    let runtime = lifecycle::relay_runtime().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    runtime.block_on(async {
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let (active, peak) = (Arc::clone(&active), Arc::clone(&peak));
                tokio::task::spawn_blocking(move || {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(40));
                    active.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
    });
    let peak = peak.load(Ordering::SeqCst);
    assert!(peak <= 8, "{peak} blocking threads at once");
    assert!(peak >= 2, "the pool still runs blocking work in parallel");
}
