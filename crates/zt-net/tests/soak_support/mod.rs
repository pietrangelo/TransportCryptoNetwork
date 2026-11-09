//! The soak harness and its leak gate (resilience.md §5.7, R6-E5): a relay, an agent and its
//! echoing sshd on real localhost sockets, clients opening sessions in a loop, the relay
//! restarted and its policy reloaded on a schedule; file descriptors, resident memory and live
//! tasks sampled throughout. The gate fails on growth, so a leak in any of them breaks CI.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zt_crypto::Identity;
use zt_domain::trust::CertTrust;
use zt_net::Revocable;
use zt_net::relay::RelayServer;

use crate::common;

/// One measurement of the process.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Seconds since the start of the run.
    pub at: f64,
    pub fds: usize,
    pub rss: usize,
    pub tasks: usize,
}

/// The process now.
pub fn sample(start: Instant) -> Sample {
    let fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: usize = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    let tasks = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    Sample {
        at: start.elapsed().as_secs_f64(),
        fds,
        rss: pages * 4096,
        tasks,
    }
}

/// How much growth the gate tolerates.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// File descriptors gained over the measured window (trend) or after the load stopped.
    pub fds: f64,
    /// Live tasks gained.
    pub tasks: f64,
    /// Resident bytes gained over the measured window (trend).
    pub rss: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fds: 8.0,
            tasks: 16.0,
            rss: 24.0 * 1024.0 * 1024.0,
        }
    }
}

/// Least-squares slope of `y` over `x`.
fn slope(points: &[(f64, f64)]) -> f64 {
    let n = points.len() as f64;
    if points.len() < 2 {
        return 0.0;
    }
    let mx = points.iter().map(|p| p.0).sum::<f64>() / n;
    let my = points.iter().map(|p| p.1).sum::<f64>() / n;
    let num: f64 = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    let den: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if den == 0.0 { 0.0 } else { num / den }
}

/// The leak gate: over the samples taken under load (the first quarter is warm-up), the trend of
/// each resource projected over the window must stay within `limits`; and once the load has
/// stopped (`quiescent`), descriptors and tasks must be back near `baseline`.
pub fn check(
    under_load: &[Sample],
    baseline: &Sample,
    quiescent: &Sample,
    limits: Limits,
) -> Result<(), String> {
    let mut problems = Vec::new();
    let skip = under_load.len() / 4;
    let window = &under_load[skip..];
    if window.len() >= 3 {
        let span = window.last().unwrap().at - window.first().unwrap().at;
        for (name, value, limit) in [
            (
                "fds",
                (|s: &Sample| s.fds as f64) as fn(&Sample) -> f64,
                limits.fds,
            ),
            ("tasks", |s: &Sample| s.tasks as f64, limits.tasks),
            ("rss", |s: &Sample| s.rss as f64, limits.rss),
        ] {
            let points: Vec<_> = window.iter().map(|s| (s.at, value(s))).collect();
            let growth = slope(&points) * span;
            if growth > limit {
                problems.push(format!(
                    "{name} grows by {growth:.0} over {span:.0} s under load (limit {limit:.0})"
                ));
            }
        }
    }
    if quiescent.fds as f64 > baseline.fds as f64 + limits.fds {
        problems.push(format!(
            "{} fds after the load stopped, {} before",
            quiescent.fds, baseline.fds
        ));
    }
    if quiescent.tasks as f64 > baseline.tasks as f64 + limits.tasks {
        problems.push(format!(
            "{} tasks after the load stopped, {} before",
            quiescent.tasks, baseline.tasks
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// What a soak run does.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// How long the load runs.
    pub duration: Duration,
    /// Concurrent client loops.
    pub clients: usize,
    /// Every how often the policy is reloaded (`SIGHUP` in production).
    pub reload_every: Duration,
    /// Every how often the relay is restarted (drain, then a new relay on the same port).
    pub restart_every: Duration,
    /// Every how often a sample is taken.
    pub sample_every: Duration,
    /// Inject a leak in every session (a descriptor, a task and 256 KiB): the gate must fail.
    pub inject_leak: bool,
}

/// What a run measured.
#[derive(Debug)]
pub struct Run {
    pub baseline: Sample,
    pub under_load: Vec<Sample>,
    pub quiescent: Sample,
    pub sessions: u64,
    pub failures: u64,
}

/// Runs the soak `plan` and returns its samples.
pub async fn run(plan: Plan) -> Run {
    let start = Instant::now();
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let relay_id = Identity::generate().unwrap();
    let relay_key = relay_id.public_key();
    let relay_secret = relay_id.to_secret_hex();
    let policy = common::relay_policy(
        &agent.fingerprint(),
        &[client.fingerprint()],
        CertTrust::default(),
    );
    let (policy_rx, policy_tx) = Revocable::new(policy.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // The relay, restarted on the same port every `restart_every`.
    let stop = Arc::new(AtomicBool::new(false));
    let relay_task = {
        let (stop, policy_rx) = (Arc::clone(&stop), policy_rx.clone());
        let secret = relay_secret.to_string();
        tokio::spawn(async move {
            let mut listener = Some(listener);
            while !stop.load(Ordering::Relaxed) {
                let l = match listener.take() {
                    Some(l) => l,
                    None => loop {
                        if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
                            break l;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    },
                };
                let id = Identity::from_secret_hex(&secret).unwrap();
                let server =
                    RelayServer::with_acceptor(l, id, policy_rx.clone(), common::relay_config())
                        .unwrap();
                let restart_every = plan.restart_every;
                let stop2 = Arc::clone(&stop);
                let shutdown = async move {
                    let until = tokio::time::Instant::now() + restart_every;
                    while tokio::time::Instant::now() < until && !stop2.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                };
                let _ = server.run_until(shutdown, Duration::from_secs(1)).await;
            }
        })
    };

    let (ssh, _sshd) = common::counting_echo().await;
    let (clients_rx, _clients_tx) = Revocable::new(common::agent_clients(
        &[client.fingerprint()],
        CertTrust::default(),
    ));
    let agent_task = tokio::spawn(zt_net::agent::run(
        Arc::new(zt_crypto::Keyring::single(common::copy_of(&agent))),
        zt_net::agent::AgentConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: addr.to_string(),
                public_key: relay_key.into(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: common::node("web-01"),
            ssh_target: ssh.to_string(),
            authorized_clients: clients_rx,
            timeouts: common::timeouts(),
            max_streams: 64,
            client_suites: zt_domain::AcceptedSuites::only(zt_domain::HandshakeSuite::NoiseIk25519),
            identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
            reconnect: zt_application::reconnect::ReconnectConfig {
                base: Duration::from_millis(100),
                cap: Duration::from_millis(500),
                spread: Duration::ZERO,
                stable_after: Duration::from_secs(1),
            },
        },
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let baseline = sample(start);

    let sessions = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let load_until = tokio::time::Instant::now() + plan.duration;
    let mut workers = Vec::new();
    for _ in 0..plan.clients {
        let (client, sessions, failures) = (
            Arc::clone(&client),
            Arc::clone(&sessions),
            Arc::clone(&failures),
        );
        let config = zt_net::client::ClientConfig {
            relays: vec![zt_net::RelayEndpoint {
                address: addr.to_string(),
                public_key: relay_key.into(),
                suite: zt_domain::HandshakeSuite::NoiseIk25519,
            }],
            node: common::node("web-01"),
            node_key: agent.public_key().into(),
            node_suite: zt_domain::HandshakeSuite::NoiseIk25519,
            certificate: None,
            timeouts: common::timeouts(),
            failover: zt_net::client::FailoverConfig::default(),
            require_outer_suite: None,
        };
        workers.push(tokio::spawn(async move {
            while tokio::time::Instant::now() < load_until {
                if one_session(&client, &config).await {
                    sessions.fetch_add(1, Ordering::Relaxed);
                } else {
                    failures.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if plan.inject_leak {
                    inject_leak();
                }
            }
        }));
    }

    let mut under_load = Vec::new();
    let mut next_reload = tokio::time::Instant::now() + plan.reload_every;
    while tokio::time::Instant::now() < load_until {
        tokio::time::sleep(plan.sample_every).await;
        under_load.push(sample(start));
        if tokio::time::Instant::now() >= next_reload {
            policy_tx.replace(policy.clone());
            next_reload = tokio::time::Instant::now() + plan.reload_every;
        }
    }
    for w in workers {
        let _ = w.await;
    }
    // Let closes, drains and the agent's stream tasks finish.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let quiescent = sample(start);
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(5), relay_task).await;
    agent_task.abort();
    Run {
        baseline,
        under_load,
        quiescent,
        sessions: sessions.load(Ordering::Relaxed),
        failures: failures.load(Ordering::Relaxed),
    }
}

/// One session: connect, 4 KiB through the echo, close.
async fn one_session(client: &Arc<Identity>, config: &zt_net::client::ClientConfig) -> bool {
    let (mut app, local) = tokio::io::duplex(64 * 1024);
    let (client, config) = (Arc::clone(client), config.clone());
    let task = tokio::spawn(async move { zt_net::client::connect(&client, &config, local).await });
    let payload = [0x42_u8; 4096];
    let ok = tokio::time::timeout(Duration::from_secs(10), async {
        app.write_all(&payload).await.ok()?;
        let mut back = [0_u8; 4096];
        app.read_exact(&mut back).await.ok()?;
        (back == payload).then_some(())
    })
    .await
    .is_ok_and(|r| r.is_some());
    drop(app);
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    ok
}

/// A descriptor, a task and 256 KiB that never go away.
fn inject_leak() {
    std::mem::forget(std::fs::File::open("/dev/null").unwrap());
    tokio::spawn(std::future::pending::<()>());
    let leaked: &'static mut [u8] = Box::leak(vec![1_u8; 256 * 1024].into_boxed_slice());
    std::hint::black_box(leaked);
}

/// The soak length from `TCN_SOAK_SECS`, or `default`.
pub fn duration_from_env(default: Duration) -> Duration {
    std::env::var("TCN_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(default, Duration::from_secs)
}

/// Prints the samples as CSV (kept by the nightly job as an artifact).
pub fn report(run: &Run) -> String {
    let mut out = String::from("at_s,fds,rss_bytes,tasks\n");
    for s in std::iter::once(&run.baseline)
        .chain(&run.under_load)
        .chain(std::iter::once(&run.quiescent))
    {
        out.push_str(&format!("{:.1},{},{},{}\n", s.at, s.fds, s.rss, s.tasks));
    }
    out
}
