//! R-5 observability, specification (resilience.md §5.5, review 0007 AP-21, D-10 as
//! corrected): counters and gauges written as a node_exporter **textfile** by the relay and the
//! agent (and optionally the client), atomically, at a configurable interval; no listening
//! socket anywhere; a `status` reader; fixed label sets only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

mod common;
mod observed;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{agent_clients, nodes, relay_config, relay_policy};
use zt_crypto::Identity;
use zt_domain::trust::CertTrust;
use zt_domain::{ClientGrant, HandshakeSuite};
use zt_net::metrics::{
    self, AgentMetrics, ClientMetrics, RelayMetrics, Snapshot, StatusError, write_textfile,
};

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zt-metrics-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn classical() -> &'static str {
    HandshakeSuite::NoiseIk25519.protocol_name()
}

// ---------------------------------------------------------------------------------------------
// Exposition format
// ---------------------------------------------------------------------------------------------

/// R5-M1: every family has `# HELP` and `# TYPE`, counters end in `_total`, and the output is
/// in the Prometheus text format 0.0.4 that node_exporter's textfile collector reads.
#[test]
fn relay_metrics_render_in_the_text_exposition_format() {
    let m = RelayMetrics::new();
    let text = m.render();
    assert!(text.ends_with('\n'), "{text}");
    for family in [
        "tcn_build_info",
        "tcn_process_start_time_seconds",
        "tcn_metrics_interval_seconds",
        "tcn_metrics_last_write_timestamp_seconds",
        "tcn_config_generation",
        "tcn_reloads_total",
        "tcn_watchdog_progress_total",
        "tcn_draining",
        "tcn_relay_preauth_failures_total",
        "tcn_relay_admission_refusals_total",
        "tcn_relay_handshakes_total",
        "tcn_relay_auth_failures_total",
        "tcn_relay_connections",
        "tcn_relay_agents_registered",
        "tcn_relay_streams",
        "tcn_relay_open_rejects_total",
        "tcn_relay_stream_closes_total",
        "tcn_relay_forwarded_bytes_total",
        "tcn_relay_queue_bytes",
        "tcn_relay_queue_budget_bytes",
        "tcn_relay_queue_shed_total",
        "tcn_relay_queue_overflow_total",
    ] {
        assert!(
            text.contains(&format!("# HELP {family} ")),
            "{family} has no HELP:\n{text}"
        );
        let kind = if family.ends_with("_total") {
            "counter"
        } else {
            "gauge"
        };
        assert!(
            text.contains(&format!("# TYPE {family} {kind}\n")),
            "{family} is not a {kind}:\n{text}"
        );
    }
    let snap = Snapshot::parse(&text).unwrap();
    assert_eq!(
        snap.get(
            "tcn_build_info",
            &[("role", "relay"), ("version", env!("CARGO_PKG_VERSION"))]
        ),
        Some(1.0)
    );
}

/// R5-M1: the agent's families, with the relay index as the only per-peer label.
#[test]
fn agent_metrics_render_per_relay_index() {
    let m = AgentMetrics::new(3);
    let text = m.render();
    for family in [
        "tcn_agent_relay_up",
        "tcn_agent_relay_registrations_total",
        "tcn_agent_relay_session_failures_total",
        "tcn_agent_relay_consecutive_failures",
        "tcn_agent_sessions",
        "tcn_agent_handshakes_total",
        "tcn_agent_auth_failures_total",
        "tcn_agent_ssh_connect_failures_total",
        "tcn_agent_session_bytes_total",
        "tcn_agent_buffer_bytes",
        "tcn_agent_buffer_budget_bytes",
        "tcn_config_generation",
        "tcn_watchdog_progress_total",
        "tcn_draining",
    ] {
        assert!(
            text.contains(&format!("# TYPE {family} ")),
            "{family}\n{text}"
        );
    }
    let snap = Snapshot::parse(&text).unwrap();
    for i in ["0", "1", "2"] {
        assert_eq!(snap.get("tcn_agent_relay_up", &[("relay", i)]), Some(0.0));
    }
    assert_eq!(snap.get("tcn_agent_relay_up", &[("relay", "3")]), None);
    assert_eq!(
        snap.get(
            "tcn_build_info",
            &[("role", "agent"), ("version", env!("CARGO_PKG_VERSION"))]
        ),
        Some(1.0)
    );
}

/// The client writes the outcome of its last session (optional, `metrics_file`).
#[test]
fn client_metrics_describe_the_last_session() {
    let m = ClientMetrics::new();
    m.attempt_started(0);
    m.attempt_started(1);
    m.finished_ok(1, HandshakeSuite::NoiseIk25519);
    let snap = Snapshot::parse(&m.render()).unwrap();
    assert_eq!(
        snap.get("tcn_client_last_session_outcome", &[("outcome", "ok")]),
        Some(1.0)
    );
    assert_eq!(
        snap.get("tcn_client_last_session_relay_index", &[]),
        Some(1.0)
    );
    assert_eq!(snap.get("tcn_client_last_session_attempts", &[]), Some(2.0));
    assert_eq!(snap.get("tcn_client_last_session_failover", &[]), Some(1.0));
}

/// Generation, reloads, drain and watchdog progress are process metrics shared by both roles.
#[test]
fn process_metrics_follow_reloads_drain_and_progress() {
    let m = RelayMetrics::new();
    m.process().set_generation(1);
    m.process().reload_applied(2);
    m.process().reload_rejected();
    m.process().set_draining(true);
    m.process().progress().advance();
    m.process().progress().advance();
    let snap = Snapshot::parse(&m.render()).unwrap();
    assert_eq!(snap.get("tcn_config_generation", &[]), Some(2.0));
    assert_eq!(
        snap.get("tcn_reloads_total", &[("result", "applied")]),
        Some(1.0)
    );
    assert_eq!(
        snap.get("tcn_reloads_total", &[("result", "rejected")]),
        Some(1.0)
    );
    assert_eq!(snap.get("tcn_draining", &[]), Some(1.0));
    assert_eq!(snap.get("tcn_watchdog_progress_total", &[]), Some(2.0));
}

// ---------------------------------------------------------------------------------------------
// Textfile
// ---------------------------------------------------------------------------------------------

/// R5-M2: the file is replaced atomically (temporary file in the same directory, then
/// `rename`), readable by node_exporter (0644) and nothing else is left behind.
#[test]
fn textfile_is_written_atomically_with_mode_0644() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("atomic");
    let path = dir.join("relay.prom");
    write_textfile(&path, "a 1\n").unwrap();
    write_textfile(&path, "a 2\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a 2\n");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644);
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(entries.len(), 1, "temporary files left: {entries:?}");
    let _ = std::fs::remove_dir_all(dir);
}

/// R5-M2: the exporter writes at once, then every interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exporter_writes_at_start_and_every_interval() {
    let dir = tmp("export");
    let path = dir.join("agent.prom");
    let m = AgentMetrics::new(1);
    let task = tokio::spawn(metrics::export(path.clone(), Duration::from_millis(200), {
        let m = Arc::clone(&m);
        move || m.render()
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first = Snapshot::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(first.get("tcn_agent_sessions", &[]), Some(0.0));
    assert_eq!(first.get("tcn_metrics_interval_seconds", &[]), Some(0.2));
    m.process().set_generation(7);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let later = Snapshot::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(later.get("tcn_config_generation", &[]), Some(7.0));
    task.abort();
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------------------------

/// R5-M3: `status` reads the file, says how old it is and lists the values.
#[test]
fn status_reports_a_fresh_file() {
    let dir = tmp("status");
    let path = dir.join("relay.prom");
    let m = RelayMetrics::new();
    m.process().set_generation(3);
    write_textfile(&path, &m.render()).unwrap();
    let report = metrics::status(&path, SystemTime::now()).unwrap();
    assert!(!report.stale);
    assert!(report.text.contains("role: relay"), "{}", report.text);
    assert!(
        report.text.contains("tcn_config_generation 3"),
        "{}",
        report.text
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// R5-M3: a file older than three intervals is stale: the process stopped writing.
#[test]
fn status_reports_a_stale_file() {
    let dir = tmp("stale");
    let path = dir.join("relay.prom");
    let m = RelayMetrics::new();
    write_textfile(&path, &m.render()).unwrap();
    let later = SystemTime::now() + Duration::from_secs(3 * 15 + 5);
    let report = metrics::status(&path, later).unwrap();
    assert!(report.stale, "{}", report.text);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn status_of_a_missing_file_is_an_error() {
    let dir = tmp("missing");
    let err = metrics::status(&dir.join("nope.prom"), SystemTime::now()).unwrap_err();
    assert!(matches!(err, StatusError::Unreadable(_)), "{err:?}");
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------------------------
// Live counters
// ---------------------------------------------------------------------------------------------

fn lab_policy(agent: &zt_domain::Fingerprint, client: &Identity) -> zt_domain::AccessPolicy {
    relay_policy(
        agent,
        &[ClientGrant::new(client.fingerprint(), nodes(&["web-01"]))],
        CertTrust::default(),
    )
}

/// R5-M4: a session moves the relay's handshake, connection, stream and byte counters, and
/// the agent's relay link, handshake and session counters.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_moves_the_relay_and_agent_counters() {
    let client = Arc::new(Identity::generate().unwrap());
    let relay_metrics = RelayMetrics::new();
    let agent_metrics = AgentMetrics::new(1);
    let agent = Arc::new(Identity::generate().unwrap());
    let mut config = relay_config();
    config.metrics = Arc::clone(&relay_metrics);
    let lab = observed::start_observed(
        Arc::clone(&agent),
        vec![(lab_policy(&agent.fingerprint(), &client), config)],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        Arc::clone(&agent_metrics),
    )
    .await;
    let (mut app, _task) = lab.session(&client, None).await.unwrap();
    common::assert_alive(&mut app).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let relay = Snapshot::parse(&relay_metrics.render()).unwrap();
    assert_eq!(
        relay.get(
            "tcn_relay_handshakes_total",
            &[("role", "agent"), ("suite", classical())]
        ),
        Some(1.0)
    );
    assert_eq!(
        relay.get(
            "tcn_relay_handshakes_total",
            &[("role", "client"), ("suite", classical())]
        ),
        Some(1.0)
    );
    assert_eq!(
        relay.get("tcn_relay_connections", &[("role", "agent")]),
        Some(1.0)
    );
    assert_eq!(
        relay.get("tcn_relay_connections", &[("role", "client")]),
        Some(1.0)
    );
    assert_eq!(relay.get("tcn_relay_agents_registered", &[]), Some(1.0));
    assert_eq!(relay.get("tcn_relay_streams", &[]), Some(1.0));
    assert!(relay.get("tcn_relay_forwarded_bytes_total", &[]).unwrap() > 0.0);

    let agent = Snapshot::parse(&agent_metrics.render()).unwrap();
    assert_eq!(
        agent.get("tcn_agent_relay_up", &[("relay", "0")]),
        Some(1.0)
    );
    assert_eq!(
        agent.get("tcn_agent_relay_registrations_total", &[("relay", "0")]),
        Some(1.0)
    );
    assert_eq!(agent.get("tcn_agent_sessions", &[]), Some(1.0));
    assert_eq!(
        agent.get("tcn_agent_handshakes_total", &[("suite", classical())]),
        Some(1.0)
    );
    assert!(
        agent
            .get("tcn_agent_session_bytes_total", &[("direction", "to_ssh")])
            .unwrap()
            > 0.0
    );

    drop(app);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let relay = Snapshot::parse(&relay_metrics.render()).unwrap();
    assert_eq!(relay.get("tcn_relay_streams", &[]), Some(0.0));
    assert_eq!(
        relay.get("tcn_relay_connections", &[("role", "client")]),
        Some(0.0)
    );
    let agent = Snapshot::parse(&agent_metrics.render()).unwrap();
    assert_eq!(agent.get("tcn_agent_sessions", &[]), Some(0.0));
}

/// R5-M4: refusals are counted by reason: an unknown key before key confirmation, a denied
/// `Open` with its reject reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_are_counted_by_reason() {
    let client = Arc::new(Identity::generate().unwrap());
    let stranger = Arc::new(Identity::generate().unwrap());
    let relay_metrics = RelayMetrics::new();
    let agent = Arc::new(Identity::generate().unwrap());
    let mut config = relay_config();
    config.metrics = Arc::clone(&relay_metrics);
    let policy = relay_policy(
        &agent.fingerprint(),
        &[ClientGrant::new(client.fingerprint(), nodes(&["db-01"]))],
        CertTrust::default(),
    );
    let lab = observed::start_observed(
        Arc::clone(&agent),
        vec![(policy, config)],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        AgentMetrics::new(1),
    )
    .await;
    assert!(lab.refused(&stranger, None).await.is_err());
    assert!(lab.refused(&client, None).await.is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let relay = Snapshot::parse(&relay_metrics.render()).unwrap();
    assert!(
        relay
            .get(
                "tcn_relay_preauth_failures_total",
                &[("reason", "unknown_peer")]
            )
            .unwrap()
            >= 1.0
    );
    assert_eq!(
        relay.get(
            "tcn_relay_open_rejects_total",
            &[("reason", "not_authorized")]
        ),
        Some(1.0)
    );
}

/// R5-M6: the client (optionally) records which relay its last session used, after how many
/// attempts, and whether it failed over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_records_its_failover_outcome() {
    use tokio::io::AsyncWriteExt;
    let client = Arc::new(Identity::generate().unwrap());
    let agent = Arc::new(Identity::generate().unwrap());
    let lab = observed::start_observed(
        Arc::clone(&agent),
        vec![(lab_policy(&agent.fingerprint(), &client), relay_config())],
        agent_clients(&[client.fingerprint()], CertTrust::default()),
        AgentMetrics::new(1),
    )
    .await;
    // A closed port first: connection refused, the client moves on to the real relay.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let mut config = lab.config(None);
    let mut dead_relay = config.relays[0].clone();
    dead_relay.address = dead.to_string();
    config.relays.insert(0, dead_relay);
    let m = ClientMetrics::new();
    let (mut app, local) = tokio::io::duplex(1024);
    let task = {
        let (m, client) = (Arc::clone(&m), Arc::clone(&client));
        tokio::spawn(async move {
            zt_net::client::connect_observed(&client, &config, local, zt_net::net::TcpDialer, &m)
                .await
        })
    };
    app.write_all(b"ping").await.unwrap();
    drop(app);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let snap = Snapshot::parse(&m.render()).unwrap();
    assert_eq!(
        snap.get("tcn_client_last_session_outcome", &[("outcome", "ok")]),
        Some(1.0)
    );
    assert_eq!(
        snap.get("tcn_client_last_session_relay_index", &[]),
        Some(1.0)
    );
    assert_eq!(snap.get("tcn_client_last_session_failover", &[]), Some(1.0));
    assert!(snap.get("tcn_client_last_session_attempts", &[]).unwrap() >= 2.0);
    assert!(
        snap.get("tcn_client_last_session_bytes", &[("direction", "sent")])
            .unwrap()
            >= 4.0
    );
}

/// The client's `metrics_file` (client.toml) is optional and resolved next to the file.
#[test]
fn client_settings_accept_a_metrics_file() {
    let r = Identity::generate().unwrap().public_key().to_string();
    let text = format!(
        "relay = \"relay.example.org:7443\"\nrelay_key = \"{r}\"\nkey = \"client.key\"\n\
         metrics_file = \"zt-client.prom\"\n"
    );
    let base = std::path::Path::new("/etc/tcn");
    let s = zt_net::config::parse_client_settings("t", base, &text).unwrap();
    assert_eq!(s.metrics_file, Some(base.join("zt-client.prom")));
    let without = text.replace("metrics_file = \"zt-client.prom\"\n", "");
    let s = zt_net::config::parse_client_settings("t", base, &without).unwrap();
    assert_eq!(s.metrics_file, None);
}
