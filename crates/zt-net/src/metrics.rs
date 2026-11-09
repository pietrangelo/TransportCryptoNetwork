//! Metrics as a `node_exporter` **textfile** (resilience.md §5.5, review 0007 AP-21 and D-10 as
//! corrected): the relay, the agent and, optionally, the client write their counters and
//! gauges in the Prometheus text format to a file, atomically, every interval. Nothing listens:
//! `node_exporter`'s textfile collector reads the file, and `zt-relay status` / `zt-agent status`
//! read it too.
//!
//! Hand-written atomics and a small writer, no new crate. Every label comes from a fixed,
//! compiled-in vocabulary (roles, suites, reasons, relay indices up to [`crate::MAX_RELAYS`]):
//! no fingerprint, node name, certificate field or address is ever a label value, so the
//! number of lines is fixed and the file reveals no inventory (catalogue R5-O2, R5-O3).

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use zt_domain::{AuthFailureReason, CloseReason, HandshakeSuite, RejectReason};

use crate::lifecycle::Progress;

/// The interval when the command line says nothing.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);

/// The file name inside the runtime directory when `--metrics-file` is not given.
pub const FILE_NAME: &str = "metrics.prom";

/// The largest file `status` reads: far above anything written here (a few KiB).
pub const MAX_FILE_LEN: u64 = 1024 * 1024;

/// A file is stale when it is older than this many intervals.
pub const STALE_INTERVALS: u32 = 3;

/// The shortest interval the exporter accepts from a library caller (the CLI takes 1–3600 s).
const MIN_INTERVAL: Duration = Duration::from_millis(10);

/// The two samples the exporter owns: it stamps them on every write.
const INTERVAL_METRIC: &str = "tcn_metrics_interval_seconds";
const WRITTEN_METRIC: &str = "tcn_metrics_last_write_timestamp_seconds";

// ---------------------------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------------------------

/// A monotonic counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// One more.
    pub fn inc(&self) {
        self.add(1);
    }

    /// `n` more.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A value that goes up and down.
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    /// Sets the value.
    pub fn set(&self, value: i64) {
        self.0.store(value, Ordering::Relaxed);
    }

    /// Sets the value from an unsigned quantity (saturating).
    pub fn set_usize(&self, value: usize) {
        self.set(i64::try_from(value).unwrap_or(i64::MAX));
    }

    /// One more.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// One less.
    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Holds a gauge one higher until dropped: a count of live things (connections, sessions)
/// that is right on every exit path.
#[derive(Debug)]
pub(crate) struct Held<T: AsRef<Gauge>>(T);

impl<T: AsRef<Gauge>> Held<T> {
    pub(crate) fn new(gauge: T) -> Self {
        gauge.as_ref().inc();
        Self(gauge)
    }
}

impl<T: AsRef<Gauge>> Drop for Held<T> {
    fn drop(&mut self) {
        self.0.as_ref().dec();
    }
}

impl AsRef<Self> for Gauge {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Counters for a fixed set of label values; anything else is counted as `other`.
#[derive(Debug)]
struct ByLabel {
    values: &'static [&'static str],
    counts: Box<[Counter]>,
    other: Counter,
}

impl ByLabel {
    fn new(values: &'static [&'static str]) -> Self {
        Self {
            values,
            counts: values.iter().map(|_| Counter::default()).collect(),
            other: Counter::default(),
        }
    }

    fn inc(&self, value: &str) {
        let slot = self
            .values
            .iter()
            .position(|v| *v == value)
            .and_then(|i| self.counts.get(i))
            .unwrap_or(&self.other);
        slot.inc();
    }

    fn render(&self, out: &mut Exposition, name: &str, label: &str) {
        for (value, count) in self.values.iter().zip(self.counts.iter()) {
            out.sample(name, &[(label, value)], count.get());
        }
        out.sample(name, &[(label, "other")], self.other.get());
    }
}

// ---------------------------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------------------------

const PREAUTH_REASONS: &[&str] = &[
    "rate_limited",
    "source_limit",
    "preauth_pool_full",
    "established_pool_full",
    "identity_limit",
    "handshake_failed",
    "timeout",
    "oversized",
    "unknown_peer",
    "unverified_certificate",
    "unconfirmed",
    "aborted",
];

const REFUSALS: &[&str] = &[
    "preauth_pool_full",
    "rate_limited",
    "source_limit",
    "established_pool_full",
    "identity_limit",
    "unknown_ticket",
];

const AUTH_REASONS: &[&str] = &[
    "handshake_failed",
    "unknown_peer",
    "node_id_mismatch",
    "rate_limited",
    "key_revoked",
    "certificate",
    "identity_downgrade",
    "suite_rejected",
    "unconfirmed",
];

const REJECTS: &[&str] = &[
    "not_authorized",
    "unknown_node",
    "node_offline",
    "rate_limited",
    "resource_exhausted",
];

const CLOSES: &[&str] = &[
    "normal",
    "timeout",
    "protocol_violation",
    "drained",
    "peer_gone",
    "unauthorized",
];

const SUITES: [HandshakeSuite; 3] = HandshakeSuite::ALL;

/// The label of an authentication failure: its kind only (a certificate's check is in the
/// audit log, not in a label).
#[must_use]
pub fn auth_reason(reason: AuthFailureReason) -> &'static str {
    match reason {
        AuthFailureReason::HandshakeFailed => "handshake_failed",
        AuthFailureReason::UnknownPeer => "unknown_peer",
        AuthFailureReason::NodeIdMismatch => "node_id_mismatch",
        AuthFailureReason::RateLimited => "rate_limited",
        AuthFailureReason::KeyRevoked => "key_revoked",
        AuthFailureReason::Certificate(_) => "certificate",
        AuthFailureReason::IdentityDowngrade => "identity_downgrade",
        _ => "other",
    }
}

/// The label of a `Reject` reason.
#[must_use]
pub const fn reject_reason(reason: RejectReason) -> &'static str {
    match reason {
        RejectReason::NotAuthorized => "not_authorized",
        RejectReason::UnknownNode => "unknown_node",
        RejectReason::NodeOffline => "node_offline",
        RejectReason::RateLimited => "rate_limited",
        RejectReason::ResourceExhausted => "resource_exhausted",
    }
}

/// The label of a `Close` reason.
#[must_use]
pub const fn close_reason(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::Normal => "normal",
        CloseReason::Timeout => "timeout",
        CloseReason::ProtocolViolation => "protocol_violation",
        CloseReason::Drained => "drained",
        CloseReason::PeerGone => "peer_gone",
        CloseReason::Unauthorized => "unauthorized",
    }
}

fn suite_index(suite: HandshakeSuite) -> usize {
    SUITES.iter().position(|s| *s == suite).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// Exposition
// ---------------------------------------------------------------------------------------------

/// Escapes a label value for the text format: `\` → `\\`, `"` → `\"`, newline → `\n`. The
/// values written here are compiled-in constants; this is defense in depth against a future
/// caller passing something else (a label value can never end the line or the label set).
#[must_use]
pub fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// A text-format document under construction.
#[derive(Debug, Default)]
struct Exposition(String);

impl Exposition {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            self.0.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.0.push(',');
                }
                let _ = write!(self.0, "{k}=\"{}\"", escape_label_value(v));
            }
            self.0.push('}');
        }
        let _ = writeln!(self.0, " {value}");
    }

    fn counter(&mut self, name: &str, help: &str, value: u64) {
        self.family(name, "counter", help);
        self.sample(name, &[], value);
    }

    fn gauge(&mut self, name: &str, help: &str, value: i64) {
        self.family(name, "gauge", help);
        self.sample(name, &[], value);
    }
}

fn unix_seconds(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

// ---------------------------------------------------------------------------------------------
// Process metrics (relay and agent)
// ---------------------------------------------------------------------------------------------

/// What both services report about themselves: build, start, configuration generation and
/// reloads, drain, and the watchdog's progress counter (AP-4).
#[derive(Debug)]
pub struct Process {
    role: &'static str,
    started: SystemTime,
    generation: Gauge,
    applied: Counter,
    rejected: Counter,
    draining: Gauge,
    progress: Progress,
}

impl Process {
    fn new(role: &'static str) -> Self {
        Self {
            role,
            started: SystemTime::now(),
            generation: Gauge::default(),
            applied: Counter::default(),
            rejected: Counter::default(),
            draining: Gauge::default(),
            progress: Progress::new(),
        }
    }

    /// The generation in force (startup).
    pub fn set_generation(&self, generation: u64) {
        self.generation
            .set(i64::try_from(generation).unwrap_or(i64::MAX));
    }

    /// A reload applied `generation`.
    pub fn reload_applied(&self, generation: u64) {
        self.applied.inc();
        self.set_generation(generation);
    }

    /// A reload was rejected: the previous generation stays in force.
    pub fn reload_rejected(&self) {
        self.rejected.inc();
    }

    /// The drain started (or not).
    pub fn set_draining(&self, draining: bool) {
        self.draining.set(i64::from(draining));
    }

    /// The progress counter the watchdog follows.
    #[must_use]
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    fn render(&self, out: &mut Exposition) {
        out.family(
            "tcn_build_info",
            "gauge",
            "Role and version of this process.",
        );
        out.sample(
            "tcn_build_info",
            &[("role", self.role), ("version", env!("CARGO_PKG_VERSION"))],
            1,
        );
        out.family(
            "tcn_process_start_time_seconds",
            "gauge",
            "Start time of the process, Unix seconds.",
        );
        out.sample(
            "tcn_process_start_time_seconds",
            &[],
            unix_seconds(self.started),
        );
        out.family(
            INTERVAL_METRIC,
            "gauge",
            "Interval at which this file is rewritten.",
        );
        out.sample(INTERVAL_METRIC, &[], DEFAULT_INTERVAL.as_secs_f64());
        out.family(
            WRITTEN_METRIC,
            "gauge",
            "When this file was written, Unix seconds.",
        );
        out.sample(WRITTEN_METRIC, &[], unix_seconds(SystemTime::now()));
        out.gauge(
            "tcn_config_generation",
            "Configuration generation in force (1 at startup, +1 per applied reload).",
            self.generation.get(),
        );
        out.family("tcn_reloads_total", "counter", "Reloads by result.");
        out.sample(
            "tcn_reloads_total",
            &[("result", "applied")],
            self.applied.get(),
        );
        out.sample(
            "tcn_reloads_total",
            &[("result", "rejected")],
            self.rejected.get(),
        );
        out.counter(
            "tcn_watchdog_progress_total",
            "Units of work the watchdog has seen (stops moving when the process is wedged).",
            self.progress.get(),
        );
        out.gauge(
            "tcn_draining",
            "1 while a graceful stop drains the open sessions.",
            self.draining.get(),
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------------------------

/// The relay's metrics.
#[derive(Debug)]
pub struct RelayMetrics {
    process: Process,
    preauth: ByLabel,
    refusals: ByLabel,
    /// Per initiator role (agent, client) and suite.
    handshakes: [[Counter; 3]; 2],
    auth_failures: ByLabel,
    agent_connections: Gauge,
    client_connections: Gauge,
    pub(crate) agents_registered: Gauge,
    pub(crate) streams: Gauge,
    open_rejects: ByLabel,
    stream_closes: ByLabel,
    pub(crate) forwarded_bytes: Counter,
    pub(crate) queue_bytes: Gauge,
    pub(crate) queue_budget: Gauge,
    pub(crate) queue_shed: Counter,
    pub(crate) queue_overflow: Counter,
}

/// An initiator's role, as a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoleLabel {
    Agent = 0,
    Client = 1,
}

impl RelayMetrics {
    /// All at zero.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            process: Process::new("relay"),
            preauth: ByLabel::new(PREAUTH_REASONS),
            refusals: ByLabel::new(REFUSALS),
            handshakes: Default::default(),
            auth_failures: ByLabel::new(AUTH_REASONS),
            agent_connections: Gauge::default(),
            client_connections: Gauge::default(),
            agents_registered: Gauge::default(),
            streams: Gauge::default(),
            open_rejects: ByLabel::new(REJECTS),
            stream_closes: ByLabel::new(CLOSES),
            forwarded_bytes: Counter::default(),
            queue_bytes: Gauge::default(),
            queue_budget: Gauge::default(),
            queue_shed: Counter::default(),
            queue_overflow: Counter::default(),
        })
    }

    /// Generation, reloads, drain, progress.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.process
    }

    pub(crate) fn preauth_failure(&self, reason: &str) {
        self.preauth.inc(reason);
    }

    pub(crate) fn admission_refused(&self, reason: &str) {
        self.refusals.inc(reason);
    }

    pub(crate) fn handshake_confirmed(&self, role: RoleLabel, suite: HandshakeSuite) {
        if let Some(c) = self
            .handshakes
            .get(role as usize)
            .and_then(|r| r.get(suite_index(suite)))
        {
            c.inc();
        }
    }

    pub(crate) fn auth_failed(&self, reason: &str) {
        self.auth_failures.inc(reason);
    }

    pub(crate) fn connection(self: &Arc<Self>, role: RoleLabel) -> Held<ConnectionGauge> {
        Held::new(ConnectionGauge(Arc::clone(self), role))
    }

    pub(crate) fn open_rejected(&self, reason: RejectReason) {
        self.open_rejects.inc(reject_reason(reason));
    }

    pub(crate) fn stream_closed(&self, reason: CloseReason) {
        self.stream_closes.inc(close_reason(reason));
    }

    /// The text format, with the exporter's samples set to their defaults.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one flat block per family
    pub fn render(&self) -> String {
        let mut out = Exposition::default();
        self.process.render(&mut out);
        out.family(
            "tcn_relay_preauth_failures_total",
            "counter",
            "Connections that ended before key confirmation, by reason (no identities).",
        );
        self.preauth
            .render(&mut out, "tcn_relay_preauth_failures_total", "reason");
        out.family(
            "tcn_relay_admission_refusals_total",
            "counter",
            "Confirmed identities refused by the established pool or the identity limit.",
        );
        self.refusals
            .render(&mut out, "tcn_relay_admission_refusals_total", "reason");
        out.family(
            "tcn_relay_handshakes_total",
            "counter",
            "Outer handshakes confirmed (first authentic frame), by initiator role and suite.",
        );
        for (role, per_suite) in ["agent", "client"].iter().zip(self.handshakes.iter()) {
            for (suite, c) in SUITES.iter().zip(per_suite.iter()) {
                out.sample(
                    "tcn_relay_handshakes_total",
                    &[("role", role), ("suite", suite.protocol_name())],
                    c.get(),
                );
            }
        }
        out.family(
            "tcn_relay_auth_failures_total",
            "counter",
            "Authentication failures of known identities, by reason.",
        );
        self.auth_failures
            .render(&mut out, "tcn_relay_auth_failures_total", "reason");
        out.family(
            "tcn_relay_connections",
            "gauge",
            "Confirmed connections, by role.",
        );
        out.sample(
            "tcn_relay_connections",
            &[("role", "agent")],
            self.agent_connections.get(),
        );
        out.sample(
            "tcn_relay_connections",
            &[("role", "client")],
            self.client_connections.get(),
        );
        out.gauge(
            "tcn_relay_agents_registered",
            "Nodes with a registered agent.",
            self.agents_registered.get(),
        );
        out.gauge(
            "tcn_relay_streams",
            "Open client streams.",
            self.streams.get(),
        );
        out.family(
            "tcn_relay_open_rejects_total",
            "counter",
            "Rejected stream opens, by reason.",
        );
        self.open_rejects
            .render(&mut out, "tcn_relay_open_rejects_total", "reason");
        out.family(
            "tcn_relay_stream_closes_total",
            "counter",
            "Stream closes forwarded or sent by the relay, by reason.",
        );
        self.stream_closes
            .render(&mut out, "tcn_relay_stream_closes_total", "reason");
        out.counter(
            "tcn_relay_forwarded_bytes_total",
            "Data payload bytes forwarded (end-to-end ciphertext).",
            self.forwarded_bytes.get(),
        );
        out.gauge(
            "tcn_relay_queue_bytes",
            "Bytes queued towards peers and not yet written (global byte budget).",
            self.queue_bytes.get(),
        );
        out.gauge(
            "tcn_relay_queue_budget_bytes",
            "The global byte budget of the outbound queues.",
            self.queue_budget.get(),
        );
        out.counter(
            "tcn_relay_queue_shed_total",
            "Connections disconnected because the byte budget was exceeded (largest backlog).",
            self.queue_shed.get(),
        );
        out.counter(
            "tcn_relay_queue_overflow_total",
            "Connections disconnected because their queue overflowed (a peer breaking the credit).",
            self.queue_overflow.get(),
        );
        out.0
    }
}

/// One confirmed connection of a role, counted while it lives.
#[derive(Debug)]
pub(crate) struct ConnectionGauge(Arc<RelayMetrics>, RoleLabel);

impl AsRef<Gauge> for ConnectionGauge {
    fn as_ref(&self) -> &Gauge {
        match self.1 {
            RoleLabel::Agent => &self.0.agent_connections,
            RoleLabel::Client => &self.0.client_connections,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------------------------

/// The state of the link to one relay, by its index in `--relay`.
#[derive(Debug, Default)]
pub(crate) struct RelayLink {
    pub(crate) up: Gauge,
    pub(crate) registrations: Counter,
    pub(crate) failures: Counter,
    pub(crate) consecutive: Gauge,
}

/// A per-relay-link family: name, type, help and how to read its value.
type LinkFamily = (
    &'static str,
    &'static str,
    &'static str,
    fn(&RelayLink) -> String,
);

/// The agent's metrics.
#[derive(Debug)]
pub struct AgentMetrics {
    process: Process,
    links: Box<[RelayLink]>,
    pub(crate) sessions: Gauge,
    handshakes: [Counter; 3],
    auth_failures: ByLabel,
    pub(crate) ssh_failures: Counter,
    pub(crate) to_ssh: Counter,
    pub(crate) from_ssh: Counter,
    pub(crate) buffer_bytes: Gauge,
    pub(crate) buffer_budget: Gauge,
    pub(crate) buffer_refusals: Counter,
}

impl AgentMetrics {
    /// All at zero, for `relays` relays (at most [`crate::MAX_RELAYS`]).
    #[must_use]
    pub fn new(relays: usize) -> Arc<Self> {
        let n = relays.min(crate::MAX_RELAYS);
        Arc::new(Self {
            process: Process::new("agent"),
            links: (0..n).map(|_| RelayLink::default()).collect(),
            sessions: Gauge::default(),
            handshakes: Default::default(),
            auth_failures: ByLabel::new(AUTH_REASONS),
            ssh_failures: Counter::default(),
            to_ssh: Counter::default(),
            from_ssh: Counter::default(),
            buffer_bytes: Gauge::default(),
            buffer_budget: Gauge::default(),
            buffer_refusals: Counter::default(),
        })
    }

    /// Generation, reloads, drain, progress.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.process
    }

    pub(crate) fn link(&self, relay: usize) -> Option<&RelayLink> {
        self.links.get(relay)
    }

    pub(crate) fn handshake_confirmed(&self, suite: HandshakeSuite) {
        if let Some(c) = self.handshakes.get(suite_index(suite)) {
            c.inc();
        }
    }

    pub(crate) fn auth_failed(&self, reason: &str) {
        self.auth_failures.inc(reason);
    }

    /// The text format, with the exporter's samples set to their defaults.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = Exposition::default();
        self.process.render(&mut out);
        let per_link: [LinkFamily; 4] = [
            (
                "tcn_agent_relay_up",
                "gauge",
                "1 while registered with the relay of this index (--relay order).",
                |l| l.up.get().to_string(),
            ),
            (
                "tcn_agent_relay_registrations_total",
                "counter",
                "Registrations with the relay of this index.",
                |l| l.registrations.get().to_string(),
            ),
            (
                "tcn_agent_relay_session_failures_total",
                "counter",
                "Sessions with the relay of this index that ended in an error (reconnects).",
                |l| l.failures.get().to_string(),
            ),
            (
                "tcn_agent_relay_consecutive_failures",
                "gauge",
                "Failures since the last registration with the relay of this index.",
                |l| l.consecutive.get().to_string(),
            ),
        ];
        for (name, kind, help, value) in per_link {
            out.family(name, kind, help);
            for (i, link) in self.links.iter().enumerate() {
                out.sample(name, &[("relay", &i.to_string())], value(link));
            }
        }
        out.gauge(
            "tcn_agent_sessions",
            "End-to-end sessions bridged to sshd.",
            self.sessions.get(),
        );
        out.family(
            "tcn_agent_handshakes_total",
            "counter",
            "End-to-end handshakes confirmed by the client, by suite.",
        );
        for (suite, c) in SUITES.iter().zip(self.handshakes.iter()) {
            out.sample(
                "tcn_agent_handshakes_total",
                &[("suite", suite.protocol_name())],
                c.get(),
            );
        }
        out.family(
            "tcn_agent_auth_failures_total",
            "counter",
            "End-to-end authentication failures, by reason.",
        );
        self.auth_failures
            .render(&mut out, "tcn_agent_auth_failures_total", "reason");
        out.counter(
            "tcn_agent_ssh_connect_failures_total",
            "Sessions for which the local sshd could not be reached.",
            self.ssh_failures.get(),
        );
        out.family(
            "tcn_agent_session_bytes_total",
            "counter",
            "Plaintext bytes bridged, by direction.",
        );
        out.sample(
            "tcn_agent_session_bytes_total",
            &[("direction", "to_ssh")],
            self.to_ssh.get(),
        );
        out.sample(
            "tcn_agent_session_bytes_total",
            &[("direction", "from_ssh")],
            self.from_ssh.get(),
        );
        out.gauge(
            "tcn_agent_buffer_bytes",
            "Receive windows reserved from the global byte budget.",
            self.buffer_bytes.get(),
        );
        out.gauge(
            "tcn_agent_buffer_budget_bytes",
            "The global byte budget of the stream receive buffers.",
            self.buffer_budget.get(),
        );
        out.counter(
            "tcn_agent_buffer_refusals_total",
            "Streams rejected or windows not grown because the byte budget was exhausted.",
            self.buffer_refusals.get(),
        );
        out.0
    }
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

const OUTCOMES: &[&str] = &[
    "none",
    "ok",
    "deadline",
    "rejected",
    "unauthorized",
    "unreachable",
    "error",
];

/// The client's last session (optional `metrics_file`): which relay it used, after how many
/// attempts, whether it failed over, how it ended. Concurrent clients writing the same file
/// leave the last one to finish: the file describes one session, not a fleet.
#[derive(Debug)]
pub struct ClientMetrics {
    started: SystemTime,
    attempts: Counter,
    relay: Gauge,
    suite: Gauge,
    outcome: Gauge,
    pub(crate) sent: Counter,
    pub(crate) received: Counter,
}

impl ClientMetrics {
    /// Nothing tried yet.
    #[must_use]
    pub fn new() -> Arc<Self> {
        let relay = Gauge::default();
        relay.set(-1);
        let suite = Gauge::default();
        suite.set(-1);
        Arc::new(Self {
            started: SystemTime::now(),
            attempts: Counter::default(),
            relay,
            suite,
            outcome: Gauge::default(),
            sent: Counter::default(),
            received: Counter::default(),
        })
    }

    /// An attempt on the relay of index `_relay` started.
    pub fn attempt_started(&self, _relay: usize) {
        self.attempts.inc();
    }

    /// The session got its `OpenAck` on relay `relay`.
    pub fn connected(&self, relay: usize, suite: HandshakeSuite) {
        self.relay.set_usize(relay);
        self.suite.set_usize(suite_index(suite));
    }

    /// The session on relay `relay` ended normally.
    pub fn finished_ok(&self, relay: usize, suite: HandshakeSuite) {
        self.connected(relay, suite);
        self.ended_ok();
    }

    /// The session (whose relay is already recorded) ended normally.
    pub(crate) fn ended_ok(&self) {
        self.set_outcome("ok");
    }

    /// The session ended with `err`.
    pub fn finished_err(&self, err: &crate::NetError) {
        use crate::NetError;
        let outcome = match err {
            NetError::Deadline(_) => "deadline",
            NetError::Rejected(_) => "rejected",
            NetError::StreamClosed(CloseReason::Unauthorized) => "unauthorized",
            NetError::Io(_) | NetError::Timeout(_) | NetError::Closed => "unreachable",
            _ => "error",
        };
        self.set_outcome(outcome);
    }

    fn set_outcome(&self, outcome: &str) {
        let i = OUTCOMES.iter().position(|o| *o == outcome).unwrap_or(0);
        self.outcome.set_usize(i);
    }

    /// The text format.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = Exposition::default();
        out.family(
            "tcn_build_info",
            "gauge",
            "Role and version of this process.",
        );
        out.sample(
            "tcn_build_info",
            &[("role", "client"), ("version", env!("CARGO_PKG_VERSION"))],
            1,
        );
        out.family(
            WRITTEN_METRIC,
            "gauge",
            "When this file was written, Unix seconds.",
        );
        out.sample(WRITTEN_METRIC, &[], unix_seconds(SystemTime::now()));
        out.family(
            "tcn_client_last_session_start_time_seconds",
            "gauge",
            "When the last session started, Unix seconds.",
        );
        out.sample(
            "tcn_client_last_session_start_time_seconds",
            &[],
            unix_seconds(self.started),
        );
        out.family(
            "tcn_client_last_session_outcome",
            "gauge",
            "How the last session ended (1 on the outcome's line).",
        );
        let current = usize::try_from(self.outcome.get()).unwrap_or(0);
        for (i, outcome) in OUTCOMES.iter().enumerate() {
            out.sample(
                "tcn_client_last_session_outcome",
                &[("outcome", outcome)],
                u8::from(i == current),
            );
        }
        out.gauge(
            "tcn_client_last_session_relay_index",
            "Index (client.toml order) of the relay the last session used; -1 if none.",
            self.relay.get(),
        );
        out.gauge(
            "tcn_client_last_session_attempts",
            "Relay attempts started by the last session (hedges included).",
            i64::try_from(self.attempts.get()).unwrap_or(i64::MAX),
        );
        out.gauge(
            "tcn_client_last_session_failover",
            "1 if the last session used another relay than the first.",
            i64::from(self.relay.get() > 0),
        );
        out.family(
            "tcn_client_last_session_bytes",
            "gauge",
            "Plaintext bytes of the last session, by direction.",
        );
        out.sample(
            "tcn_client_last_session_bytes",
            &[("direction", "sent")],
            self.sent.get(),
        );
        out.sample(
            "tcn_client_last_session_bytes",
            &[("direction", "received")],
            self.received.get(),
        );
        out.0
    }
}

/// The plaintext byte counters of one bridged stream.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Traffic<'a> {
    /// Bytes read from the local side (sshd, or ssh on the client).
    pub(crate) from_local: &'a Counter,
    /// Bytes written to the local side.
    pub(crate) to_local: &'a Counter,
}

// ---------------------------------------------------------------------------------------------
// Textfile
// ---------------------------------------------------------------------------------------------

/// The temporary name of the `n`-th write of `path`: a hidden file next to it whose name does
/// not end in `.prom`, so `node_exporter` never reads it half-written. `None` if `path` has no
/// file name.
#[must_use]
pub fn temporary_name(path: &Path, n: u64) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy();
    let tmp = format!(".{name}.{}.{n}.tmp", std::process::id());
    Some(path.with_file_name(tmp))
}

/// Writes `content` to `path` atomically: a new temporary file in the same directory
/// (`O_CREAT | O_EXCL`, so a planted file or symlink is never opened), mode 0644 whatever the
/// umask, flushed, then renamed over `path` (which replaces a symlink there instead of
/// following it). A reader sees the old file or the new one, never a part.
///
/// # Errors
/// The directory is missing or not writable, the disk is full, or no temporary name is free.
pub fn write_textfile(path: &Path, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let tmp = temporary_name(path, n).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the metrics path has no file name",
            )
        })?;
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        let written = file
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .and_then(|()| file.write_all(content.as_bytes()))
            .and_then(|()| file.sync_data())
            .and_then(|()| {
                drop(file);
                std::fs::rename(&tmp, path)
            });
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        return written;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free temporary name for the metrics file",
    ))
}

/// `text` with the exporter's own samples set: the interval and the time of this write.
#[must_use]
pub fn stamp(text: &str, interval: Duration, now: SystemTime) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(128));
    let (mut has_interval, mut has_written) = (false, false);
    for line in text.lines() {
        if line.starts_with(&format!("{INTERVAL_METRIC} ")) {
            has_interval = true;
            let _ = writeln!(out, "{INTERVAL_METRIC} {}", interval.as_secs_f64());
        } else if line.starts_with(&format!("{WRITTEN_METRIC} ")) {
            has_written = true;
            let _ = writeln!(out, "{WRITTEN_METRIC} {}", unix_seconds(now));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !has_interval {
        let _ = writeln!(out, "{INTERVAL_METRIC} {}", interval.as_secs_f64());
    }
    if !has_written {
        let _ = writeln!(out, "{WRITTEN_METRIC} {}", unix_seconds(now));
    }
    out
}

/// Writes `render()` to `path` at once and then every `interval`, forever. A failed write is
/// logged once (`metrics_write_failed`) and retried at the next interval; the recovery is
/// logged too. It never ends, so it can be supervised like any critical task, and it opens
/// no socket.
pub async fn export<F>(path: PathBuf, interval: Duration, render: F)
where
    F: Fn() -> String,
{
    let interval = interval.max(MIN_INTERVAL);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        tick.tick().await;
        let text = stamp(&render(), interval, SystemTime::now());
        let target = path.clone();
        let written = tokio::task::spawn_blocking(move || write_textfile(&target, &text))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::other("metrics writer stopped")));
        match (written, failing) {
            (Ok(()), true) => {
                failing = false;
                tracing::info!(path = %path.display(), "metrics file written again");
            }
            (Err(err), false) => {
                failing = true;
                tracing::warn!(
                    target: "zt_audit",
                    event_kind = "metrics_write_failed",
                    path = %path.display(),
                    error = %err,
                    "metrics file not written: retrying every interval"
                );
            }
            // Written as before, or still failing (already logged once).
            (Ok(()), false) | (Err(_), true) => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Reading back: Snapshot and status
// ---------------------------------------------------------------------------------------------

/// One sample read back.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Metric name.
    pub name: String,
    /// Label pairs, in file order.
    pub labels: Vec<(String, String)>,
    /// Value.
    pub value: f64,
}

/// A parsed text-format file.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Samples in file order.
    pub samples: Vec<Sample>,
}

impl Snapshot {
    /// Parses the text format (comments and blank lines skipped, an optional timestamp
    /// ignored).
    ///
    /// # Errors
    /// The first malformed line, with its number.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut samples = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let sample = parse_sample(line)
                .ok_or_else(|| format!("line {}: malformed", n.saturating_add(1)))?;
            samples.push(sample);
        }
        Ok(Self { samples })
    }

    /// The value of `name` with exactly `labels` (in any order).
    #[must_use]
    pub fn get(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        self.samples
            .iter()
            .find(|s| {
                s.name == name
                    && s.labels.len() == labels.len()
                    && labels
                        .iter()
                        .all(|(k, v)| s.labels.iter().any(|(sk, sv)| sk == k && sv == v))
            })
            .map(|s| s.value)
    }

    /// The first sample named `name`, whatever its labels.
    #[must_use]
    pub fn first(&self, name: &str) -> Option<&Sample> {
        self.samples.iter().find(|s| s.name == name)
    }
}

fn is_name_char(c: char, first: bool) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':' || (!first && c.is_ascii_digit())
}

fn parse_name(s: &str) -> Option<(&str, &str)> {
    let end = s
        .char_indices()
        .find(|&(i, c)| !is_name_char(c, i == 0))
        .map_or(s.len(), |(i, _)| i);
    if end == 0 {
        return None;
    }
    Some((s.get(..end)?, s.get(end..)?))
}

fn parse_sample(line: &str) -> Option<Sample> {
    let (name, mut rest) = parse_name(line)?;
    let mut labels = Vec::new();
    if let Some(after) = rest.strip_prefix('{') {
        rest = after;
        loop {
            if let Some(after) = rest.strip_prefix('}') {
                rest = after;
                break;
            }
            let (key, after) = parse_name(rest)?;
            let after = after.strip_prefix("=\"")?;
            let mut value = String::new();
            let mut chars = after.char_indices();
            let end = loop {
                let (i, c) = chars.next()?;
                match c {
                    '"' => break i,
                    '\\' => match chars.next()?.1 {
                        'n' => value.push('\n'),
                        c @ ('\\' | '"') => value.push(c),
                        _ => return None,
                    },
                    c => value.push(c),
                }
            };
            labels.push((key.to_owned(), value));
            rest = after.get(end.checked_add(1)?..)?;
            if let Some(after) = rest.strip_prefix(',') {
                rest = after;
            } else if !rest.starts_with('}') {
                return None;
            }
        }
    }
    let rest = rest.strip_prefix(' ')?;
    let mut fields = rest.split(' ');
    let value = match fields.next()? {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        "NaN" => f64::NAN,
        v => v.parse().ok()?,
    };
    // An optional integer timestamp, nothing more.
    if let Some(ts) = fields.next()
        && ts.parse::<i64>().is_err()
    {
        return None;
    }
    if fields.next().is_some() {
        return None;
    }
    Some(Sample {
        name: name.to_owned(),
        labels,
        value,
    })
}

/// Why `status` could not report.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// The file is missing or unreadable (metrics disabled, wrong path, no permission).
    #[error("cannot read the metrics file: {0}")]
    Unreadable(std::io::Error),
    /// Larger than [`MAX_FILE_LEN`]: not a file this process wrote.
    #[error("the metrics file is larger than {MAX_FILE_LEN} bytes")]
    TooLarge,
    /// Not the text format, or without the samples every file has.
    #[error("the metrics file is not valid: {0}")]
    Invalid(String),
}

/// What `status` prints, and whether the file is stale.
#[derive(Debug, Clone)]
pub struct StatusReport {
    /// Human-readable lines, control characters replaced.
    pub text: String,
    /// Older than [`STALE_INTERVALS`] intervals: the process stopped writing.
    pub stale: bool,
}

/// Reads the metrics file at `path` for `status`: how old it is and every value in it.
///
/// # Errors
/// See [`StatusError`].
pub fn status(path: &Path, now: SystemTime) -> Result<StatusReport, StatusError> {
    let file = std::fs::File::open(path).map_err(StatusError::Unreadable)?;
    let len = file.metadata().map_err(StatusError::Unreadable)?.len();
    if len > MAX_FILE_LEN {
        return Err(StatusError::TooLarge);
    }
    let mut text = String::new();
    file.take(MAX_FILE_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(StatusError::Unreadable)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(StatusError::TooLarge);
    }
    let snap = Snapshot::parse(&text).map_err(StatusError::Invalid)?;
    let info = snap
        .first("tcn_build_info")
        .ok_or_else(|| StatusError::Invalid("no tcn_build_info".into()))?;
    let label = |k: &str| {
        info.labels
            .iter()
            .find(|(key, _)| key == k)
            .map_or("?", |(_, v)| v.as_str())
    };
    let written = snap
        .get(WRITTEN_METRIC, &[])
        .ok_or_else(|| StatusError::Invalid(format!("no {WRITTEN_METRIC}")))?;
    let interval = snap
        .get(INTERVAL_METRIC, &[])
        .filter(|i| i.is_finite() && *i > 0.0)
        .unwrap_or(DEFAULT_INTERVAL.as_secs_f64());
    let age = unix_seconds(now) - written;
    let stale = !age.is_finite() || age > interval * f64::from(STALE_INTERVALS);
    let mut out = String::new();
    let _ = writeln!(out, "role: {}", label("role"));
    let _ = writeln!(out, "version: {}", label("version"));
    let _ = writeln!(
        out,
        "{}: written {age:.0} s ago (interval {interval} s)",
        if stale { "stale" } else { "fresh" }
    );
    for s in &snap.samples {
        out.push_str(&s.name);
        if !s.labels.is_empty() {
            out.push('{');
            for (i, (k, v)) in s.labels.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{k}=\"{}\"", escape_label_value(v));
            }
            out.push('}');
        }
        let _ = writeln!(out, " {}", s.value);
    }
    let text = out
        .chars()
        .map(|c| if c.is_control() && c != '\n' { '?' } else { c })
        .collect();
    Ok(StatusReport { text, stale })
}

/// The metrics path of a service: `--metrics-file` if given, otherwise [`FILE_NAME`] in the
/// runtime directory (systemd's `RuntimeDirectory=`), otherwise none (metrics off).
#[must_use]
pub fn default_path(explicit: Option<PathBuf>, runtime_dir: Option<&Path>) -> Option<PathBuf> {
    explicit.or_else(|| runtime_dir.map(|d| d.join(FILE_NAME)))
}

/// `zt-relay status` / `zt-agent status`: prints the report of `path` on `out` (a reason on
/// `err`) and returns the exit status: 0 fresh, 1 missing or invalid, 2 stale.
pub fn status_command(
    path: &Path,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> u8 {
    match status(path, SystemTime::now()) {
        Ok(report) => {
            let _ = out.write_all(report.text.as_bytes());
            if report.stale {
                let _ = writeln!(
                    err,
                    "{}: stale, the process stopped writing it",
                    path.display()
                );
                2
            } else {
                0
            }
        }
        Err(e) => {
            let _ = writeln!(err, "{}: {e}", path.display());
            1
        }
    }
}
