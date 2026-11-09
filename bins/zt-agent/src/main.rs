//! `zt-agent`: runs on target servers with no listening ports. It connects outbound to the
//! relay and forwards to the local SSH daemon only streams of end-to-end authorized clients.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use zt_crypto::Keyring;
use zt_crypto::PeerKey;
use zt_domain::{HandshakeChannel, NodeId};
use zt_net::Timeouts;
use zt_net::agent::{self, AgentConfig};
use zt_net::config::{ConfigError, Digests};
use zt_net::lifecycle::{self, Generation, Supervisor, Terminate};
use zt_net::logging::{self, LogFormat};
use zt_net::metrics::{self, AgentMetrics};
use zt_net::net::TcpDialer;
use zt_net::reload::{self, Hangups, Outcome, Publisher};
use zt_net::{Revocable, config, systemd};

/// TCN agent.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Log format on stderr.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    log_format: Format,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Format {
    /// Human-readable text.
    Text,
    /// One JSON line per event (for SIEM and `jq`).
    Json,
}

/// The files and settings of an agent, shared by `run` and `check`.
#[derive(Debug, clap::Args)]
struct AgentArgs {
    /// Relay (`host:port`). Repeatable, or comma-separated: the agent stays connected to all
    /// of them (at most 8).
    #[arg(long, required = true, value_delimiter = ',')]
    relay: Vec<String>,
    /// Public key of each relay (64 hex characters, or its `tcn-pub-v2:` key, required by
    /// the hybrid IK suite), in the same order as `--relay`.
    #[arg(long, required = true, value_delimiter = ',')]
    relay_key: Vec<PeerKey>,
    /// Handshake suite pinned for the relays (its exact Noise protocol name, PROTOCOL
    /// §7.5): one for all of them, or one per `--relay` in the same order. Without it, the
    /// classical suite; there is never a fallback to another suite. Pin the hybrid suite
    /// only once the relay accepts it for agents (OPERATIONS §13).
    #[arg(long, value_delimiter = ',')]
    relay_suite: Vec<String>,
    /// Handshake suites accepted from clients on the end-to-end channel (exact Noise
    /// protocol names, comma-separated), for example
    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s,Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`.
    /// Without it, the classical suite only (a default that never changes between
    /// releases); new installations set both in `agent.env` (OPERATIONS §12).
    #[arg(long, env = "TCN_ACCEPT_CLIENT_SUITES", value_delimiter = ',')]
    accept_client_suites: Vec<String>,
    /// Name of this node, as in the relay policy.
    #[arg(long)]
    node: String,
    /// Secret key of the agent.
    #[arg(long)]
    key: PathBuf,
    /// Previous secret key, during a rotation: the end-to-end channel still accepts it, so
    /// clients can update gradually (PROTOCOL §14).
    #[arg(long)]
    previous_key: Option<PathBuf>,
    /// Clients accepted end-to-end (TOML, `[[clients]]` sections). `SIGHUP` reloads it and
    /// immediately closes the sessions of removed clients.
    #[arg(long)]
    authorized_clients: PathBuf,
    /// Denylist of certificates and keys (`revoked.toml`, PROTOCOL §15.8). Mandatory if the
    /// authorized clients pin a CA (`[[authorities]]`), even if empty. `SIGHUP` reloads it
    /// together with the authorized clients.
    #[arg(long)]
    revocations: Option<PathBuf>,
    /// Local SSH daemon.
    #[arg(long, default_value = "127.0.0.1:22")]
    ssh_target: String,
    /// Spread window, in seconds, of the first reconnect to a relay after a session that
    /// lived (a relay restart or drain): the fleet comes back over this window instead of
    /// in one wave. 0 reconnects at once (a single relay); at most 3600.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(0..=3600))]
    reconnect_spread: u64,
    /// Concurrent sessions (from 1 to 4096).
    #[arg(long, default_value_t = 16, value_parser = parse_max_streams)]
    max_streams: usize,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // value built once, at startup
enum Command {
    /// Generates the agent key (new file, 0600 permissions) and prints the public key.
    Keygen {
        /// File to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Prints the public keys of an existing key file (v1 and `tcn-pub-v2:`, OPERATIONS §15),
    /// without changing it.
    Pubkey {
        /// The secret key file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Starts the agent. `SIGTERM` drains it (OPERATIONS §14).
    Run {
        #[command(flatten)]
        args: AgentArgs,
        /// On `SIGTERM`, how long the open sessions may go on (seconds, 1 to 3600); new ones
        /// are rejected with `NodeOffline` meanwhile. Keep it below the unit's
        /// `TimeoutStopSec`.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
        drain_timeout: u64,
        /// Where the reload state for `reload` is published. Default: `$RUNTIME_DIRECTORY`
        /// (systemd's `RuntimeDirectory=`); without either, `reload` cannot be used.
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        #[command(flatten)]
        metrics: MetricsArgs,
    },
    /// Prints the metrics file the running agent writes (R-5): its age and every value.
    /// Exit 0 if fresh, 1 if missing or invalid, 2 if stale (older than three intervals).
    Status {
        /// The metrics file (`run --metrics-file`).
        #[arg(long, default_value = "/run/zt-agent/metrics.prom")]
        metrics_file: PathBuf,
    },
    /// Validates every file and option `run` uses at startup, with the same options and the
    /// same code, and prints the SHA-256 of the trust files; exits 78 on an invalid file or
    /// option, 1 on a missing or unreadable file. A pre-flight before a restart;
    /// `systemctl reload` uses `reload`.
    Check {
        #[command(flatten)]
        args: AgentArgs,
    },
    /// Asks the running agent to reload its authorized clients (`SIGHUP`) and reports its
    /// outcome: exit 0 if applied, 78 if rejected (the previous clients remain), 1 if the agent
    /// did not answer. The agent validates its own files with its own arguments, so this takes
    /// none (`ExecReload=`, finding A10-1).
    Reload {
        /// The agent's process id (`$MAINPID` in the unit).
        #[arg(long)]
        pid: u32,
        /// The agent's runtime directory. Default: `$RUNTIME_DIRECTORY`.
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        /// How long to wait for the outcome (seconds, 1 to 600).
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout: u64,
    },
}

/// Where and how often the metrics textfile is written (R-5, OPERATIONS §17), and the byte
/// budget (R-6, OPERATIONS §18).
#[derive(Debug, clap::Args)]
struct MetricsArgs {
    /// The metrics file, in the Prometheus text format for `node_exporter`'s textfile collector
    /// (rewritten atomically, mode 0644; its directory must be writable by the service).
    /// Default: `metrics.prom` in the runtime directory. The agent never listens, for metrics
    /// or anything else.
    #[arg(long)]
    metrics_file: Option<PathBuf>,
    /// How often the metrics file is rewritten, in seconds (1 to 3600).
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=3600))]
    metrics_interval: u64,
    /// The global byte budget of the streams' receive windows, in MiB (16 to 65536; R-6,
    /// OPERATIONS §18). A stream whose initial window does not fit is rejected; windows grow
    /// only within three quarters of it. Default: a quarter of the memory, from 64 MiB to 1 GiB.
    #[arg(long, value_parser = clap::value_parser!(u64).range(16..=65536))]
    buffer_budget_mib: Option<u64>,
}

impl MetricsArgs {
    /// The byte budget, from `--buffer-budget-mib` or the default.
    fn budget(&self) -> usize {
        self.buffer_budget_mib
            .map_or_else(zt_net::budget::default_queue_budget, |mib| {
                usize::try_from(mib.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
            })
    }
}

/// `--max-streams` within the agent's limits (finding 0005b-4: beyond the maximum of the tokio
/// semaphore the agent panicked at startup).
fn parse_max_streams(value: &str) -> Result<usize, String> {
    let n: usize = value.parse().map_err(|e| format!("{e}"))?;
    if (1..=agent::MAX_STREAMS).contains(&n) {
        Ok(n)
    } else {
        Err(format!("must be between 1 and {}", agent::MAX_STREAMS))
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = match cli.log_format {
        Format::Text => LogFormat::Text,
        Format::Json => LogFormat::Json,
    };
    logging::init(format, "info");
    lifecycle::harden_process();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Config(message)) => {
            tracing::error!("{message}");
            ExitCode::from(EX_CONFIG)
        }
        Err(Failure::Runtime(message)) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
        Err(Failure::Exit(code)) => ExitCode::from(code),
    }
}

/// How the process fails: a configuration error is `EX_CONFIG` (78), which the unit does not
/// restart on (`RestartPreventExitStatus=78`); anything else is 1 and is restarted.
enum Failure {
    Config(String),
    Runtime(String),
    /// An exit status already reported on stderr (`status`).
    Exit(u8),
}

/// `EX_CONFIG` of `sysexits.h`.
const EX_CONFIG: u8 = 78;

fn config_error(e: impl std::fmt::Display) -> Failure {
    Failure::Config(e.to_string())
}

/// A file that could not be read (missing, unreadable: provisioning not finished, a late
/// mount) is restarted with the unit's backoff; a file that was read and is invalid is
/// `EX_CONFIG` (finding A10-8).
fn load_error(e: &ConfigError) -> Failure {
    if e.is_transient() {
        Failure::Runtime(e.to_string())
    } else {
        Failure::Config(e.to_string())
    }
}

fn runtime_error(e: impl std::fmt::Display) -> Failure {
    Failure::Runtime(e.to_string())
}

/// `--relay-suite` (one for all relays, or one per `--relay`) and `--accept-client-suites`
/// (PROTOCOL §7.5): exact Noise protocol names, the classical suite when absent.
fn pin_suites(
    relays: &mut [zt_net::RelayEndpoint],
    relay_suite: &[String],
    accept_client_suites: &[String],
) -> Result<zt_domain::AcceptedSuites, String> {
    let suites = relay_suite
        .iter()
        .map(|name| config::parse_suite("--relay-suite", name, HandshakeChannel::Outer))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    match suites.as_slice() {
        [] => {}
        [one] => relays.iter_mut().for_each(|r| r.suite = *one),
        many if many.len() == relays.len() => {
            for (r, suite) in relays.iter_mut().zip(many) {
                r.suite = *suite;
            }
        }
        _ => return Err("--relay-suite: give one suite, or one per --relay".into()),
    }
    for relay in relays.iter() {
        config::hybrid_key_for(
            "--relay-key",
            &relay.address,
            relay.suite,
            &relay.public_key,
        )
        .map_err(|e| e.to_string())?;
    }
    if accept_client_suites.is_empty() {
        return Ok(zt_domain::AcceptedSuites::only(
            zt_domain::HandshakeSuite::NoiseIk25519,
        ));
    }
    config::parse_suites(
        "--accept-client-suites",
        accept_client_suites,
        HandshakeChannel::EndToEnd,
    )
    .map_err(|e| e.to_string())
}

fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::Pubkey { key } => {
            let identity = config::load_identity(&key).map_err(|e| load_error(&e))?;
            write!(
                std::io::stdout(),
                "{}",
                config::public_identity_text(&identity)
            )
            .map_err(runtime_error)
        }
        Command::Keygen { out } => {
            let identity = config::create_identity(&out).map_err(config_error)?;
            write!(
                std::io::stdout(),
                "{}",
                config::public_identity_text(&identity)
            )
            .map_err(runtime_error)
        }
        Command::Check { args } => {
            let prepared = prepare(args)?;
            let mut out = std::io::stdout();
            writeln!(out, "configuration OK").map_err(runtime_error)?;
            for line in prepared.digests.to_string().split(", ") {
                writeln!(out, "{line}").map_err(runtime_error)?;
            }
            Ok(())
        }
        Command::Run {
            args,
            drain_timeout,
            runtime_dir,
            metrics,
        } => serve(
            prepare(args)?,
            Duration::from_secs(drain_timeout),
            runtime_dir,
            metrics,
        ),
        Command::Status { metrics_file } => {
            match metrics::status_command(
                &metrics_file,
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            ) {
                0 => Ok(()),
                code => Err(Failure::Exit(code)),
            }
        }
        Command::Reload {
            pid,
            runtime_dir,
            timeout,
        } => request_reload(pid, runtime_dir, Duration::from_secs(timeout)),
    }
}

/// `reload`: the outcome of the running agent's own reload.
fn request_reload(pid: u32, runtime_dir: Option<PathBuf>, wait: Duration) -> Result<(), Failure> {
    let outcome = reload::request_in(pid, runtime_dir, wait).map_err(runtime_error)?;
    outcome
        .write_report(&mut std::io::stdout(), &mut std::io::stderr())
        .map_err(runtime_error)?;
    outcome.result.map(drop).map_err(|reason| {
        Failure::Config(format!(
            "reload rejected, the previous authorized clients remain in force: {reason}"
        ))
    })
}

/// Loads the authorized clients and denylist, with the digests of the bytes parsed.
type ClientsLoader =
    Box<dyn Fn() -> Result<(zt_domain::AuthorizedClients, Digests), ConfigError> + Send>;

/// Everything `run` needs, loaded and validated: what `check` checks.
struct Prepared {
    keys: Arc<Keyring>,
    config: AgentConfig,
    updater: zt_net::Updater<zt_domain::AuthorizedClients>,
    load: ClientsLoader,
    digests: Digests,
}

fn prepare(args: AgentArgs) -> Result<Prepared, Failure> {
    let AgentArgs {
        relay,
        relay_key,
        relay_suite,
        accept_client_suites,
        node,
        key,
        previous_key,
        authorized_clients,
        revocations,
        ssh_target,
        reconnect_spread,
        max_streams,
    } = args;
    let mut relays =
        config::relay_endpoints("--relay", &relay, &relay_key).map_err(config_error)?;
    let client_suites =
        pin_suites(&mut relays, &relay_suite, &accept_client_suites).map_err(Failure::Config)?;
    let keys =
        Arc::new(config::load_keyring(&key, previous_key.as_deref()).map_err(|e| load_error(&e))?);
    let path = authorized_clients;
    // Authorized clients and denylist in a single step; a CA equal to the agent's key
    // (current or previous) or to a `--relay-key` is rejected, at startup and on every
    // reload (PROTOCOL §15.9, finding 0006-1): a compromised relay cannot sign certificates
    // that the agent admits.
    let mut forbidden = config::own_keys(&keys, "agent");
    forbidden.extend(relays.iter().map(|r| config::ForbiddenKey {
        fingerprint: r.public_key.fingerprint(),
        role: "relay",
    }));
    let load = move || {
        let (clients, digests) =
            config::load_authorized_clients_digested(&path, revocations.as_deref())?;
        config::reject_infrastructure_keys_as_authority(
            &path.display().to_string(),
            clients.cert_trust(),
            &forbidden,
        )?;
        Ok((clients, digests))
    };
    let (authorized, digests) = load().map_err(|e| load_error(&e))?;
    let (authorized_clients, updater) = Revocable::new(authorized);
    let node = NodeId::try_from(node.as_str()).map_err(config_error)?;
    let config = AgentConfig {
        relays,
        node,
        ssh_target,
        authorized_clients,
        timeouts: Timeouts::default(),
        max_streams,
        client_suites,
        identity_log_interval: zt_net::agent::IDENTITY_LOG_INTERVAL,
        reconnect: zt_net::agent::ReconnectConfig {
            spread: Duration::from_secs(reconnect_spread),
            ..zt_net::agent::ReconnectConfig::default()
        },
    };
    Ok(Prepared {
        keys,
        config,
        updater,
        load: Box::new(load),
        digests,
    })
}

#[allow(clippy::too_many_lines)] // the startup sequence, in the order it must happen
fn serve(
    prepared: Prepared,
    drain_timeout: Duration,
    runtime_dir: Option<PathBuf>,
    metrics_args: MetricsArgs,
) -> Result<(), Failure> {
    // A watchdog too short for the heartbeat would kill a healthy agent (finding A10-3).
    lifecycle::check_watchdog().map_err(Failure::Config)?;
    // Two workers: an agent serves few streams, and one worker per core of a large host only
    // costs memory (R-6, resilience.md §5.6). Two, not one, so a blocked task cannot stall the
    // watchdog's heartbeat.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(runtime_error)?;
    runtime.block_on(async move {
        let terminate = Terminate::listen().map_err(runtime_error)?;
        let hangups = Hangups::listen().map_err(runtime_error)?;
        let Prepared {
            keys,
            config,
            updater,
            load,
            ..
        } = prepared;
        // A SIGHUP between the first read (in `prepare`) and `Hangups::listen` would be lost:
        // the files are read again now that it is collected.
        let (authorized, digests) = load().map_err(|e| load_error(&e))?;
        updater.replace(authorized);
        let generation = Generation::new();
        let first = lifecycle::configuration_loaded(&generation, &digests);
        let metrics = AgentMetrics::new(config.relays.len());
        metrics.process().set_generation(first);
        let runtime_dir = reload::runtime_dir(runtime_dir);
        let metrics_file =
            metrics::default_path(metrics_args.metrics_file.clone(), runtime_dir.as_deref());
        let publisher = Publisher::new(
            runtime_dir,
            Outcome::applied(first, digests.to_string()),
        );
        publisher.publish();
        let mut supervisor = Supervisor::new();
        // The agent key changes only with a restart (PROTOCOL §14).
        supervisor.spawn(
            "agent_key_watch",
            zt_net::keys::watch(
                "agent",
                Revocable::fixed_shared(Arc::clone(&keys)),
                zt_net::keys::ROTATION_REMINDER,
            ),
        );
        supervisor.spawn(
            "authority_watch",
            zt_net::keys::watch_authorities(
                "agent",
                config.authorized_clients.clone(),
                zt_net::keys::ROTATION_REMINDER,
            ),
        );
        // The authorized clients and denylist on every SIGHUP, validated by this process with
        // its own arguments; `reload` reports the outcome (finding A10-1).
        let reload_metrics = Arc::clone(&metrics);
        supervisor.spawn(
            "authorized_clients_reload",
            reload::on_sighup(hangups, publisher, generation, move |generation| {
                match load() {
                    Ok((clients, digests)) => {
                        let generation = generation.next();
                        updater.replace(clients);
                        tracing::info!(
                            target: "zt_audit",
                            event_kind = "authorized_clients_reloaded",
                            generation,
                            files = %digests,
                            "configuration reloaded"
                        );
                        reload_metrics.process().reload_applied(generation);
                        Outcome::applied(generation, digests.to_string())
                    }
                    Err(err) => {
                        tracing::error!(
                            target: "zt_audit",
                            event_kind = "authorized_clients_reload_failed",
                            error = %err,
                            "reload failed: keeping the previous configuration"
                        );
                        reload_metrics.process().reload_rejected();
                        Outcome::rejected(err.to_string())
                    }
                }
            }),
        );
        // The agent has no central hub: its watchdog proves that the runtime still schedules
        // tasks (a wedged runtime stops this heartbeat too).
        let progress = metrics.process().progress().clone();
        let beat = progress.clone();
        supervisor.spawn("heartbeat", async move {
            let mut every = tokio::time::interval(Duration::from_secs(1));
            loop {
                every.tick().await;
                beat.advance();
            }
        });
        supervisor.spawn("watchdog", lifecycle::watchdog("agent", progress));
        supervisor.spawn("clock_watch", lifecycle::watch_clock("agent"));
        let interval = Duration::from_secs(metrics_args.metrics_interval);
        if let Some(path) = metrics_file.clone() {
            let m = Arc::clone(&metrics);
            supervisor.spawn("metrics", metrics::export(path, interval, move || m.render()));
        }
        lifecycle::check_clock("agent");
        systemd::notify_ready();
        let observed = agent::Observed {
            metrics: Arc::clone(&metrics),
            buffer_budget: metrics_args.budget(),
        };
        let outcome = tokio::select! {
            () = agent::run_observed(keys, config, TcpDialer, terminate.wait(), drain_timeout, observed) => Ok(()),
            failure = supervisor.failed() => Err(Failure::Runtime(failure)),
        };
        // The drain's end is in the last file the agent writes.
        if let Some(path) = metrics_file {
            let text = metrics::stamp(&metrics.render(), interval, std::time::SystemTime::now());
            let _ = metrics::write_textfile(&path, &text);
        }
        outcome
    })
}
