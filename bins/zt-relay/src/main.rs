//! `zt-relay`: public rendezvous point. It authenticates peers, enforces the policy and
//! forwards end-to-end encrypted flows without being able to read them.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use zt_crypto::Keyring;
use zt_domain::AccessPolicy;
use zt_net::config::{ConfigError, Digests};
use zt_net::lifecycle::{self, Generation, Supervisor, Terminate};
use zt_net::logging::{self, LogFormat};
use zt_net::metrics::{self, RelayMetrics};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::reload::{self, Hangups, Outcome, Publisher};
use zt_net::{Revocable, Updater, config, sunset, systemd};

/// TCN relay.
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

/// The files and settings of a relay, shared by `run` and `check`.
#[derive(Debug, clap::Args)]
struct RelayArgs {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:7443")]
    listen: std::net::SocketAddr,
    /// Secret key of the relay. `SIGHUP` reloads it: it applies to new connections.
    #[arg(long)]
    key: PathBuf,
    /// Previous secret key, during a rotation: peers that still pin the old public key
    /// remain accepted (PROTOCOL §14). `SIGHUP` reloads this one too; removing it requires
    /// a restart without the option.
    #[arg(long)]
    previous_key: Option<PathBuf>,
    /// Access policy (TOML). `SIGHUP` reloads it and also applies it to open connections; an
    /// invalid file leaves the previous one in force.
    #[arg(long)]
    policy: PathBuf,
    /// Denylist of certificates and keys (`revoked.toml`, PROTOCOL §15.8). Mandatory if the
    /// policy pins a CA (`[[authorities]]`), even if empty. `SIGHUP` reloads it together with
    /// the policy: if either file is invalid, both previous ones remain.
    #[arg(long)]
    revocations: Option<PathBuf>,
    /// Handshake suites per role, admission limits and idle timeouts (`relay.toml`,
    /// OPERATIONS §4.1). Without it, the classical suite and the defaults of PROTOCOL §10.1.
    /// Read at startup only: `SIGHUP` does not reload it.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generates the relay key (new file, 0600 permissions) and prints the public key.
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
    /// Starts the relay. `SIGTERM` drains it (OPERATIONS §14).
    Run {
        #[command(flatten)]
        args: RelayArgs,
        /// On `SIGTERM`, how long the open sessions may go on (seconds, 1 to 3600) before
        /// they are closed with `Close Drained`. Keep it below the unit's `TimeoutStopSec`.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
        drain_timeout: u64,
        /// Where the reload state for `reload` is published. Default: `$RUNTIME_DIRECTORY`
        /// (systemd's `RuntimeDirectory=`); without either, `reload` cannot be used.
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        #[command(flatten)]
        metrics: MetricsArgs,
    },
    /// Prints the metrics file the running relay writes (R-5): its age and every value.
    /// Exit 0 if fresh, 1 if missing or invalid, 2 if stale (older than three intervals).
    Status {
        /// The metrics file (`run --metrics-file`).
        #[arg(long, default_value = "/run/zt-relay/metrics.prom")]
        metrics_file: PathBuf,
    },
    /// Validates every file `run` loads at startup, with the same options and the same code,
    /// and prints their SHA-256; exits 78 on an invalid file, 1 on a missing or unreadable one.
    /// A pre-flight before a restart; `systemctl reload` uses `reload`.
    Check {
        #[command(flatten)]
        args: RelayArgs,
    },
    /// Asks the running relay to reload (`SIGHUP`) and reports its outcome: exit 0 if the
    /// relay applied the policy (warnings, e.g. a key file it could not reload, on stderr), 78
    /// if it rejected it and kept the previous one, 1 if it did not answer. The relay validates
    /// its own files with its own arguments, so this takes none (`ExecReload=`, finding A10-1).
    Reload {
        /// The relay's process id (`$MAINPID` in the unit).
        #[arg(long)]
        pid: u32,
        /// The relay's runtime directory. Default: `$RUNTIME_DIRECTORY`.
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
    /// Default: `metrics.prom` in the runtime directory. Nothing ever listens for metrics.
    #[arg(long)]
    metrics_file: Option<PathBuf>,
    /// How often the metrics file is rewritten, in seconds (1 to 3600).
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=3600))]
    metrics_interval: u64,
    /// The global byte budget of the frames queued towards peers, in MiB (16 to 65536; R-6,
    /// OPERATIONS §18). Past it, the identity holding the most of it loses its largest
    /// connection; no identity may hold more than a quarter of it. Default: a quarter of the
    /// memory (cgroup limit included), from 128 MiB to 1 GiB.
    #[arg(long, value_parser = clap::value_parser!(u64).range(16..=65536))]
    queue_budget_mib: Option<u64>,
}

impl MetricsArgs {
    /// The byte budget, from `--queue-budget-mib` or the default.
    fn budget(&self) -> usize {
        self.queue_budget_mib
            .map_or_else(zt_net::budget::default_queue_budget, |mib| {
                usize::try_from(mib.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
            })
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

/// Everything `run` loads at startup, validated: what `check` checks, by the same code.
struct Startup {
    settings: config::RelaySettings,
    keys: Keyring,
    policy: AccessPolicy,
    digests: Digests,
}

fn load_startup(args: &RelayArgs) -> Result<Startup, Failure> {
    let mut digests = Digests::new();
    let settings = match &args.config {
        Some(path) => {
            let (settings, d) =
                config::load_relay_settings_digested(path).map_err(|e| load_error(&e))?;
            digests.extend(d);
            settings
        }
        None => config::RelaySettings::default(),
    };
    let keys = config::load_keyring(&args.key, args.previous_key.as_deref())
        .map_err(|e| load_error(&e))?;
    let (policy, d) = config::load_relay_policy_checked(
        &args.policy,
        args.revocations.as_deref(),
        &keys,
        settings.pq_only,
    )
    .map_err(|e| load_error(&e))?;
    digests.extend(d);
    Ok(Startup {
        settings,
        keys,
        policy,
        digests,
    })
}

/// What a `SIGHUP` reloads, and how it applies it.
struct Reloader {
    key: PathBuf,
    previous_key: Option<PathBuf>,
    policy_path: PathBuf,
    revocations: Option<PathBuf>,
    keys: Revocable<Keyring>,
    key_updater: Updater<Keyring>,
    policy: Revocable<AccessPolicy>,
    policy_updater: Updater<AccessPolicy>,
    metrics: std::sync::Arc<RelayMetrics>,
    /// `relay.toml` as read at startup: every reloaded policy is checked against its
    /// `[handshake] pq_only`, and reported against its suites (review 0014, A14-3, A14-4).
    settings: config::RelaySettings,
}

impl Reloader {
    /// One `SIGHUP` (finding A10-2): the policy and denylist, checked against the keys in
    /// force, and the keys, checked against the policy in force and the new one (a key and a
    /// CA that are equal never get in together, finding 0006-2). The policy is the urgent part
    /// (revocation): a key file that cannot be reloaded is a warning and does not block it.
    /// `relay.toml` is read at startup only and is not part of a reload. One generation for
    /// both, taken only if something was applied.
    fn reload(&self, generation: &Generation) -> Outcome {
        let policy = config::load_relay_policy_checked(
            &self.policy_path,
            self.revocations.as_deref(),
            &self.keys.current(),
            self.settings.pq_only,
        );
        let keys = self.load_keys(policy.as_ref().ok().map(|(p, _)| p));
        let generation = (policy.is_ok() || keys.is_ok()).then(|| generation.next());
        let mut warnings = Vec::new();
        match keys {
            Ok(keys) => {
                self.key_updater.replace(keys);
                tracing::info!(
                    target: "zt_audit",
                    event_kind = "relay_keys_reloaded",
                    generation,
                    "relay keys reloaded"
                );
            }
            Err(err) => {
                tracing::error!(
                    target: "zt_audit",
                    event_kind = "relay_keys_reload_failed",
                    error = %err,
                    "relay key reload failed: keeping the keys in force"
                );
                warnings.push(format!(
                    "relay keys not reloaded, the keys in force remain: {err}"
                ));
            }
        }
        let result = match policy {
            Ok((policy, digests)) => {
                let report = sunset::relay_report(&self.settings, &policy);
                self.policy_updater.replace(policy);
                tracing::info!(
                    target: "zt_audit",
                    event_kind = "policy_reloaded",
                    generation,
                    files = %digests,
                    "configuration reloaded"
                );
                sunset::log_profile("relay", self.settings.pq_only, &report);
                self.metrics
                    .process()
                    .reload_applied(generation.unwrap_or_default());
                Ok((generation.unwrap_or_default(), digests.to_string()))
            }
            Err(err) => {
                tracing::error!(
                    target: "zt_audit",
                    event_kind = "policy_reload_failed",
                    error = %err,
                    "reload failed: keeping the previous configuration"
                );
                self.metrics.process().reload_rejected();
                Err(err.to_string())
            }
        };
        Outcome { result, warnings }
    }

    /// The keys on disk, with no CA of the policy in force or of `next` equal to one of them.
    fn load_keys(&self, next: Option<&AccessPolicy>) -> Result<Keyring, ConfigError> {
        let keys = config::load_keyring(&self.key, self.previous_key.as_deref())?;
        let forbidden = config::own_keys(&keys, "relay");
        let origin = self.policy_path.display().to_string();
        config::reject_infrastructure_keys_as_authority(
            &origin,
            self.policy.current().cert_trust(),
            &forbidden,
        )?;
        if let Some(next) = next {
            config::reject_infrastructure_keys_as_authority(
                &origin,
                next.cert_trust(),
                &forbidden,
            )?;
        }
        Ok(keys)
    }
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
        Command::Check { args } => check(&args),
        Command::Run {
            args,
            drain_timeout,
            runtime_dir,
            metrics,
        } => serve(
            args,
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

/// `reload`: the outcome of the running relay's own reload.
fn request_reload(pid: u32, runtime_dir: Option<PathBuf>, wait: Duration) -> Result<(), Failure> {
    let outcome = reload::request_in(pid, runtime_dir, wait).map_err(runtime_error)?;
    outcome
        .write_report(&mut std::io::stdout(), &mut std::io::stderr())
        .map_err(runtime_error)?;
    outcome.result.map(drop).map_err(|reason| {
        Failure::Config(format!(
            "reload rejected, the previous configuration remains in force: {reason}"
        ))
    })
}

/// `check`: every file `run` loads at startup, through the same function.
fn check(args: &RelayArgs) -> Result<(), Failure> {
    let startup = load_startup(args)?;
    let mut out = std::io::stdout();
    writeln!(out, "configuration OK").map_err(runtime_error)?;
    for line in startup.digests.to_string().split(", ") {
        writeln!(out, "{line}").map_err(runtime_error)?;
    }
    let report = sunset::relay_report(&startup.settings, &startup.policy);
    sunset::write_report(&mut out, startup.settings.pq_only, &report).map_err(runtime_error)
}

#[allow(clippy::too_many_lines)] // the startup sequence, in the order it must happen
fn serve(
    args: RelayArgs,
    drain_timeout: Duration,
    runtime_dir: Option<PathBuf>,
    metrics_args: MetricsArgs,
) -> Result<(), Failure> {
    // A watchdog too short for the hub's tick would kill a healthy relay (finding A10-3).
    lifecycle::check_watchdog().map_err(Failure::Config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(runtime_error)?;
    runtime.block_on(async {
        // First of all: from here on `SIGTERM` drains instead of killing.
        let terminate = Terminate::listen().map_err(runtime_error)?;
        // Before reading the files: a SIGHUP during the read is not lost.
        let hangups = Hangups::listen().map_err(runtime_error)?;
        let Startup {
            settings,
            keys,
            policy,
            digests,
        } = load_startup(&args)?;
        // The profile and what is still classical, in the journal and not only in `check`
        // (review 0014, A14-4).
        sunset::log_profile(
            "relay",
            settings.pq_only,
            &sunset::relay_report(&settings, &policy),
        );
        let metrics = RelayMetrics::new();
        let relay_config = RelayConfig {
            metrics: std::sync::Arc::clone(&metrics),
            queue_budget: metrics_args.budget(),
            admission: settings.admission.clone(),
            suites: settings.suites,
            agent_idle: Some(settings.agent_idle),
            client_idle: Some(settings.client_idle),
            ..RelayConfig::default()
        };
        let generation = Generation::new();
        let first = lifecycle::configuration_loaded(&generation, &digests);
        metrics.process().set_generation(first);
        let runtime_dir = reload::runtime_dir(runtime_dir);
        let metrics_file = metrics::default_path(metrics_args.metrics_file, runtime_dir.as_deref());
        let publisher = Publisher::new(
            runtime_dir,
            Outcome::applied(first, digests.to_string()),
        );
        publisher.publish();
        // Relay key rotation without restart (PROTOCOL §14): the new keys apply to
        // subsequent handshakes; open connections remain.
        let (keys, key_updater) = Revocable::new(keys);
        let (policy, policy_updater) = Revocable::new(policy);
        let mut supervisor = Supervisor::new();
        supervisor.spawn(
            "relay_key_watch",
            zt_net::keys::watch("relay", keys.clone(), zt_net::keys::ROTATION_REMINDER),
        );
        let RelayArgs {
            listen,
            key,
            previous_key,
            policy: policy_path,
            revocations,
            ..
        } = args;
        let reloader = Reloader {
            settings,
            key,
            previous_key,
            policy_path,
            revocations,
            keys: keys.clone(),
            key_updater,
            policy: policy.clone(),
            policy_updater,
            metrics: std::sync::Arc::clone(&metrics),
        };
        // Policy, denylist and keys on every SIGHUP, in one step with one outcome.
        supervisor.spawn(
            "reload",
            reload::on_sighup(hangups, publisher, generation, move |g| reloader.reload(g)),
        );
        // Unfinished agent rotations (two keys for one node): reported at startup, on every
        // reload and every hour while they remain (finding 0005b-2).
        supervisor.spawn(
            "agent_rotation_watch",
            zt_net::keys::watch_agent_rotations(policy.clone(), zt_net::keys::ROTATION_REMINDER),
        );
        let authorities = policy.clone();
        let server = RelayServer::bind(listen, keys, policy, relay_config)
            .await
            .map_err(runtime_error)?;
        // Pinned CAs and denylist announced after "relay listening" and on every reload;
        // unfinished CA rotations every hour (PROTOCOL §15.11).
        supervisor.spawn(
            "authority_watch",
            zt_net::keys::watch_authorities(
                "relay",
                authorities,
                zt_net::keys::ROTATION_REMINDER,
            ),
        );
        // The watchdog follows the hub's progress, not a timer of its own (AP-4).
        supervisor.spawn("watchdog", lifecycle::watchdog("relay", server.progress()));
        supervisor.spawn("clock_watch", lifecycle::watch_clock("relay"));
        let interval = Duration::from_secs(metrics_args.metrics_interval);
        if let Some(path) = metrics_file.clone() {
            let m = std::sync::Arc::clone(&metrics);
            supervisor.spawn("metrics", metrics::export(path, interval, move || m.render()));
        }
        lifecycle::check_clock("relay");
        systemd::notify_ready();
        let outcome = tokio::select! {
            outcome = server.run_until(terminate.wait(), drain_timeout) => outcome.map_err(runtime_error),
            failure = supervisor.failed() => Err(Failure::Runtime(failure)),
        };
        // The drain's end is in the last file the relay writes.
        if let Some(path) = metrics_file {
            let text = metrics::stamp(&metrics.render(), interval, std::time::SystemTime::now());
            let _ = metrics::write_textfile(&path, &text);
        }
        outcome
    })
}
