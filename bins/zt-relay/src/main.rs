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
use zt_net::lifecycle::{self, Generation, Supervisor, Terminate};
use zt_net::logging::{self, LogFormat};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::reload::{self, Hangups, ReloadEvents};
use zt_net::{Revocable, config, systemd};

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

impl RelayArgs {
    /// The trust and settings files, whose SHA-256 identifies the configuration in force (the
    /// key files are identified by their public keys in `keys_in_use` instead).
    fn digested(&self) -> Vec<&std::path::Path> {
        std::iter::once(self.policy.as_path())
            .chain(self.revocations.as_deref())
            .chain(self.config.as_deref())
            .collect()
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generates the relay key (new file, 0600 permissions) and prints the public key.
    Keygen {
        /// File to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Starts the relay. `SIGTERM` drains it (OPERATIONS §14).
    Run {
        #[command(flatten)]
        args: RelayArgs,
        /// On `SIGTERM`, how long the open sessions may go on (seconds, 1 to 3600) before
        /// they are closed with `Close Drained`. Keep it below the unit's `TimeoutStopSec`.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
        drain_timeout: u64,
    },
    /// Validates every file `run` would load, with the same options, and prints their
    /// SHA-256; exits 78 on a configuration error. `ExecReload` runs it before `SIGHUP`.
    Check {
        #[command(flatten)]
        args: RelayArgs,
    },
}

/// How the process fails: a configuration error is `EX_CONFIG` (78), which the unit does not
/// restart on (`RestartPreventExitStatus=78`); anything else is 1 and is restarted.
enum Failure {
    Config(String),
    Runtime(String),
}

/// `EX_CONFIG` of `sysexits.h`.
const EX_CONFIG: u8 = 78;

fn config_error(e: impl std::fmt::Display) -> Failure {
    Failure::Config(e.to_string())
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
    }
}

/// The files needed to reload the relay keys.
struct KeyFiles {
    key: PathBuf,
    previous_key: Option<PathBuf>,
    policy: PathBuf,
    revocations: Option<PathBuf>,
}

/// Reloads the relay keys (`SIGHUP`, PROTOCOL §14) and rejects a key equal to a CA (§15.9,
/// finding 0006-2). The same `SIGHUP` reloads policy and keys in two tasks, so the new key is
/// compared both with the policy in force and with the one on disk: a key rotation and a new
/// CA that are equal, in the same reload, do not get in together. The policy is compared only
/// with the keys in force: a wrong key file does not block an urgent revocation.
fn reload_keys(
    files: &KeyFiles,
    policy_in_force: &Revocable<AccessPolicy>,
) -> Result<Keyring, config::ConfigError> {
    let keys = config::load_keyring(&files.key, files.previous_key.as_deref())?;
    let forbidden = config::own_keys(&keys, "relay");
    let origin = files.policy.display().to_string();
    config::reject_infrastructure_keys_as_authority(
        &origin,
        policy_in_force.current().cert_trust(),
        &forbidden,
    )?;
    if let Ok(next) = config::load_relay_policy(&files.policy, files.revocations.as_deref()) {
        config::reject_infrastructure_keys_as_authority(&origin, next.cert_trust(), &forbidden)?;
    }
    Ok(keys)
}

fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::Keygen { out } => {
            let identity = config::create_identity(&out).map_err(config_error)?;
            writeln!(
                std::io::stdout(),
                "public_key  = \"{}\"\nfingerprint = {}",
                identity.public_key(),
                identity.fingerprint()
            )
            .map_err(runtime_error)
        }
        Command::Check { args } => check(&args),
        Command::Run {
            args,
            drain_timeout,
        } => serve(args, Duration::from_secs(drain_timeout)),
    }
}

/// The policy and denylist, with a CA equal to a relay key (current or previous) rejected
/// (PROTOCOL §15.9).
fn load_policy(
    policy: &std::path::Path,
    revocations: Option<&std::path::Path>,
    keys: &Keyring,
) -> Result<AccessPolicy, config::ConfigError> {
    let loaded = config::load_relay_policy(policy, revocations)?;
    config::reject_infrastructure_keys_as_authority(
        &policy.display().to_string(),
        loaded.cert_trust(),
        &config::own_keys(keys, "relay"),
    )?;
    Ok(loaded)
}

/// `check`: every file `run` loads, with the same checks, and nothing else.
fn check(args: &RelayArgs) -> Result<(), Failure> {
    if let Some(path) = &args.config {
        config::load_relay_settings(path).map_err(config_error)?;
    }
    let keys =
        config::load_keyring(&args.key, args.previous_key.as_deref()).map_err(config_error)?;
    load_policy(&args.policy, args.revocations.as_deref(), &keys).map_err(config_error)?;
    let digests = lifecycle::digests(&args.digested());
    let mut out = std::io::stdout();
    writeln!(out, "configuration OK").map_err(runtime_error)?;
    for line in digests.split(", ") {
        writeln!(out, "{line}").map_err(runtime_error)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // the startup sequence, in the order it must happen
fn serve(args: RelayArgs, drain_timeout: Duration) -> Result<(), Failure> {
    let settings = match &args.config {
        Some(path) => config::load_relay_settings(path).map_err(config_error)?,
        None => config::RelaySettings::default(),
    };
    let relay_config = RelayConfig {
        admission: settings.admission,
        suites: settings.suites,
        agent_idle: Some(settings.agent_idle),
        client_idle: Some(settings.client_idle),
        ..RelayConfig::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(runtime_error)?;
    runtime.block_on(async {
        // First of all: from here on `SIGTERM` drains instead of killing.
        let terminate = Terminate::listen().map_err(runtime_error)?;
        // Before reading the files: a SIGHUP during the read is not lost.
        let hangups = Hangups::listen().map_err(runtime_error)?;
        let key_hangups = Hangups::listen().map_err(runtime_error)?;
        let digested: Vec<PathBuf> = args.digested().into_iter().map(PathBuf::from).collect();
        let RelayArgs {
            listen,
            key,
            previous_key,
            policy,
            revocations,
            ..
        } = args;
        let keys = config::load_keyring(&key, previous_key.as_deref()).map_err(config_error)?;
        // Relay key rotation without restart (PROTOCOL §14): the new keys apply to
        // subsequent handshakes; open connections remain.
        let (keys, key_updater) = Revocable::new(keys);
        let mut supervisor = Supervisor::new();
        supervisor.spawn(
            "relay_key_watch",
            zt_net::keys::watch("relay", keys.clone(), zt_net::keys::ROTATION_REMINDER),
        );
        let path = policy;
        let (path_for_keys, revocations_for_keys) = (path.clone(), revocations.clone());
        // Policy and denylist in a single step; a CA equal to the relay key (current or
        // previous, the one in force at that moment) is rejected (PROTOCOL §15.9), at startup
        // and on every reload.
        let relay_keys = keys.clone();
        let load = move || load_policy(&path, revocations.as_deref(), &relay_keys.current());
        let policy = load().map_err(config_error)?;
        let generation = Generation::new();
        lifecycle::configuration_loaded(
            &generation,
            &digested.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
        );
        let (policy, updater) = Revocable::new(policy);
        // The same check in the opposite direction (finding 0006-2), see `reload_keys`.
        let key_events = ReloadEvents {
            reloaded: "relay_keys_reloaded",
            failed: "relay_keys_reload_failed",
            generation: generation.clone(),
            files: Vec::new(),
        };
        let files = KeyFiles {
            key,
            previous_key,
            policy: path_for_keys,
            revocations: revocations_for_keys,
        };
        let policy_in_force = policy.clone();
        supervisor.spawn(
            "relay_key_reload",
            reload::on_sighup(key_hangups, key_updater, key_events, move || {
                reload_keys(&files, &policy_in_force)
            }),
        );
        // Unfinished agent rotations (two keys for one node): reported at startup, on every
        // reload and every hour while they remain (finding 0005b-2).
        supervisor.spawn(
            "agent_rotation_watch",
            zt_net::keys::watch_agent_rotations(policy.clone(), zt_net::keys::ROTATION_REMINDER),
        );
        let events = ReloadEvents {
            reloaded: "policy_reloaded",
            failed: "policy_reload_failed",
            generation,
            files: digested,
        };
        supervisor.spawn("policy_reload", reload::on_sighup(hangups, updater, events, load));
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
        lifecycle::check_clock("relay");
        systemd::notify_ready();
        tokio::select! {
            outcome = server.run_until(terminate.wait(), drain_timeout) => outcome.map_err(runtime_error),
            failure = supervisor.failed() => Err(Failure::Runtime(failure)),
        }
    })
}
