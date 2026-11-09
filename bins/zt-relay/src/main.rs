//! `zt-relay`: public rendezvous point. It authenticates peers, enforces the policy and
//! forwards end-to-end encrypted flows without being able to read them.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zt_crypto::Keyring;
use zt_domain::AccessPolicy;
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

#[derive(Debug, Subcommand)]
enum Command {
    /// Generates the relay key (new file, 0600 permissions) and prints the public key.
    Keygen {
        /// File to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Starts the relay.
    Run {
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
        /// Handshake suites per role and admission limits (`relay.toml`, OPERATIONS §4.1).
        /// Without it, the classical suite and the defaults of PROTOCOL §10.1. Read at
        /// startup only: `SIGHUP` does not reload it.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = match cli.log_format {
        Format::Text => LogFormat::Text,
        Format::Json => LogFormat::Json,
    };
    logging::init(format, "info");
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
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

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Keygen { out } => {
            let identity = config::create_identity(&out).map_err(|e| e.to_string())?;
            writeln!(
                std::io::stdout(),
                "public_key  = \"{}\"\nfingerprint = {}",
                identity.public_key(),
                identity.fingerprint()
            )
            .map_err(|e| e.to_string())
        }
        Command::Run {
            listen,
            key,
            previous_key,
            policy,
            revocations,
            config: settings,
        } => {
            let settings = match &settings {
                Some(path) => config::load_relay_settings(path).map_err(|e| e.to_string())?,
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
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                // Before reading the files: a SIGHUP during the read is not lost.
                let hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let key_hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let keys = config::load_keyring(&key, previous_key.as_deref())
                    .map_err(|e| e.to_string())?;
                // Relay key rotation without restart (PROTOCOL §14): the new keys apply to
                // subsequent handshakes; open connections remain.
                let (keys, key_updater) = Revocable::new(keys);
                tokio::spawn(zt_net::keys::watch(
                    "relay",
                    keys.clone(),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let path = policy;
                let (path_for_keys, revocations_for_keys) = (path.clone(), revocations.clone());
                // Policy and denylist in a single step; a CA equal to the relay key (current or
                // previous, the one in force at that moment) is rejected (PROTOCOL §15.9), at
                // startup and on every reload.
                let relay_keys = keys.clone();
                let load = move || {
                    let policy = config::load_relay_policy(&path, revocations.as_deref())?;
                    config::reject_infrastructure_keys_as_authority(
                        &path.display().to_string(),
                        policy.cert_trust(),
                        &config::own_keys(&relay_keys.current(), "relay"),
                    )?;
                    Ok(policy)
                };
                let policy = load().map_err(|e: config::ConfigError| e.to_string())?;
                let (policy, updater) = Revocable::new(policy);
                // The same check in the opposite direction (finding 0006-2), see `reload_keys`.
                let key_events = ReloadEvents {
                    reloaded: "relay_keys_reloaded",
                    failed: "relay_keys_reload_failed",
                };
                let files = KeyFiles {
                    key,
                    previous_key,
                    policy: path_for_keys,
                    revocations: revocations_for_keys,
                };
                let policy_in_force = policy.clone();
                tokio::spawn(reload::on_sighup(
                    key_hangups,
                    key_updater,
                    key_events,
                    move || reload_keys(&files, &policy_in_force),
                ));
                // Unfinished agent rotations (two keys for one node): reported at startup, on
                // every reload and every hour while they remain (finding 0005b-2).
                tokio::spawn(zt_net::keys::watch_agent_rotations(
                    policy.clone(),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let events = ReloadEvents {
                    reloaded: "policy_reloaded",
                    failed: "policy_reload_failed",
                };
                tokio::spawn(reload::on_sighup(hangups, updater, events, load));
                let authorities = policy.clone();
                let server = RelayServer::bind(listen, keys, policy, relay_config)
                    .await
                    .map_err(|e| e.to_string())?;
                // Pinned CAs and denylist announced after "relay listening" and on every reload;
                // unfinished CA rotations every hour (PROTOCOL §15.11).
                tokio::spawn(zt_net::keys::watch_authorities(
                    "relay",
                    authorities,
                    zt_net::keys::ROTATION_REMINDER,
                ));
                systemd::notify_ready();
                server.run().await.map_err(|e| e.to_string())
            })
        }
    }
}
