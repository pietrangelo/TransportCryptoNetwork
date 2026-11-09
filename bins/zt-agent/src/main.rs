//! `zt-agent`: runs on target servers with no listening ports. It connects outbound to the
//! relay and forwards to the local SSH daemon only streams of end-to-end authorized clients.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use zt_crypto::PublicKey;
use zt_domain::NodeId;
use zt_net::Timeouts;
use zt_net::agent::{self, AgentConfig};
use zt_net::logging::{self, LogFormat};
use zt_net::reload::{self, Hangups, ReloadEvents};
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

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // value built once, at startup
enum Command {
    /// Generates the agent key (new file, 0600 permissions) and prints the public key.
    Keygen {
        /// File to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Starts the agent.
    Run {
        /// Relay (`host:port`). Repeatable, or comma-separated: the agent stays connected to all
        /// of them (at most 8).
        #[arg(long, required = true, value_delimiter = ',')]
        relay: Vec<String>,
        /// Public key of each relay (64 hex characters), in the same order as `--relay`.
        #[arg(long, required = true, value_delimiter = ',')]
        relay_key: Vec<PublicKey>,
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
        /// Concurrent sessions (from 1 to 4096).
        #[arg(long, default_value_t = 16, value_parser = parse_max_streams)]
        max_streams: usize,
    },
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
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
    }
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
            relay,
            relay_key,
            node,
            key,
            previous_key,
            authorized_clients,
            revocations,
            ssh_target,
            max_streams,
        } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async move {
                // Before reading the files: a SIGHUP during the read is not lost.
                let hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let relays = config::relay_endpoints("--relay", &relay, &relay_key)
                    .map_err(|e| e.to_string())?;
                let keys = Arc::new(
                    config::load_keyring(&key, previous_key.as_deref())
                        .map_err(|e| e.to_string())?,
                );
                // The agent key changes only with a restart (PROTOCOL §14).
                tokio::spawn(zt_net::keys::watch(
                    "agent",
                    Revocable::fixed_shared(Arc::clone(&keys)),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let path = authorized_clients;
                // Authorized clients and denylist in a single step; a CA equal to the agent's key
                // (current or previous) or to a `--relay-key` is rejected, at startup and on every
                // reload (PROTOCOL §15.9, finding 0006-1): a compromised relay cannot sign
                // certificates that the agent admits.
                let mut forbidden = config::own_keys(&keys, "agent");
                forbidden.extend(relays.iter().map(|r| config::ForbiddenKey {
                    fingerprint: r.public_key.fingerprint(),
                    role: "relay",
                }));
                let load = move || {
                    let clients = config::load_authorized_clients(&path, revocations.as_deref())?;
                    config::reject_infrastructure_keys_as_authority(
                        &path.display().to_string(),
                        clients.cert_trust(),
                        &forbidden,
                    )?;
                    Ok(clients)
                };
                let authorized = load().map_err(|e: config::ConfigError| e.to_string())?;
                let (authorized_clients, updater) = Revocable::new(authorized);
                tokio::spawn(zt_net::keys::watch_authorities(
                    "agent",
                    authorized_clients.clone(),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let node = NodeId::try_from(node.as_str()).map_err(|e| e.to_string())?;
                let config = AgentConfig {
                    relays,
                    node,
                    ssh_target,
                    authorized_clients,
                    timeouts: Timeouts::default(),
                    max_streams,
                    client_suites: zt_domain::AcceptedSuites::only(
                        zt_domain::HandshakeSuite::NoiseIk25519,
                    ),
                };
                let events = ReloadEvents {
                    reloaded: "authorized_clients_reloaded",
                    failed: "authorized_clients_reload_failed",
                };
                tokio::spawn(reload::on_sighup(hangups, updater, events, load));
                systemd::notify_ready();
                agent::run(keys, config).await;
                Ok(())
            })
        }
    }
}
