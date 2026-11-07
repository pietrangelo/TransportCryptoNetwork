//! `zt-relay`: punto d'incontro pubblico. Autentica i peer, applica la policy e inoltra flussi
//! cifrati end-to-end senza poterli leggere.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zt_net::config;
use zt_net::relay::{RelayConfig, RelayServer};

/// Relay TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genera la chiave del relay (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
    /// Avvia il relay.
    Run {
        /// Indirizzo di ascolto.
        #[arg(long, default_value = "0.0.0.0:7443")]
        listen: std::net::SocketAddr,
        /// Chiave segreta del relay.
        #[arg(long)]
        key: PathBuf,
        /// Policy di accesso (TOML).
        #[arg(long)]
        policy: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run(Cli::parse().command) {
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
            listen,
            key,
            policy,
        } => {
            let identity = config::load_identity(&key).map_err(|e| e.to_string())?;
            let policy = config::load_policy(&policy).map_err(|e| e.to_string())?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let server = RelayServer::bind(listen, identity, policy, RelayConfig::default())
                    .await
                    .map_err(|e| e.to_string())?;
                server.run().await.map_err(|e| e.to_string())
            })
        }
    }
}
