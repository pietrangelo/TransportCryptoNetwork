//! `zt-agent`: gira sui server target senza porte in ascolto. Si connette in uscita al relay e
//! inoltra al demone SSH locale solo gli stream di client autorizzati end-to-end.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zt_crypto::PublicKey;
use zt_domain::NodeId;
use zt_net::Timeouts;
use zt_net::agent::{self, AgentConfig};
use zt_net::config;

/// Agent TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)] // valore costruito una volta, all'avvio
enum Command {
    /// Genera la chiave dell'agent (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
    /// Avvia l'agent.
    Run {
        /// Indirizzo del relay (`host:porta`).
        #[arg(long)]
        relay: String,
        /// Chiave pubblica del relay (64 caratteri esadecimali).
        #[arg(long)]
        relay_key: PublicKey,
        /// Nome di questo nodo, come nella policy del relay.
        #[arg(long)]
        node: String,
        /// Chiave segreta dell'agent.
        #[arg(long)]
        key: PathBuf,
        /// Client accettati end-to-end (TOML, sezioni `[[clients]]`).
        #[arg(long)]
        authorized_clients: PathBuf,
        /// Demone SSH locale.
        #[arg(long, default_value = "127.0.0.1:22")]
        ssh_target: String,
        /// Sessioni contemporanee.
        #[arg(long, default_value_t = 16)]
        max_streams: usize,
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
            relay,
            relay_key,
            node,
            key,
            authorized_clients,
            ssh_target,
            max_streams,
        } => {
            let identity = Arc::new(config::load_identity(&key).map_err(|e| e.to_string())?);
            let authorized =
                config::load_authorized_clients(&authorized_clients).map_err(|e| e.to_string())?;
            let node = NodeId::try_from(node.as_str()).map_err(|e| e.to_string())?;
            let config = AgentConfig {
                relay,
                relay_key,
                node,
                ssh_target,
                authorized_clients: Arc::new(authorized),
                timeouts: Timeouts::default(),
                max_streams,
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(agent::run(identity, config));
            Ok(())
        }
    }
}
