//! `zt-agent`: gira sui server target senza porte in ascolto. Si connette in uscita al relay e
//! inoltra al demone SSH locale solo gli stream di client autorizzati end-to-end.
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

/// Agent TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Formato dei log su stderr.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    log_format: Format,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Format {
    /// Testo leggibile.
    Text,
    /// Una riga JSON per evento (per SIEM e `jq`).
    Json,
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
        /// Relay (`host:porta`). Ripetibile, o separati da virgole: l'agent resta connesso a
        /// tutti (al massimo 8).
        #[arg(long, required = true, value_delimiter = ',')]
        relay: Vec<String>,
        /// Chiave pubblica di ogni relay (64 caratteri esadecimali), nello stesso ordine di
        /// `--relay`.
        #[arg(long, required = true, value_delimiter = ',')]
        relay_key: Vec<PublicKey>,
        /// Nome di questo nodo, come nella policy del relay.
        #[arg(long)]
        node: String,
        /// Chiave segreta dell'agent.
        #[arg(long)]
        key: PathBuf,
        /// Chiave segreta precedente, durante una rotazione: il canale end-to-end la accetta
        /// ancora, così i client si aggiornano un po' alla volta (PROTOCOL §14).
        #[arg(long)]
        previous_key: Option<PathBuf>,
        /// Client accettati end-to-end (TOML, sezioni `[[clients]]`). `SIGHUP` lo ricarica e
        /// chiude subito le sessioni dei client rimossi.
        #[arg(long)]
        authorized_clients: PathBuf,
        /// Denylist di certificati e chiavi (`revoked.toml`, PROTOCOL §15.8). Obbligatoria se
        /// i client autorizzati pinnano una CA (`[[authorities]]`), anche vuota. `SIGHUP` la
        /// ricarica insieme ai client autorizzati.
        #[arg(long)]
        revocations: Option<PathBuf>,
        /// Demone SSH locale.
        #[arg(long, default_value = "127.0.0.1:22")]
        ssh_target: String,
        /// Sessioni contemporanee (da 1 a 4096).
        #[arg(long, default_value_t = 16, value_parser = parse_max_streams)]
        max_streams: usize,
    },
}

/// `--max-streams` entro i limiti dell'agent (finding 0005b-4: oltre il massimo del semaforo
/// di tokio l'agent andava in panic all'avvio).
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
                // Prima di leggere i file: un SIGHUP durante la lettura non va perso.
                let hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let relays = config::relay_endpoints("--relay", &relay, &relay_key)
                    .map_err(|e| e.to_string())?;
                let keys = Arc::new(
                    config::load_keyring(&key, previous_key.as_deref())
                        .map_err(|e| e.to_string())?,
                );
                // La chiave dell'agent cambia solo con un riavvio (PROTOCOL §14).
                tokio::spawn(zt_net::keys::watch(
                    "agent",
                    Revocable::fixed_shared(Arc::clone(&keys)),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let path = authorized_clients;
                let authorized = config::load_authorized_clients(&path, revocations.as_deref())
                    .map_err(|e| e.to_string())?;
                let (authorized_clients, updater) = Revocable::new(authorized);
                let node = NodeId::try_from(node.as_str()).map_err(|e| e.to_string())?;
                let config = AgentConfig {
                    relays,
                    node,
                    ssh_target,
                    authorized_clients,
                    timeouts: Timeouts::default(),
                    max_streams,
                };
                let events = ReloadEvents {
                    reloaded: "authorized_clients_reloaded",
                    failed: "authorized_clients_reload_failed",
                };
                tokio::spawn(reload::on_sighup(hangups, updater, events, move || {
                    config::load_authorized_clients(&path, revocations.as_deref())
                }));
                systemd::notify_ready();
                agent::run(keys, config).await;
                Ok(())
            })
        }
    }
}
