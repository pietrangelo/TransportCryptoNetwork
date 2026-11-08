//! `zt-relay`: punto d'incontro pubblico. Autentica i peer, applica la policy e inoltra flussi
//! cifrati end-to-end senza poterli leggere.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zt_net::logging::{self, LogFormat};
use zt_net::relay::{RelayConfig, RelayServer};
use zt_net::reload::{self, Hangups, ReloadEvents};
use zt_net::{Revocable, config, systemd};

/// Relay TCN.
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
        /// Chiave segreta del relay. `SIGHUP` la ricarica: vale per le connessioni nuove.
        #[arg(long)]
        key: PathBuf,
        /// Chiave segreta precedente, durante una rotazione: i peer che pinnano ancora la
        /// vecchia chiave pubblica restano accettati (PROTOCOL §14). `SIGHUP` ricarica anche
        /// questa; per toglierla serve un riavvio senza l'opzione.
        #[arg(long)]
        previous_key: Option<PathBuf>,
        /// Policy di accesso (TOML). `SIGHUP` la ricarica e la applica anche alle connessioni
        /// aperte; un file non valido lascia in vigore quella precedente.
        #[arg(long)]
        policy: PathBuf,
        /// Denylist di certificati e chiavi (`revoked.toml`, PROTOCOL §15.8). Obbligatoria se
        /// la policy pinna una CA (`[[authorities]]`), anche vuota. `SIGHUP` la ricarica
        /// insieme alla policy: se uno dei due file non è valido restano entrambi i precedenti.
        #[arg(long)]
        revocations: Option<PathBuf>,
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
        } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                // Prima di leggere i file: un SIGHUP durante la lettura non va perso.
                let hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let key_hangups = Hangups::listen().map_err(|e| e.to_string())?;
                let keys = config::load_keyring(&key, previous_key.as_deref())
                    .map_err(|e| e.to_string())?;
                // Rotazione della chiave del relay senza riavvio (PROTOCOL §14): le chiavi nuove
                // valgono per gli handshake successivi; le connessioni aperte restano.
                let (keys, key_updater) = Revocable::new(keys);
                tokio::spawn(zt_net::keys::watch(
                    "relay",
                    keys.clone(),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let key_events = ReloadEvents {
                    reloaded: "relay_keys_reloaded",
                    failed: "relay_keys_reload_failed",
                };
                tokio::spawn(reload::on_sighup(
                    key_hangups,
                    key_updater,
                    key_events,
                    move || config::load_keyring(&key, previous_key.as_deref()),
                ));
                let path = policy;
                let policy = config::load_relay_policy(&path, revocations.as_deref())
                    .map_err(|e| e.to_string())?;
                let (policy, updater) = Revocable::new(policy);
                // Rotazioni di agent non completate (due chiavi per un nodo): segnalate
                // all'avvio, a ogni ricarica e ogni ora finché restano (finding 0005b-2).
                tokio::spawn(zt_net::keys::watch_agent_rotations(
                    policy.clone(),
                    zt_net::keys::ROTATION_REMINDER,
                ));
                let events = ReloadEvents {
                    reloaded: "policy_reloaded",
                    failed: "policy_reload_failed",
                };
                tokio::spawn(reload::on_sighup(hangups, updater, events, move || {
                    config::load_relay_policy(&path, revocations.as_deref())
                }));
                let server = RelayServer::bind(listen, keys, policy, RelayConfig::default())
                    .await
                    .map_err(|e| e.to_string())?;
                systemd::notify_ready();
                server.run().await.map_err(|e| e.to_string())
            })
        }
    }
}
