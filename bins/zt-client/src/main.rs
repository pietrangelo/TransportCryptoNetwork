//! `zt-client`: bridge stdio per OpenSSH `ProxyCommand` verso un nodo, attraverso il relay.
//!
//! ```text
//! Host web-01 db-01
//!     ProxyCommand zt-client connect %n
//! ```
//!
//! stdout è il canale SSH: ogni log e ogni errore vanno su stderr, e in caso di errore su
//! stdout non arriva nulla.
#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zt_domain::{CloseReason, NodeId, RejectReason};
use zt_net::config::{self, ClientSettings};
use zt_net::{NetError, Timeouts, client};

/// Variabile d'ambiente con il percorso della configurazione.
const CONFIG_ENV: &str = "TCN_CLIENT_CONFIG";

/// Client TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Configurazione del client. Default: `$TCN_CLIENT_CONFIG`, poi
    /// `$XDG_CONFIG_HOME/tcn/client.toml`, poi `~/.config/tcn/client.toml`.
    /// Va indicata prima del comando: dopo il nome del nodo non si legge nessuna opzione.
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genera la chiave del client (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
    /// Collega stdin/stdout al demone SSH del nodo (uso: `ProxyCommand zt-client connect %n`).
    Connect {
        /// Suffisso da togliere dal nome host prima di cercarlo tra i nodi (es. `.tcn` per
        /// `Host *.tcn`). Se indicato, il nome deve terminare con esso.
        #[arg(long)]
        strip_suffix: Option<String>,
        /// Nodo di destinazione. È l'ultimo argomento: tutto ciò che segue finisce qui e
        /// viene rifiutato, così un nome host con spazi passato da `ssh` tramite `sh -c` non
        /// può aggiungere opzioni (finding 0003-4).
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        node: Vec<String>,
    },
}

fn main() -> ExitCode {
    // I log vanno sempre su stderr: in modalità ProxyCommand stdout è il canale SSH.
    // Default `warn`, per non sporcare l'output di ssh.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { out } => keygen(&out),
        Command::Connect { strip_suffix, node } => match node.as_slice() {
            [name] => connect(cli.config, strip_suffix.as_deref(), name),
            _ => Err("expected exactly one node name, and no option after it".into()),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Su stderr OpenSSH lo mostra all'utente, che è il destinatario giusto.
            let _ = writeln!(std::io::stderr(), "zt-client: {message}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(out: &Path) -> Result<(), String> {
    let identity = config::create_identity(out).map_err(|e| e.to_string())?;
    writeln!(
        std::io::stdout(),
        "public_key  = \"{}\"\nfingerprint = {}",
        identity.public_key(),
        identity.fingerprint()
    )
    .map_err(|e| e.to_string())
}

/// Risolve il nome host passato da ssh nel nodo. Nessuna normalizzazione oltre al suffisso:
/// un nome che non è già un `NodeId` valido viene rifiutato.
fn target(name: &str, strip_suffix: Option<&str>) -> Result<NodeId, String> {
    let bare = match strip_suffix {
        None => name,
        Some("") => return Err("--strip-suffix must not be empty".into()),
        Some(suffix) => name
            .strip_suffix(suffix)
            .ok_or_else(|| format!("host name does not end with {suffix:?}"))?,
    };
    NodeId::try_from(bare).map_err(|e| format!("invalid node name: {e}"))
}

fn config_path(flag: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if let Some(p) = std::env::var_os(CONFIG_ENV).filter(|p| !p.is_empty()) {
        return Ok(p.into());
    }
    // Per la specifica XDG un valore relativo va ignorato.
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(xdg.join("tcn/client.toml"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|home| home.join(".config/tcn/client.toml"))
        .ok_or_else(|| format!("no configuration: use --config or {CONFIG_ENV}"))
}

fn connect(flag: Option<PathBuf>, strip_suffix: Option<&str>, name: &str) -> Result<(), String> {
    // Tutto ciò che è locale si valida prima di aprire qualsiasi connessione.
    let node = target(name, strip_suffix)?;
    let settings: ClientSettings =
        config::load_client_settings(&config_path(flag)?).map_err(|e| e.to_string())?;
    let config = settings
        .client_config(&node, Timeouts::default())
        .map_err(|e| e.to_string())?;
    let identity = config::load_identity(&settings.key).map_err(|e| e.to_string())?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let result = runtime.block_on(async {
        let local = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        client::connect(&identity, &config, local).await
    });
    // La lettura di stdin gira su un thread bloccante che non si può interrompere: se la
    // sessione è finita dal lato del nodo non si aspetta che ssh chiuda stdin.
    runtime.shutdown_background();
    result.map_err(|e| describe(&e, &node))
}

/// Messaggio per l'utente di ssh. Non contiene mai byte ricevuti dalla rete.
fn describe(err: &NetError, node: &NodeId) -> String {
    match err {
        NetError::Rejected(RejectReason::NotAuthorized) => {
            format!("access to {node} denied by the relay policy")
        }
        NetError::Rejected(RejectReason::UnknownNode) => {
            format!("node {node} is not known to the relay")
        }
        NetError::Rejected(RejectReason::NodeOffline) => format!("node {node} is offline"),
        NetError::Rejected(RejectReason::RateLimited) => "rate limited by the relay".into(),
        NetError::Rejected(reason) => format!("relay rejected the stream: {reason:?}"),
        NetError::StreamClosed(CloseReason::Unauthorized) => {
            format!("access denied by the agent of {node} (client key not authorized there)")
        }
        NetError::StreamClosed(CloseReason::PeerGone) => format!(
            "node {node}: the agent closed the session (ssh daemon unreachable, or agent restarting)"
        ),
        NetError::StreamClosed(CloseReason::Drained) => {
            format!("node {node} is draining (maintenance or shutdown)")
        }
        NetError::StreamClosed(reason) => format!("node {node}: session closed: {reason:?}"),
        NetError::Crypto(_) => {
            format!("secure channel failed: check relay_key and the pinned key of {node} ({err})")
        }
        NetError::Closed => "the relay closed the connection (wrong relay_key, client key \
             not in the relay policy, or relay restart)"
            .into(),
        other => other.to_string(),
    }
}
