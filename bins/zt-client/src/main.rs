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

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zt_crypto::{Identity, PublicKey, cert_key};
use zt_domain::{CertBody, CertScope, CloseReason, NodeId, RejectReason, UnixTime};
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
    /// Stampa nome, nodi, CA, numero di serie e validità del certificato configurato
    /// (`certificate` in `client.toml`, PROTOCOL §15).
    Certificate,
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
        Command::Certificate => certificate(cli.config.as_deref()),
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

/// Sotto questa durata residua `zt-client` avvisa che il certificato sta per scadere.
const EXPIRY_WARNING_SECS: u64 = 15 * 60;

/// `zt-client certificate`: i campi del certificato configurato, senza rete.
fn certificate(flag: Option<&Path>) -> Result<(), String> {
    let path = config_path(flag.map(Path::to_path_buf))?;
    let settings = config::load_client_settings(&path).map_err(|e| e.to_string())?;
    let Some(cert_path) = settings.certificate.as_deref() else {
        return Err(format!("{}: no certificate configured", path.display()));
    };
    let cert = config::load_certificate(cert_path).map_err(|e| e.to_string())?;
    let body = &cert.body;
    let identity = config::load_identity(&settings.key).map_err(|e| e.to_string())?;
    reject_leaked_secret(cert_path, body, &identity)?;
    let mut out = String::new();
    let _ = writeln!(out, "file        = {}", cert_path.display());
    let _ = writeln!(out, "name        = {}", body.name());
    let nodes = match body.scope() {
        CertScope::All => "* (every node the CA may grant)".to_owned(),
        CertScope::Only(nodes) => nodes
            .iter()
            .map(NodeId::as_str)
            .collect::<Vec<_>>()
            .join(", "),
    };
    let _ = writeln!(out, "nodes       = {nodes}");
    match PublicKey::from_canonical_bytes(body.ca_key().as_bytes()) {
        Ok(ca) => {
            let _ = writeln!(out, "ca          = {}", ca.fingerprint());
        }
        Err(_) => {
            let _ = writeln!(out, "ca          = invalid key");
        }
    }
    match PublicKey::from_canonical_bytes(body.subject_key().as_bytes()) {
        Ok(subject) => {
            let _ = writeln!(out, "subject     = {}", subject.fingerprint());
        }
        Err(_) => {
            let _ = writeln!(out, "subject     = invalid key");
        }
    }
    let _ = writeln!(out, "serial      = {}", body.serial());
    let _ = writeln!(out, "not_before  = {}", zt_net::utc_text(body.not_before()));
    let _ = writeln!(out, "not_after   = {}", zt_net::utc_text(body.not_after()));
    let status = match check_validity(body, zt_net::unix_now()) {
        Validity::Expired => "expired: renew it",
        Validity::NotYetValid => "not yet valid",
        Validity::ExpiringSoon => "valid, expires in less than 15 minutes",
        Validity::Valid => "valid",
    };
    let _ = writeln!(out, "status      = {status} (local clock)");
    std::io::stdout()
        .write_all(out.as_bytes())
        .map_err(|e| e.to_string())
}

/// Stato di un certificato secondo l'orologio locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validity {
    Valid,
    ExpiringSoon,
    NotYetValid,
    Expired,
}

fn check_validity(body: &CertBody, now: UnixTime) -> Validity {
    if now >= body.not_after() {
        Validity::Expired
    } else if now < body.not_before() {
        Validity::NotYetValid
    } else if body.not_after().as_secs().saturating_sub(now.as_secs()) < EXPIRY_WARNING_SECS {
        Validity::ExpiringSoon
    } else {
        Validity::Valid
    }
}

/// Carica il certificato configurato e controlla, prima di qualsiasi connessione, che sia per
/// `identity` e non sia scaduto. Un certificato non ancora valido o vicino alla scadenza
/// provoca solo un avviso su stderr (gli orologi di relay e agent decidono).
fn load_own_certificate(
    path: &Path,
    identity: &Identity,
) -> Result<config::CertificateFile, String> {
    let cert = config::load_certificate(path).map_err(|e| e.to_string())?;
    reject_leaked_secret(path, &cert.body, identity)?;
    if *cert.body.subject_key() != cert_key(&identity.public_key()) {
        return Err(format!(
            "{}: the certificate is for another key (subject {}), not for this client's key {}",
            path.display(),
            PublicKey::from_canonical_bytes(cert.body.subject_key().as_bytes())
                .map_or_else(|_| "invalid".to_owned(), |k| k.fingerprint().to_string()),
            identity.fingerprint()
        ));
    }
    let (nb, na) = (
        zt_net::utc_text(cert.body.not_before()),
        zt_net::utc_text(cert.body.not_after()),
    );
    match check_validity(&cert.body, zt_net::unix_now()) {
        Validity::Expired => {
            return Err(format!(
                "{}: certificate expired at {na}: renew it",
                path.display()
            ));
        }
        Validity::NotYetValid => warn(&format!(
            "warning: {}: certificate not yet valid (from {nb}, local clock)",
            path.display()
        )),
        Validity::ExpiringSoon => warn(&format!(
            "warning: {}: certificate will expire at {na}, in less than 15 minutes: renew it",
            path.display()
        )),
        Validity::Valid => {}
    }
    Ok(cert)
}

/// Un certificato il cui `subject_key` è il **segreto** del client (`--subject` di `zt-ca` con
/// il contenuto del file della chiave, 64 caratteri esadecimali come una chiave pubblica):
/// il segreto è ormai in un file pubblico e nel registro della CA, quindi la chiave va
/// rigenerata (finding 0006-6). Il messaggio non riporta mai il segreto.
fn reject_leaked_secret(path: &Path, body: &CertBody, identity: &Identity) -> Result<(), String> {
    if identity.is_own_secret(body.subject_key().as_bytes()) {
        return Err(format!(
            "{}: secret key leaked into a certificate: regenerate the client key \
             (zt-client keygen), send the CA the public key, and revoke this certificate",
            path.display()
        ));
    }
    Ok(())
}

fn warn(message: &str) {
    let _ = writeln!(std::io::stderr(), "zt-client: {message}");
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
    let mut config = settings
        .client_config(&node, Timeouts::default())
        .map_err(|e| e.to_string())?;
    let identity = config::load_identity(&settings.key).map_err(|e| e.to_string())?;
    let not_after = match settings.certificate.as_deref() {
        Some(path) => {
            let cert = load_own_certificate(path, &identity)?;
            config.certificate = Some(cert.bytes);
            Some(cert.body.not_after())
        }
        None => None,
    };

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
    result.map_err(|e| describe(&e, &node, not_after))
}

/// Messaggio per l'utente di ssh. Non contiene mai byte ricevuti dalla rete. `not_after` è la
/// scadenza del certificato usato, se c'è.
fn describe(err: &NetError, node: &NodeId, not_after: Option<UnixTime>) -> String {
    let expired = not_after.is_some_and(|na| zt_net::unix_now() >= na);
    match err {
        NetError::StreamClosed(CloseReason::Unauthorized) if expired => {
            "certificate expired: renew it".into()
        }
        NetError::Closed if not_after.is_some() => "the relay closed the connection: \
             certificate not accepted by the relay (expired, revoked, CA not pinned) or relay \
             restart"
            .into(),
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
            format!("node {node} is draining (maintenance, shutdown, or too many sessions)")
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
