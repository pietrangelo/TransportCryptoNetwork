//! File di configurazione: chiavi segrete, policy del relay, client autorizzati di un agent,
//! nodi noti a un client.
//!
//! Formato TOML. Ogni file è letto con un limite di dimensione e validato per intero: una
//! voce non valida fa fallire il caricamento (meglio non partire che partire con una policy
//! diversa da quella scritta).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use zt_crypto::{CryptoError, Identity, PublicKey};
use zt_domain::{AccessPolicy, AllowedNodes, ClientGrant, DomainError, Fingerprint, NodeId};

/// Dimensione massima di un file di configurazione.
const MAX_FILE_LEN: u64 = 1024 * 1024;

/// Errore di configurazione. Non riporta mai il contenuto di un segreto.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Errore di I/O sul file.
    #[error("{path}: {source}")]
    Io {
        /// Il file.
        path: String,
        /// L'errore.
        source: std::io::Error,
    },
    /// File oltre il limite di dimensione.
    #[error("{0}: file too large")]
    TooLarge(String),
    /// Il file della chiave segreta è leggibile da altri utenti.
    #[error("{0}: secret key file must not be accessible by group or others (chmod 600)")]
    InsecurePermissions(String),
    /// TOML non valido.
    #[error("{path}: {message}")]
    Syntax {
        /// Il file.
        path: String,
        /// Il messaggio del parser.
        message: String,
    },
    /// Chiave non valida.
    #[error("{path}: entry {entry}: {source}")]
    Key {
        /// Il file.
        path: String,
        /// La voce.
        entry: String,
        /// L'errore.
        source: CryptoError,
    },
    /// Violazione di un'invariante di dominio.
    #[error("{path}: entry {entry}: {source}")]
    Domain {
        /// Il file.
        path: String,
        /// La voce.
        entry: String,
        /// L'errore.
        source: DomainError,
    },
}

fn read_limited(path: &Path) -> Result<String, ConfigError> {
    let file = std::fs::File::open(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    read_file_limited(file, path)
}

fn read_file_limited(file: std::fs::File, path: &Path) -> Result<String, ConfigError> {
    let display = path.display().to_string();
    let mut text = String::new();
    file.take(MAX_FILE_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|source| ConfigError::Io {
            path: display.clone(),
            source,
        })?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(ConfigError::TooLarge(display));
    }
    Ok(text)
}

/// Verifica i permessi sul file **già aperto**: nessuna finestra tra controllo e lettura.
#[cfg(unix)]
fn check_private(file: &std::fs::File, path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let display = path.display().to_string();
    let meta = file.metadata().map_err(|source| ConfigError::Io {
        path: display.clone(),
        source,
    })?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions(display));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_file: &std::fs::File, _path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

/// Carica un'identità da file, rifiutando permessi troppo larghi (come fa OpenSSH).
///
/// # Errors
/// File illeggibile, permessi insicuri, contenuto non valido.
pub fn load_identity(path: &Path) -> Result<Identity, ConfigError> {
    let file = std::fs::File::open(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    check_private(&file, path)?;
    let text = zeroize::Zeroizing::new(read_file_limited(file, path)?);
    Identity::from_secret_hex(&text).map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "secret key".into(),
        source,
    })
}

/// Genera una nuova identità e la scrive in un file nuovo con permessi `0600`.
/// Non sovrascrive mai un file esistente.
///
/// # Errors
/// File già esistente, errore di I/O, RNG non disponibile.
pub fn create_identity(path: &Path) -> Result<Identity, ConfigError> {
    use std::io::Write;
    let display = path.display().to_string();
    let io = |source| ConfigError::Io {
        path: display.clone(),
        source,
    };
    let identity = Identity::generate().map_err(|source| ConfigError::Key {
        path: display.clone(),
        entry: "secret key".into(),
        source,
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io)?;
    file.write_all(identity.to_secret_hex().as_bytes())
        .map_err(io)?;
    file.write_all(b"\n").map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(identity)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEntry {
    node: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientEntry {
    name: String,
    public_key: String,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEntry {
    node: String,
    public_key: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    agents: Vec<AgentEntry>,
    #[serde(default)]
    clients: Vec<ClientEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodesFile {
    #[serde(default)]
    nodes: Vec<NodeEntry>,
}

struct Ctx<'a>(&'a str);

impl Ctx<'_> {
    fn syntax(&self, err: &toml::de::Error) -> ConfigError {
        ConfigError::Syntax {
            path: self.0.into(),
            message: err.message().into(),
        }
    }
    fn key(&self, entry: &str, text: &str) -> Result<PublicKey, ConfigError> {
        text.parse().map_err(|source| ConfigError::Key {
            path: self.0.into(),
            entry: entry.into(),
            source,
        })
    }
    fn node(&self, entry: &str, text: &str) -> Result<NodeId, ConfigError> {
        NodeId::try_from(text).map_err(|source| self.domain(entry, source))
    }
    fn domain(&self, entry: &str, source: DomainError) -> ConfigError {
        ConfigError::Domain {
            path: self.0.into(),
            entry: entry.into(),
            source,
        }
    }
}

/// Interpreta la policy del relay.
///
/// ```toml
/// [[agents]]
/// node = "web-01"
/// public_key = "<64 hex>"
///
/// [[clients]]
/// name = "ansible"
/// public_key = "<64 hex>"
/// allow = ["web-01"]      # oppure ["*"] per tutti i nodi
/// ```
///
/// # Errors
/// Qualsiasi voce non valida, duplicata o in conflitto.
pub fn parse_policy(origin: &str, text: &str) -> Result<AccessPolicy, ConfigError> {
    let ctx = Ctx(origin);
    let file: PolicyFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut policy = AccessPolicy::new();
    for entry in &file.agents {
        let node = ctx.node(&entry.node, &entry.node)?;
        let key = ctx.key(&entry.node, &entry.public_key)?;
        policy
            .add_agent(key.fingerprint(), node)
            .map_err(|e| ctx.domain(&entry.node, e))?;
    }
    for entry in &file.clients {
        let name = ctx.node(&entry.name, &entry.name)?;
        let key = ctx.key(&entry.name, &entry.public_key)?;
        let allowed = if entry.allow.iter().any(|a| a == "*") {
            AllowedNodes::All
        } else {
            let nodes = entry
                .allow
                .iter()
                .map(|n| ctx.node(&entry.name, n))
                .collect::<Result<BTreeSet<_>, _>>()?;
            AllowedNodes::Only(nodes)
        };
        policy
            .add_client(key.fingerprint(), ClientGrant { name, allowed })
            .map_err(|e| ctx.domain(&entry.name, e))?;
    }
    Ok(policy)
}

/// Interpreta l'elenco dei client che un agent accetta end-to-end (stesso formato della
/// sezione `[[clients]]` della policy; `allow` è ignorato).
///
/// # Errors
/// Qualsiasi voce non valida.
pub fn parse_authorized_clients(
    origin: &str,
    text: &str,
) -> Result<HashSet<Fingerprint>, ConfigError> {
    let ctx = Ctx(origin);
    let file: PolicyFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    file.clients
        .iter()
        .map(|c| Ok(ctx.key(&c.name, &c.public_key)?.fingerprint()))
        .collect()
}

/// Interpreta l'elenco dei nodi noti a un client (`[[nodes]] node, public_key`).
///
/// # Errors
/// Qualsiasi voce non valida o duplicata.
pub fn parse_known_nodes(
    origin: &str,
    text: &str,
) -> Result<HashMap<NodeId, PublicKey>, ConfigError> {
    let ctx = Ctx(origin);
    let file: NodesFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut nodes = HashMap::new();
    for entry in &file.nodes {
        let node = ctx.node(&entry.node, &entry.node)?;
        let key = ctx.key(&entry.node, &entry.public_key)?;
        if nodes.insert(node.clone(), key).is_some() {
            return Err(ctx.domain(&entry.node, DomainError::DuplicateNode(node)));
        }
    }
    Ok(nodes)
}

/// Legge e interpreta la policy del relay.
///
/// # Errors
/// Vedi [`parse_policy`].
pub fn load_policy(path: &Path) -> Result<AccessPolicy, ConfigError> {
    parse_policy(&path.display().to_string(), &read_limited(path)?)
}

/// Legge e interpreta i client autorizzati di un agent.
///
/// # Errors
/// Vedi [`parse_authorized_clients`].
pub fn load_authorized_clients(path: &Path) -> Result<HashSet<Fingerprint>, ConfigError> {
    parse_authorized_clients(&path.display().to_string(), &read_limited(path)?)
}

/// Legge e interpreta i nodi noti a un client.
///
/// # Errors
/// Vedi [`parse_known_nodes`].
pub fn load_known_nodes(path: &Path) -> Result<HashMap<NodeId, PublicKey>, ConfigError> {
    parse_known_nodes(&path.display().to_string(), &read_limited(path)?)
}
