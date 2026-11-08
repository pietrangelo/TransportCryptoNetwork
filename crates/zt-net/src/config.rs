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
    /// Un file di trust (pin delle chiavi, policy, client autorizzati) è scrivibile da gruppo
    /// o altri: chi può scriverlo può sostituire una chiave.
    #[error("{0}: trust file must not be writable by group or others (chmod go-w)")]
    WritableByOthers(String),
    /// Il file non è un file regolare (FIFO, dispositivo, directory).
    #[error("{0}: not a regular file")]
    NotRegular(String),
    /// Il file appartiene a un utente diverso da quello corrente e da root.
    #[error("{0}: must be owned by the current user or root")]
    UntrustedOwner(String),
    /// La directory che contiene il file è di un altro utente o scrivibile da gruppo o altri.
    #[error(
        "{0}: directory must be owned by the current user or root and not writable by group or others"
    )]
    InsecureDirectory(String),
    /// Nodo senza chiave pinnata nella configurazione del client.
    #[error("unknown node {0}: no pinned key in the client configuration")]
    UnknownNode(String),
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

/// Apre un file di trust o una chiave segreta e verifica, sul file **già aperto** (nessuna
/// finestra tra controllo e lettura), ciò che verifica OpenSSH con `StrictModes`
/// (finding 0003-1): file regolare, proprietario l'utente corrente o root, nessun permesso di
/// scrittura per gruppo e altri (per una chiave segreta: nessun permesso per gruppo e altri).
/// La directory che lo contiene deve rispettare le stesse regole di proprietà e scrittura,
/// perché chi può scriverci può sostituire il file.
fn open_trusted(path: &Path, private: bool) -> Result<std::fs::File, ConfigError> {
    let display = || path.display().to_string();
    let io = |source| ConfigError::Io {
        path: display(),
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // Un FIFO aperto senza O_NONBLOCK blocca finché qualcuno non lo apre in scrittura.
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
    }
    let file = options.open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    let uid = current_uid();
    check_trusted(&meta, uid, path, private)?;
    check_directory(path, uid)?;
    Ok(file)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Controllo puro sui metadati di un file di configurazione aperto: `uid` è l'utente per cui
/// il file deve essere affidabile. `private` vale per le chiavi segrete.
///
/// # Errors
/// [`ConfigError::NotRegular`], [`ConfigError::UntrustedOwner`],
/// [`ConfigError::InsecurePermissions`] (solo `private`), [`ConfigError::WritableByOthers`].
pub fn check_trusted(
    meta: &std::fs::Metadata,
    uid: u32,
    path: &Path,
    private: bool,
) -> Result<(), ConfigError> {
    let display = path.display().to_string();
    if !meta.is_file() {
        return Err(ConfigError::NotRegular(display));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(ConfigError::UntrustedOwner(display));
        }
        let mode = meta.mode();
        if private && mode & 0o077 != 0 {
            return Err(ConfigError::InsecurePermissions(display));
        }
        if mode & 0o022 != 0 {
            return Err(ConfigError::WritableByOthers(display));
        }
    }
    #[cfg(not(unix))]
    let _ = (uid, private);
    Ok(())
}

#[cfg(unix)]
fn check_directory(path: &Path, uid: u32) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let display = dir.display().to_string();
    let meta = std::fs::metadata(dir).map_err(|source| ConfigError::Io {
        path: display.clone(),
        source,
    })?;
    if (meta.uid() != uid && meta.uid() != 0) || meta.mode() & 0o022 != 0 {
        return Err(ConfigError::InsecureDirectory(display));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_directory(_path: &Path, _uid: u32) -> Result<(), ConfigError> {
    Ok(())
}

/// Legge un file di trust (vedi [`open_trusted`]).
fn read_limited(path: &Path) -> Result<String, ConfigError> {
    read_file_limited(open_trusted(path, false)?, path)
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

/// Carica un'identità da file, con le stesse verifiche di OpenSSH sulle chiavi private.
///
/// # Errors
/// File illeggibile, non regolare, di un altro utente, con permessi insicuri o in una
/// directory insicura; contenuto non valido.
pub fn load_identity(path: &Path) -> Result<Identity, ConfigError> {
    let file = open_trusted(path, true)?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientFile {
    relay: String,
    relay_key: String,
    key: String,
    #[serde(default)]
    nodes: Vec<NodeEntry>,
}

/// Sostituisce le sequenze esadecimali lunghe (32 caratteri o più) di un messaggio del parser.
///
/// serde riporta nomi di campo e valori sbagliati: una chiave privata incollata per errore in un
/// file di trust finirebbe nel messaggio, e da lì nel journal (finding 0004-6, trovato dal
/// fuzzer `config_parsers`).
fn redact_hex(message: &str) -> String {
    const MIN: usize = 32;
    let mut out = String::with_capacity(message.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= MIN {
            out.push_str("<redacted>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in message.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

struct Ctx<'a>(&'a str);

impl Ctx<'_> {
    fn syntax(&self, err: &toml::de::Error) -> ConfigError {
        ConfigError::Syntax {
            path: self.0.into(),
            message: redact_hex(err.message()),
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

/// Lunghezza massima dell'indirizzo del relay (nome DNS completo più porta).
const MAX_RELAY_LEN: usize = 261;

/// Configurazione di `zt-client`.
#[derive(Debug, Clone)]
pub struct ClientSettings {
    /// Indirizzo del relay (`host:porta`).
    pub relay: String,
    /// Chiave pubblica del relay, pinnata.
    pub relay_key: PublicKey,
    /// File della chiave segreta del client.
    pub key: std::path::PathBuf,
    /// Nodi raggiungibili, ciascuno con la chiave pinnata del suo agent. Un nodo assente non
    /// è raggiungibile: non esiste trust-on-first-use.
    pub nodes: HashMap<NodeId, PublicKey>,
}

impl ClientSettings {
    /// Configurazione di connessione verso `node`.
    ///
    /// # Errors
    /// [`ConfigError::UnknownNode`] se il nodo non ha una chiave pinnata.
    pub fn client_config(
        &self,
        node: &NodeId,
        timeouts: crate::Timeouts,
    ) -> Result<crate::client::ClientConfig, ConfigError> {
        let node_key = self
            .nodes
            .get(node)
            .ok_or_else(|| ConfigError::UnknownNode(node.to_string()))?;
        Ok(crate::client::ClientConfig {
            relay: self.relay.clone(),
            relay_key: self.relay_key,
            node: node.clone(),
            node_key: *node_key,
            timeouts,
        })
    }
}

/// `host:porta` con porta numerica non nulla, senza spazi né caratteri di controllo.
fn valid_relay(text: &str) -> bool {
    if text.is_empty()
        || text.len() > MAX_RELAY_LEN
        || text.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    match text.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0) && !port.starts_with('+')
        }
        None => false,
    }
}

/// Interpreta la configurazione del client. `base` è la directory del file: un percorso
/// relativo della chiave si risolve rispetto a essa.
///
/// ```toml
/// relay = "relay.example.org:7443"
/// relay_key = "<64 hex>"
/// key = "client.key"
///
/// [[nodes]]
/// node = "web-01"
/// public_key = "<64 hex>"
/// ```
///
/// # Errors
/// Qualsiasi voce non valida, duplicata o in conflitto.
pub fn parse_client_settings(
    origin: &str,
    base: &Path,
    text: &str,
) -> Result<ClientSettings, ConfigError> {
    let ctx = Ctx(origin);
    let file: ClientFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    if !valid_relay(&file.relay) {
        return Err(ConfigError::Syntax {
            path: origin.into(),
            message: "relay must be host:port".into(),
        });
    }
    if file.key.is_empty() {
        return Err(ConfigError::Syntax {
            path: origin.into(),
            message: "key must name the client secret key file".into(),
        });
    }
    let relay_key = ctx.key("relay_key", &file.relay_key)?;
    let mut nodes = HashMap::new();
    for entry in &file.nodes {
        let node = ctx.node(&entry.node, &entry.node)?;
        let key = ctx.key(&entry.node, &entry.public_key)?;
        if key.fingerprint() == relay_key.fingerprint() {
            return Err(ctx.domain(&entry.node, DomainError::DuplicatePeer(key.fingerprint())));
        }
        if nodes.insert(node.clone(), key).is_some() {
            return Err(ctx.domain(&entry.node, DomainError::DuplicateNode(node)));
        }
    }
    Ok(ClientSettings {
        relay: file.relay,
        relay_key,
        key: base.join(&file.key),
        nodes,
    })
}

/// Legge e interpreta la configurazione del client.
///
/// # Errors
/// Vedi [`parse_client_settings`]; inoltre file scrivibile da gruppo o altri.
pub fn load_client_settings(path: &Path) -> Result<ClientSettings, ConfigError> {
    let base = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    parse_client_settings(&path.display().to_string(), base, &read_limited(path)?)
}
