//! File di configurazione: chiavi segrete, policy del relay, client autorizzati di un agent,
//! nodi noti a un client.
//!
//! Formato TOML. Ogni file è letto con un limite di dimensione e validato per intero: una
//! voce non valida fa fallire il caricamento (meglio non partire che partire con una policy
//! diversa da quella scritta).

use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;
use zt_crypto::{
    CaSigningKey, CryptoError, Identity, Keyring, PublicKey, decode_certificate_text,
    trusted_ca_key,
};
use zt_domain::limits::DEFAULT_AUTHORITY_LIFETIME_SECS;
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthorizedClients, CertBody, CertFormatError, CertSerial,
    ClientGrant, DomainError, NodeId, decode_certificate,
};

/// Dimensione massima di un file di configurazione.
const MAX_FILE_LEN: u64 = 1024 * 1024;

/// Dimensione massima di un file di certificato: il certificato più grande in esadecimale sta
/// ampiamente in 16 KiB.
const MAX_CERT_FILE_LEN: u64 = 16 * 1024;

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
    /// La configurazione pinna almeno una CA ma non ha una denylist (`--revocations`,
    /// PROTOCOL §15.8).
    #[error("{0}: [[authorities]] require a revocation list (--revocations, may be empty)")]
    RevocationsRequired(String),
    /// Una CA ha la chiave del processo o di un relay pinnato (PROTOCOL §15.9).
    #[error("{path}: authority {ca}: authority key equals the {role} key")]
    AuthorityIsInfrastructureKey {
        /// Il file (o l'opzione) che pinna la CA.
        path: String,
        /// L'impronta della CA.
        ca: zt_domain::Fingerprint,
        /// Il ruolo della chiave uguale: `relay` o `agent`.
        role: &'static str,
    },
    /// File di certificato non valido.
    #[error("{path}: {source}")]
    Certificate {
        /// Il file.
        path: String,
        /// L'errore di formato.
        source: CertFormatError,
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
    read_file_bounded(file, path, MAX_FILE_LEN)
}

fn read_file_bounded(file: std::fs::File, path: &Path, max: u64) -> Result<String, ConfigError> {
    let display = path.display().to_string();
    let mut text = String::new();
    file.take(max.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|source| ConfigError::Io {
            path: display.clone(),
            source,
        })?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > max {
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

/// Carica la chiave corrente e, durante una rotazione, quella precedente (PROTOCOL §14).
///
/// # Errors
/// Come [`load_identity`] per ciascun file; [`ConfigError::Key`] se le due chiavi coincidono.
pub fn load_keyring(current: &Path, previous: Option<&Path>) -> Result<Keyring, ConfigError> {
    let key = load_identity(current)?;
    match previous {
        None => Ok(Keyring::single(key)),
        Some(path) => {
            Keyring::rotating(key, load_identity(path)?).map_err(|source| ConfigError::Key {
                path: path.display().to_string(),
                entry: "previous key (same as the current key)".into(),
                source,
            })
        }
    }
}

/// Genera una nuova identità e la scrive in un file nuovo con permessi `0600`.
/// Non sovrascrive mai un file esistente.
///
/// # Errors
/// File già esistente, errore di I/O, RNG non disponibile.
pub fn create_identity(path: &Path) -> Result<Identity, ConfigError> {
    let identity = Identity::generate().map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "secret key".into(),
        source,
    })?;
    let mut text = identity.to_secret_hex();
    text.push('\n');
    write_private_new(path, text.as_bytes())?;
    Ok(identity)
}

/// Scrive `contents` in un file **nuovo** con permessi `0600` e lo sincronizza su disco.
fn write_private_new(path: &Path, contents: &[u8]) -> Result<(), ConfigError> {
    use std::io::Write;
    let display = path.display().to_string();
    let io = |source| ConfigError::Io {
        path: display.clone(),
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io)?;
    file.write_all(contents).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEntry {
    node: String,
    /// Una chiave; durante una rotazione si usa `public_keys` (PROTOCOL §14).
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    public_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayEntry {
    address: String,
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

/// Una voce `[[authorities]]` (PROTOCOL §15.9, OPERATIONS §10.2), uguale nella policy del
/// relay e nei `clients.toml` degli agent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    name: String,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    public_keys: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    max_lifetime: Option<u64>,
}

/// `revoked.toml` (PROTOCOL §15.8).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationsFile {
    #[serde(default)]
    serials: Vec<String>,
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    agents: Vec<AgentEntry>,
    #[serde(default)]
    clients: Vec<ClientEntry>,
    #[serde(default)]
    authorities: Vec<AuthorityEntry>,
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
    /// Forma con un solo relay.
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    relay_key: Option<String>,
    /// Forma con più relay, in ordine di preferenza (PROTOCOL §13).
    #[serde(default)]
    relays: Vec<RelayEntry>,
    key: String,
    /// File del certificato del client (PROTOCOL §15), relativo a questo file.
    #[serde(default)]
    certificate: Option<String>,
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
    /// Una chiave che DEVE essere la codifica canonica di un punto valido e non debole: le
    /// chiavi di CA e della denylist (il confronto byte per byte del passo 5 di PROTOCOL §15.4
    /// presuppone pin canonici).
    fn canonical_key(&self, entry: &str, text: &str) -> Result<PublicKey, ConfigError> {
        let fail = |source| ConfigError::Key {
            path: self.0.into(),
            entry: entry.into(),
            source,
        };
        // Esattamente 64 caratteri esadecimali, senza spazi (`FromStr` li toglierebbe).
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail(CryptoError::InvalidKey));
        }
        let parsed: PublicKey = text.parse().map_err(fail)?;
        // `to_bytes` restituisce i 32 byte scritti, non la ricodifica del punto.
        PublicKey::from_canonical_bytes(&parsed.to_bytes()).map_err(fail)
    }
    fn allowed(&self, entry: &str, allow: &[String]) -> Result<AllowedNodes, ConfigError> {
        if allow.iter().any(|a| a == "*") {
            return Ok(AllowedNodes::All);
        }
        let nodes = allow
            .iter()
            .map(|n| self.node(entry, n))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(AllowedNodes::Only(nodes))
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
/// public_key = "<64 hex>"    # in rotazione: public_keys = ["<nuova>", "<vecchia>"]
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
        // `public_key` oppure `public_keys` (rotazione), mai entrambi né nessuno.
        let texts: Vec<&str> = match (&entry.public_key, entry.public_keys.as_slice()) {
            (Some(one), []) => vec![one.as_str()],
            (None, many) if !many.is_empty() => many.iter().map(String::as_str).collect(),
            _ => return Err(ctx.domain(&entry.node, DomainError::AgentKeys(node))),
        };
        let keys = texts
            .into_iter()
            .map(|t| ctx.key(&entry.node, t).map(|k| k.fingerprint()))
            .collect::<Result<Vec<_>, _>>()?;
        policy
            .add_agent_keys(node, &keys)
            .map_err(|e| ctx.domain(&entry.node, e))?;
    }
    for entry in &file.clients {
        let name = ctx.node(&entry.name, &entry.name)?;
        let key = ctx.key(&entry.name, &entry.public_key)?;
        let allowed = ctx.allowed(&entry.name, &entry.allow)?;
        policy
            .add_client(key.fingerprint(), ClientGrant { name, allowed })
            .map_err(|e| ctx.domain(&entry.name, e))?;
    }
    // Le CA per ultime: `set_cert_trust` rifiuta una chiave di CA uguale a quella di un peer.
    let trust = parse_authorities(&ctx, &file.authorities)?;
    policy
        .set_cert_trust(trust)
        .map_err(|e| ctx.domain("authorities", e))?;
    Ok(policy)
}

/// Le voci `[[authorities]]` (PROTOCOL §15.9), senza denylist.
fn parse_authorities(ctx: &Ctx<'_>, entries: &[AuthorityEntry]) -> Result<CertTrust, ConfigError> {
    let mut trust = CertTrust::new();
    for entry in entries {
        let name = ctx.node(&entry.name, &entry.name)?;
        // `public_key` oppure `public_keys` (rotazione), mai entrambi né nessuno.
        let texts: Vec<&str> = match (&entry.public_key, entry.public_keys.as_slice()) {
            (Some(one), []) => vec![one.as_str()],
            (None, many) if !many.is_empty() => many.iter().map(String::as_str).collect(),
            _ => return Err(ctx.domain(&entry.name, DomainError::AuthorityKeys(name))),
        };
        let keys = texts
            .into_iter()
            .map(|t| {
                ctx.canonical_key(&entry.name, t)
                    .map(|k| trusted_ca_key(&k))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowed = ctx.allowed(&entry.name, &entry.allow)?;
        let max_lifetime = entry
            .max_lifetime
            .unwrap_or(DEFAULT_AUTHORITY_LIFETIME_SECS);
        trust
            .add_authority(name, &keys, allowed, max_lifetime)
            .map_err(|e| ctx.domain(&entry.name, e))?;
    }
    Ok(trust)
}

/// Interpreta l'elenco dei client che un agent accetta end-to-end (stesso formato della
/// sezione `[[clients]]` della policy; `allow` è ignorato).
///
/// # Errors
/// Qualsiasi voce non valida.
pub fn parse_authorized_clients(
    origin: &str,
    text: &str,
) -> Result<AuthorizedClients, ConfigError> {
    let ctx = Ctx(origin);
    let file: PolicyFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut clients = AuthorizedClients::new();
    for entry in &file.clients {
        let key = ctx.key(&entry.name, &entry.public_key)?;
        // Una chiave ripetuta non è un errore (era un insieme prima della Fase 6).
        if !clients.contains_key(&key.fingerprint()) {
            clients
                .add_client(key.fingerprint())
                .map_err(|e| ctx.domain(&entry.name, e))?;
        }
    }
    let trust = parse_authorities(&ctx, &file.authorities)?;
    clients
        .set_cert_trust(trust)
        .map_err(|e| ctx.domain("authorities", e))?;
    Ok(clients)
}

/// Interpreta la denylist `revoked.toml` (`serials`, `keys`; PROTOCOL §15.8).
///
/// # Errors
/// Qualsiasi voce non valida, o oltre i limiti.
pub fn parse_revocations(origin: &str, text: &str) -> Result<Revocations, ConfigError> {
    let ctx = Ctx(origin);
    let file: RevocationsFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let serials = file
        .serials
        .iter()
        .enumerate()
        .map(|(i, text)| parse_serial(&ctx, i, text))
        .collect::<Result<Vec<_>, _>>()?;
    let keys = file
        .keys
        .iter()
        .enumerate()
        .map(|(i, text)| {
            ctx.canonical_key(&format!("keys[{i}]"), text)
                .map(|k| k.fingerprint())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Revocations::new(serials, keys).map_err(|e| ctx.domain("revocations", e))
}

/// 32 caratteri esadecimali → 16 byte.
fn decode_hex16(text: &str) -> Option<[u8; CertSerial::LEN]> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a' - 10),
            b'A'..=b'F' => c.checked_sub(b'A' - 10),
            _ => None,
        }
    }
    let raw = text.as_bytes();
    if raw.len() != CertSerial::LEN * 2 {
        return None;
    }
    let mut out = [0_u8; CertSerial::LEN];
    for (byte, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        let [hi, lo] = pair else { return None };
        *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Some(out)
}

/// Un numero di serie: esattamente 32 caratteri esadecimali, mai tutto zero. L'errore non
/// riporta il valore.
fn parse_serial(ctx: &Ctx<'_>, index: usize, text: &str) -> Result<CertSerial, ConfigError> {
    let fail = |message: &str| ConfigError::Syntax {
        path: ctx.0.into(),
        message: format!("serials[{index}]: {message}"),
    };
    let bytes =
        decode_hex16(text).ok_or_else(|| fail("a serial must be 32 hexadecimal characters"))?;
    CertSerial::try_from(bytes).map_err(|_| fail("a serial must not be all zeros"))
}

/// Un file di certificato letto e decodificato (la firma la verificano relay e agent).
#[derive(Debug, Clone)]
pub struct CertificateFile {
    /// I byte del certificato, da inviare nel messaggio 1.
    pub bytes: Arc<[u8]>,
    /// Il corpo decodificato.
    pub body: CertBody,
}

/// Interpreta un file di certificato (`tcn-client-cert-v1:<hex>`, PROTOCOL §15.1).
///
/// # Errors
/// [`ConfigError::Certificate`] per un testo o un certificato non validi.
pub fn parse_certificate_file(origin: &str, text: &str) -> Result<CertificateFile, ConfigError> {
    let fail = |source| ConfigError::Certificate {
        path: origin.into(),
        source,
    };
    let bytes = decode_certificate_text(text).map_err(fail)?;
    let body = decode_certificate(&bytes).map_err(fail)?.body;
    Ok(CertificateFile {
        bytes: bytes.into(),
        body,
    })
}

/// Legge un file di certificato, con le regole dei file di trust.
///
/// # Errors
/// Come [`parse_certificate_file`]; file insicuro, illeggibile o troppo grande.
pub fn load_certificate(path: &Path) -> Result<CertificateFile, ConfigError> {
    let text = read_file_bounded(open_trusted(path, false)?, path, MAX_CERT_FILE_LEN)?;
    parse_certificate_file(&path.display().to_string(), &text)
}

/// Genera la chiave di una CA e la scrive in un file nuovo con permessi `0600`. Non
/// sovrascrive mai un file esistente.
///
/// # Errors
/// File già esistente, errore di I/O, RNG non disponibile.
pub fn create_ca_key(path: &Path) -> Result<CaSigningKey, ConfigError> {
    let ca = CaSigningKey::generate().map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "ca secret key".into(),
        source,
    })?;
    write_private_new(path, ca.to_secret_text().as_bytes())?;
    Ok(ca)
}

/// Carica la chiave di una CA, con le regole delle chiavi segrete.
///
/// # Errors
/// Come [`load_identity`]; un file di chiave di nodo è rifiutato.
pub fn load_ca_key(path: &Path) -> Result<CaSigningKey, ConfigError> {
    let file = open_trusted(path, true)?;
    let text = zeroize::Zeroizing::new(read_file_limited(file, path)?);
    CaSigningKey::from_secret_text(&text).map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "ca secret key".into(),
        source,
    })
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

/// Legge e interpreta la policy del relay. Una policy con `[[authorities]]` richiede
/// [`load_relay_policy`] con una denylist.
///
/// # Errors
/// Vedi [`parse_policy`]; [`ConfigError::RevocationsRequired`] con una CA.
pub fn load_policy(path: &Path) -> Result<AccessPolicy, ConfigError> {
    load_relay_policy(path, None)
}

/// Legge la policy del relay e, se c'è, la denylist, in un solo passo: se uno dei due file non
/// è valido non si carica nulla (PROTOCOL §15.8).
///
/// # Errors
/// Vedi [`parse_policy`] e [`parse_revocations`]; [`ConfigError::RevocationsRequired`] con una
/// CA e senza denylist.
pub fn load_relay_policy(
    policy: &Path,
    revocations: Option<&Path>,
) -> Result<AccessPolicy, ConfigError> {
    let origin = policy.display().to_string();
    // Entrambi i file letti e validati prima di costruire il risultato: nessun effetto parziale.
    let text = read_limited(policy)?;
    let revoked = revocations.map(load_revocations).transpose()?;
    let mut parsed = parse_policy(&origin, &text)?;
    let trust = with_revocations(parsed.cert_trust(), revoked, &origin)?;
    parsed
        .set_cert_trust(trust)
        .map_err(|e| Ctx(&origin).domain("authorities", e))?;
    Ok(parsed)
}

/// Le chiavi di un keyring (corrente e precedente) come chiavi vietate alle CA, con il ruolo
/// da riportare nell'errore (es. `"relay"`, `"agent"`).
#[must_use]
pub fn own_keys(keys: &Keyring, role: &'static str) -> Vec<ForbiddenKey> {
    std::iter::once(keys.current())
        .chain(keys.previous())
        .map(|k| ForbiddenKey {
            fingerprint: k.fingerprint(),
            role,
        })
        .collect()
}

/// Una chiave che nessuna CA della configurazione può avere (PROTOCOL §15.9): la chiave del
/// processo o quella di un relay pinnato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForbiddenKey {
    /// L'impronta della chiave.
    pub fingerprint: zt_domain::Fingerprint,
    /// Il ruolo della chiave, per il messaggio d'errore.
    pub role: &'static str,
}

/// Rifiuta una CA la cui chiave è una di `forbidden` (PROTOCOL §15.9, finding 0006-1): un
/// relay o un agent non è mai anche una CA della propria configurazione (chiave corrente o
/// precedente, [`own_keys`]) e un agent non accetta come CA nessun `--relay-key`. Un relay
/// compromesso non deve poter firmare certificati che l'agent ammette con il proprio seme di
/// nodo.
///
/// # Errors
/// [`ConfigError::AuthorityIsInfrastructureKey`] per la prima CA vietata.
pub fn reject_infrastructure_keys_as_authority(
    origin: &str,
    trust: &CertTrust,
    forbidden: &[ForbiddenKey],
) -> Result<(), ConfigError> {
    for ca in trust.ca_fingerprints() {
        if let Some(key) = forbidden.iter().find(|k| k.fingerprint == ca) {
            return Err(ConfigError::AuthorityIsInfrastructureKey {
                path: origin.into(),
                ca,
                role: key.role,
            });
        }
    }
    Ok(())
}

/// Legge una denylist con le regole dei file di trust.
fn load_revocations(path: &Path) -> Result<Revocations, ConfigError> {
    parse_revocations(&path.display().to_string(), &read_limited(path)?)
}

/// Le CA di `trust` con la denylist; una CA senza denylist non è avviabile (PROTOCOL §15.8).
fn with_revocations(
    trust: &CertTrust,
    revoked: Option<Revocations>,
    origin: &str,
) -> Result<CertTrust, ConfigError> {
    let mut trust = trust.clone();
    if let Some(revoked) = revoked {
        trust.set_revocations(revoked);
    }
    if trust.needs_revocations() {
        return Err(ConfigError::RevocationsRequired(origin.into()));
    }
    Ok(trust)
}

/// Legge e interpreta i client autorizzati di un agent e, se c'è, la denylist.
///
/// # Errors
/// Vedi [`parse_authorized_clients`] e [`load_relay_policy`].
pub fn load_authorized_clients(
    path: &Path,
    revocations: Option<&Path>,
) -> Result<AuthorizedClients, ConfigError> {
    let origin = path.display().to_string();
    let text = read_limited(path)?;
    let revoked = revocations.map(load_revocations).transpose()?;
    let mut clients = parse_authorized_clients(&origin, &text)?;
    let trust = with_revocations(clients.cert_trust(), revoked, &origin)?;
    clients
        .set_cert_trust(trust)
        .map_err(|e| Ctx(&origin).domain("authorities", e))?;
    Ok(clients)
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
    /// Relay da provare nell'ordine, ciascuno con la chiave pinnata (PROTOCOL §13).
    pub relays: Vec<crate::RelayEndpoint>,
    /// File della chiave segreta del client.
    pub key: std::path::PathBuf,
    /// Nodi raggiungibili, ciascuno con la chiave pinnata del suo agent. Un nodo assente non
    /// è raggiungibile: non esiste trust-on-first-use.
    pub nodes: HashMap<NodeId, PublicKey>,
    /// File del certificato del client, se configurato (PROTOCOL §15).
    pub certificate: Option<std::path::PathBuf>,
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
            relays: self.relays.clone(),
            node: node.clone(),
            node_key: *node_key,
            certificate: None,
            timeouts,
        })
    }
}

/// Elenco dei relay da indirizzi e chiavi appaiati per posizione (opzioni ripetute di
/// `zt-agent`, o voci `[[relays]]` del client). Da 1 a [`crate::MAX_RELAYS`] voci, stesso
/// numero di indirizzi e di chiavi, nessun indirizzo e nessuna chiave ripetuti.
///
/// # Errors
/// [`ConfigError::Syntax`] per un elenco che non rispetta le regole.
pub fn relay_endpoints(
    origin: &str,
    addresses: &[String],
    keys: &[PublicKey],
) -> Result<Vec<crate::RelayEndpoint>, ConfigError> {
    let fail = |message: &str| ConfigError::Syntax {
        path: origin.into(),
        message: message.into(),
    };
    if addresses.is_empty() || addresses.len() > crate::MAX_RELAYS {
        return Err(fail("relay list must have between 1 and 8 relays"));
    }
    if addresses.len() != keys.len() {
        return Err(fail("relay list: every relay needs exactly one relay key"));
    }
    let mut out: Vec<crate::RelayEndpoint> = Vec::with_capacity(addresses.len());
    for (address, key) in addresses.iter().zip(keys) {
        if !valid_relay(address) {
            return Err(fail("relay list: each relay must be host:port"));
        }
        if out
            .iter()
            .any(|r| r.address == *address || r.public_key.fingerprint() == key.fingerprint())
        {
            return Err(fail("relay list: a relay address or relay key is repeated"));
        }
        out.push(crate::RelayEndpoint {
            address: address.clone(),
            public_key: *key,
        });
    }
    Ok(out)
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
/// # oppure, con più relay provati nell'ordine (PROTOCOL §13):
/// # [[relays]]
/// # address = "r1.example.org:7443"
/// # public_key = "<64 hex>"
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
    // `relay` + `relay_key` oppure `[[relays]]`, mai entrambi.
    let (addresses, key_texts): (Vec<String>, Vec<String>) =
        match (&file.relay, &file.relay_key, file.relays.as_slice()) {
            (Some(relay), Some(key), []) => (vec![relay.clone()], vec![key.clone()]),
            (None, None, list) if !list.is_empty() => list
                .iter()
                .map(|r| (r.address.clone(), r.public_key.clone()))
                .unzip(),
            _ => {
                return Err(ConfigError::Syntax {
                    path: origin.into(),
                    message: "give either relay and relay_key, or a [[relays]] list".into(),
                });
            }
        };
    let relay_keys = key_texts
        .iter()
        .map(|t| ctx.key("relay_key", t))
        .collect::<Result<Vec<_>, _>>()?;
    let relays = relay_endpoints(origin, &addresses, &relay_keys)?;
    if file.certificate.as_deref() == Some("") {
        return Err(ConfigError::Syntax {
            path: origin.into(),
            message: "certificate must name the client certificate file".into(),
        });
    }
    if file.key.is_empty() {
        return Err(ConfigError::Syntax {
            path: origin.into(),
            message: "key must name the client secret key file".into(),
        });
    }
    let mut nodes = HashMap::new();
    for entry in &file.nodes {
        let node = ctx.node(&entry.node, &entry.node)?;
        let key = ctx.key(&entry.node, &entry.public_key)?;
        if relays
            .iter()
            .any(|r| r.public_key.fingerprint() == key.fingerprint())
        {
            return Err(ctx.domain(&entry.node, DomainError::DuplicatePeer(key.fingerprint())));
        }
        if nodes.insert(node.clone(), key).is_some() {
            return Err(ctx.domain(&entry.node, DomainError::DuplicateNode(node)));
        }
    }
    Ok(ClientSettings {
        relays,
        key: base.join(&file.key),
        nodes,
        certificate: file.certificate.as_ref().map(|c| base.join(c)),
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
