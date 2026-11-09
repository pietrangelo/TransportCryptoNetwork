//! Configuration files: secret keys, relay policy, authorized clients of an agent, nodes known
//! to a client.
//!
//! TOML format. Every file is read with a size limit and validated in full: an invalid entry
//! makes loading fail (better not to start than to start with a policy different from the one
//! written).

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

/// Maximum size of a configuration file.
const MAX_FILE_LEN: u64 = 1024 * 1024;

/// Maximum size of a certificate file: the largest certificate in hexadecimal fits comfortably
/// in 16 KiB.
const MAX_CERT_FILE_LEN: u64 = 16 * 1024;

/// Configuration error. It never reports the contents of a secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// I/O error on the file.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The error.
        source: std::io::Error,
    },
    /// File over the size limit.
    #[error("{0}: file too large")]
    TooLarge(String),
    /// The secret key file is readable by other users.
    #[error("{0}: secret key file must not be accessible by group or others (chmod 600)")]
    InsecurePermissions(String),
    /// A trust file (key pins, policy, authorized clients) is writable by group or others:
    /// whoever can write it can replace a key.
    #[error("{0}: trust file must not be writable by group or others (chmod go-w)")]
    WritableByOthers(String),
    /// The file is not a regular file (FIFO, device, directory).
    #[error("{0}: not a regular file")]
    NotRegular(String),
    /// The file belongs to a user other than the current one and root.
    #[error("{0}: must be owned by the current user or root")]
    UntrustedOwner(String),
    /// The directory containing the file belongs to another user or is writable by group or
    /// others.
    #[error(
        "{0}: directory must be owned by the current user or root and not writable by group or others"
    )]
    InsecureDirectory(String),
    /// Node without a pinned key in the client configuration.
    #[error("unknown node {0}: no pinned key in the client configuration")]
    UnknownNode(String),
    /// Invalid TOML.
    #[error("{path}: {message}")]
    Syntax {
        /// The file.
        path: String,
        /// The parser's message.
        message: String,
    },
    /// Invalid key.
    #[error("{path}: entry {entry}: {source}")]
    Key {
        /// The file.
        path: String,
        /// The entry.
        entry: String,
        /// The error.
        source: CryptoError,
    },
    /// Violation of a domain invariant.
    #[error("{path}: entry {entry}: {source}")]
    Domain {
        /// The file.
        path: String,
        /// The entry.
        entry: String,
        /// The error.
        source: DomainError,
    },
    /// The configuration pins at least one CA but has no denylist (`--revocations`,
    /// PROTOCOL §15.8).
    #[error("{0}: [[authorities]] require a revocation list (--revocations, may be empty)")]
    RevocationsRequired(String),
    /// A CA has the key of the process or of a pinned relay (PROTOCOL §15.9).
    #[error("{path}: authority {ca}: authority key equals the {role} key")]
    AuthorityIsInfrastructureKey {
        /// The file (or the option) that pins the CA.
        path: String,
        /// The fingerprint of the CA.
        ca: zt_domain::Fingerprint,
        /// The role of the matching key: `relay` or `agent`.
        role: &'static str,
    },
    /// Invalid certificate file.
    #[error("{path}: {source}")]
    Certificate {
        /// The file.
        path: String,
        /// The format error.
        source: CertFormatError,
    },
    /// Invalid handshake suite or accepted set (PROTOCOL §7.5).
    #[error("{path}: {entry}: {source}")]
    Suite {
        /// The file (or the option).
        path: String,
        /// The entry.
        entry: String,
        /// The error.
        source: zt_domain::SuiteError,
    },
    /// Invalid admission limits (PROTOCOL §10.1).
    #[error("{path}: [admission]: {source}")]
    Admission {
        /// The file.
        path: String,
        /// The error.
        source: zt_application::admission::AdmissionConfigError,
    },
}

/// Opens a trust file or a secret key and checks, on the **already open** file (no window
/// between check and read), what OpenSSH checks with `StrictModes` (finding 0003-1): regular
/// file, owned by the current user or root, no write permission for group and others (for a
/// secret key: no permissions at all for group and others). The directory containing it must
/// satisfy the same ownership and write rules, because whoever can write to it can replace
/// the file.
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
        // A FIFO opened without O_NONBLOCK blocks until someone opens it for writing.
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

/// Pure check on the metadata of an open configuration file: `uid` is the user for whom the
/// file must be trustworthy. `private` applies to secret keys.
///
/// # Errors
/// [`ConfigError::NotRegular`], [`ConfigError::UntrustedOwner`],
/// [`ConfigError::InsecurePermissions`] (only `private`), [`ConfigError::WritableByOthers`].
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

/// Reads a trust file (see [`open_trusted`]).
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

/// Loads an identity from a file, with the same checks OpenSSH applies to private keys.
///
/// # Errors
/// Unreadable file, not regular, owned by another user, with insecure permissions or in an
/// insecure directory; invalid contents.
pub fn load_identity(path: &Path) -> Result<Identity, ConfigError> {
    let file = open_trusted(path, true)?;
    let text = zeroize::Zeroizing::new(read_file_limited(file, path)?);
    Identity::from_secret_hex(&text).map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "secret key".into(),
        source,
    })
}

/// Loads the current key and, during a rotation, the previous one (PROTOCOL §14).
///
/// # Errors
/// Like [`load_identity`] for each file; [`ConfigError::Key`] if the two keys are identical.
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

/// Generates a new identity and writes it to a new file with `0600` permissions.
/// Never overwrites an existing file.
///
/// # Errors
/// File already exists, I/O error, RNG unavailable.
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

/// Writes `contents` to a **new** file with `0600` permissions and syncs it to disk.
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
    /// A single key; during a rotation `public_keys` is used (PROTOCOL §14).
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
    /// The pinned suite (PROTOCOL §7.5); the classical suite if absent.
    #[serde(default)]
    suite: Option<String>,
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

/// An `[[authorities]]` entry (PROTOCOL §15.9, OPERATIONS §10.2), identical in the relay policy
/// and in the agents' `clients.toml`.
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

/// A `[[nodes]]` entry of `client.toml`: a known node, optionally with its pinned suite.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientNodeEntry {
    node: String,
    public_key: String,
    #[serde(default)]
    suite: Option<String>,
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
    /// Form with a single relay.
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    relay_key: Option<String>,
    /// The pinned suite of the single relay (PROTOCOL §7.5).
    #[serde(default)]
    relay_suite: Option<String>,
    /// Form with several relays, in order of preference (PROTOCOL §13).
    #[serde(default)]
    relays: Vec<RelayEntry>,
    key: String,
    /// Client certificate file (PROTOCOL §15), relative to this file.
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    nodes: Vec<ClientNodeEntry>,
}

/// Replaces long hexadecimal sequences (32 characters or more) in a parser message.
///
/// serde reports field names and wrong values: a private key pasted by mistake into a trust
/// file would end up in the message, and from there in the journal (finding 0004-6, found by
/// the `config_parsers` fuzzer).
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
    /// A key that MUST be the canonical encoding of a valid, non-weak point: the CA and
    /// denylist keys (the byte-by-byte comparison in step 5 of PROTOCOL §15.4 assumes
    /// canonical pins).
    fn canonical_key(&self, entry: &str, text: &str) -> Result<PublicKey, ConfigError> {
        let fail = |source| ConfigError::Key {
            path: self.0.into(),
            entry: entry.into(),
            source,
        };
        // Exactly 64 hexadecimal characters, no spaces (`FromStr` would strip them).
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail(CryptoError::InvalidKey));
        }
        let parsed: PublicKey = text.parse().map_err(fail)?;
        // `to_bytes` returns the 32 bytes as written, not the re-encoding of the point.
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

/// Parses the relay policy.
///
/// ```toml
/// [[agents]]
/// node = "web-01"
/// public_key = "<64 hex>"    # during rotation: public_keys = ["<new>", "<old>"]
///
/// [[clients]]
/// name = "ansible"
/// public_key = "<64 hex>"
/// allow = ["web-01"]      # or ["*"] for every node
/// ```
///
/// # Errors
/// Any invalid, duplicate or conflicting entry.
pub fn parse_policy(origin: &str, text: &str) -> Result<AccessPolicy, ConfigError> {
    let ctx = Ctx(origin);
    let file: PolicyFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut policy = AccessPolicy::new();
    for entry in &file.agents {
        let node = ctx.node(&entry.node, &entry.node)?;
        // `public_key` or `public_keys` (rotation), never both nor neither.
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
    // The CAs last: `set_cert_trust` rejects a CA key equal to that of a peer.
    let trust = parse_authorities(&ctx, &file.authorities)?;
    policy
        .set_cert_trust(trust)
        .map_err(|e| ctx.domain("authorities", e))?;
    Ok(policy)
}

/// The `[[authorities]]` entries (PROTOCOL §15.9), without a denylist.
fn parse_authorities(ctx: &Ctx<'_>, entries: &[AuthorityEntry]) -> Result<CertTrust, ConfigError> {
    let mut trust = CertTrust::new();
    for entry in entries {
        let name = ctx.node(&entry.name, &entry.name)?;
        // `public_key` or `public_keys` (rotation), never both nor neither.
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

/// Parses the list of clients an agent accepts end-to-end (same format as the `[[clients]]`
/// section of the policy; `allow` is ignored).
///
/// # Errors
/// Any invalid entry.
pub fn parse_authorized_clients(
    origin: &str,
    text: &str,
) -> Result<AuthorizedClients, ConfigError> {
    let ctx = Ctx(origin);
    let file: PolicyFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut clients = AuthorizedClients::new();
    for entry in &file.clients {
        let key = ctx.key(&entry.name, &entry.public_key)?;
        // A repeated key is not an error (it was a set before Phase 6).
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

/// Parses the `revoked.toml` denylist (`serials`, `keys`; PROTOCOL §15.8).
///
/// # Errors
/// Any invalid entry, or one over the limits.
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

/// 32 hexadecimal characters → 16 bytes.
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

/// A serial number: exactly 32 hexadecimal characters, never all zero. The error does not
/// report the value.
fn parse_serial(ctx: &Ctx<'_>, index: usize, text: &str) -> Result<CertSerial, ConfigError> {
    let fail = |message: &str| ConfigError::Syntax {
        path: ctx.0.into(),
        message: format!("serials[{index}]: {message}"),
    };
    let bytes =
        decode_hex16(text).ok_or_else(|| fail("a serial must be 32 hexadecimal characters"))?;
    CertSerial::try_from(bytes).map_err(|_| fail("a serial must not be all zeros"))
}

/// A certificate file, read and decoded (relay and agent verify the signature).
#[derive(Debug, Clone)]
pub struct CertificateFile {
    /// The certificate bytes, to be sent in message 1.
    pub bytes: Arc<[u8]>,
    /// The decoded body.
    pub body: CertBody,
}

/// Parses a certificate file (`tcn-client-cert-v1:<hex>`, PROTOCOL §15.1).
///
/// # Errors
/// [`ConfigError::Certificate`] for an invalid text or certificate.
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

/// Reads a certificate file, with the trust file rules.
///
/// # Errors
/// Like [`parse_certificate_file`]; insecure, unreadable or too large file.
pub fn load_certificate(path: &Path) -> Result<CertificateFile, ConfigError> {
    let text = read_file_bounded(open_trusted(path, false)?, path, MAX_CERT_FILE_LEN)?;
    parse_certificate_file(&path.display().to_string(), &text)
}

/// Generates a CA key and writes it to a new file with `0600` permissions. Never overwrites
/// an existing file.
///
/// # Errors
/// File already exists, I/O error, RNG unavailable.
pub fn create_ca_key(path: &Path) -> Result<CaSigningKey, ConfigError> {
    let ca = CaSigningKey::generate().map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "ca secret key".into(),
        source,
    })?;
    write_private_new(path, ca.to_secret_text().as_bytes())?;
    Ok(ca)
}

/// Loads a CA key, with the secret key rules.
///
/// # Errors
/// Like [`load_identity`]; a node key file is rejected.
pub fn load_ca_key(path: &Path) -> Result<CaSigningKey, ConfigError> {
    let file = open_trusted(path, true)?;
    let text = zeroize::Zeroizing::new(read_file_limited(file, path)?);
    CaSigningKey::from_secret_text(&text).map_err(|source| ConfigError::Key {
        path: path.display().to_string(),
        entry: "ca secret key".into(),
        source,
    })
}

/// Parses the list of nodes known to a client (`[[nodes]] node, public_key`).
///
/// # Errors
/// Any invalid or duplicate entry.
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

/// Reads and parses the relay policy. A policy with `[[authorities]]` requires
/// [`load_relay_policy`] with a denylist.
///
/// # Errors
/// See [`parse_policy`]; [`ConfigError::RevocationsRequired`] with a CA.
pub fn load_policy(path: &Path) -> Result<AccessPolicy, ConfigError> {
    load_relay_policy(path, None)
}

/// Reads the relay policy and, if present, the denylist, in a single step: if either file is
/// invalid nothing is loaded (PROTOCOL §15.8).
///
/// # Errors
/// See [`parse_policy`] and [`parse_revocations`]; [`ConfigError::RevocationsRequired`] with a
/// CA and no denylist.
pub fn load_relay_policy(
    policy: &Path,
    revocations: Option<&Path>,
) -> Result<AccessPolicy, ConfigError> {
    let origin = policy.display().to_string();
    // Both files read and validated before building the result: no partial effect.
    let text = read_limited(policy)?;
    let revoked = revocations.map(load_revocations).transpose()?;
    let mut parsed = parse_policy(&origin, &text)?;
    let trust = with_revocations(parsed.cert_trust(), revoked, &origin)?;
    parsed
        .set_cert_trust(trust)
        .map_err(|e| Ctx(&origin).domain("authorities", e))?;
    Ok(parsed)
}

/// The keys of a keyring (current and previous) as keys forbidden to CAs, with the role to
/// report in the error (e.g. `"relay"`, `"agent"`).
#[must_use]
pub fn own_keys(keys: &Keyring, role: &'static str) -> Vec<ForbiddenKey> {
    keys.identities()
        .map(|k| ForbiddenKey {
            fingerprint: k.fingerprint(),
            role,
        })
        .collect()
}

/// A key that no CA in the configuration may have (PROTOCOL §15.9): the process's key or
/// that of a pinned relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForbiddenKey {
    /// The fingerprint of the key.
    pub fingerprint: zt_domain::Fingerprint,
    /// The role of the key, for the error message.
    pub role: &'static str,
}

/// Rejects a CA whose key is one of `forbidden` (PROTOCOL §15.9, finding 0006-1): a relay or
/// an agent is never also a CA of its own configuration (current or previous key,
/// [`own_keys`]) and an agent does not accept any `--relay-key` as a CA. A compromised relay
/// must not be able to sign certificates that the agent admits with its own node seed.
///
/// # Errors
/// [`ConfigError::AuthorityIsInfrastructureKey`] for the first forbidden CA.
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

/// Reads a denylist with the trust file rules.
fn load_revocations(path: &Path) -> Result<Revocations, ConfigError> {
    parse_revocations(&path.display().to_string(), &read_limited(path)?)
}

/// The CAs of `trust` with the denylist; a CA without a denylist cannot start (PROTOCOL §15.8).
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

/// Reads and parses the authorized clients of an agent and, if present, the denylist.
///
/// # Errors
/// See [`parse_authorized_clients`] and [`load_relay_policy`].
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

/// Reads and parses the nodes known to a client.
///
/// # Errors
/// See [`parse_known_nodes`].
pub fn load_known_nodes(path: &Path) -> Result<HashMap<NodeId, PublicKey>, ConfigError> {
    parse_known_nodes(&path.display().to_string(), &read_limited(path)?)
}

/// Maximum length of the relay address (full DNS name plus port).
const MAX_RELAY_LEN: usize = 261;

/// `zt-client` configuration.
#[derive(Debug, Clone)]
pub struct ClientSettings {
    /// Relays to try in order, each with its pinned key (PROTOCOL §13).
    pub relays: Vec<crate::RelayEndpoint>,
    /// The client's secret key file.
    pub key: std::path::PathBuf,
    /// Reachable nodes, each with the pinned key of its agent. A missing node is not
    /// reachable: there is no trust-on-first-use.
    pub nodes: HashMap<NodeId, PublicKey>,
    /// The client certificate file, if configured (PROTOCOL §15).
    pub certificate: Option<std::path::PathBuf>,
    /// The end-to-end handshake suite pinned per node (PROTOCOL §7.5).
    pub node_suites: HashMap<NodeId, zt_domain::HandshakeSuite>,
}

impl ClientSettings {
    /// Connection configuration towards `node`.
    ///
    /// # Errors
    /// [`ConfigError::UnknownNode`] if the node has no pinned key.
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
            node_suite: self
                .node_suites
                .get(node)
                .copied()
                .unwrap_or(zt_domain::HandshakeSuite::NoiseIk25519),
            certificate: None,
            timeouts,
        })
    }
}

/// List of relays from addresses and keys paired by position (repeated `zt-agent` options, or
/// the client's `[[relays]]` entries). From 1 to [`crate::MAX_RELAYS`] entries, the same number
/// of addresses and keys, no repeated address and no repeated key.
///
/// # Errors
/// [`ConfigError::Syntax`] for a list that does not follow the rules.
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
            suite: zt_domain::HandshakeSuite::NoiseIk25519,
        });
    }
    Ok(out)
}

/// `host:port` with a non-zero numeric port, without spaces or control characters.
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

/// Parses the client configuration. `base` is the directory of the file: a relative key path
/// is resolved against it.
///
/// ```toml
/// relay = "relay.example.org:7443"
/// relay_key = "<64 hex>"
/// # or, with several relays tried in order (PROTOCOL §13):
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
/// Any invalid, duplicate or conflicting entry.
pub fn parse_client_settings(
    origin: &str,
    base: &Path,
    text: &str,
) -> Result<ClientSettings, ConfigError> {
    let ctx = Ctx(origin);
    let file: ClientFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    // `relay` + `relay_key` or `[[relays]]`, never both.
    let (addresses, key_texts): (Vec<String>, Vec<String>) =
        match (&file.relay, &file.relay_key, file.relays.as_slice()) {
            (Some(relay), Some(key), []) => (vec![relay.clone()], vec![key.clone()]),
            (None, None, list) if !list.is_empty() && file.relay_suite.is_none() => list
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
    let mut relays = relay_endpoints(origin, &addresses, &relay_keys)?;
    // Without `suite` the classical suite: a fixed default that never changes between
    // releases (finding AP-7).
    let suite_texts: Vec<Option<&String>> = if file.relays.is_empty() {
        vec![file.relay_suite.as_ref()]
    } else {
        file.relays.iter().map(|r| r.suite.as_ref()).collect()
    };
    for (relay, text) in relays.iter_mut().zip(suite_texts) {
        if let Some(text) = text {
            relay.suite = parse_suite(origin, text, zt_domain::HandshakeChannel::Outer)?;
        }
    }
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
    let mut node_suites = HashMap::new();
    for entry in &file.nodes {
        let node = ctx.node(&entry.node, &entry.node)?;
        let key = ctx.key(&entry.node, &entry.public_key)?;
        if relays
            .iter()
            .any(|r| r.public_key.fingerprint() == key.fingerprint())
        {
            return Err(ctx.domain(&entry.node, DomainError::DuplicatePeer(key.fingerprint())));
        }
        if let Some(text) = &entry.suite {
            // The node pin is the end-to-end channel (PROTOCOL §7.5).
            let suite = parse_suite(origin, text, zt_domain::HandshakeChannel::EndToEnd)?;
            node_suites.insert(node.clone(), suite);
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
        node_suites,
    })
}

/// Reads and parses the client configuration.
///
/// # Errors
/// See [`parse_client_settings`]; also a file writable by group or others.
pub fn load_client_settings(path: &Path) -> Result<ClientSettings, ConfigError> {
    let base = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    parse_client_settings(&path.display().to_string(), base, &read_limited(path)?)
}

/// Handshake suites and admission limits of the relay (`relay.toml`, OPERATIONS §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySettings {
    /// Admission limits.
    pub admission: zt_application::admission::AdmissionConfig,
    /// Suites accepted per role.
    pub suites: zt_domain::SuitePolicy,
    /// Idle timeout of agent connections (`[liveness] agent_idle_secs`, resilience R-2).
    pub agent_idle: std::time::Duration,
    /// Idle timeout of client connections (`[liveness] client_idle_secs`).
    pub client_idle: std::time::Duration,
}

/// The default idle timeout of both roles: three times the keepalive of agents older than
/// R-2 (30 s), so that they survive a relay upgrade (catalogue R2-L3).
pub const DEFAULT_RELAY_IDLE: std::time::Duration = std::time::Duration::from_secs(90);

/// The shortest idle timeout `relay.toml` accepts: above the agent's dead-peer window of
/// 3 × 10 s plus one keepalive of slack.
const MIN_RELAY_IDLE_SECS: u64 = 15;
/// The longest: one hour.
const MAX_RELAY_IDLE_SECS: u64 = 3_600;

impl Default for RelaySettings {
    /// What an empty `relay.toml` gives.
    fn default() -> Self {
        Self {
            admission: zt_application::admission::AdmissionConfig::default(),
            suites: zt_domain::SuitePolicy::classical(),
            agent_idle: DEFAULT_RELAY_IDLE,
            client_idle: DEFAULT_RELAY_IDLE,
        }
    }
}

/// `relay.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayFile {
    #[serde(default)]
    handshake: HandshakeSection,
    #[serde(default)]
    admission: AdmissionSection,
    #[serde(default)]
    liveness: LivenessSection,
}

/// `[liveness]` of `relay.toml`: the idle timeout per role (resilience R-2).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LivenessSection {
    #[serde(default)]
    agent_idle_secs: Option<u64>,
    #[serde(default)]
    client_idle_secs: Option<u64>,
}

/// `[handshake]` of `relay.toml`: the accepted suites per role (finding AP-7). There is no
/// minimum suite, only explicit sets.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandshakeSection {
    #[serde(default)]
    agent_suites: Option<Vec<String>>,
    #[serde(default)]
    client_suites: Option<Vec<String>>,
}

/// `[admission]` of `relay.toml`: every key optional, the defaults of PROTOCOL §10.1.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSection {
    max_preauth: Option<usize>,
    max_established: Option<usize>,
    max_per_identity: Option<usize>,
    source_burst: Option<u32>,
    source_refill_secs: Option<u64>,
    msg1_deadline_secs: Option<u64>,
    handshake_timeout_secs: Option<u64>,
    first_frame_deadline_secs: Option<u64>,
    max_pending_per_source: Option<usize>,
    max_pending_per_wide: Option<usize>,
    wide_burst: Option<u32>,
    wide_refill_secs: Option<u64>,
    max_tracked_sources: Option<usize>,
    max_tracked_wide: Option<usize>,
    identity_refund_burst: Option<u32>,
    identity_refund_refill_ms: Option<u64>,
    agent_reserve_percent: Option<u8>,
    summary_interval_secs: Option<u64>,
}

/// Parses `relay.toml` (OPERATIONS §4.1). An empty file gives the defaults: the classical
/// suite for both roles and the admission limits of PROTOCOL §10.1.
///
/// ```toml
/// [handshake]
/// agent_suites = ["Noise_IK_25519_ChaChaPoly_BLAKE2s"]
/// client_suites = ["Noise_IK_25519_ChaChaPoly_BLAKE2s"]
///
/// [admission]
/// max_preauth = 1024
/// max_pending_per_source = 50
/// max_pending_per_wide = 100
/// source_burst = 64
/// msg1_deadline_secs = 5
/// ```
///
/// # Errors
/// [`ConfigError::Syntax`] for an unknown key or a wrong type, [`ConfigError::Suite`] for an
/// unknown, unsupported, repeated or empty suite list, [`ConfigError::Admission`] for limits
/// that do not validate.
pub fn parse_relay_settings(origin: &str, text: &str) -> Result<RelaySettings, ConfigError> {
    let ctx = Ctx(origin);
    let file: RelayFile = toml::from_str(text).map_err(|e| ctx.syntax(&e))?;
    let mut suites = zt_domain::SuitePolicy::classical();
    if let Some(names) = &file.handshake.agent_suites {
        suites.agents = parse_suites(origin, names, zt_domain::HandshakeChannel::Outer)?;
    }
    if let Some(names) = &file.handshake.client_suites {
        suites.clients = parse_suites(origin, names, zt_domain::HandshakeChannel::Outer)?;
    }
    let a = file.admission;
    let mut admission = zt_application::admission::AdmissionConfig::default();
    let secs = std::time::Duration::from_secs;
    admission.max_preauth = a.max_preauth.unwrap_or(admission.max_preauth);
    admission.max_established = a.max_established.unwrap_or(admission.max_established);
    admission.max_per_identity = a.max_per_identity.unwrap_or(admission.max_per_identity);
    admission.source_burst = a.source_burst.unwrap_or(admission.source_burst);
    admission.source_refill = a.source_refill_secs.map_or(admission.source_refill, secs);
    admission.msg1_deadline = a.msg1_deadline_secs.map_or(admission.msg1_deadline, secs);
    admission.handshake_timeout = a
        .handshake_timeout_secs
        .map_or(admission.handshake_timeout, secs);
    admission.first_frame_deadline = a
        .first_frame_deadline_secs
        .map_or(admission.first_frame_deadline, secs);
    admission.max_pending_per_source = a
        .max_pending_per_source
        .unwrap_or(admission.max_pending_per_source);
    admission.max_pending_per_wide = a
        .max_pending_per_wide
        .unwrap_or(admission.max_pending_per_wide);
    admission.wide_burst = a.wide_burst.unwrap_or(admission.wide_burst);
    admission.wide_refill = a.wide_refill_secs.map_or(admission.wide_refill, secs);
    admission.max_tracked_sources = a
        .max_tracked_sources
        .unwrap_or(admission.max_tracked_sources);
    admission.max_tracked_wide = a.max_tracked_wide.unwrap_or(admission.max_tracked_wide);
    admission.identity_refund_burst = a
        .identity_refund_burst
        .unwrap_or(admission.identity_refund_burst);
    admission.identity_refund_refill = a.identity_refund_refill_ms.map_or(
        admission.identity_refund_refill,
        std::time::Duration::from_millis,
    );
    admission.agent_reserve_percent = a
        .agent_reserve_percent
        .unwrap_or(admission.agent_reserve_percent);
    admission.summary_interval = a
        .summary_interval_secs
        .map_or(admission.summary_interval, secs);
    admission
        .validate()
        .map_err(|source| ConfigError::Admission {
            path: origin.into(),
            source,
        })?;
    let idle = |value: Option<u64>, key: &str| -> Result<std::time::Duration, ConfigError> {
        match value {
            None => Ok(DEFAULT_RELAY_IDLE),
            Some(s) if (MIN_RELAY_IDLE_SECS..=MAX_RELAY_IDLE_SECS).contains(&s) => {
                Ok(std::time::Duration::from_secs(s))
            }
            Some(_) => Err(ConfigError::Syntax {
                path: origin.into(),
                message: format!(
                    "[liveness] {key} must be between {MIN_RELAY_IDLE_SECS} and {MAX_RELAY_IDLE_SECS}"
                ),
            }),
        }
    };
    let agent_idle = idle(file.liveness.agent_idle_secs, "agent_idle_secs")?;
    let client_idle = idle(file.liveness.client_idle_secs, "client_idle_secs")?;
    Ok(RelaySettings {
        admission,
        suites,
        agent_idle,
        client_idle,
    })
}

/// Reads and parses `relay.toml`.
///
/// # Errors
/// See [`parse_relay_settings`]; also a file writable by group or others.
pub fn load_relay_settings(path: &Path) -> Result<RelaySettings, ConfigError> {
    parse_relay_settings(&path.display().to_string(), &read_limited(path)?)
}

/// One handshake suite by its exact Noise protocol name (no case folding, trimming or
/// aliases), which this build must be able to run on `channel`.
///
/// # Errors
/// [`ConfigError::Suite`] with [`zt_domain::SuiteError::Unknown`] or
/// [`zt_domain::SuiteError::Unsupported`].
pub fn parse_suite(
    origin: &str,
    name: &str,
    channel: zt_domain::HandshakeChannel,
) -> Result<zt_domain::HandshakeSuite, ConfigError> {
    let fail = |source| ConfigError::Suite {
        path: origin.into(),
        entry: redact_hex(name),
        source,
    };
    let suite: zt_domain::HandshakeSuite = name.parse().map_err(fail)?;
    if !suite.is_supported(channel) {
        return Err(fail(zt_domain::SuiteError::Unsupported));
    }
    Ok(suite)
}

/// An accepted set of suites by their Noise protocol names: non-empty, no repetition, every
/// suite supported by this build on `channel`.
///
/// # Errors
/// [`ConfigError::Suite`].
pub fn parse_suites(
    origin: &str,
    names: &[String],
    channel: zt_domain::HandshakeChannel,
) -> Result<zt_domain::AcceptedSuites, ConfigError> {
    let suites = names
        .iter()
        .map(|name| name.parse::<zt_domain::HandshakeSuite>())
        .collect::<Result<Vec<_>, _>>();
    let set = suites.and_then(zt_domain::AcceptedSuites::new);
    let set = set.map_err(|source| ConfigError::Suite {
        path: origin.into(),
        entry: "suites".into(),
        source,
    })?;
    if !set.all_supported(channel) {
        return Err(ConfigError::Suite {
            path: origin.into(),
            entry: "suites".into(),
            source: zt_domain::SuiteError::Unsupported,
        });
    }
    Ok(set)
}
