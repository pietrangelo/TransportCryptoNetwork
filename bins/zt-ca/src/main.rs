//! `zt-ca`: la CA offline dei certificati client (PROTOCOL §15, OPERATIONS §10).
//!
//! Gira solo sulla macchina della CA, senza rete: genera la chiave della CA, firma certificati
//! brevi e li ispeziona. Nessun runtime tokio.
//!
//! Nessun messaggio d'errore riporta i valori passati sulla riga di comando o il contenuto di un
//! file: un operatore che incolla per sbaglio il segreto della CA al posto di una chiave pubblica
//! non lo ritrova a terminale (né nella cronologia di un terminale condiviso).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand};
use zt_crypto::{
    CaSigningKey, PublicKey, cert_key, encode_certificate_text, sign_certificate, trusted_ca_key,
    verify_certificate,
};
use zt_domain::limits::{MAX_CERT_LIFETIME_SECS, MAX_CERT_NODES};
use zt_domain::{
    AllowedNodes, CertBody, CertScope, CertSerial, CertTrust, NodeId, Revocations, UnixTime,
};
use zt_net::config;

/// CA offline di TCN.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Genera la chiave della CA (file nuovo, permessi 0600) e stampa la chiave pubblica.
    Keygen {
        /// File da creare.
        #[arg(long)]
        out: PathBuf,
    },
    /// Firma un certificato per la chiave pubblica di un client.
    #[command(group(ArgGroup::new("scope").required(true).multiple(false).args(["nodes", "all_nodes"])))]
    Sign {
        /// Chiave segreta della CA (`tcn-ca-secret-v1:`).
        #[arg(long)]
        ca: PathBuf,
        /// Registro delle emissioni (TSV, in append, 0600). Obbligatorio.
        #[arg(long)]
        log: PathBuf,
        /// Chiave pubblica del client (64 caratteri esadecimali).
        #[arg(long)]
        subject: String,
        /// Nome del client, per gli audit log (`[a-z0-9-]`, 1..=63).
        #[arg(long)]
        name: String,
        /// Nodi concessi (al massimo 64), separati da virgole.
        #[arg(long, value_delimiter = ',')]
        nodes: Vec<String>,
        /// Tutti i nodi in `allow` della CA.
        #[arg(long)]
        all_nodes: bool,
        /// Durata: `<n>s`, `<n>m` o `<n>h`, al massimo 24 ore.
        #[arg(long)]
        validity: String,
        /// Inizio della validità in secondi Unix (default: adesso).
        #[arg(long)]
        not_before: Option<u64>,
        /// File del certificato da creare (mai sovrascritto).
        #[arg(long)]
        out: PathBuf,
    },
    /// Mostra i campi di un certificato e la riga per la denylist.
    Inspect {
        /// File del certificato.
        #[arg(long)]
        cert: PathBuf,
        /// Chiave pubblica della CA con cui verificare la firma (64 caratteri esadecimali).
        #[arg(long)]
        ca_key: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "zt-ca: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: &Command) -> Result<(), String> {
    match command {
        Command::Keygen { out } => keygen(out),
        Command::Sign {
            ca,
            log,
            subject,
            name,
            nodes,
            all_nodes,
            validity,
            not_before,
            out,
        } => sign(&SignArgs {
            ca,
            log,
            subject,
            name,
            nodes,
            all_nodes: *all_nodes,
            validity,
            not_before: *not_before,
            out,
        }),
        Command::Inspect { cert, ca_key } => inspect(cert, ca_key.as_deref()),
    }
}

/// Un errore di configurazione di `zt-net`: riporta il percorso e il tipo di errore, mai il
/// contenuto del file.
fn config_error(error: &config::ConfigError) -> String {
    error.to_string()
}

fn keygen(out: &Path) -> Result<(), String> {
    let ca = config::create_ca_key(out).map_err(|e| config_error(&e))?;
    let public = ca.public_key();
    let mut out = String::new();
    let _ = writeln!(out, "public_key  = \"{public}\"");
    let _ = writeln!(out, "fingerprint = {}", public.fingerprint());
    emit(&out)
}

struct SignArgs<'a> {
    ca: &'a Path,
    log: &'a Path,
    subject: &'a str,
    name: &'a str,
    nodes: &'a [String],
    all_nodes: bool,
    validity: &'a str,
    not_before: Option<u64>,
    out: &'a Path,
}

fn sign(args: &SignArgs<'_>) -> Result<(), String> {
    // Tutti i controlli sugli argomenti prima di toccare un file.
    let lifetime = parse_validity(args.validity)?;
    let subject = parse_public_key(args.subject)
        .ok_or("--subject: not a valid Ed25519 public key (64 lowercase hexadecimal characters)")?;
    let name =
        NodeId::try_from(args.name).map_err(|_| "--name: must be [a-z0-9-], 1..=63 characters")?;
    let scope = parse_scope(args.nodes, args.all_nodes)?;
    let not_before = UnixTime::from_secs(match args.not_before {
        Some(secs) => secs,
        None => zt_net::unix_now().as_secs(),
    });
    let not_after = not_before
        .checked_add(lifetime)
        .ok_or("--not-before: the validity ends after the end of time")?;

    let ca = config::load_ca_key(args.ca).map_err(|e| config_error(&e))?;
    // Il segreto della CA incollato al posto della chiave del client: rifiutato, perché il
    // certificato e il registro lo renderebbero pubblico.
    if is_ca_secret(&ca, args.subject) {
        return Err("--subject: this is a secret key, not a public key".into());
    }
    let subject_key = cert_key(&subject);
    let ca_key = cert_key(&ca.public_key());
    if subject_key == ca_key {
        return Err("--subject: the CA cannot certify its own key".into());
    }
    let serial = random_serial()?;
    let body = CertBody::new(
        ca_key,
        subject_key,
        serial,
        not_before,
        not_after,
        name.clone(),
        scope,
    )
    .map_err(|e| format!("certificate not valid: {e}"))?;
    let cert = sign_certificate(&ca, &body).map_err(|e| format!("signing failed: {e}"))?;
    let text = encode_certificate_text(&cert);

    // `--out` non si sovrascrive mai (`create_new` lo garantisce comunque): controllarlo prima
    // evita una riga nel registro per un certificato che non verrà creato.
    if args.out.symlink_metadata().is_ok() {
        return Err(format!("{}: already exists", args.out.display()));
    }
    let subject_fp = subject.fingerprint();
    let line = format!(
        "{serial}\t{subject_fp}\t{name}\t{}\t{}\t{}\n",
        not_before.as_secs(),
        not_after.as_secs(),
        scope_column(body.scope()),
    );
    // Prima il registro, sincronizzato; poi il certificato. Un certificato senza riga nel
    // registro non deve esistere (OPERATIONS §10.3).
    append_log(args.log, args.ca, line.as_bytes())?;
    write_public_new(args.out, text.as_bytes())?;

    let mut out = String::new();
    let _ = writeln!(out, "serial      = {serial}");
    let _ = writeln!(out, "subject     = {subject_fp}");
    let _ = writeln!(out, "not_before  = {}", zt_net::utc_text(not_before));
    let _ = writeln!(out, "not_after   = {}", zt_net::utc_text(not_after));
    emit(&out)
}

fn inspect(cert: &Path, ca_key: Option<&str>) -> Result<(), String> {
    let expected_ca = match ca_key {
        Some(text) => Some(parse_public_key(text).ok_or(
            "--ca-key: not a valid Ed25519 public key (64 lowercase hexadecimal characters)",
        )?),
        None => None,
    };
    let file = config::load_certificate(cert).map_err(|e| config_error(&e))?;
    let body = &file.body;
    let ca = PublicKey::from_canonical_bytes(body.ca_key().as_bytes()).ok();
    let subject = PublicKey::from_canonical_bytes(body.subject_key().as_bytes()).ok();

    let mut out = String::new();
    let _ = writeln!(out, "name        = \"{}\"", body.name());
    match body.scope() {
        CertScope::All => {
            let _ = writeln!(out, "nodes       = \"*\"");
        }
        CertScope::Only(nodes) => {
            let list: Vec<String> = nodes.iter().map(|n| format!("\"{n}\"")).collect();
            let _ = writeln!(out, "nodes       = [{}]", list.join(", "));
        }
    }
    let _ = writeln!(
        out,
        "ca_key      = \"{}\"",
        hex_of(body.ca_key().as_bytes())
    );
    match ca {
        Some(key) => {
            let _ = writeln!(out, "ca          = {}", key.fingerprint());
        }
        None => {
            let _ = writeln!(out, "ca          = invalid key");
        }
    }
    match subject {
        Some(key) => {
            let _ = writeln!(out, "subject     = {}", key.fingerprint());
        }
        None => {
            let _ = writeln!(out, "subject     = invalid key");
        }
    }
    let _ = writeln!(out, "serial      = {}", body.serial());
    let _ = writeln!(
        out,
        "not_before  = {} ({})",
        zt_net::utc_text(body.not_before()),
        body.not_before().as_secs()
    );
    let _ = writeln!(
        out,
        "not_after   = {} ({})",
        zt_net::utc_text(body.not_after()),
        body.not_after().as_secs()
    );
    let _ = writeln!(out, "lifetime    = {}s", body.lifetime_secs());
    let now = zt_net::unix_now();
    let status = if now < body.not_before() {
        "not yet valid"
    } else if now >= body.not_after() {
        "expired"
    } else {
        "valid"
    };
    let _ = writeln!(out, "status      = {status} (local clock)");
    out.push('\n');
    let _ = writeln!(out, "# revoked.toml");
    let _ = writeln!(out, "serials = [\"{}\"]", body.serial());

    let Some(expected_ca) = expected_ca else {
        return emit(&out);
    };
    let verdict = verify_signature(&file.bytes, subject, &expected_ca);
    if verdict.is_ok() {
        let _ = writeln!(
            out,
            "signature   = verified with {}",
            expected_ca.fingerprint()
        );
    }
    emit(&out)?;
    verdict
}

/// Verifica la firma con `ca` come unica CA pinnata (passi 3–6 di PROTOCOL §15.4).
fn verify_signature(
    bytes: &[u8],
    subject: Option<PublicKey>,
    ca: &PublicKey,
) -> Result<(), String> {
    let subject = subject.ok_or("signature: the certificate's subject key is not valid")?;
    let name = NodeId::try_from("inspect").map_err(|_| "internal error")?;
    let mut trust = CertTrust::new();
    trust
        .add_authority(
            name,
            &[trusted_ca_key(ca)],
            AllowedNodes::All,
            MAX_CERT_LIFETIME_SECS,
        )
        .map_err(|_| "--ca-key: not usable as a CA key")?;
    let empty = Revocations::new([], []).map_err(|_| "internal error")?;
    trust.set_revocations(empty);
    verify_certificate(bytes, &subject.fingerprint(), &trust)
        .map(|_| ())
        .map_err(|rejection| {
            format!(
                "signature: not verified with this CA key ({})",
                rejection.as_str()
            )
        })
}

/// Scrive l'output di un comando su stdout, in una volta.
fn emit(text: &str) -> Result<(), String> {
    std::io::stdout()
        .write_all(text.as_bytes())
        .map_err(|e| format!("stdout: {e}"))
}

/// `<n>s`, `<n>m` o `<n>h`: cifre ASCII e un suffisso minuscolo, niente segni o spazi;
/// `1..=86400` secondi.
fn parse_validity(text: &str) -> Result<u64, String> {
    const MESSAGE: &str = "--validity: expected <n>s, <n>m or <n>h, at most 24h";
    let (digits, unit) = match text.as_bytes().split_last() {
        Some((b's', rest)) => (rest, 1_u64),
        Some((b'm', rest)) => (rest, 60),
        Some((b'h', rest)) => (rest, 3_600),
        _ => return Err(MESSAGE.into()),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(MESSAGE.into());
    }
    let count: u64 = std::str::from_utf8(digits)
        .ok()
        .and_then(|d| d.parse().ok())
        .ok_or(MESSAGE)?;
    let secs = count.checked_mul(unit).ok_or(MESSAGE)?;
    if secs == 0 || secs > MAX_CERT_LIFETIME_SECS {
        return Err(MESSAGE.into());
    }
    Ok(secs)
}

/// Una chiave pubblica Ed25519: esattamente 64 caratteri esadecimali minuscoli, punto canonico
/// e non di ordine piccolo (PROTOCOL §15.1 regola 8).
fn parse_public_key(text: &str) -> Option<PublicKey> {
    let bytes = decode_hex32(text)?;
    PublicKey::from_canonical_bytes(&bytes).ok()
}

fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let [hi, lo] = pair else { return None };
        *slot = nibble(*hi)?.checked_mul(16)?.checked_add(nibble(*lo)?)?;
    }
    Some(out)
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => match c.checked_sub(b'a') {
            Some(v) => v.checked_add(10),
            None => None,
        },
        _ => None,
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `true` se `text` è il segreto della CA (con o senza prefisso).
fn is_ca_secret(ca: &CaSigningKey, text: &str) -> bool {
    let secret = ca.to_secret_text();
    let Some(hex) = secret
        .trim_end_matches('\n')
        .strip_prefix(CaSigningKey::FILE_PREFIX)
    else {
        return true;
    };
    let candidate = text.trim();
    let candidate = candidate
        .strip_prefix(CaSigningKey::FILE_PREFIX)
        .unwrap_or(candidate);
    candidate.eq_ignore_ascii_case(hex)
}

fn parse_scope(nodes: &[String], all_nodes: bool) -> Result<CertScope, String> {
    // `clap` garantisce già esattamente uno dei due; il controllo resta per difesa.
    match (nodes.is_empty(), all_nodes) {
        (true, true) => return Ok(CertScope::All),
        (false, false) => {}
        _ => return Err("exactly one of --nodes and --all-nodes is required".into()),
    }
    if nodes.len() > MAX_CERT_NODES {
        return Err(format!("--nodes: at most {MAX_CERT_NODES} nodes"));
    }
    let mut set = BTreeSet::new();
    for node in nodes {
        let id = NodeId::try_from(node.as_str())
            .map_err(|_| "--nodes: each node must be [a-z0-9-], 1..=63 characters")?;
        if !set.insert(id) {
            return Err("--nodes: a node is listed twice".into());
        }
    }
    if set.is_empty() {
        return Err("--nodes: at least one node is required".into());
    }
    Ok(CertScope::Only(set))
}

fn scope_column(scope: &CertScope) -> String {
    match scope {
        CertScope::All => "*".into(),
        CertScope::Only(nodes) => nodes
            .iter()
            .map(NodeId::as_str)
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// 16 byte casuali, mai tutti a zero (PROTOCOL §15.2).
fn random_serial() -> Result<CertSerial, String> {
    for _ in 0..4 {
        let mut bytes = [0_u8; CertSerial::LEN];
        getrandom::fill(&mut bytes).map_err(|_| "random number generator not available")?;
        if let Ok(serial) = CertSerial::try_from(bytes) {
            return Ok(serial);
        }
    }
    Err("random number generator returned zeros".into())
}

/// Aggiunge una riga al registro: file regolare, creato `0600`, mai accessibile da gruppo o
/// altri; scritto con una sola `write` e sincronizzato prima di tornare.
///
/// Il registro non è mai il file della chiave della CA (finding 0006-5): un `--log` uguale a
/// `--ca` aggiungerebbe una riga alla chiave e la renderebbe illeggibile. Si rifiutano quindi un
/// collegamento simbolico (`O_NOFOLLOW`), lo stesso file di `--ca` (stesso dispositivo e
/// inode, anche con un hard link) e un file che inizia come una chiave di CA (una copia).
fn append_log(path: &Path, ca: &Path, line: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut options = std::fs::OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    let mut file = options.open(path).map_err(|e| {
        if is_symlink_refusal(&e) {
            format!(
                "{}: the issuance log must not be a symbolic link",
                path.display()
            )
        } else {
            io(e)
        }
    })?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: the issuance log must not be accessible by group or others (chmod 600)",
                path.display()
            ));
        }
        let ca_meta = std::fs::metadata(ca).map_err(|e| format!("{}: {e}", ca.display()))?;
        if ca_meta.dev() == meta.dev() && ca_meta.ino() == meta.ino() {
            return Err(format!(
                "{}: the issuance log is the CA key file (--ca): use a separate file",
                path.display()
            ));
        }
    }
    // Il file è aperto in lettura dall'inizio: i primi byte dicono se è una chiave di CA.
    let prefix = CaSigningKey::FILE_PREFIX.as_bytes();
    let mut head = Vec::with_capacity(prefix.len());
    (&mut file)
        .take(u64::try_from(prefix.len()).unwrap_or(u64::MAX))
        .read_to_end(&mut head)
        .map_err(io)?;
    if head == prefix {
        return Err(format!(
            "{}: the issuance log looks like a CA key file: use a separate file",
            path.display()
        ));
    }
    file.write_all(line).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}

/// `true` se `open` ha rifiutato un collegamento simbolico (`O_NOFOLLOW`).
#[cfg(unix)]
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
}

#[cfg(not(unix))]
const fn is_symlink_refusal(_: &std::io::Error) -> bool {
    false
}

/// Crea il file del certificato (`0644`, mai sovrascritto).
fn write_public_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(path).map_err(io)?;
    file.write_all(contents).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn validity_parser() {
        assert_eq!(parse_validity("90m").unwrap(), 5_400);
        assert_eq!(parse_validity("24h").unwrap(), 86_400);
        for bad in ["0s", "25h", "1d", "", "h", "+8h", "8H", "8 h", "1h30m"] {
            assert!(parse_validity(bad).is_err(), "{bad}");
        }
    }
}
