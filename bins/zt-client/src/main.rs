//! `zt-client`: stdio bridge for OpenSSH `ProxyCommand` to a node, through the relay.
//!
//! ```text
//! Host web-01 db-01
//!     ProxyCommand zt-client connect %n
//! ```
//!
//! stdout is the SSH channel: every log and every error goes to stderr, and on error nothing
//! reaches stdout.
#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zt_crypto::{Identity, PublicKey, cert_key};
use zt_domain::{
    AnyCertBody, CertScope, CloseReason, HandshakeSuite, NodeId, RejectReason, UnixTime,
};
use zt_net::config::{self, ClientSettings};
use zt_net::{NetError, Timeouts, client};

/// Environment variable with the configuration path.
const CONFIG_ENV: &str = "TCN_CLIENT_CONFIG";

/// TCN client.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Client configuration. Default: `$TCN_CLIENT_CONFIG`, then
    /// `$XDG_CONFIG_HOME/tcn/client.toml`, then `~/.config/tcn/client.toml`.
    /// Must be given before the command: no option is read after the node name.
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generates the client key (new file, 0600 permissions) and prints the public key.
    Keygen {
        /// File to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Connects stdin/stdout to the node's SSH daemon (usage: `ProxyCommand zt-client connect %n`).
    Connect {
        /// Suffix to strip from the host name before looking it up among the nodes (e.g. `.tcn` for
        /// `Host *.tcn`). If given, the name must end with it.
        #[arg(long)]
        strip_suffix: Option<String>,
        /// Destination node. It is the last argument: everything that follows ends up here and is
        /// rejected, so a host name with spaces passed by `ssh` through `sh -c` cannot add
        /// options (finding 0003-4).
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        node: Vec<String>,
    },
    /// Prints name, nodes, CA, serial number and validity of the configured certificate
    /// (`certificate` in `client.toml`, PROTOCOL §15).
    Certificate,
}

fn main() -> ExitCode {
    // Logs always go to stderr: in ProxyCommand mode stdout is the SSH channel.
    // Default `warn`, so as not to clutter ssh's output.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { out } => keygen(&out).map_err(Failure::from),
        Command::Connect { strip_suffix, node } => match node.as_slice() {
            [name] => connect(cli.config, strip_suffix.as_deref(), name),
            _ => Err(Failure::from(
                "expected exactly one node name, and no option after it".to_owned(),
            )),
        },
        Command::Certificate => certificate(cli.config.as_deref()).map_err(Failure::from),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            // On stderr OpenSSH shows it to the user, who is the right recipient.
            let _ = writeln!(std::io::stderr(), "zt-client: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

/// `EX_TEMPFAIL` (sysexits.h): no relay completed the connection within the deadline; trying
/// again later may work. OpenSSH itself then exits with 255, which Ansible retries.
const EXIT_TEMPFAIL: u8 = 75;

/// A failed command: the message for stderr and the exit status.
struct Failure {
    message: String,
    code: u8,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self { message, code: 1 }
    }
}

/// Below this remaining lifetime `zt-client` warns that the certificate is about to expire.
const EXPIRY_WARNING_SECS: u64 = 15 * 60;

/// `zt-client certificate`: the fields of the configured certificate, without network.
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
    let _ = writeln!(out, "version     = {}", body.version());
    match body {
        AnyCertBody::V1(body) => {
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
        }
        AnyCertBody::V2(body) => {
            let _ = writeln!(out, "ca_fp       = {}", body.ca_fp());
            let _ = writeln!(out, "subject     = {}", body.subject().classical());
            if let Some(hybrid) = body.subject().hybrid() {
                let _ = writeln!(out, "subject_v2  = {hybrid}");
            }
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

/// State of a certificate according to the local clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validity {
    Valid,
    ExpiringSoon,
    NotYetValid,
    Expired,
}

fn check_validity(body: &AnyCertBody, now: UnixTime) -> Validity {
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

/// Loads the configured certificate and checks, before any connection, that it is for
/// `identity` and has not expired. A certificate not yet valid or close to expiry only
/// causes a warning on stderr (the relay and agent clocks decide).
fn load_own_certificate(
    path: &Path,
    identity: &Identity,
) -> Result<config::CertificateFile, String> {
    let cert = config::load_certificate(path).map_err(|e| e.to_string())?;
    reject_leaked_secret(path, &cert.body, identity)?;
    let subject = match &cert.body {
        AnyCertBody::V1(body) => (*body.subject_key() == cert_key(&identity.public_key()))
            .then_some(())
            .ok_or_else(|| {
                PublicKey::from_canonical_bytes(body.subject_key().as_bytes())
                    .map_or_else(|_| "invalid".to_owned(), |k| k.fingerprint().to_string())
            }),
        AnyCertBody::V2(body) => (*body.subject().classical() == identity.fingerprint())
            .then_some(())
            .ok_or_else(|| body.subject().classical().to_string()),
    };
    if let Err(subject) = subject {
        return Err(format!(
            "{}: the certificate is for another key (subject {subject}), not for this client's \
             key {}",
            path.display(),
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

/// A certificate whose `subject_key` is the client's **secret** (`--subject` of `zt-ca` with
/// the content of the key file, 64 hex characters like a public key): the secret is now in a
/// public file and in the CA log, so the key must be regenerated (finding 0006-6). The
/// message never reports the secret.
fn reject_leaked_secret(
    path: &Path,
    body: &AnyCertBody,
    identity: &Identity,
) -> Result<(), String> {
    // A v2 certificate carries fingerprints, not keys: a secret cannot leak into it.
    let AnyCertBody::V1(body) = body else {
        return Ok(());
    };
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

/// Resolves the host name passed by ssh into the node. No normalization beyond the suffix:
/// a name that is not already a valid `NodeId` is rejected.
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
    // Per the XDG specification a relative value must be ignored.
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

fn connect(flag: Option<PathBuf>, strip_suffix: Option<&str>, name: &str) -> Result<(), Failure> {
    // Everything local is validated before opening any connection.
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
    // Reading stdin runs on a blocking thread that cannot be interrupted: if the session
    // has ended on the node side we do not wait for ssh to close stdin.
    runtime.shutdown_background();
    let suite = config.node_suite;
    result.map_err(|e| Failure {
        message: describe(&e, &node, not_after, suite),
        code: exit_code(&e),
    })
}

/// 75 (`EX_TEMPFAIL`) when trying again later may succeed: the deadline, and every give-up
/// that says nothing about the right of access (finding A11-4): a relay unreachable, silent
/// or dropping the connection without a reply (restart, overload, R-1 admission; also a client
/// key the relay does not know, which it cannot tell apart), a node offline or draining, a
/// rate limit. 1 for a definitive answer: a policy refusal, a failed handshake with a pinned
/// key, a protocol error, the local configuration.
fn exit_code(err: &NetError) -> u8 {
    let temporary = matches!(
        err,
        NetError::Deadline(_)
            | NetError::Io(_)
            | NetError::Timeout(_)
            | NetError::Closed
            | NetError::Rejected(RejectReason::NodeOffline | RejectReason::RateLimited)
            | NetError::StreamClosed(CloseReason::Drained)
    );
    if temporary { EXIT_TEMPFAIL } else { 1 }
}

/// Message for the ssh user. It never contains bytes received from the network. `not_after`
/// is the expiry of the certificate used, if any; `suite` is the suite pinned for the node.
fn describe(
    err: &NetError,
    node: &NodeId,
    not_after: Option<UnixTime>,
    suite: HandshakeSuite,
) -> String {
    let text = describe_error(err, node, not_after);
    // The agent does not say why it refused (no oracle), but the client knows its own pin: an
    // agent that does not accept the suite closes with `Unauthorized`, one older than PQ-1
    // sees an invalid handshake (finding A9-6).
    let refused_by_agent = matches!(
        err,
        NetError::StreamClosed(CloseReason::Unauthorized | CloseReason::ProtocolViolation)
    );
    if refused_by_agent && suite != HandshakeSuite::NoiseIk25519 {
        format!(
            "{text}, or the agent does not accept the pinned suite {} (OPERATIONS §12)",
            suite.protocol_name()
        )
    } else {
        text
    }
}

fn describe_error(err: &NetError, node: &NodeId, not_after: Option<UnixTime>) -> String {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

    /// Finding A9-6: a client pinned to the hybrid suite, refused by an agent that does not
    /// accept it, is told so, not only that its key is not authorized.
    #[test]
    fn a_refusal_names_the_pinned_hybrid_suite() {
        let node = NodeId::try_from("web-01").unwrap();
        for err in [
            NetError::StreamClosed(CloseReason::Unauthorized),
            // An agent older than PQ-1 sees an invalid handshake.
            NetError::StreamClosed(CloseReason::ProtocolViolation),
        ] {
            let text = describe(&err, &node, None, HFS);
            assert!(
                text.contains("does not accept the pinned suite")
                    && text.contains(HFS.protocol_name())
                    && text.contains("OPERATIONS"),
                "{text}"
            );
        }
    }

    /// Finding A11-4: what is temporary exits 75, a definitive answer 1.
    #[test]
    fn temporary_failures_exit_with_tempfail() {
        for err in [
            NetError::Deadline(std::time::Duration::from_secs(8)),
            NetError::Io(std::io::ErrorKind::ConnectionRefused.into()),
            NetError::Timeout("handshake"),
            NetError::Closed,
            NetError::Rejected(RejectReason::NodeOffline),
            NetError::Rejected(RejectReason::RateLimited),
            NetError::StreamClosed(CloseReason::Drained),
        ] {
            assert_eq!(exit_code(&err), EXIT_TEMPFAIL, "{err:?}");
        }
        for err in [
            NetError::Rejected(RejectReason::NotAuthorized),
            NetError::Rejected(RejectReason::UnknownNode),
            NetError::StreamClosed(CloseReason::Unauthorized),
            NetError::Protocol("unexpected frame"),
        ] {
            assert_eq!(exit_code(&err), 1, "{err:?}");
        }
    }

    /// With the classical suite the messages stay as they were.
    #[test]
    fn a_classical_refusal_does_not_mention_suites() {
        let node = NodeId::try_from("web-01").unwrap();
        let text = describe(
            &NetError::StreamClosed(CloseReason::Unauthorized),
            &node,
            None,
            HandshakeSuite::NoiseIk25519,
        );
        assert_eq!(
            text,
            "access denied by the agent of web-01 (client key not authorized there)"
        );
    }
}
