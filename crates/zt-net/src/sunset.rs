//! Phase 7, PQ-SUNSET (OPERATIONS §19; analysis/pq.md PQ-5): the `pq_only` profile and the
//! report of the classical paths a configuration still accepts.
//!
//! Retiring the classical-only paths is a **configuration** step, never a new default: an
//! empty `relay.toml`, an agent without flags and a `client.toml` without `pq_only` keep
//! accepting the classical suite, so a mixed fleet keeps working. The profile only refuses, at
//! load time (startup, `check` and every reload), a setting that would still accept:
//!
//! - a suite other than the hybrid IK suite. `IKhfs` gives hybrid forward secrecy but
//!   classical authentication, and a role in `require_hybrid_identity` cannot pass it anyway;
//! - a v1 identity: every role in `require_hybrid_identity`, so every pinned key is a v2 key;
//! - a v1 certificate: composite (v2) CA keys only, and on the client a certificate v2 bound
//!   to its hybrid identity.

use zt_domain::trust::CertTrust;
use zt_domain::{AcceptedSuites, AccessPolicy, AnyCertBody, AuthorizedClients, HandshakeSuite};

use crate::RelayEndpoint;
use crate::config::{CertificateFile, ClientSettings, ConfigError, RelaySettings};

/// The one suite the profile accepts: hybrid key exchange **and** hybrid authentication.
pub const PQ_ONLY_SUITE: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;

fn refuse(origin: &str, reason: String) -> ConfigError {
    ConfigError::PqOnly {
        path: origin.into(),
        reason,
    }
}

/// The suites of `set` the profile does not accept, by name.
fn classical_suites(set: AcceptedSuites) -> Vec<&'static str> {
    set.iter()
        .filter(|s| !s.requires_hybrid_identity())
        .map(HandshakeSuite::protocol_name)
        .collect()
}

/// `Ok` if `set` holds the hybrid IK suite only.
///
/// # Errors
/// [`ConfigError::PqOnly`] naming the other suites.
pub fn check_suites(origin: &str, entry: &str, set: AcceptedSuites) -> Result<(), ConfigError> {
    let classical = classical_suites(set);
    if classical.is_empty() {
        Ok(())
    } else {
        Err(refuse(
            origin,
            format!(
                "{entry} accepts {}; only {} is allowed",
                classical.join(", "),
                PQ_ONLY_SUITE.protocol_name()
            ),
        ))
    }
}

/// `Ok` if the pin `suite` is the hybrid IK suite.
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_suite(origin: &str, entry: &str, suite: HandshakeSuite) -> Result<(), ConfigError> {
    if suite.requires_hybrid_identity() {
        Ok(())
    } else {
        Err(refuse(
            origin,
            format!(
                "{entry} is pinned to {}; only {} is allowed",
                suite.protocol_name(),
                PQ_ONLY_SUITE.protocol_name()
            ),
        ))
    }
}

/// The pinned CA keys that sign certificates v1, as `authority name`.
fn v1_authorities(trust: &CertTrust) -> Vec<String> {
    trust
        .authorities()
        .filter(|a| a.keys().iter().any(|k| k.version() == 1))
        .map(|a| a.name().to_string())
        .collect()
}

fn check_trust(origin: &str, trust: &CertTrust) -> Result<(), ConfigError> {
    let v1 = v1_authorities(trust);
    if v1.is_empty() {
        Ok(())
    } else {
        Err(refuse(
            origin,
            format!(
                "authority {} pins a v1 (Ed25519) CA key; only composite (tcn-ca-pub-v2) keys are allowed",
                v1.join(", ")
            ),
        ))
    }
}

/// The relay policy under the profile: `require_hybrid_identity = ["agents", "clients"]` and
/// composite CA keys only.
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_policy(origin: &str, policy: &AccessPolicy) -> Result<(), ConfigError> {
    let required = policy.hybrid_requirement();
    let missing: Vec<&str> = [
        ("agents", required.agents()),
        ("clients", required.clients()),
    ]
    .into_iter()
    .filter(|(_, on)| !on)
    .map(|(role, _)| role)
    .collect();
    if !missing.is_empty() {
        return Err(refuse(
            origin,
            format!(
                "require_hybrid_identity must name agents and clients (missing: {})",
                missing.join(", ")
            ),
        ));
    }
    check_trust(origin, policy.cert_trust())
}

/// The agent's `clients.toml` under the profile: `require_hybrid_identity = ["clients"]` and
/// composite CA keys only.
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_authorized_clients(
    origin: &str,
    clients: &AuthorizedClients,
) -> Result<(), ConfigError> {
    if !clients.requires_hybrid_identity() {
        return Err(refuse(
            origin,
            "require_hybrid_identity must name clients".into(),
        ));
    }
    check_trust(origin, clients.cert_trust())
}

/// The agent's suites under the profile: every `--relay-suite` and `--accept-client-suites`
/// the hybrid IK suite.
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_agent_suites(
    relays: &[RelayEndpoint],
    client_suites: AcceptedSuites,
) -> Result<(), ConfigError> {
    for relay in relays {
        check_suite("--relay-suite", &relay.address, relay.suite)?;
    }
    check_suites(
        "--accept-client-suites",
        "the end-to-end channel",
        client_suites,
    )
}

/// The client's certificate under the profile: a certificate v2 bound to a hybrid identity.
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_certificate(origin: &str, cert: &CertificateFile) -> Result<(), ConfigError> {
    match &cert.body {
        AnyCertBody::V2(body) if body.subject().hybrid().is_some() => Ok(()),
        AnyCertBody::V2(_) => Err(refuse(
            origin,
            "the certificate v2 is bound to the classical identity only; ask the CA for one \
             bound to the fingerprint v2 (zt-ca issue --subject tcn-pub-v2:…)"
                .into(),
        )),
        AnyCertBody::V1(_) => Err(refuse(
            origin,
            "a certificate v1 is not allowed; ask the CA for a certificate v2 bound to the \
             fingerprint v2"
                .into(),
        )),
    }
}

/// The client settings under the profile: every relay and every node pinned to the hybrid
/// IK suite (a node without `suite` is pinned to the classical default).
///
/// # Errors
/// [`ConfigError::PqOnly`].
pub fn check_client(origin: &str, settings: &ClientSettings) -> Result<(), ConfigError> {
    for relay in &settings.relays {
        check_suite(origin, &format!("relay {}", relay.address), relay.suite)?;
    }
    let mut nodes: Vec<_> = settings.nodes.keys().collect();
    nodes.sort();
    for node in nodes {
        let suite = settings
            .node_suites
            .get(node)
            .copied()
            .unwrap_or(HandshakeSuite::NoiseIk25519);
        check_suite(origin, &format!("node {node}"), suite)?;
    }
    Ok(())
}

fn report_suites(out: &mut Vec<String>, what: &str, set: AcceptedSuites) {
    let classical = classical_suites(set);
    if !classical.is_empty() {
        out.push(format!("{what}: {}", classical.join(", ")));
    }
}

fn report_trust(out: &mut Vec<String>, trust: &CertTrust) {
    for name in v1_authorities(trust) {
        out.push(format!(
            "authority {name}: certificates v1 (Ed25519 CA key)"
        ));
    }
}

/// The classical paths the relay's configuration still accepts, one line each; empty for
/// the end state of OPERATIONS §19. `check` prints them.
#[must_use]
pub fn relay_report(settings: &RelaySettings, policy: &AccessPolicy) -> Vec<String> {
    let mut out = Vec::new();
    report_suites(&mut out, "agent suites", settings.suites.agents);
    report_suites(&mut out, "client suites", settings.suites.clients);
    let required = policy.hybrid_requirement();
    if !required.agents() {
        out.push("agents: v1 identities (require_hybrid_identity lacks agents)".into());
    }
    if !required.clients() {
        out.push("clients: v1 identities (require_hybrid_identity lacks clients)".into());
    }
    report_trust(&mut out, policy.cert_trust());
    out
}

/// The classical paths the agent's configuration still accepts.
#[must_use]
pub fn agent_report(
    relays: &[RelayEndpoint],
    client_suites: AcceptedSuites,
    clients: &AuthorizedClients,
) -> Vec<String> {
    let mut out = Vec::new();
    for relay in relays {
        report_suites(
            &mut out,
            &format!("relay {}", relay.address),
            AcceptedSuites::only(relay.suite),
        );
    }
    report_suites(&mut out, "end-to-end suites", client_suites);
    if !clients.requires_hybrid_identity() {
        out.push("clients: v1 identities (require_hybrid_identity lacks clients)".into());
    }
    report_trust(&mut out, clients.cert_trust());
    out
}

/// What `check` prints after the digests: under the profile one line saying so, otherwise
/// one `classical still accepted:` line per path of `report` (nothing when there is none).
///
/// # Errors
/// A write error.
pub fn write_report(
    out: &mut impl std::io::Write,
    pq_only: bool,
    report: &[String],
) -> std::io::Result<()> {
    if pq_only {
        return writeln!(out, "pq-only profile in force (OPERATIONS §19)");
    }
    for line in report {
        writeln!(out, "classical still accepted: {line}")?;
    }
    Ok(())
}

/// The profile in force and the classical paths a running process still accepts, in the
/// audit log at startup and after every applied reload (review 0014, A14-4), so that the
/// journal shows what `check` shows: `pq_only_profile` with `role`, `pq_only` and the number
/// of `classical_paths`, then one `classical_paths_accepted` line per path of `report` (none
/// under the profile, whose checks refuse every one of them).
pub fn log_profile(role: &'static str, pq_only: bool, report: &[String]) {
    tracing::info!(
        target: "zt_audit",
        event_kind = "pq_only_profile",
        role,
        pq_only,
        classical_paths = report.len(),
        "pq-only profile (OPERATIONS §19)"
    );
    for path in report {
        tracing::info!(
            target: "zt_audit",
            event_kind = "classical_paths_accepted",
            role,
            path = %path,
            "classical path still accepted"
        );
    }
}

/// The value of the agent's `--pq-only` (or `TCN_PQ_ONLY`), as an operator writes it in a
/// drop-in or in `agent.env`: `true`, `1`, `yes`, `on` or `false`, `0`, `no`, `off`, in any
/// case (review 0014, A14-2).
///
/// # Errors
/// [`ConfigError::PqOnly`] for any other value, the empty one included: the setting of a
/// security profile is never guessed, and the agent exits 78 instead of starting without it.
pub fn parse_pq_only(origin: &str, value: &str) -> Result<bool, ConfigError> {
    const ON: [&str; 4] = ["true", "1", "yes", "on"];
    const OFF: [&str; 4] = ["false", "0", "no", "off"];
    if ON.iter().any(|v| v.eq_ignore_ascii_case(value)) {
        Ok(true)
    } else if OFF.iter().any(|v| v.eq_ignore_ascii_case(value)) {
        Ok(false)
    } else {
        Err(refuse(
            origin,
            format!(
                "invalid value {:?}: use true or false (also 1/0, yes/no, on/off)",
                value.chars().take(32).collect::<String>()
            ),
        ))
    }
}
