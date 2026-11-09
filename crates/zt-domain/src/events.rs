use crate::cert::{CertClaims, CertRef, CertRejection};
use crate::crypto::Fingerprint;
use crate::frame::CloseReason;
use crate::ids::{NodeId, SessionId};

/// Why an authentication attempt failed.
///
/// Used in audit logs: detailed enough for investigation, never the cryptographic material
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthFailureReason {
    /// Noise handshake not completed (wrong key, corrupted message, timeout).
    HandshakeFailed,
    /// Valid key but absent from the whitelist.
    UnknownPeer,
    /// The agent declared a `NodeId` not associated with its key.
    NodeIdMismatch,
    /// Too many attempts from the same address.
    RateLimited,
    /// The key is in the denylist (`keys`, PROTOCOL §15.8), with any credential.
    KeyRevoked,
    /// The presented certificate was not accepted (PROTOCOL §15.4).
    Certificate(CertRejection),
}

impl AuthFailureReason {
    /// The certificate to report in an `authentication_failed` (PROTOCOL §15.11, finding
    /// 0006-3): only if the signature was verified (`verified` comes from `zt-crypto`) and the
    /// rejection comes from a later check (steps 7–12 of §15.4). Before the signature, the
    /// certificate's fields belong to no one: an event naming a serial always concerns a
    /// certificate truly signed by a pinned CA.
    #[must_use]
    pub fn certificate_ref(self, verified: Option<&CertClaims>) -> Option<CertRef> {
        match self {
            Self::Certificate(check) if check.after_signature() => {
                verified.map(CertClaims::reference)
            }
            _ => None,
        }
    }
}

/// Significant domain facts, emitted by the use cases and consumed by the adapters
/// (audit log via `tracing`, metrics).
///
/// Events contain neither timestamps nor network addresses: the adapter that records them adds
/// those, because the domain has no clock and no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainEvent {
    /// An agent authenticated and registered with the relay.
    AgentRegistered {
        /// The logical name of the node.
        node: NodeId,
        /// The cryptographic identity of the agent.
        fingerprint: Fingerprint,
    },
    /// A client→node session was authorized and opened.
    SessionEstablished {
        /// The session.
        session: SessionId,
        /// The identity of the client.
        client: Fingerprint,
        /// The destination node.
        target: NodeId,
        /// The certificate that authorized the client, if it is not the whitelist.
        certificate: Option<CertRef>,
    },
    /// An authentication attempt failed.
    AuthenticationFailed {
        /// The peer's fingerprint, if the handshake got far enough to know it.
        peer: Option<Fingerprint>,
        /// The reason.
        reason: AuthFailureReason,
        /// The rejected certificate, only after the signature has been verified
        /// ([`AuthFailureReason::certificate_ref`]).
        certificate: Option<CertRef>,
    },
    /// An authenticated client requested a node that the policy does not grant it.
    AccessDenied {
        /// The identity of the client.
        client: Fingerprint,
        /// The requested node.
        target: NodeId,
        /// The client's certificate, if it is not the whitelist.
        certificate: Option<CertRef>,
    },
    /// A peer violated the protocol and its connection was closed.
    ProtocolViolation {
        /// The identity of the peer.
        peer: Fingerprint,
        /// What it violated (static text, never received data).
        rule: &'static str,
    },
    /// A session ended and its resources were released.
    ConnectionDrained {
        /// The session.
        session: SessionId,
        /// The reason.
        reason: CloseReason,
    },
    /// A new policy removed a peer's role or its access to a node: its sessions
    /// (all of them, or only those towards `target`) were closed.
    AccessRevoked {
        /// The revoked identity.
        peer: Fingerprint,
        /// The node no longer granted; `None` if the peer lost its role.
        target: Option<NodeId>,
        /// The client's certificate, if it is not the whitelist.
        certificate: Option<CertRef>,
    },
    /// A connection authorized by a certificate was closed on expiry
    /// (PROTOCOL §15.7).
    CertificateExpired {
        /// The identity of the client.
        peer: Fingerprint,
        /// The expired certificate.
        certificate: CertRef,
    },
}

impl DomainEvent {
    /// Stable name of the event, in `snake_case`: it is the `event_kind` field of the audit log and
    /// does not depend on the `Debug` format.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AgentRegistered { .. } => "agent_registered",
            Self::SessionEstablished { .. } => "session_established",
            Self::AuthenticationFailed { .. } => "authentication_failed",
            Self::AccessDenied { .. } => "access_denied",
            Self::ProtocolViolation { .. } => "protocol_violation",
            Self::ConnectionDrained { .. } => "connection_drained",
            Self::AccessRevoked { .. } => "access_revoked",
            Self::CertificateExpired { .. } => "certificate_expired",
        }
    }

    /// `true` for events that deserve attention (`WARN` level in the audit log).
    #[must_use]
    pub const fn is_security_alert(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed { .. }
                | Self::AccessDenied { .. }
                | Self::ProtocolViolation { .. }
                | Self::AccessRevoked { .. }
        )
    }
}
