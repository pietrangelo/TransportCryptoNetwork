use crate::cert::{CertRef, CertRejection};
use crate::crypto::Fingerprint;
use crate::frame::CloseReason;
use crate::ids::{NodeId, SessionId};

/// Perché un tentativo di autenticazione è fallito.
///
/// Usato negli audit log: abbastanza dettagliato per l'investigazione, mai il materiale
/// crittografico in sé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthFailureReason {
    /// Handshake Noise non completato (chiave errata, messaggio corrotto, timeout).
    HandshakeFailed,
    /// Chiave valida ma assente dalla whitelist.
    UnknownPeer,
    /// L'agent ha dichiarato un `NodeId` non associato alla sua chiave.
    NodeIdMismatch,
    /// Troppi tentativi dallo stesso indirizzo.
    RateLimited,
    /// La chiave è nella denylist (`keys`, PROTOCOL §15.8), con qualsiasi credenziale.
    KeyRevoked,
    /// Il certificato presentato non è stato accettato (PROTOCOL §15.4).
    Certificate(CertRejection),
}

/// Fatti significativi del dominio, emessi dai casi d'uso e consumati dagli adapter
/// (audit log via `tracing`, metriche).
///
/// Gli eventi non contengono timestamp né indirizzi di rete: li aggiunge l'adapter che li
/// registra, perché il dominio non ha orologio né I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainEvent {
    /// Un agent si è autenticato e registrato presso il relay.
    AgentRegistered {
        /// Il nome logico del nodo.
        node: NodeId,
        /// L'identità crittografica dell'agent.
        fingerprint: Fingerprint,
    },
    /// Una sessione client→nodo è stata autorizzata e aperta.
    SessionEstablished {
        /// La sessione.
        session: SessionId,
        /// L'identità del client.
        client: Fingerprint,
        /// Il nodo di destinazione.
        target: NodeId,
        /// Il certificato che ha autorizzato il client, se non è la whitelist.
        certificate: Option<CertRef>,
    },
    /// Un tentativo di autenticazione è fallito.
    AuthenticationFailed {
        /// L'impronta del peer, se l'handshake è arrivato abbastanza avanti da conoscerla.
        peer: Option<Fingerprint>,
        /// Il motivo.
        reason: AuthFailureReason,
    },
    /// Un client autenticato ha chiesto un nodo che la policy non gli concede.
    AccessDenied {
        /// L'identità del client.
        client: Fingerprint,
        /// Il nodo richiesto.
        target: NodeId,
        /// Il certificato del client, se non è la whitelist.
        certificate: Option<CertRef>,
    },
    /// Un peer ha violato il protocollo e la sua connessione è stata chiusa.
    ProtocolViolation {
        /// L'identità del peer.
        peer: Fingerprint,
        /// Che cosa ha violato (testo statico, mai dati ricevuti).
        rule: &'static str,
    },
    /// Una sessione è terminata e le sue risorse sono state rilasciate.
    ConnectionDrained {
        /// La sessione.
        session: SessionId,
        /// Il motivo.
        reason: CloseReason,
    },
    /// Una nuova policy ha tolto a un peer il ruolo o l'accesso a un nodo: le sue sessioni
    /// (tutte, o solo quelle verso `target`) sono state chiuse.
    AccessRevoked {
        /// L'identità revocata.
        peer: Fingerprint,
        /// Il nodo non più concesso; `None` se il peer ha perso il proprio ruolo.
        target: Option<NodeId>,
        /// Il certificato del client, se non è la whitelist.
        certificate: Option<CertRef>,
    },
    /// Una connessione autorizzata da un certificato è stata chiusa alla scadenza
    /// (PROTOCOL §15.7).
    CertificateExpired {
        /// L'identità del client.
        peer: Fingerprint,
        /// Il certificato scaduto.
        certificate: CertRef,
    },
}

impl DomainEvent {
    /// Nome stabile dell'evento, in `snake_case`: è il campo `event_kind` dell'audit log e non
    /// dipende dal formato `Debug`.
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

    /// `true` per gli eventi che meritano attenzione (livello `WARN` nell'audit log).
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
