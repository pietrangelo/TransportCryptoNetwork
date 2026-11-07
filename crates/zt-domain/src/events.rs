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
    },
    /// Un tentativo di autenticazione è fallito.
    AuthenticationFailed {
        /// L'impronta del peer, se l'handshake è arrivato abbastanza avanti da conoscerla.
        peer: Option<Fingerprint>,
        /// Il motivo.
        reason: AuthFailureReason,
    },
    /// Una sessione è terminata e le sue risorse sono state rilasciate.
    ConnectionDrained {
        /// La sessione.
        session: SessionId,
        /// Il motivo.
        reason: CloseReason,
    },
}
