use thiserror::Error;

/// Violazione di un'invariante di dominio.
///
/// Gli errori non contengono mai il contenuto dei dati rifiutati (che potrebbe essere
/// segreto o controllato da un attaccante), solo metadati come lunghezze e posizioni.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// Il `NodeId` è vuoto.
    #[error("node id is empty")]
    NodeIdEmpty,
    /// Il `NodeId` supera la lunghezza massima.
    #[error("node id is {len} bytes, maximum is {max}")]
    NodeIdTooLong {
        /// Lunghezza ricevuta.
        len: usize,
        /// Lunghezza massima ammessa.
        max: usize,
    },
    /// Il `NodeId` contiene un byte fuori dall'alfabeto `[a-z0-9-]`.
    #[error("node id has a forbidden byte at position {position}")]
    NodeIdInvalidByte {
        /// Posizione (0-based) del primo byte non valido.
        position: usize,
    },
    /// Il `NodeId` inizia o finisce con `-`.
    #[error("node id must not start or end with '-'")]
    NodeIdHyphenAtEdge,
    /// Identificativo di sessione tutto a zero (riservato come valore sentinella).
    #[error("session id must not be all zeros")]
    SessionIdZero,
    /// Lo stream 0 è riservato al controllo della connessione.
    #[error("stream id 0 is reserved for connection control")]
    StreamIdZero,
    /// Lunghezza errata per un valore a dimensione fissa.
    #[error("{what} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// Il tipo di valore.
        what: &'static str,
        /// Lunghezza attesa.
        expected: usize,
        /// Lunghezza ricevuta.
        actual: usize,
    },
    /// Un frame `Data` non può avere payload vuoto.
    #[error("payload must not be empty")]
    PayloadEmpty,
    /// Payload oltre il limite.
    #[error("payload is {len} bytes, maximum is {max}")]
    PayloadTooLarge {
        /// Lunghezza ricevuta.
        len: usize,
        /// Lunghezza massima ammessa.
        max: usize,
    },
    /// Un aggiornamento di finestra a credito zero non ha senso ed è rifiutato.
    #[error("window credit must be greater than zero")]
    CreditZero,
    /// Codice di rifiuto sconosciuto.
    #[error("unknown reject reason code {0:#04x}")]
    UnknownRejectReason(u8),
    /// Codice di chiusura sconosciuto.
    #[error("unknown close reason code {0:#04x}")]
    UnknownCloseReason(u8),
    /// La stessa chiave compare due volte nella policy.
    #[error("peer {0} appears more than once in the access policy")]
    DuplicatePeer(crate::Fingerprint),
    /// Due agent dichiarano lo stesso nome di nodo.
    #[error("node {0} is assigned to more than one agent key")]
    DuplicateNode(crate::NodeId),
    /// Un nodo ha zero chiavi di agent, più di [`crate::MAX_AGENT_KEYS`], o chiavi ripetute.
    #[error("node {0} must have one or two distinct agent keys")]
    AgentKeys(crate::NodeId),
}
