use thiserror::Error;

/// Errore dell'adapter crittografico.
///
/// Volutamente povero di dettagli: un errore di handshake non dice *quale* controllo è
/// fallito, per non offrire un oracolo a chi prova chiavi o messaggi.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Chiave malformata (lunghezza, esadecimale, punto non valido).
    #[error("invalid key encoding")]
    InvalidKey,
    /// Chiave pubblica di ordine piccolo: un DH con essa produrrebbe un segreto prevedibile.
    #[error("weak (small-order) public key")]
    WeakKey,
    /// Handshake Noise fallito.
    #[error("handshake failed")]
    Handshake,
    /// Messaggio di trasporto non autentico, riordinato o ripetuto.
    #[error("message authentication failed")]
    Decrypt,
    /// Plaintext oltre il massimo di un messaggio Noise.
    #[error("message too large")]
    MessageTooLarge,
    /// Il generatore di numeri casuali del sistema non è disponibile.
    #[error("system random generator unavailable")]
    Random,
}
