use thiserror::Error;

/// Error of the cryptographic adapter.
///
/// Deliberately poor in detail: a handshake error does not say *which* check failed, so as
/// not to offer an oracle to whoever is trying keys or messages.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Malformed key (length, hex, invalid point).
    #[error("invalid key encoding")]
    InvalidKey,
    /// Small-order public key: a DH with it would produce a predictable secret.
    #[error("weak (small-order) public key")]
    WeakKey,
    /// Noise handshake failed.
    #[error("handshake failed")]
    Handshake,
    /// Transport message not authentic, reordered or replayed.
    #[error("message authentication failed")]
    Decrypt,
    /// Plaintext over the maximum of a Noise message.
    #[error("message too large")]
    MessageTooLarge,
    /// The system random number generator is not available.
    #[error("system random generator unavailable")]
    Random,
    /// The handshake suite is not supported by this build (PROTOCOL §7.5).
    #[error("handshake suite not supported")]
    UnsupportedSuite,
    /// A certificate just signed does not verify with the fleet's verifier (finding AP-5):
    /// it is not issued.
    #[error("the new certificate failed verification after signing")]
    VerifyAfterSign,
}
