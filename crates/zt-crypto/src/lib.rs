//! # zt-crypto
//!
//! Adapter crittografico di TCN (RED: stub, implementazione in arrivo).
#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;

use thiserror::Error;
use zt_domain::Fingerprint;

/// Errore crittografico.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// Chiave malformata.
    #[error("invalid key")]
    InvalidKey,
    /// Chiave debole.
    #[error("weak key")]
    WeakKey,
    /// Handshake fallito.
    #[error("handshake failed")]
    Handshake,
    /// Decifratura fallita.
    #[error("decrypt")]
    Decrypt,
    /// Messaggio troppo grande.
    #[error("too large")]
    MessageTooLarge,
    /// RNG.
    #[error("rng")]
    Random,
}

/// Identità (RED).
pub struct Identity;
impl Identity {
    /// RED.
    /// # Errors
    /// Sempre.
    pub fn generate() -> Result<Self, CryptoError> { Err(CryptoError::Random) }
    /// RED.
    /// # Errors
    /// Sempre.
    pub fn from_secret_hex(_s: &str) -> Result<Self, CryptoError> { Err(CryptoError::InvalidKey) }
    /// RED.
    #[must_use]
    pub fn to_secret_hex(&self) -> zeroize::Zeroizing<String> { zeroize::Zeroizing::new(String::new()) }
    /// RED.
    #[must_use]
    pub fn public_key(&self) -> PublicKey { PublicKey }
    /// RED.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint { Fingerprint::from_bytes([0; 32]) }
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Identity") }
}
/// Chiave pubblica (RED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey;
impl PublicKey {
    /// RED.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint { Fingerprint::from_bytes([0; 32]) }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("") }
}
impl FromStr for PublicKey {
    type Err = CryptoError;
    fn from_str(_s: &str) -> Result<Self, CryptoError> { Err(CryptoError::InvalidKey) }
}

/// Noise (RED).
pub mod noise {
    use super::{CryptoError, Identity, PublicKey};
    use zt_domain::Fingerprint;
    /// RED.
    pub const MAX_PLAINTEXT_LEN: usize = 65_535 - 16;
    /// RED.
    #[derive(Debug, Clone, Copy)]
    pub enum Channel { /** RED */ Outer, /** RED */ EndToEnd }
    /// RED.
    #[derive(Debug)]
    pub struct AwaitingResponse;
    /// RED.
    #[derive(Debug)]
    pub struct AuthorizationPending;
    /// RED.
    #[derive(Debug)]
    pub struct Transport;
    /// RED.
    /// # Errors
    /// Sempre.
    pub fn initiate(_l: &Identity, _r: &PublicKey, _c: Channel) -> Result<(Vec<u8>, AwaitingResponse), CryptoError> { Err(CryptoError::Handshake) }
    /// RED.
    /// # Errors
    /// Sempre.
    pub fn respond(_l: &Identity, _m: &[u8], _c: Channel) -> Result<AuthorizationPending, CryptoError> { Err(CryptoError::Handshake) }
    impl AwaitingResponse {
        /// RED.
        /// # Errors
        /// Sempre.
        pub fn complete(self, _m: &[u8]) -> Result<Transport, CryptoError> { Err(CryptoError::Handshake) }
    }
    impl AuthorizationPending {
        /// RED.
        #[must_use]
        pub fn peer(&self) -> Fingerprint { Fingerprint::from_bytes([0; 32]) }
        /// RED.
        /// # Errors
        /// Sempre.
        pub fn accept(self) -> Result<(Vec<u8>, Transport), CryptoError> { Err(CryptoError::Handshake) }
    }
    impl Transport {
        /// RED.
        #[must_use]
        pub fn peer(&self) -> Fingerprint { Fingerprint::from_bytes([0; 32]) }
        /// RED.
        /// # Errors
        /// Sempre.
        pub fn encrypt(&mut self, _p: &[u8]) -> Result<Vec<u8>, CryptoError> { Err(CryptoError::Handshake) }
        /// RED.
        /// # Errors
        /// Sempre.
        pub fn decrypt(&mut self, _c: &[u8]) -> Result<Vec<u8>, CryptoError> { Err(CryptoError::Decrypt) }
    }
}
