//! # zt-crypto
//!
//! Cryptographic adapter of TCN.
//!
//! - [`Identity`] / [`PublicKey`]: long-term Ed25519 identity. For Noise its X25519 form is
//!   used (birational map Edwards → Montgomery), so a single key per node suffices for the
//!   whitelist, fingerprints and handshake.
//! - [`noise`]: `Noise_IK_25519_ChaChaPoly_BLAKE2s` handshake and, end to end, the hybrid
//!   `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s` (PQ-1), **sans-IO** with typestate: a
//!   [`noise::Transport`] exists only after a completed handshake and, on the responder side,
//!   only after an explicit authorization decision.
//! - [`kem`]: the KEM provider trait and ML-KEM-768 (libcrux), which the hybrid suite plugs
//!   into the vendored `snow` through a resolver.
#![forbid(unsafe_code)]

pub mod cert;
mod error;
mod hybrid;
mod identity;
pub mod kem;
mod keyring;
pub mod mldsa;
pub mod noise;
mod resolver;

pub use cert::{
    CERT_FILE_PREFIX, CERT_FILE_PREFIX_V2, CaSigningKey, CompositeCaPublicKey,
    CompositeCaSigningKey, cert_key, decode_certificate_text, encode_certificate_text,
    sign_certificate, sign_certificate_v2, trusted_ca_key, trusted_composite_ca_key,
    verify_certificate, verify_certificate_hybrid,
};
pub use error::CryptoError;
pub use hybrid::{HybridPublicKey, PeerKey, hybrid_fingerprint_of};
pub use identity::{Identity, PublicKey, fingerprint_of_x25519};
pub use keyring::Keyring;
