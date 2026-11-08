//! # zt-crypto
//!
//! Adapter crittografico di TCN.
//!
//! - [`Identity`] / [`PublicKey`]: identità a lungo termine Ed25519. Per Noise se ne usa la
//!   forma X25519 (mappa birazionale Edwards → Montgomery), così una sola chiave per nodo
//!   basta per whitelist, fingerprint e handshake.
//! - [`noise`]: handshake `Noise_IK_25519_ChaChaPoly_BLAKE2s` **sans-IO** con typestate:
//!   un [`noise::Transport`] esiste solo dopo un handshake completato e, lato responder,
//!   solo dopo una decisione esplicita di autorizzazione.
#![forbid(unsafe_code)]

pub mod cert;
mod error;
mod identity;
mod keyring;
pub mod noise;

pub use cert::{
    CERT_FILE_PREFIX, CaSigningKey, cert_key, decode_certificate_text, encode_certificate_text,
    sign_certificate, trusted_ca_key, verify_certificate,
};
pub use error::CryptoError;
pub use identity::{Identity, PublicKey, fingerprint_of_x25519};
pub use keyring::Keyring;
