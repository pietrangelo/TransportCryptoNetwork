//! # zt-proto
//!
//! Adapter del wire format di TCN: traduce byte ⇄ [`Frame`](zt_domain::Frame) di dominio.
//!
//! Il cuore è **sans-IO** ([`FrameDecoder`], [`encode`]): lavora su buffer in memoria, non
//! conosce socket né runtime, ed è quindi testabile in modo deterministico. L'adapter per
//! `tokio-util` (feature `codec`) è un sottile strato sopra di esso.
//!
//! La specifica del formato è in `docs/PROTOCOL.md`.
#![forbid(unsafe_code)]

#[cfg(feature = "codec")]
pub mod codec;
mod decoder;
mod encoder;
mod error;
pub mod wire;

pub use decoder::FrameDecoder;
pub use encoder::{encode, encoded_len};
pub use error::DecodeError;
