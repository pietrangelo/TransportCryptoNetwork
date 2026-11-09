//! # zt-proto
//!
//! TCN wire format adapter: translates bytes ⇄ domain [`Frame`](zt_domain::Frame).
//!
//! The core is **sans-IO** ([`FrameDecoder`], [`encode`]): it works on in-memory buffers, knows
//! nothing of sockets or runtimes, and is therefore deterministically testable. The adapter for
//! `tokio-util` (feature `codec`) is a thin layer on top of it.
//!
//! The format specification is in `docs/PROTOCOL.md`.
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
