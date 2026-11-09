//! # zt-application
//!
//! Application layer of TCN: the use cases, as **sans-IO** state machines.
//!
//! - [`relay::RelayCore`]: authorization, stream routing, flow control and limits of the
//!   relay. It receives events ([`relay::Input`]) and produces actions ([`relay::Output`]);
//!   the network adapters execute the actions.
//! - [`ratelimit`]: token bucket with an injected clock.
//!
//! Time enters only as a `now: Instant` parameter; randomness only through the
//! [`relay::SessionIds`] port. Everything is therefore deterministic in tests.
#![forbid(unsafe_code)]

pub mod ratelimit;
pub mod relay;
