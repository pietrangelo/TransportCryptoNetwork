//! # zt-application
//!
//! Application layer di TCN: i casi d'uso, come macchine a stati **sans-IO**.
//!
//! - [`relay::RelayCore`]: autorizzazione, routing degli stream, controllo di flusso e limiti
//!   del relay. Riceve eventi ([`relay::Input`]) e produce azioni ([`relay::Output`]); gli
//!   adapter di rete eseguono le azioni.
//! - [`ratelimit`]: token bucket con orologio iniettato.
//!
//! Il tempo entra solo come parametro `now: Instant`; la casualità solo tramite la porta
//! [`relay::SessionIds`]. Tutto è quindi deterministico nei test.
#![forbid(unsafe_code)]

pub mod ratelimit;
pub mod relay;
