//! # zt-domain
//!
//! Il *domain core* di TCN (Transport Crypto Network).
//!
//! Questo crate è volutamente **puro**: nessun runtime async, nessun socket, nessun file.
//! Contiene soltanto concetti del dominio e le loro invarianti:
//!
//! - **Value object** ([`NodeId`], [`SessionId`], [`StreamId`], [`Fingerprint`], [`AuthToken`],
//!   [`FramePayload`], [`Credit`]): si costruiscono solo tramite `TryFrom`/factory che validano
//!   l'input, quindi un valore esistente è per costruzione un valore valido.
//! - **Messaggi di protocollo** ([`Frame`]): un enum immutabile in cui ogni variante porta solo
//!   value object già validati. Un frame malformato non è rappresentabile.
//! - **Eventi di dominio** ([`DomainEvent`]) ed **errori** ([`DomainError`]).
//!
//! La traduzione da/verso byte vive in `zt-proto` (adapter), non qui.
#![forbid(unsafe_code)]

mod crypto;
mod error;
mod events;
pub mod flow;
mod frame;
mod ids;
pub mod limits;
mod payload;
mod policy;

pub use crypto::{AuthToken, Fingerprint};
pub use error::DomainError;
pub use events::{AuthFailureReason, DomainEvent};
pub use frame::{CloseReason, Credit, Frame, FrameKind, RejectReason};
pub use ids::{NodeId, SessionId, StreamId};
pub use payload::FramePayload;
pub use policy::{AccessPolicy, AllowedNodes, ClientGrant, PeerRole};
