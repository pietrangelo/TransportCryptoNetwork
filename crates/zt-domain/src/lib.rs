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

pub mod cert;
mod clients;
mod crypto;
mod error;
mod events;
pub mod flow;
mod frame;
mod ids;
pub mod limits;
mod payload;
mod policy;
pub mod trust;

pub use cert::{
    CertBody, CertClaims, CertFormatError, CertKey, CertRef, CertRejection, CertScope, CertSerial,
    ParsedCert, UnixTime, decode_certificate,
};
pub use clients::AuthorizedClients;
pub use crypto::{AuthToken, Fingerprint};
pub use error::DomainError;
pub use events::{AuthFailureReason, DomainEvent};
pub use frame::{CloseReason, Credit, Frame, FrameKind, RejectReason};
pub use ids::{NodeId, SessionId, StreamId};
pub use payload::FramePayload;
pub use policy::{
    AccessPolicy, Admission, AllowedNodes, ClientCredential, ClientGrant, MAX_AGENT_KEYS, PeerRole,
};
pub use trust::{Authority, CertTrust, Revocations, TrustedCaKey};
