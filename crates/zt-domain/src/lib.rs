//! # zt-domain
//!
//! The *domain core* of TCN (Transport Crypto Network).
//!
//! This crate is deliberately **pure**: no async runtime, no sockets, no files.
//! It contains only domain concepts and their invariants:
//!
//! - **Value objects** ([`NodeId`], [`SessionId`], [`StreamId`], [`Fingerprint`], [`AuthToken`],
//!   [`FramePayload`], [`Credit`]): constructed only through `TryFrom`/factories that validate
//!   the input, so any existing value is valid by construction.
//! - **Protocol messages** ([`Frame`]): an immutable enum in which every variant carries only
//!   already-validated value objects. A malformed frame is unrepresentable.
//! - **Domain events** ([`DomainEvent`]) and **errors** ([`DomainError`]).
//!
//! Translation to/from bytes lives in `zt-proto` (the adapter), not here.
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
pub mod suite;
pub mod trust;

pub use cert::{
    AnyCertBody, AnyParsedCert, CaFingerprint, CaKeyRef, CertBody, CertBodyV2, CertClaims,
    CertFormatError, CertKey, CertRef, CertRejection, CertScope, CertSerial, CertSubject,
    ParsedCert, ParsedCertV2, UnixTime, decode_any_certificate, decode_certificate,
    decode_certificate_v2,
};
pub use clients::AuthorizedClients;
pub use crypto::{AuthToken, Fingerprint, FingerprintText, HybridFingerprint};
pub use error::DomainError;
pub use events::{AuthFailureReason, DomainEvent};
pub use frame::{CloseReason, Credit, Frame, FrameKind, RejectReason};
pub use ids::{NodeId, SessionId, StreamId};
pub use payload::FramePayload;
pub use policy::{
    AccessPolicy, Admission, AllowedNodes, ClientCredential, ClientGrant, MAX_AGENT_KEYS, PeerRole,
};
pub use suite::{
    AcceptedSuites, HandshakeChannel, HandshakeSuite, InitiatorRole, SuiteError, SuitePolicy,
};
pub use trust::{Authority, CertTrust, CompositeCaPin, Revocations, TrustedCaKey};
