//! Nomi stabili degli eventi di audit (Fase 4): sono l'interfaccia verso SIEM e alerting, quindi
//! non devono dipendere dal formato `Debug` di Rust.
#![allow(clippy::unwrap_used)]

use zt_domain::{AuthFailureReason, CloseReason, DomainEvent, Fingerprint, NodeId, SessionId};

#[test]
fn every_event_has_a_stable_snake_case_kind() {
    let fp = Fingerprint::from_bytes([1; 32]);
    let node = NodeId::try_from("web-01").unwrap();
    let session = SessionId::from_bytes([2; 16]).unwrap();
    let cases = [
        (
            DomainEvent::AgentRegistered {
                node: node.clone(),
                fingerprint: fp,
            },
            "agent_registered",
        ),
        (
            DomainEvent::SessionEstablished {
                session,
                client: fp,
                target: node.clone(),
                certificate: None,
            },
            "session_established",
        ),
        (
            DomainEvent::AuthenticationFailed {
                peer: None,
                reason: AuthFailureReason::HandshakeFailed,
                certificate: None,
            },
            "authentication_failed",
        ),
        (
            DomainEvent::AccessDenied {
                client: fp,
                target: node.clone(),
                certificate: None,
            },
            "access_denied",
        ),
        (
            DomainEvent::ProtocolViolation {
                peer: fp,
                rule: "x",
            },
            "protocol_violation",
        ),
        (
            DomainEvent::ConnectionDrained {
                session,
                reason: CloseReason::Normal,
            },
            "connection_drained",
        ),
        (
            DomainEvent::AccessRevoked {
                peer: fp,
                target: Some(node),
                certificate: None,
            },
            "access_revoked",
        ),
    ];
    for (event, kind) in cases {
        assert_eq!(event.kind(), kind);
    }
}

#[test]
fn security_relevant_events_are_flagged() {
    let fp = Fingerprint::from_bytes([1; 32]);
    assert!(
        DomainEvent::AccessRevoked {
            peer: fp,
            target: None,
            certificate: None,
        }
        .is_security_alert()
    );
    assert!(
        DomainEvent::ProtocolViolation {
            peer: fp,
            rule: "x"
        }
        .is_security_alert()
    );
    assert!(
        !DomainEvent::ConnectionDrained {
            session: SessionId::from_bytes([2; 16]).unwrap(),
            reason: CloseReason::Normal
        }
        .is_security_alert()
    );
}
