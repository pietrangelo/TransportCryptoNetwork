//! Fase 6, passo 7: client certificati su TCP reale, relay e agent veri (PROTOCOL §15.3–§15.8,
//! §15.10, §15.11).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    Ca, Captured, Lab, agent_clients, assert_alive, ended, field, now_secs, relay_policy, scope,
    trust,
};
use zt_crypto::Identity;
use zt_domain::trust::CertTrust;
use zt_domain::{AllowedNodes, CloseReason};
use zt_net::NetError;

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

/// Spec: un client che non è in nessuna whitelist arriva al nodo con il solo certificato, e
/// relay e agent lo registrano come `credential = certificate` con CA e serie.
#[tokio::test]
async fn a_certified_client_reaches_its_node_through_relay_and_agent() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let alice = id();
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (cert, serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (mut app, _task) = lab.session(&alice, Some(&cert)).await.unwrap();
    assert_alive(&mut app).await;
    assert_eq!(lab.sshd.load(Ordering::SeqCst), 1);

    let established = log.events("session_established");
    assert_eq!(established.len(), 1, "{}", log.text());
    let line = &established[0];
    assert_eq!(
        field(line, "credential").as_deref(),
        Some("certificate"),
        "{line}"
    );
    assert_eq!(field(line, "serial"), Some(serial.to_string()), "{line}");
    assert_eq!(field(line, "cert_name").as_deref(), Some("alice"), "{line}");
    assert!(field(line, "ca").is_some(), "{line}");
    assert!(line.contains("\"not_after\":"), "{line}");
    let started = log.events("e2e_session_started");
    assert_eq!(started.len(), 1, "{}", log.text());
    assert_eq!(
        field(&started[0], "credential").as_deref(),
        Some("certificate")
    );
    assert_eq!(field(&started[0], "serial"), Some(serial.to_string()));
    // Il certificato non compare mai nei log (§15.11).
    assert!(!log.text().contains(&hex::encode(&cert[..])));
}

/// Spec: con una CA pinnata, un client della whitelist senza certificato funziona come prima.
#[tokio::test]
async fn a_whitelisted_client_without_certificate_still_works() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let ansible = id();
    let fp = ansible.fingerprint();
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[fp],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[fp], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (mut app, task) = lab.session(&ansible, None).await.unwrap();
    assert_alive(&mut app).await;
    let established = log.events("session_established");
    assert_eq!(established.len(), 1, "{}", log.text());
    assert_eq!(field(&established[0], "credential").as_deref(), Some("key"));
    assert!(field(&established[0], "serial").is_none());
    // Nessuna scadenza in sessione per la whitelist.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!task.is_finished());
    assert_alive(&mut app).await;
}

/// Spec (§15.10): il primo relay non pinna la CA e tace; il client passa al secondo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certified_client_falls_back_past_a_relay_without_the_authority() {
    let ca = Ca::new();
    let alice = id();
    let lab = Lab::start(
        |agent| {
            vec![
                relay_policy(agent, &[], CertTrust::new()),
                relay_policy(agent, &[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
            ]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (cert, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (mut app, _task) = lab.session(&alice, Some(&cert)).await.unwrap();
    assert_alive(&mut app).await;
}

/// Spec (§15.7): un certificato di pochi secondi chiude la sessione alla scadenza, con
/// `Close Unauthorized` al client e `certificate_expired` nell'audit.
#[tokio::test]
async fn the_session_ends_when_the_certificate_expires() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let alice = id();
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let now = now_secs();
    let (cert, serial) = ca.issue_at(&alice.public_key(), scope(&["web-01"]), now - 60, now + 4);
    let (mut app, task) = lab.session(&alice, Some(&cert)).await.unwrap();
    assert_alive(&mut app).await;
    assert!(matches!(
        ended(task, Duration::from_secs(10)).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
    assert!(now_secs() >= now + 4, "closed before not_after");
    let expired = log.events("certificate_expired");
    assert!(!expired.is_empty(), "{}", log.text());
    assert!(
        expired
            .iter()
            .all(|l| field(l, "serial") == Some(serial.to_string())),
        "{expired:?}"
    );
    assert!(
        expired
            .iter()
            .all(|l| field(l, "peer") == Some(alice.fingerprint().to_string()))
    );
}

/// Spec (§15.8, difesa in profondità): solo l'agent riceve la denylist con la serie; la
/// sessione cade anche se il relay la permette ancora, e un altro certificato resta valido.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_revocation_of_a_serial_cuts_the_session_even_if_the_relay_still_allows_it() {
    let ca = Ca::new();
    let (alice, bob) = (id(), id());
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let (revoked_cert, serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let (bob_cert, _) = ca.issue(&bob.public_key(), scope(&["web-01"]));
    let (_app, revoked) = lab.session(&alice, Some(&revoked_cert)).await.unwrap();
    let (mut other, survivor) = lab.session(&bob, Some(&bob_cert)).await.unwrap();

    lab.clients.replace(agent_clients(
        &[],
        trust(&[(&ca, AllowedNodes::All)], &[serial], &[]),
    ));
    assert!(matches!(
        ended(revoked, Duration::from_secs(5)).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
    assert_alive(&mut other).await;
    assert!(!survivor.is_finished());
    // Una nuova sessione con la serie revocata è rifiutata dall'agent.
    assert!(matches!(
        lab.refused(&alice, Some(&revoked_cert)).await,
        Err(NetError::StreamClosed(CloseReason::Unauthorized))
    ));
}
