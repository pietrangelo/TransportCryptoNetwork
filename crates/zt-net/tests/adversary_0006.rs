//! Adversary review 0006 (Fase 6, certificati client brevi): le ipotesi smentite o accettate,
//! tenute come test di regressione (docs/adversary/0006-client-certs.md). I finding corretti
//! hanno i loro test accanto al codice che li corregge.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    Ca, Captured, Lab, agent_clients, assert_alive, ended, next_serial, node, now_secs,
    relay_policy, scope, trust,
};
use zt_crypto::{CaSigningKey, Identity, verify_certificate};
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{AllowedNodes, CertRejection, CloseReason};
use zt_net::NetError;

/// Relay compromesso o non aggiornato: il relay ammette il client dalla whitelist (nessuna
/// scadenza in sessione sul relay), l'agent solo con il certificato. L'agent chiude da solo la
/// sessione alla scadenza (PROTOCOL §15.7): `Close Unauthorized` e `certificate_expired`.
#[tokio::test(flavor = "current_thread")]
async fn the_agent_alone_cuts_a_certified_session_at_not_after() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new();
    let alice = Arc::new(Identity::generate().unwrap());
    let alice_fp = alice.fingerprint();
    let lab = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[alice_fp],
                trust(&[(&ca, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&ca, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let now = now_secs();
    let (cert, _) = ca.issue_at(&alice.public_key(), scope(&["web-01"]), now - 60, now + 4);
    let (mut app, task) = lab.session(&alice, Some(&cert)).await.unwrap();
    assert_alive(&mut app).await;
    let r = ended(task, Duration::from_secs(70)).await;
    assert!(
        matches!(r, Err(NetError::StreamClosed(CloseReason::Unauthorized))),
        "{r:?}"
    );
    assert!(now_secs() >= now + 4);
    assert!(
        !log.events("certificate_expired").is_empty(),
        "{}",
        log.text()
    );
}

/// Bypass della denylist con l'esadecimale maiuscolo nella serie o con la chiave `-P`:
/// entrambe le voci revocano ancora.
#[test]
fn uppercase_serials_and_negated_keys_still_revoke() {
    let serial = next_serial();
    let victim = Identity::generate().unwrap();
    let mut neg = victim.public_key().to_bytes();
    neg[31] ^= 0x80; // -P: stessa y, segno di x invertito
    let text = format!(
        "serials = [\"{}\"]\nkeys = [\"{}\"]\n",
        serial.to_string().to_uppercase(),
        hex::encode(neg).to_uppercase()
    );
    let r = zt_net::config::parse_revocations("revoked.toml", &text).unwrap();
    assert!(r.is_serial_revoked(&serial));
    assert!(r.is_key_revoked(&victim.fingerprint()));
}

/// Due voci `[[authorities]]` (o due chiavi della stessa voce) con `P` e `-P`, stessa
/// fingerprint e byte diversi, per avere due ambiti con la stessa CA: rifiutate.
#[test]
fn authorities_with_p_and_minus_p_are_refused() {
    let ca = CaSigningKey::generate().unwrap().public_key();
    let mut neg = ca.to_bytes();
    neg[31] ^= 0x80;
    let two = format!(
        "[[authorities]]\nname = \"a\"\npublic_key = \"{ca}\"\nallow = [\"web-01\"]\n\
         [[authorities]]\nname = \"b\"\npublic_key = \"{}\"\nallow = [\"*\"]\n",
        hex::encode(neg)
    );
    assert!(zt_net::config::parse_policy("p.toml", &two).is_err());
    let one = format!(
        "[[authorities]]\nname = \"a\"\npublic_keys = [\"{ca}\", \"{}\"]\nallow = [\"*\"]\n",
        hex::encode(neg)
    );
    assert!(zt_net::config::parse_policy("p.toml", &one).is_err());
}

/// Rotazione della CA: tolta la chiave vecchia da una voce con due chiavi, i certificati della
/// vecchia non valgono più, anche se il nome della CA resta.
#[test]
fn removing_the_old_ca_key_invalidates_its_certificates() {
    let (old, new) = (Ca::new(), Ca::new());
    let alice = Identity::generate().unwrap();
    let (cert, _) = old.issue(&alice.public_key(), scope(&["web-01"]));
    let mk = |keys: &[TrustedCaKey]| {
        let mut t = CertTrust::new();
        t.add_authority(node("ops-ca"), keys, AllowedNodes::All, 28_800)
            .unwrap();
        t.set_revocations(Revocations::default());
        t
    };
    let both = mk(&[new.trusted(), old.trusted()]);
    assert!(verify_certificate(&cert, &alice.fingerprint(), &both).is_ok());
    let only_new = mk(&[new.trusted()]);
    assert_eq!(
        verify_certificate(&cert, &alice.fingerprint(), &only_new).unwrap_err(),
        CertRejection::UnknownAuthority
    );
}

/// Accettata (fail closed, OPERATIONS §10.4): un client ancora nella whitelist che riceve un
/// certificato prima che un agent pinni la CA viene rifiutato da quell'agent.
#[test]
fn a_certificate_from_an_unpinned_ca_is_refused_even_for_a_whitelisted_client() {
    let ca = Ca::new();
    let alice = Identity::generate().unwrap();
    let (cert, _) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let mut clients = agent_clients(&[alice.fingerprint()], CertTrust::new());
    let mut t = clients.cert_trust().clone();
    t.set_revocations(Revocations::default());
    clients.set_cert_trust(t).unwrap();
    assert_eq!(
        verify_certificate(&cert, &alice.fingerprint(), clients.cert_trust()).unwrap_err(),
        CertRejection::UnknownAuthority
    );
}
