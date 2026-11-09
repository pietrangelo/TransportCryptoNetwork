//! PQ-AUTH, certificates v2 on the network (PROTOCOL §15.14; OPERATIONS §10.8):
//! composite CA keys in `[[authorities]]`, certificate v2 files, and clients admitted with a
//! v2 certificate through relay and agent, with the `cert_version` audit field. Migration is
//! the two-key `[[authorities]]` rotation: v1 certificates pass only while a v1 key is pinned.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::{Ca, Captured, Lab, agent_clients, assert_alive, field, relay_policy, scope, trust};
use zt_crypto::{CompositeCaSigningKey, Identity, encode_certificate_text};
use zt_domain::AllowedNodes;
use zt_domain::trust::{CertTrust, TrustedCaKey};
use zt_net::config::{ConfigError, parse_certificate_file, parse_policy};

fn id() -> Arc<Identity> {
    Arc::new(Identity::generate().unwrap())
}

fn agent_key() -> String {
    Identity::generate().unwrap().public_key().to_string()
}

fn policy_with(keys: &[String]) -> String {
    let list: Vec<String> = keys.iter().map(|k| format!("\"{k}\"")).collect();
    format!(
        "[[agents]]\nnode = \"web-01\"\npublic_key = \"{}\"\n\n[[authorities]]\nname = \"ops\"\npublic_keys = [{}]\nallow = [\"*\"]\n",
        agent_key(),
        list.join(", ")
    )
}

/// Spec: `[[authorities]]` pins a composite key by its `tcn-ca-pub-v2:` text, alone or next to
/// the v1 key it replaces; the pin carries the algorithm.
#[test]
fn authorities_accept_composite_keys_and_mixed_rotation() {
    let v2 = CompositeCaSigningKey::generate().unwrap().public_key();
    let v1 = Identity::generate().unwrap().public_key();
    let policy = parse_policy("p", &policy_with(&[v2.to_string()])).unwrap();
    let authority = policy.cert_trust().authorities().next().unwrap();
    assert_eq!(authority.keys().len(), 1);
    assert_eq!(authority.keys()[0].version(), 2);
    assert_eq!(authority.keys()[0].fingerprint, v2.fingerprint());
    let rotating = parse_policy("p", &policy_with(&[v2.to_string(), v1.to_string()])).unwrap();
    let authority = rotating.cert_trust().authorities().next().unwrap();
    let mut versions: Vec<u8> = authority.keys().iter().map(TrustedCaKey::version).collect();
    versions.sort_unstable();
    assert_eq!(versions, vec![1, 2]);
    assert_eq!(rotating.cert_trust().rotations_pending().count(), 1);
}

/// Attack (AP-13, Parsing): a composite key reusing the v1 key of the same entry, a malformed
/// composite text and a truncated one are load errors that never echo the key.
#[test]
fn bad_composite_pins_are_refused_without_echo() {
    let ca = CompositeCaSigningKey::generate().unwrap();
    let v2 = ca.public_key();
    let reused = v2.ed25519().to_string();
    assert!(matches!(
        parse_policy("p", &policy_with(&[v2.to_string(), reused])),
        Err(ConfigError::Domain { .. })
    ));
    let text = v2.to_string();
    for bad in [
        text[..text.len() - 2].to_owned(),
        text.to_uppercase(),
        format!("{text}00"),
        text.replacen("tcn-ca-pub-v2:", "tcn-ca-pub-v3:", 1),
    ] {
        let err = parse_policy("p", &policy_with(std::slice::from_ref(&bad))).unwrap_err();
        let shown = err.to_string();
        assert!(!shown.contains(&text[20..80]), "{shown}");
    }
}

/// Spec: a v2 certificate file loads with its version, and the v1 loader path is the same.
#[test]
fn certificate_v2_files_load() {
    let ca = Ca::new_v2();
    let alice = id();
    let (cert, serial) = ca.issue(&alice.public_key(), scope(&["web-01"]));
    let file = parse_certificate_file("alice.cert", &encode_certificate_text(&cert)).unwrap();
    assert_eq!(file.body.version(), 2);
    assert_eq!(file.body.serial(), serial);
    assert_eq!(&file.bytes[..], &cert[..]);
}

/// Spec: a client with a v2 certificate reaches its node through relay and agent; both log
/// `credential = certificate` and `cert_version = 2`.
#[tokio::test]
async fn a_v2_certified_client_reaches_its_node() {
    let log = Captured::default();
    let _guard = log.install();
    let ca = Ca::new_v2();
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
    assert_eq!(field(&established[0], "serial"), Some(serial.to_string()));
    assert!(
        established[0].contains("\"cert_version\":2"),
        "{}",
        established[0]
    );
    let started = log.events("e2e_session_started");
    assert!(started[0].contains("\"cert_version\":2"), "{}", started[0]);
    assert!(!log.text().contains(&hex::encode(&cert[..64])));
}

/// State (rotation): with `[v2, v1]` pinned, v1 and v2 certificates both pass; with only the
/// v2 key, the v1 certificate is refused (`unknown_authority`), never silently accepted.
#[tokio::test]
async fn v1_certificates_pass_only_while_the_v1_key_is_pinned() {
    let log = Captured::default();
    let _guard = log.install();
    let old = Ca::new();
    let new = Ca::new_v2();
    let rotating = || {
        let mut t = CertTrust::new();
        t.add_authority(
            common::node("ops"),
            &[new.trusted(), old.trusted()],
            AllowedNodes::All,
            28_800,
        )
        .unwrap();
        t.set_revocations(zt_domain::Revocations::new([], []).unwrap());
        t
    };
    let alice = id();
    let bob = id();
    let lab = Lab::start(
        |agent| vec![relay_policy(agent, &[], rotating())],
        agent_clients(&[], rotating()),
    )
    .await;
    let (v1_cert, _) = old.issue(&alice.public_key(), scope(&["web-01"]));
    let (v2_cert, _) = new.issue(&bob.public_key(), scope(&["web-01"]));
    let (mut a, _ta) = lab.session(&alice, Some(&v1_cert)).await.unwrap();
    assert_alive(&mut a).await;
    let (mut b, _tb) = lab.session(&bob, Some(&v2_cert)).await.unwrap();
    assert_alive(&mut b).await;

    let only_v2 = Lab::start(
        |agent| {
            vec![relay_policy(
                agent,
                &[],
                trust(&[(&new, AllowedNodes::All)], &[], &[]),
            )]
        },
        agent_clients(&[], trust(&[(&new, AllowedNodes::All)], &[], &[])),
    )
    .await;
    let carol = id();
    let (v1_again, _) = old.issue(&carol.public_key(), scope(&["web-01"]));
    assert!(only_v2.session(&carol, Some(&v1_again)).await.is_err());
    // Before the signature the rejection is aggregated (no identity-named line), and no
    // session names the client.
    let carol_fp = carol.fingerprint().to_string();
    assert!(
        log.events("session_established")
            .iter()
            .all(|l| !l.contains(&carol_fp)),
        "{}",
        log.text()
    );
}
