//! Phase 6, step 2: CA trust, denylist and authorization with certificates
//! (PROTOCOL §15.4 steps 1, 2, 5, 7–12; §15.5; §15.6; §15.8; §15.9).
//!
//! The domain receives the data of already-verified certificates (`CertClaims::from_verified`):
//! here the keys are arbitrary bytes; the cryptography is in `zt-crypto`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use zt_domain::limits::{MAX_REVOKED_KEYS, MAX_REVOKED_SERIALS};
use zt_domain::trust::{CertTrust, Revocations, TrustedCaKey};
use zt_domain::{
    AccessPolicy, Admission, AllowedNodes, AuthFailureReason, AuthorizedClients, CertBody,
    CertClaims, CertKey, CertRejection, CertScope, CertSerial, ClientCredential, ClientGrant,
    DomainError, Fingerprint, NodeId, UnixTime,
};

// ---------- fixtures ----------

const WEB_AGENT: u8 = 1;
const DB_AGENT: u8 = 2;
const APP_AGENT: u8 = 3;
const ANSIBLE: u8 = 10;
const ALICE: u8 = 50;
const BOB: u8 = 51;
const WEB_CA: u8 = 0xa1;
const DB_CA: u8 = 0xa2;
const ROGUE_CA: u8 = 0xee;

const NB: u64 = 1_800_000_000;
const NA: u64 = NB + 3_600;
const NOW: u64 = NB + 60;
const EIGHT_HOURS: u64 = 8 * 3_600;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn nodes(list: &[&str]) -> BTreeSet<NodeId> {
    list.iter().map(|n| node(n)).collect()
}
fn only(list: &[&str]) -> AllowedNodes {
    AllowedNodes::Only(nodes(list))
}
fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}
fn serial(b: u8) -> CertSerial {
    CertSerial::try_from([b; 16]).unwrap()
}
/// The pinned key of CA `b`: 32 bytes `[b; 32]`, fingerprint `[b; 32]`.
fn ca(b: u8) -> TrustedCaKey {
    TrustedCaKey {
        key: CertKey::from_bytes([b; 32]),
        fingerprint: fp(b),
        composite: None,
    }
}

/// Parameters of a certificate; `claims()` "verifies" it.
#[derive(Clone)]
struct Cert {
    ca: u8,
    subject: u8,
    serial: u8,
    not_before: u64,
    not_after: u64,
    name: &'static str,
    scope: CertScope,
}

impl Cert {
    fn new(ca: u8, subject: u8, scope: CertScope) -> Self {
        Self {
            ca,
            subject,
            serial: subject,
            not_before: NB,
            not_after: NA,
            name: "alice",
            scope,
        }
    }
    fn for_nodes(ca: u8, subject: u8, list: &[&str]) -> Self {
        Self::new(ca, subject, CertScope::Only(nodes(list)))
    }
    fn claims(&self) -> Arc<CertClaims> {
        let body = CertBody::new(
            CertKey::from_bytes([self.ca; 32]),
            CertKey::from_bytes([self.subject; 32]),
            serial(self.serial),
            at(self.not_before),
            at(self.not_after),
            node(self.name),
            self.scope.clone(),
        )
        .unwrap();
        Arc::new(CertClaims::from_verified(
            body,
            fp(self.ca),
            fp(self.subject),
        ))
    }
}

fn revocations(serials: &[u8], keys: &[u8]) -> Revocations {
    Revocations::new(
        serials.iter().map(|b| serial(*b)),
        keys.iter().map(|b| fp(*b)),
    )
    .unwrap()
}

/// `web-ca` (allow web-01, app-01; 8 h) and `db-ca` (allow db-01; 8 h), empty denylist.
fn standard_trust() -> CertTrust {
    trust_with(revocations(&[], &[]))
}

fn trust_with(revoked: Revocations) -> CertTrust {
    let mut t = CertTrust::new();
    t.add_authority(
        node("web-ca"),
        &[ca(WEB_CA)],
        only(&["web-01", "app-01"]),
        EIGHT_HOURS,
    )
    .unwrap();
    t.add_authority(node("db-ca"), &[ca(DB_CA)], only(&["db-01"]), EIGHT_HOURS)
        .unwrap();
    t.set_revocations(revoked);
    t
}

/// Relay policy: agents web-01, db-01, app-01; client `ansible` admitted to web-01.
fn policy_with(trust: CertTrust) -> AccessPolicy {
    let mut p = AccessPolicy::new();
    p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
    p.add_agent(fp(DB_AGENT), node("db-01")).unwrap();
    p.add_agent(fp(APP_AGENT), node("app-01")).unwrap();
    p.add_client(
        fp(ANSIBLE),
        ClientGrant {
            name: node("ansible"),
            allowed: only(&["web-01"]),
        },
    )
    .unwrap();
    p.set_cert_trust(trust).unwrap();
    p
}

/// Authorized clients of an agent: `ansible` and the same CAs.
fn clients_with(trust: CertTrust) -> AuthorizedClients {
    let mut c = AuthorizedClients::new();
    c.add_client(fp(ANSIBLE)).unwrap();
    c.set_cert_trust(trust).unwrap();
    c
}

fn certified(admission: Result<Admission<'_>, AuthFailureReason>) -> ClientCredential {
    match admission {
        Ok(Admission::Client {
            credential: credential @ ClientCredential::Certificate(_),
        }) => credential,
        other => panic!("expected a certificate admission, got {other:?}"),
    }
}

fn reachable(p: &AccessPolicy, peer: u8, credential: &ClientCredential, now: u64) -> Vec<String> {
    ["web-01", "db-01", "app-01", "ghost"]
        .into_iter()
        .filter(|n| p.may_open_with(&fp(peer), credential, &node(n), at(now)))
        .map(str::to_owned)
        .collect()
}

// ======================= specification =======================

#[test]
fn a_valid_certificate_grants_its_nodes_within_the_authority() {
    let p = policy_with(standard_trust());
    // The certificate lists web-01, db-01 and a node that does not exist; the CA grants web-01 and
    // app-01. Effective: only web-01.
    let claims = Cert::for_nodes(WEB_CA, ALICE, &["db-01", "ghost", "web-01"]).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
    assert_eq!(reachable(&p, ALICE, &credential, NOW), ["web-01"]);
    // The CA that counts is the pinned one: `permits` is `scope(cert) ∩ allow`.
    let authority = p.cert_trust().check(&claims, at(NOW)).unwrap();
    assert_eq!(authority.name(), &node("web-ca"));
    assert!(authority.permits(&claims, &node("web-01")));
    assert!(!authority.permits(&claims, &node("db-01")));
    assert!(!authority.permits(&claims, &node("app-01")));
    // The audit reference carries CA, serial, name and expiry.
    let reference = claims.reference();
    assert_eq!(reference.ca, fp(WEB_CA));
    assert_eq!(reference.serial, serial(ALICE));
    assert_eq!(reference.name, node("alice"));
    assert_eq!(reference.not_after, at(NA));
}

#[test]
fn scope_all_means_the_authority_allow_list() {
    let mut t = CertTrust::new();
    t.add_authority(
        node("web-ca"),
        &[ca(WEB_CA)],
        only(&["web-01"]),
        EIGHT_HOURS,
    )
    .unwrap();
    t.set_revocations(revocations(&[], &[]));
    let p = policy_with(t.clone());
    let claims = Cert::new(WEB_CA, ALICE, CertScope::All).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
    assert_eq!(reachable(&p, ALICE, &credential, NOW), ["web-01"]);
    // Agent side: only the node in `allow`.
    let c = clients_with(t);
    assert!(
        c.admit(&fp(ALICE), Some(&claims), &node("web-01"), at(NOW))
            .is_ok()
    );
    assert_eq!(
        c.admit(&fp(ALICE), Some(&claims), &node("db-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(
            CertRejection::NodeOutOfScope
        ))
    );
}

#[test]
fn authority_allow_all_means_every_policy_node() {
    let mut t = CertTrust::new();
    t.add_authority(
        node("ops-ca"),
        &[ca(WEB_CA)],
        AllowedNodes::All,
        EIGHT_HOURS,
    )
    .unwrap();
    t.set_revocations(revocations(&[], &[]));
    let p = policy_with(t);
    let claims = Cert::new(WEB_CA, ALICE, CertScope::All).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
    // `["*"]` does not invent nonexistent nodes: `ghost` is not in the policy.
    assert_eq!(
        reachable(&p, ALICE, &credential, NOW),
        ["web-01", "db-01", "app-01"]
    );
    let listed = Cert::for_nodes(WEB_CA, BOB, &["db-01", "ghost"]).claims();
    let credential = certified(p.admit(&fp(BOB), Some(&listed), at(NOW)));
    assert_eq!(reachable(&p, BOB, &credential, NOW), ["db-01"]);
}

#[test]
fn validity_has_skew_only_on_not_before() {
    let t = standard_trust();
    let claims = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    assert!(t.check(&claims, at(NB - 120)).is_ok(), "nb - 120 is valid");
    assert!(t.check(&claims, at(NB)).is_ok());
    assert_eq!(
        t.check(&claims, at(NB - 121)).err(),
        Some(CertRejection::NotYetValid)
    );
    assert!(t.check(&claims, at(NA - 1)).is_ok(), "na - 1 is valid");
    assert_eq!(t.check(&claims, at(NA)).err(), Some(CertRejection::Expired));
    assert_eq!(
        t.check(&claims, at(NA + 120)).err(),
        Some(CertRejection::Expired),
        "no skew on not_after"
    );
    // The same through the policy and the agent side.
    let p = policy_with(t.clone());
    assert_eq!(
        p.admit(&fp(ALICE), Some(&claims), at(NB - 121)).err(),
        Some(AuthFailureReason::Certificate(CertRejection::NotYetValid))
    );
    assert_eq!(
        p.admit(&fp(ALICE), Some(&claims), at(NA)).err(),
        Some(AuthFailureReason::Certificate(CertRejection::Expired))
    );
    let c = clients_with(t);
    assert!(
        c.admit(&fp(ALICE), Some(&claims), &node("web-01"), at(NB - 120))
            .is_ok()
    );
    assert_eq!(
        c.admit(&fp(ALICE), Some(&claims), &node("web-01"), at(NA)),
        Err(AuthFailureReason::Certificate(CertRejection::Expired))
    );
    // A certificate starting close to 0: no underflow.
    let early = Cert {
        not_before: 10,
        not_after: 100,
        ..Cert::for_nodes(WEB_CA, ALICE, &["web-01"])
    }
    .claims();
    assert!(t_check_ok(&early, 0));
}

fn t_check_ok(claims: &CertClaims, now: u64) -> bool {
    standard_trust().check(claims, at(now)).is_ok()
}

#[test]
fn whitelisted_keys_keep_their_grant_and_the_certificate_adds_nothing() {
    let p = policy_with(standard_trust());
    // `ansible` has allow = [web-01]; it presents a valid certificate for app-01.
    let claims = Cert::for_nodes(WEB_CA, ANSIBLE, &["app-01"]).claims();
    let admission = p.admit(&fp(ANSIBLE), Some(&claims), at(NOW)).unwrap();
    assert_eq!(
        admission,
        Admission::Client {
            credential: ClientCredential::Key
        }
    );
    assert_eq!(
        reachable(&p, ANSIBLE, &ClientCredential::Key, NOW),
        ["web-01"]
    );
    // Without a certificate: same credential.
    assert_eq!(
        p.admit(&fp(ANSIBLE), None, at(NOW)).unwrap(),
        Admission::Client {
            credential: ClientCredential::Key
        }
    );
    // No in-session expiry for the whitelist.
    assert_eq!(
        reachable(&p, ANSIBLE, &ClientCredential::Key, NA + 1_000_000),
        ["web-01"]
    );
    // Agent side: the whitelist admits with `Key`, even with the certificate.
    let c = clients_with(standard_trust());
    assert_eq!(
        c.admit(&fp(ANSIBLE), Some(&claims), &node("web-01"), at(NOW)),
        Ok(ClientCredential::Key)
    );
    assert!(c.still_admits(
        &fp(ANSIBLE),
        &ClientCredential::Key,
        &node("web-01"),
        at(NA + 1_000_000)
    ));
}

#[test]
fn agent_side_accepts_only_its_own_node_in_scope() {
    let c = clients_with(standard_trust());
    let claims = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    let credential = c
        .admit(&fp(ALICE), Some(&claims), &node("web-01"), at(NOW))
        .unwrap();
    assert!(matches!(credential, ClientCredential::Certificate(_)));
    // app-01 is in the CA's `allow` but not in the certificate; db-01 is in neither.
    for other in ["app-01", "db-01", "ghost"] {
        assert_eq!(
            c.admit(&fp(ALICE), Some(&claims), &node(other), at(NOW)),
            Err(AuthFailureReason::Certificate(
                CertRejection::NodeOutOfScope
            )),
            "{other}"
        );
    }
    // The credential is valid until `not_after`, exclusive.
    assert!(c.still_admits(&fp(ALICE), &credential, &node("web-01"), at(NA - 1)));
    assert!(!c.still_admits(&fp(ALICE), &credential, &node("web-01"), at(NA)));
    assert!(!c.still_admits(&fp(ALICE), &credential, &node("app-01"), at(NOW)));
    // Without a certificate an unknown key stays unknown.
    assert_eq!(
        c.admit(&fp(ALICE), None, &node("web-01"), at(NOW)),
        Err(AuthFailureReason::UnknownPeer)
    );
}

#[test]
fn an_empty_effective_scope_admits_but_grants_nothing() {
    let p = policy_with(standard_trust());
    // db-ca grants only db-01; the certificate lists only web-01.
    let claims = Cert::for_nodes(DB_CA, ALICE, &["web-01"]).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
    assert!(reachable(&p, ALICE, &credential, NOW).is_empty());
}

#[test]
fn rotations_pending_lists_authorities_with_two_keys() {
    let mut t = CertTrust::new();
    let (new, old) = (ca(0xb1), ca(0xb2));
    t.add_authority(
        node("web-ca"),
        &[new.clone(), old.clone()],
        only(&["web-01"]),
        EIGHT_HOURS,
    )
    .unwrap();
    t.add_authority(node("db-ca"), &[ca(DB_CA)], only(&["db-01"]), EIGHT_HOURS)
        .unwrap();
    t.set_revocations(revocations(&[], &[]));
    let pending: Vec<(NodeId, Vec<TrustedCaKey>)> = t
        .rotations_pending()
        .map(|(n, k)| (n.clone(), k.to_vec()))
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, node("web-ca"));
    assert_eq!(pending[0].1.len(), 2);
    assert!(pending[0].1.contains(&new) && pending[0].1.contains(&old));
    // Both keys are valid, with the same name, `allow` and `max_lifetime`.
    for key in [0xb1, 0xb2] {
        let claims = Cert::for_nodes(key, ALICE, &["web-01"]).claims();
        let authority = t.check(&claims, at(NOW)).unwrap();
        assert_eq!(authority.name(), &node("web-ca"));
        assert_eq!(authority.max_lifetime_secs(), EIGHT_HOURS);
        assert!(
            t.authority_for_key(&CertKey::from_bytes([key; 32]))
                .is_some()
        );
    }
    let fingerprints: Vec<Fingerprint> = t.ca_fingerprints().collect();
    assert_eq!(fingerprints.len(), 3);
    for f in [fp(0xb1), fp(0xb2), fp(DB_CA)] {
        assert!(fingerprints.contains(&f));
    }
    // Rotation completed: nothing more.
    let mut done = CertTrust::new();
    done.add_authority(node("web-ca"), &[new], only(&["web-01"]), EIGHT_HOURS)
        .unwrap();
    assert_eq!(done.rotations_pending().count(), 0);
}

// ======================= attacks =======================

#[test]
fn a_certificate_cannot_grant_nodes_of_another_authority() {
    let p = policy_with(standard_trust());
    // web-ca signs a certificate for db-01, which belongs to db-ca.
    let claims = Cert::for_nodes(WEB_CA, ALICE, &["db-01"]).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
    assert!(!p.may_open_with(&fp(ALICE), &credential, &node("db-01"), at(NOW)));
    let c = clients_with(standard_trust());
    assert_eq!(
        c.admit(&fp(ALICE), Some(&claims), &node("db-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(
            CertRejection::NodeOutOfScope
        ))
    );
    // Control: the same certificate signed by db-ca grants db-01.
    let good = Cert::for_nodes(DB_CA, BOB, &["db-01"]).claims();
    let credential = certified(p.admit(&fp(BOB), Some(&good), at(NOW)));
    assert!(p.may_open_with(&fp(BOB), &credential, &node("db-01"), at(NOW)));
}

#[test]
fn an_unpinned_authority_is_rejected() {
    let t = standard_trust();
    let rogue = Cert::for_nodes(ROGUE_CA, ALICE, &["web-01"]).claims();
    assert_eq!(
        t.check(&rogue, at(NOW)).err(),
        Some(CertRejection::UnknownAuthority)
    );
    assert!(
        t.authority_for_key(&CertKey::from_bytes([ROGUE_CA; 32]))
            .is_none()
    );
    let p = policy_with(t.clone());
    assert_eq!(
        p.admit(&fp(ALICE), Some(&rogue), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(
            CertRejection::UnknownAuthority
        ))
    );
    // Step 5 comes before step 9: an expired certificate from an unknown CA is `UnknownAuthority`.
    assert_eq!(
        t.check(&rogue, at(NA + 10)).err(),
        Some(CertRejection::UnknownAuthority)
    );

    // A reload removes web-ca: claims verified earlier are no longer valid.
    let good = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    let credential = certified(p.admit(&fp(ALICE), Some(&good), at(NOW)));
    let mut reduced = CertTrust::new();
    reduced
        .add_authority(node("db-ca"), &[ca(DB_CA)], only(&["db-01"]), EIGHT_HOURS)
        .unwrap();
    reduced.set_revocations(revocations(&[], &[]));
    let reloaded = policy_with(reduced.clone());
    assert_eq!(
        reloaded.admit(&fp(ALICE), Some(&good), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(
            CertRejection::UnknownAuthority
        ))
    );
    assert!(!reloaded.may_open_with(&fp(ALICE), &credential, &node("web-01"), at(NOW)));
    let c = clients_with(reduced);
    assert!(!c.still_admits(&fp(ALICE), &credential, &node("web-01"), at(NOW)));
    assert_eq!(
        c.admit(&fp(ALICE), Some(&good), &node("web-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(
            CertRejection::UnknownAuthority
        ))
    );
}

#[test]
fn a_lifetime_over_the_authority_max_is_rejected() {
    let t = standard_trust();
    let exactly = Cert {
        not_before: NB,
        not_after: NB + EIGHT_HOURS,
        ..Cert::for_nodes(WEB_CA, ALICE, &["web-01"])
    }
    .claims();
    assert!(t.check(&exactly, at(NOW)).is_ok());
    let over = Cert {
        not_before: NB,
        not_after: NB + EIGHT_HOURS + 1,
        ..Cert::for_nodes(WEB_CA, ALICE, &["web-01"])
    }
    .claims();
    assert_eq!(
        t.check(&over, at(NOW)).err(),
        Some(CertRejection::LifetimeExceedsAuthority)
    );
    let p = policy_with(t.clone());
    assert_eq!(
        p.admit(&fp(ALICE), Some(&over), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(
            CertRejection::LifetimeExceedsAuthority
        ))
    );
    let c = clients_with(t);
    assert_eq!(
        c.admit(&fp(ALICE), Some(&over), &node("web-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(
            CertRejection::LifetimeExceedsAuthority
        ))
    );
}

#[test]
fn a_revoked_serial_is_rejected() {
    let t = trust_with(revocations(&[ALICE], &[]));
    let revoked = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    assert_eq!(
        t.check(&revoked, at(NOW)).err(),
        Some(CertRejection::SerialRevoked)
    );
    // Step 7 comes before steps 8 and 9.
    assert_eq!(
        t.check(&revoked, at(NA + 10)).err(),
        Some(CertRejection::SerialRevoked)
    );
    // Another serial of the same key is not revoked.
    let other = Cert {
        serial: 0x77,
        ..Cert::for_nodes(WEB_CA, ALICE, &["web-01"])
    }
    .claims();
    assert!(t.check(&other, at(NOW)).is_ok());
    let p = policy_with(t.clone());
    assert_eq!(
        p.admit(&fp(ALICE), Some(&revoked), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(CertRejection::SerialRevoked))
    );
    let c = clients_with(t);
    assert_eq!(
        c.admit(&fp(ALICE), Some(&revoked), &node("web-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(CertRejection::SerialRevoked))
    );
}

#[test]
fn a_revoked_key_is_rejected_with_any_credential() {
    let t = trust_with(revocations(&[], &[ALICE, ANSIBLE, WEB_AGENT]));
    assert!(t.is_key_revoked(&fp(ALICE)));
    assert!(!t.is_key_revoked(&fp(BOB)));
    let p = policy_with(t.clone());
    // Valid certificate of a revoked key.
    let alice = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    assert_eq!(
        p.admit(&fp(ALICE), Some(&alice), at(NOW)).err(),
        Some(AuthFailureReason::KeyRevoked)
    );
    // Whitelist entry, with and without a certificate.
    assert_eq!(
        p.admit(&fp(ANSIBLE), None, at(NOW)).err(),
        Some(AuthFailureReason::KeyRevoked)
    );
    let ansible = Cert::for_nodes(WEB_CA, ANSIBLE, &["web-01"]).claims();
    assert_eq!(
        p.admit(&fp(ANSIBLE), Some(&ansible), at(NOW)).err(),
        Some(AuthFailureReason::KeyRevoked)
    );
    assert!(!p.may_open_with(
        &fp(ANSIBLE),
        &ClientCredential::Key,
        &node("web-01"),
        at(NOW)
    ));
    // Agent key.
    assert_eq!(
        p.admit(&fp(WEB_AGENT), None, at(NOW)).err(),
        Some(AuthFailureReason::KeyRevoked)
    );
    // Control: a non-revoked key passes.
    let bob = Cert::for_nodes(WEB_CA, BOB, &["web-01"]).claims();
    assert!(p.admit(&fp(BOB), Some(&bob), at(NOW)).is_ok());
    assert!(p.admit(&fp(DB_AGENT), None, at(NOW)).is_ok());
    // Agent side.
    let c = clients_with(t);
    assert_eq!(
        c.admit(&fp(ANSIBLE), None, &node("web-01"), at(NOW)),
        Err(AuthFailureReason::KeyRevoked)
    );
    assert_eq!(
        c.admit(&fp(ALICE), Some(&alice), &node("web-01"), at(NOW)),
        Err(AuthFailureReason::KeyRevoked)
    );
    assert!(!c.still_admits(
        &fp(ANSIBLE),
        &ClientCredential::Key,
        &node("web-01"),
        at(NOW)
    ));
    assert!(
        c.admit(&fp(BOB), Some(&bob), &node("web-01"), at(NOW))
            .is_ok()
    );
}

#[test]
fn a_whitelisted_key_with_an_invalid_certificate_is_rejected() {
    let p = policy_with(standard_trust());
    let c = clients_with(standard_trust());
    let valid = Cert::for_nodes(WEB_CA, ANSIBLE, &["web-01"]).claims();
    assert_eq!(
        p.admit(&fp(ANSIBLE), Some(&valid), at(NOW)).unwrap(),
        Admission::Client {
            credential: ClientCredential::Key
        }
    );
    let expired = valid.clone();
    assert_eq!(
        p.admit(&fp(ANSIBLE), Some(&expired), at(NA)).err(),
        Some(AuthFailureReason::Certificate(CertRejection::Expired))
    );
    let rogue = Cert::for_nodes(ROGUE_CA, ANSIBLE, &["web-01"]).claims();
    assert_eq!(
        p.admit(&fp(ANSIBLE), Some(&rogue), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(
            CertRejection::UnknownAuthority
        ))
    );
    assert_eq!(
        c.admit(&fp(ANSIBLE), Some(&rogue), &node("web-01"), at(NOW)),
        Err(AuthFailureReason::Certificate(
            CertRejection::UnknownAuthority
        ))
    );
    assert_eq!(
        c.admit(&fp(ANSIBLE), Some(&expired), &node("web-01"), at(NA)),
        Err(AuthFailureReason::Certificate(CertRejection::Expired))
    );
}

#[test]
fn an_agent_key_presenting_a_certificate_is_a_role_conflict() {
    let p = policy_with(standard_trust());
    assert_eq!(
        p.admit(&fp(WEB_AGENT), None, at(NOW)).unwrap(),
        Admission::Agent {
            node: &node("web-01")
        }
    );
    let claims = Cert::for_nodes(WEB_CA, WEB_AGENT, &["web-01"]).claims();
    assert_eq!(
        p.admit(&fp(WEB_AGENT), Some(&claims), at(NOW)).err(),
        Some(AuthFailureReason::Certificate(CertRejection::RoleConflict))
    );
}

#[test]
fn authority_keys_cannot_double_as_peer_keys_in_any_order() {
    let trust_on = |key: u8| {
        let mut t = CertTrust::new();
        t.add_authority(node("x-ca"), &[ca(key)], AllowedNodes::All, EIGHT_HOURS)
            .unwrap();
        t.set_revocations(revocations(&[], &[]));
        t
    };
    // First the peers, then the CA.
    for peer in [WEB_AGENT, ANSIBLE] {
        let mut p = AccessPolicy::new();
        p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
        p.add_client(
            fp(ANSIBLE),
            ClientGrant {
                name: node("ansible"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
        assert_eq!(
            p.set_cert_trust(trust_on(peer)),
            Err(DomainError::DuplicatePeer(fp(peer)))
        );
    }
    // First the CA, then the peers.
    let mut p = AccessPolicy::new();
    p.set_cert_trust(trust_on(0xc1)).unwrap();
    assert_eq!(
        p.add_agent(fp(0xc1), node("web-01")),
        Err(DomainError::DuplicatePeer(fp(0xc1)))
    );
    assert_eq!(
        p.add_agent_keys(node("db-01"), &[fp(DB_AGENT), fp(0xc1)]),
        Err(DomainError::DuplicatePeer(fp(0xc1)))
    );
    assert_eq!(
        p.add_client(
            fp(0xc1),
            ClientGrant {
                name: node("c"),
                allowed: AllowedNodes::All
            }
        ),
        Err(DomainError::DuplicatePeer(fp(0xc1)))
    );
    // Control: different keys are fine.
    p.add_agent(fp(WEB_AGENT), node("web-01")).unwrap();
    // Agent side, in both orders.
    let mut c = AuthorizedClients::new();
    c.add_client(fp(ANSIBLE)).unwrap();
    assert_eq!(
        c.set_cert_trust(trust_on(ANSIBLE)),
        Err(DomainError::DuplicatePeer(fp(ANSIBLE)))
    );
    let mut c = AuthorizedClients::new();
    c.set_cert_trust(trust_on(0xc1)).unwrap();
    assert_eq!(
        c.add_client(fp(0xc1)),
        Err(DomainError::DuplicatePeer(fp(0xc1)))
    );
    c.add_client(fp(ANSIBLE)).unwrap();
}

#[test]
fn a_ca_key_cannot_appear_in_two_authorities() {
    let mut t = CertTrust::new();
    t.add_authority(
        node("web-ca"),
        &[ca(WEB_CA)],
        only(&["web-01"]),
        EIGHT_HOURS,
    )
    .unwrap();
    // Same key, different name and scope.
    assert_eq!(
        t.add_authority(node("db-ca"), &[ca(WEB_CA)], only(&["db-01"]), EIGHT_HOURS),
        Err(DomainError::DuplicatePeer(fp(WEB_CA)))
    );
    // Also as the second key of a rotation.
    assert_eq!(
        t.add_authority(
            node("db-ca"),
            &[ca(DB_CA), ca(WEB_CA)],
            only(&["db-01"]),
            EIGHT_HOURS
        ),
        Err(DomainError::DuplicatePeer(fp(WEB_CA)))
    );
    // The failure leaves no effects: db-ca does not exist and DB_CA is not pinned.
    assert!(
        t.authority_for_key(&CertKey::from_bytes([DB_CA; 32]))
            .is_none()
    );
    let claims = Cert::for_nodes(WEB_CA, ALICE, &["web-01"]).claims();
    t.set_revocations(revocations(&[], &[]));
    assert_eq!(t.check(&claims, at(NOW)).unwrap().name(), &node("web-ca"));
    // Control: a new key with that name is fine.
    t.add_authority(node("db-ca"), &[ca(DB_CA)], only(&["db-01"]), EIGHT_HOURS)
        .unwrap();
}

#[test]
fn authority_entries_are_validated() {
    let mut t = CertTrust::new();
    let name = node("ops-ca");
    assert_eq!(
        t.add_authority(name.clone(), &[], AllowedNodes::All, EIGHT_HOURS),
        Err(DomainError::AuthorityKeys(name.clone()))
    );
    assert_eq!(
        t.add_authority(
            name.clone(),
            &[ca(0xd1), ca(0xd2), ca(0xd3)],
            AllowedNodes::All,
            EIGHT_HOURS
        ),
        Err(DomainError::AuthorityKeys(name.clone()))
    );
    assert_eq!(
        t.add_authority(
            name.clone(),
            &[ca(0xd1), ca(0xd1)],
            AllowedNodes::All,
            EIGHT_HOURS
        ),
        Err(DomainError::AuthorityKeys(name.clone()))
    );
    for secs in [0, 59, 86_401, u64::MAX] {
        assert_eq!(
            t.add_authority(name.clone(), &[ca(0xd1)], AllowedNodes::All, secs),
            Err(DomainError::AuthorityLifetime { secs }),
            "{secs}"
        );
    }
    assert!(t.is_empty(), "failed additions must leave no trace");
    t.add_authority(name.clone(), &[ca(0xd1)], AllowedNodes::All, 60)
        .unwrap();
    assert!(!t.is_empty());
    assert_eq!(
        t.add_authority(name.clone(), &[ca(0xd2)], AllowedNodes::All, 86_400),
        Err(DomainError::DuplicateAuthority(name))
    );
    // At most 16 CAs.
    let mut t = CertTrust::new();
    for i in 0..16_u8 {
        t.add_authority(
            node(&format!("ca-{i}")),
            &[ca(0x10 + i)],
            AllowedNodes::All,
            86_400,
        )
        .unwrap();
    }
    assert_eq!(
        t.add_authority(node("ca-16"), &[ca(0x30)], AllowedNodes::All, 86_400),
        Err(DomainError::TooManyAuthorities)
    );
    assert_eq!(t.authorities().count(), 16);
}

#[test]
fn revocation_lists_are_bounded() {
    let serials = |n: usize| {
        (1..=n).map(|i| {
            let mut b = [0_u8; 16];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            CertSerial::try_from(b).unwrap()
        })
    };
    let keys = |n: usize| {
        (1..=n).map(|i| {
            let mut b = [0_u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Fingerprint::from_bytes(b)
        })
    };
    let full = Revocations::new(serials(MAX_REVOKED_SERIALS), keys(MAX_REVOKED_KEYS)).unwrap();
    assert_eq!(full.counts(), (MAX_REVOKED_SERIALS, MAX_REVOKED_KEYS));
    assert_eq!(
        Revocations::new(serials(MAX_REVOKED_SERIALS + 1), keys(0)),
        Err(DomainError::TooManyRevocations { what: "serials" })
    );
    assert_eq!(
        Revocations::new(serials(0), keys(MAX_REVOKED_KEYS + 1)),
        Err(DomainError::TooManyRevocations { what: "keys" })
    );
    let small = revocations(&[1, 2], &[3]);
    assert_eq!(small.counts(), (2, 1));
    assert!(small.is_serial_revoked(&serial(1)));
    assert!(!small.is_serial_revoked(&serial(9)));
    assert!(small.is_key_revoked(&fp(3)));
    assert!(!small.is_key_revoked(&fp(4)));
}

#[test]
fn certificate_names_never_affect_authorization() {
    let p = policy_with(standard_trust());
    // Names equal to a whitelisted client, to a node, to a CA: same permissions as
    // any other name.
    for name in ["ansible", "web-01", "web-ca", "db-ca", "bob"] {
        let claims = Cert {
            name,
            ..Cert::for_nodes(WEB_CA, ALICE, &["app-01"])
        }
        .claims();
        let credential = certified(p.admit(&fp(ALICE), Some(&claims), at(NOW)));
        assert_eq!(reachable(&p, ALICE, &credential, NOW), ["app-01"], "{name}");
        let c = clients_with(standard_trust());
        assert!(matches!(
            c.admit(&fp(ALICE), Some(&claims), &node("app-01"), at(NOW)),
            Ok(ClientCredential::Certificate(_))
        ));
        assert_eq!(
            c.admit(&fp(ALICE), Some(&claims), &node("web-01"), at(NOW)),
            Err(AuthFailureReason::Certificate(
                CertRejection::NodeOutOfScope
            ))
        );
    }
}

#[test]
fn authorities_without_revocations_are_flagged() {
    let empty = CertTrust::new();
    assert!(empty.is_empty());
    assert!(
        !empty.needs_revocations(),
        "no authority, no denylist needed"
    );
    let mut t = CertTrust::new();
    t.add_authority(
        node("web-ca"),
        &[ca(WEB_CA)],
        AllowedNodes::All,
        EIGHT_HOURS,
    )
    .unwrap();
    assert!(t.needs_revocations());
    t.set_revocations(revocations(&[], &[]));
    assert!(!t.needs_revocations(), "an empty denylist is enough");
    assert!(t.revocations().is_some());
}
