//! PQ-AUTH, hybrid identities in the domain (PROTOCOL §7.5.3, §15.14; findings AP-6, AP-12 of
//! review 0007): the hybrid IK suite, hybrid pins in the relay policy and in the agent's
//! authorized clients, and the X25519-level fingerprint as the one revocation unit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{
    AcceptedSuites, AccessPolicy, Admission, AllowedNodes, AuthFailureReason, AuthorizedClients,
    ClientCredential, ClientGrant, DomainError, Fingerprint, FingerprintText, HandshakeChannel,
    HandshakeSuite, HybridFingerprint, NodeId, UnixTime,
};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const NOW: UnixTime = UnixTime::from_secs(1_800_000_000);

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn hfp(b: u8) -> HybridFingerprint {
    HybridFingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}
fn grant(name: &str) -> ClientGrant {
    ClientGrant {
        name: node(name),
        allowed: AllowedNodes::All,
    }
}
fn revoking(keys: &[Fingerprint]) -> CertTrust {
    let mut t = CertTrust::new();
    t.set_revocations(Revocations::new([], keys.iter().copied()).unwrap());
    t
}

// --- the suite --------------------------------------------------------------------------

/// Spec: suite 0x02 is the hybrid IK: its own name, id, confirmation and sizes. msg1 =
/// `ct1 (1 088) ‖ IKhfs msg1 (1 296)` plus the initiator's encapsulation key (1 184) in the
/// payload; msg2 = `ct2 (1 088) ‖ IKhfs msg2 (1 152)`.
#[test]
fn the_hybrid_ik_suite_has_its_id_name_and_sizes() {
    assert_eq!(HYBRID.id(), 0x02);
    assert_eq!(
        HYBRID.protocol_name(),
        "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s"
    );
    assert_eq!(
        "Noise_IKhfs+psk0+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s".parse::<HandshakeSuite>(),
        Ok(HYBRID)
    );
    assert_eq!(HandshakeSuite::try_from(0x02), Ok(HYBRID));
    assert_eq!(HYBRID.confirmation(), b"TCN/3 ready");
    assert_eq!(HYBRID.msg1_overhead(), 3_568);
    assert_eq!(HYBRID.msg2_len(), 2_240);
    assert_eq!(HYBRID.max_msg1_len(), 3_568 + 7_670);
    assert!(HYBRID.max_msg1_len() <= zt_domain::limits::MAX_PAYLOAD_LEN);
    assert!(HYBRID.is_supported(HandshakeChannel::Outer));
    assert!(HYBRID.is_supported(HandshakeChannel::EndToEnd));
    assert!(HYBRID.requires_hybrid_identity());
    assert!(!HFS.requires_hybrid_identity());
    assert!(!CLASSIC.requires_hybrid_identity());
    assert_eq!(HandshakeSuite::ALL.len(), 3);
    // The sets: the hybrid suite is never implied by another.
    let all = AcceptedSuites::new([CLASSIC, HFS, HYBRID]).unwrap();
    assert_eq!(all.max_msg1_len(), HYBRID.max_msg1_len());
    assert!(
        !AcceptedSuites::new([CLASSIC, HFS])
            .unwrap()
            .contains(HYBRID)
    );
}

// --- fingerprints (AP-6) ------------------------------------------------------------------

/// Attack (AP-6, Identity): v1 and v2 fingerprints have distinct texts; a loader that expects
/// one kind can tell the other apart instead of matching nothing.
#[test]
fn v1_and_v2_fingerprint_texts_never_coincide() {
    let v1 = fp(0xab);
    let v2 = HybridFingerprint::from_bytes(*v1.as_bytes());
    assert_ne!(v1.to_string(), v2.to_string());
    assert!(v2.to_string().starts_with("SHA256v2:"));
    assert_eq!(
        FingerprintText::parse(&v1.to_string()),
        Ok(FingerprintText::V1(v1))
    );
    assert_eq!(
        FingerprintText::parse(&v2.to_string()),
        Ok(FingerprintText::V2(v2))
    );
}

// --- relay policy -------------------------------------------------------------------------

/// Spec: a client pinned by its v2 key is admitted only through a hybrid handshake that
/// proved that very hybrid identity.
#[test]
fn a_v2_pinned_client_is_admitted_only_with_its_hybrid_identity() {
    let mut p = AccessPolicy::new();
    p.add_client(fp(10), grant("alice")).unwrap();
    p.pin_hybrid(fp(10), hfp(10)).unwrap();
    assert_eq!(p.hybrid_identity(&fp(10)), Some(&hfp(10)));
    assert!(matches!(
        p.admit_hybrid(&fp(10), Some(&hfp(10)), None, NOW),
        Ok(Admission::Client {
            credential: ClientCredential::Key
        })
    ));
    // Attack (Downgrade): the same X25519 key over a classical or IKhfs handshake.
    assert_eq!(
        p.admit_hybrid(&fp(10), None, None, NOW).err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
    assert_eq!(
        p.admit(&fp(10), None, NOW).err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
    // Attack (Identity): the victim's X25519 key with another ML-KEM key.
    assert_eq!(
        p.admit_hybrid(&fp(10), Some(&hfp(11)), None, NOW).err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
}

/// Spec: agents too; and a v1 entry still admits a hybrid handshake (the operator sees it as
/// `classical_identity_match` in the adapters).
#[test]
fn v2_pins_apply_to_agents_and_v1_entries_admit_hybrid_handshakes() {
    let mut p = AccessPolicy::new();
    p.add_agent(fp(1), node("web-01")).unwrap();
    p.pin_hybrid(fp(1), hfp(1)).unwrap();
    p.add_agent(fp(2), node("db-01")).unwrap();
    assert!(matches!(
        p.admit_hybrid(&fp(1), Some(&hfp(1)), None, NOW),
        Ok(Admission::Agent { .. })
    ));
    assert_eq!(
        p.admit_hybrid(&fp(1), None, None, NOW).err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
    assert!(matches!(
        p.admit_hybrid(&fp(2), Some(&hfp(2)), None, NOW),
        Ok(Admission::Agent { .. })
    ));
    assert_eq!(p.hybrid_identity(&fp(2)), None);
}

/// Attack (Parsing/State): a pin for a key without a role, or a second pin, is refused.
#[test]
fn hybrid_pins_need_a_role_and_are_unique() {
    let mut p = AccessPolicy::new();
    assert!(matches!(
        p.pin_hybrid(fp(9), hfp(9)),
        Err(DomainError::UnknownPeer(_))
    ));
    p.add_client(fp(10), grant("alice")).unwrap();
    p.pin_hybrid(fp(10), hfp(10)).unwrap();
    assert!(matches!(
        p.pin_hybrid(fp(10), hfp(12)),
        Err(DomainError::DuplicatePeer(_))
    ));
    // The same hybrid identity for two keys is impossible (it covers the X25519 key).
    p.add_client(fp(11), grant("bob")).unwrap();
    assert!(p.pin_hybrid(fp(11), hfp(10)).is_err());
}

/// Attack (AP-6): the denylist is keyed by the X25519-level fingerprint, so it applies to a
/// v2-pinned key over every suite, before the pin is even looked at.
#[test]
fn the_denylist_applies_whatever_the_handshake() {
    let mut p = AccessPolicy::new();
    p.add_client(fp(10), grant("alice")).unwrap();
    p.pin_hybrid(fp(10), hfp(10)).unwrap();
    p.set_cert_trust(revoking(&[fp(10)])).unwrap();
    for hybrid in [None, Some(&hfp(10)), Some(&hfp(11))] {
        assert_eq!(
            p.admit_hybrid(&fp(10), hybrid, None, NOW).err(),
            Some(AuthFailureReason::KeyRevoked)
        );
    }
}

// --- agent ---------------------------------------------------------------------------------

/// Spec: the agent's authorized clients carry the same pins, also on recheck.
#[test]
fn authorized_clients_check_hybrid_pins() {
    let mut c = AuthorizedClients::new();
    c.add_client(fp(10)).unwrap();
    c.pin_hybrid(fp(10), hfp(10)).unwrap();
    c.add_client(fp(11)).unwrap();
    let web = node("web-01");
    assert_eq!(
        c.admit_hybrid(&fp(10), Some(&hfp(10)), None, &web, NOW),
        Ok(ClientCredential::Key)
    );
    assert_eq!(
        c.admit_hybrid(&fp(10), None, None, &web, NOW),
        Err(AuthFailureReason::IdentityDowngrade)
    );
    assert_eq!(
        c.admit(&fp(10), None, &web, NOW),
        Err(AuthFailureReason::IdentityDowngrade)
    );
    assert_eq!(
        c.admit_hybrid(&fp(11), Some(&hfp(11)), None, &web, NOW),
        Ok(ClientCredential::Key)
    );
    assert_eq!(c.hybrid_identity(&fp(11)), None);
    // Recheck after a reload that pins the key: a classical session no longer holds.
    assert!(c.still_admits_hybrid(&fp(10), Some(&hfp(10)), &ClientCredential::Key, &web, NOW));
    assert!(!c.still_admits_hybrid(&fp(10), None, &ClientCredential::Key, &web, NOW));
    assert!(!c.still_admits(&fp(10), &ClientCredential::Key, &web, NOW));
    let _ = Arc::new(());
}
