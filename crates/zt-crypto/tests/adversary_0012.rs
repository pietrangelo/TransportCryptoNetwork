//! Regression tests of adversary review 0012 (Phase 5, PQ-AUTH): the reviewer's reproducers,
//! flipped to assert the safe behaviour.
//!
//! - A12-1: a policy that requires hybrid identities refuses a classical-kind certificate
//!   (the CRQC impostor), and admits a certificate-only client only through a hybrid-bound
//!   certificate that its handshake proved.
//! - A12-4: a responder that does not accept the hybrid IK suite never decapsulates with its
//!   static key, so it cannot identify a hybrid IK message 1.
//! - A12-5: two composite CA keys never share their ML-DSA-65 half.
//! - A12-6: the cost of an invalid message 1 with every suite accepted, against the classical
//!   responder of the release before PQ-AUTH (ignored by default: run it with `--release`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use std::sync::Arc;
use std::time::Instant;

use zt_crypto::noise::{self, Channel, Responded};
use zt_crypto::{
    CompositeCaSigningKey, Identity, Keyring, PeerKey, sign_certificate_v2,
    trusted_composite_ca_key, verify_certificate_hybrid,
};
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{
    AcceptedSuites, AccessPolicy, AllowedNodes, AuthFailureReason, AuthorizedClients, CertBodyV2,
    CertScope, CertSerial, CertSubject, ClientCredential, DomainError, HandshakeSuite,
    HybridFingerprint, HybridRequirement, NodeId, UnixTime,
};

const HYBRID: HandshakeSuite = HandshakeSuite::NoiseIkHybrid25519MlKem768;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;
const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const NOW: u64 = 1_800_000_100;

fn ca(ed: u8, ml: u8) -> CompositeCaSigningKey {
    let text = format!(
        "{}{}{}\n",
        CompositeCaSigningKey::FILE_PREFIX,
        hex::encode([ed; 32]),
        hex::encode([ml; 32])
    );
    CompositeCaSigningKey::from_secret_text(&text).unwrap()
}

fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

fn id(b: u8) -> Identity {
    Identity::from_secret_hex(&hex::encode([b; 32])).unwrap()
}

fn trust_of(ca: &CompositeCaSigningKey) -> CertTrust {
    let mut trust = CertTrust::new();
    trust
        .add_authority(
            node("ops"),
            &[trusted_composite_ca_key(&ca.public_key()).unwrap()],
            AllowedNodes::All,
            28_800,
        )
        .unwrap();
    trust.set_revocations(Revocations::new([], []).unwrap());
    trust
}

fn certificate(ca: &CompositeCaSigningKey, subject: CertSubject) -> Vec<u8> {
    let body = CertBodyV2::new(
        ca.public_key().ca_fp(),
        subject,
        CertSerial::try_from([7; 16]).unwrap(),
        UnixTime::from_secs(1_800_000_000),
        UnixTime::from_secs(1_800_003_600),
        node("victim"),
        CertScope::All,
    )
    .unwrap();
    sign_certificate_v2(ca, &body).unwrap()
}

/// The relay policy of a fleet of certificate-only clients, with or without the requirement.
fn cert_only_policy(ca: &CompositeCaSigningKey, required: bool) -> AccessPolicy {
    let mut policy = AccessPolicy::new();
    policy.set_cert_trust(trust_of(ca)).unwrap();
    if required {
        policy
            .require_hybrid_identity(HybridRequirement::new(false, true))
            .unwrap();
    }
    policy
}

/// A12-1 (part b, flipped): the CRQC impostor pairs the victim's X25519 key with its own
/// ML-KEM key and presents the victim's classical-kind certificate v2. The crypto layer only
/// checks the binding it can check; a policy that requires hybrid identities for clients
/// refuses it (`identity_downgrade`), and so does an agent that requires them.
#[test]
fn a_crqc_impostor_with_a_classical_kind_certificate_is_refused_when_hybrid_is_required() {
    let (victim, attacker) = (id(0x51), id(0x52));
    let ca = ca(0x61, 0x62);
    let cert = certificate(&ca, CertSubject::Classical(victim.fingerprint()));
    let impostor_v2: HybridFingerprint = zt_crypto::hybrid_fingerprint_of(
        &victim.public_key().x25519(),
        attacker.hybrid_public_key().encapsulation_key(),
    );
    let claims = Arc::new(
        verify_certificate_hybrid(
            &cert,
            &victim.fingerprint(),
            Some(&impostor_v2),
            &trust_of(&ca),
        )
        .unwrap(),
    );
    let now = UnixTime::from_secs(NOW);
    // Without the requirement: admitted (the operator sees `classical_identity_match`).
    let open = cert_only_policy(&ca, false);
    assert!(
        open.admit_hybrid(
            &victim.fingerprint(),
            Some(&impostor_v2),
            Some(&claims),
            now
        )
        .is_ok()
    );
    // With it: refused, before any message 2.
    let strict = cert_only_policy(&ca, true);
    assert_eq!(
        strict
            .admit_hybrid(
                &victim.fingerprint(),
                Some(&impostor_v2),
                Some(&claims),
                now
            )
            .err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
    // The same at an agent.
    let mut clients = AuthorizedClients::new();
    clients.set_cert_trust(trust_of(&ca)).unwrap();
    clients.require_hybrid_identity().unwrap();
    assert!(clients.requires_hybrid_identity());
    assert_eq!(
        clients
            .admit_hybrid(
                &victim.fingerprint(),
                Some(&impostor_v2),
                Some(&claims),
                &node("web-01"),
                now
            )
            .err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
    // And over a classical handshake, with no hybrid identity at all.
    let classical = Arc::new(
        verify_certificate_hybrid(&cert, &victim.fingerprint(), None, &trust_of(&ca)).unwrap(),
    );
    assert_eq!(
        strict
            .admit_hybrid(&victim.fingerprint(), None, Some(&classical), now)
            .err(),
        Some(AuthFailureReason::IdentityDowngrade)
    );
}

/// A12-1 (part a, flipped): a certificate-only client has no policy entry to pin, so with the
/// requirement it is PQ-authenticated only by a hybrid-bound certificate, over a handshake
/// that proved exactly that fingerprint v2.
#[test]
fn a_certificate_only_client_is_pq_authenticated_only_by_a_hybrid_bound_certificate() {
    let alice = id(0x53);
    let ca = ca(0x63, 0x64);
    let cert = certificate(
        &ca,
        CertSubject::Hybrid {
            classical: alice.fingerprint(),
            hybrid: alice.hybrid_fingerprint(),
        },
    );
    let proved = alice.hybrid_fingerprint();
    let claims = Arc::new(
        verify_certificate_hybrid(&cert, &alice.fingerprint(), Some(&proved), &trust_of(&ca))
            .unwrap(),
    );
    let strict = cert_only_policy(&ca, true);
    let now = UnixTime::from_secs(NOW);
    assert!(matches!(
        strict.admit_hybrid(&alice.fingerprint(), Some(&proved), Some(&claims), now),
        Ok(zt_domain::Admission::Client {
            credential: ClientCredential::Certificate(_)
        })
    ));
    // Claims bound to the hybrid identity, but a handshake that proved another one (or none):
    // refused by the policy too (defence in depth behind the crypto binding).
    let other = id(0x54).hybrid_fingerprint();
    for proved in [Some(&other), None] {
        assert_eq!(
            strict
                .admit_hybrid(&alice.fingerprint(), proved, Some(&claims), now)
                .err(),
            Some(AuthFailureReason::IdentityDowngrade)
        );
    }
    // No certificate and no entry: unknown, as before.
    assert_eq!(
        strict
            .admit_hybrid(&alice.fingerprint(), Some(&proved), None, now)
            .err(),
        Some(AuthFailureReason::UnknownPeer)
    );
}

/// A12-1: once the requirement is set, an entry of a required role that is not pinned in v2
/// is refused when the policy is built, not warned about at the first connection.
#[test]
fn a_v1_entry_of_a_required_role_is_refused() {
    let (agent, alice) = (id(0x55), id(0x56));
    let mut policy = AccessPolicy::new();
    policy
        .add_agent(agent.fingerprint(), node("web-01"))
        .unwrap();
    policy
        .pin_hybrid(agent.fingerprint(), agent.hybrid_fingerprint())
        .unwrap();
    policy
        .add_client(
            alice.fingerprint(),
            zt_domain::ClientGrant {
                name: node("alice"),
                allowed: AllowedNodes::All,
            },
        )
        .unwrap();
    // Agents only: the v1 client entry is allowed.
    let mut agents_only = policy.clone();
    agents_only
        .require_hybrid_identity(HybridRequirement::new(true, false))
        .unwrap();
    assert_eq!(
        agents_only.hybrid_requirement(),
        HybridRequirement::new(true, false)
    );
    // Clients too: the v1 client entry is an error.
    assert_eq!(
        policy.require_hybrid_identity(HybridRequirement::new(true, true)),
        Err(DomainError::HybridIdentityRequired(alice.fingerprint()))
    );
    let mut clients = AuthorizedClients::new();
    clients.add_client(alice.fingerprint()).unwrap();
    assert_eq!(
        clients.require_hybrid_identity(),
        Err(DomainError::HybridIdentityRequired(alice.fingerprint()))
    );
}

/// A12-4 (flipped): a responder that does not accept the hybrid IK suite (an agent in Phase
/// 0 of the runbook) does not identify a hybrid IK message 1: that would need a decapsulation
/// with its long-term ML-KEM key. The initiator gets the generic failure.
#[test]
fn an_unaccepted_hybrid_ik_message_1_is_never_decapsulated() {
    let (client, agent) = (id(0x41), id(0x42));
    let agent_pin = PeerKey::from(agent.hybrid_public_key());
    let (msg1, _) =
        noise::initiate_suite(&client, &agent_pin, Channel::EndToEnd, HYBRID, &[]).unwrap();
    let ring = Keyring::single(agent);
    for accepted in [
        AcceptedSuites::only(CLASSIC),
        AcceptedSuites::only(HFS),
        AcceptedSuites::new([CLASSIC, HFS]).unwrap(),
    ] {
        assert!(
            noise::respond_or_identify(&ring, &msg1, Channel::EndToEnd, accepted).is_err(),
            "{accepted:?}"
        );
    }
    // The classical and IKhfs suites are still identified (A9-3).
    let (classical, _) =
        noise::initiate_suite(&client, &agent_pin, Channel::EndToEnd, CLASSIC, &[]).unwrap();
    assert!(matches!(
        noise::respond_or_identify(&ring, &classical, Channel::EndToEnd, AcceptedSuites::only(HFS))
            .unwrap(),
        Responded::Unaccepted(found) if found.suite() == CLASSIC
    ));
}

/// A12-5 (flipped): two composite CA keys that share their ML-DSA-65 half are refused, in one
/// entry and across entries (AP-13: component keys are never reused).
#[test]
fn a_shared_ml_dsa_component_is_refused() {
    let (a, b) = (ca(0x01, 0x77), ca(0x02, 0x77));
    assert_eq!(a.public_key().mldsa(), b.public_key().mldsa());
    let ka = trusted_composite_ca_key(&a.public_key()).unwrap();
    let kb = trusted_composite_ca_key(&b.public_key()).unwrap();
    let mut same_entry = CertTrust::new();
    assert!(
        same_entry
            .add_authority(
                node("ca"),
                &[ka.clone(), kb.clone()],
                AllowedNodes::All,
                28_800
            )
            .is_err()
    );
    let mut two_entries = CertTrust::new();
    two_entries
        .add_authority(node("ca-a"), &[ka], AllowedNodes::All, 28_800)
        .unwrap();
    assert!(
        two_entries
            .add_authority(node("ca-b"), &[kb], AllowedNodes::All, 28_800)
            .is_err()
    );
    // Distinct halves are still fine.
    let mut distinct = CertTrust::new();
    distinct
        .add_authority(
            node("ca"),
            &[
                trusted_composite_ca_key(&ca(0x03, 0x78).public_key()).unwrap(),
                trusted_composite_ca_key(&ca(0x04, 0x79).public_key()).unwrap(),
            ],
            AllowedNodes::All,
            28_800,
        )
        .unwrap();
}

/// The classical responder of the release before PQ-AUTH: one `snow` trial per key. This is
/// the baseline of the PQ-3 budget (pq.md §7: unauthenticated-msg1 cost ≤ 2.5× baseline).
fn baseline_trial(seeds: &[[u8; 32]], msg1: &[u8]) {
    for seed in seeds {
        let secret = ed25519_dalek::SigningKey::from_bytes(seed).to_scalar_bytes();
        let mut state = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .prologue(b"TCN/1 outer")
            .unwrap()
            .local_private_key(&secret)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut out = vec![0_u8; msg1.len()];
        assert!(state.read_message(msg1, &mut out).is_err());
    }
}

/// A12-6: an invalid message 1 of a length that fits every suite, at a responder that accepts
/// all three suites, costs at most 2.5× the classical responder of the release before PQ-AUTH
/// with the same keys (one key, and two during a rotation). Timing: run with
/// `cargo test --release -p zt-crypto --test adversary_0012 -- --ignored --nocapture`. The
/// counted-operations version of this property runs in every build (`noise.rs` unit tests).
#[test]
#[ignore = "timing: run in release mode"]
fn the_union_of_suites_stays_within_the_unauthenticated_msg1_budget() {
    const ROUNDS: u32 = 1_000;
    let mut garbage = vec![0_u8; 4_000];
    getrandom::fill(&mut garbage).unwrap();
    let all = AcceptedSuites::new([CLASSIC, HFS, HYBRID]).unwrap();
    let mut ratios = Vec::new();
    for seeds in [vec![[0x71_u8; 32]], vec![[0x72; 32], [0x73; 32]]] {
        let ring = match seeds.as_slice() {
            [one] => Keyring::single(Identity::from_secret_hex(&hex::encode(one)).unwrap()),
            [a, b] => Keyring::rotating(
                Identity::from_secret_hex(&hex::encode(a)).unwrap(),
                Identity::from_secret_hex(&hex::encode(b)).unwrap(),
            )
            .unwrap(),
            _ => unreachable!(),
        };
        // Best of three runs of each, interleaved: a shared machine is noisy.
        let (mut base, mut union) = (f64::MAX, f64::MAX);
        for _ in 0..3 {
            let start = Instant::now();
            for _ in 0..ROUNDS {
                baseline_trial(&seeds, &garbage[..160]);
            }
            base = base.min(start.elapsed().as_secs_f64());
            let start = Instant::now();
            for _ in 0..ROUNDS {
                assert!(noise::respond_suites(&ring, &garbage, Channel::Outer, all).is_err());
            }
            union = union.min(start.elapsed().as_secs_f64());
        }
        let per = |t: f64| t * 1e6 / f64::from(ROUNDS);
        println!(
            "A12-6: {} key(s): classical baseline {:.0} us, all suites {:.0} us ({:.2}x)",
            seeds.len(),
            per(base),
            per(union),
            union / base
        );
        ratios.push(union / base);
    }
    for ratio in ratios {
        assert!(ratio <= 2.5, "{ratio:.2}x over the 2.5x budget");
    }
}
