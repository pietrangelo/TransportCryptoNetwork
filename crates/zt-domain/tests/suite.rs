//! PQ-0 specification: handshake suites, accepted sets per role, message sizes per suite
//! (PROTOCOL §7.5, finding AP-7) and the corrected message 1 bound (side finding of the plan).
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects, missing_docs)]

use zt_domain::limits::{
    MAX_CERT_LEN, MAX_PAYLOAD_LEN, NOISE_MAX_MESSAGE_LEN, NOISE_MSG1_OVERHEAD,
};
use zt_domain::{
    AcceptedSuites, DomainEvent, Fingerprint, HandshakeSuite, InitiatorRole, SuiteError,
    SuitePolicy,
};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

#[test]
fn the_classical_suite_is_todays_noise_ik() {
    assert_eq!(CLASSIC.protocol_name(), "Noise_IK_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(CLASSIC.to_string(), "Noise_IK_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(CLASSIC.id(), 0x00);
    assert!(CLASSIC.is_supported());
}

#[test]
fn the_hybrid_suite_is_reserved_but_not_supported_yet() {
    assert_eq!(
        HFS.protocol_name(),
        "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s"
    );
    assert_eq!(HFS.id(), 0x01);
    assert!(!HFS.is_supported(), "PQ-1 enables it, not PQ-0");
}

#[test]
fn suite_names_and_ids_round_trip() {
    for suite in HandshakeSuite::ALL {
        assert_eq!(suite.protocol_name().parse::<HandshakeSuite>(), Ok(suite));
        assert_eq!(HandshakeSuite::try_from(suite.id()), Ok(suite));
    }
    let ids: Vec<u8> = HandshakeSuite::ALL.iter().map(|s| s.id()).collect();
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "one id per suite");
}

/// Side finding of the plan: `NOISE_MSG1_OVERHEAD` already contains the payload tag, so the
/// longest message 1 is `96 + 4 328`, the value the agent enforces, not `96 + 4 328 + 16`.
#[test]
fn classical_message_sizes_are_exact() {
    assert_eq!(NOISE_MSG1_OVERHEAD, 32 + (32 + 16) + 16);
    assert_eq!(CLASSIC.msg1_overhead(), NOISE_MSG1_OVERHEAD);
    assert_eq!(CLASSIC.max_msg1_len(), 96 + MAX_CERT_LEN);
    assert_eq!(CLASSIC.max_msg1_len(), 4_424);
    // msg2: e (32) + empty payload tag (16).
    assert_eq!(CLASSIC.msg2_len(), 48);
}

/// IKhfs (PROTOCOL §7.5): `e1` (1 184, in clear) after `e`; `ekem1` (1 088 + 16) in msg2.
#[test]
fn hybrid_message_sizes_are_those_of_the_plan() {
    assert_eq!(HFS.msg1_overhead(), 32 + 1_184 + (32 + 16) + 16);
    assert_eq!(HFS.msg1_overhead(), 1_280);
    assert_eq!(HFS.max_msg1_len(), 1_280 + MAX_CERT_LEN);
    assert_eq!(HFS.msg2_len(), 32 + (1_088 + 16) + 16);
    assert_eq!(HFS.msg2_len(), 1_152);
}

#[test]
fn every_suite_fits_a_noise_message_and_a_data_frame() {
    for suite in HandshakeSuite::ALL {
        assert!(suite.max_msg1_len() <= MAX_PAYLOAD_LEN, "{suite}");
        assert!(suite.max_msg1_len() <= NOISE_MAX_MESSAGE_LEN, "{suite}");
        assert!(suite.msg2_len() <= NOISE_MAX_MESSAGE_LEN, "{suite}");
    }
}

#[test]
fn an_accepted_set_is_explicit_and_non_empty() {
    let set = AcceptedSuites::new([CLASSIC]).unwrap();
    assert!(set.contains(CLASSIC));
    assert!(!set.contains(HFS));
    assert_eq!(set.iter().collect::<Vec<_>>(), vec![CLASSIC]);
    assert_eq!(set, AcceptedSuites::only(CLASSIC));
    assert!(set.all_supported());
    assert_eq!(AcceptedSuites::new([]), Err(SuiteError::Empty));
    assert_eq!(
        AcceptedSuites::new([CLASSIC, CLASSIC]),
        Err(SuiteError::Duplicate)
    );
}

#[test]
fn a_set_with_a_reserved_suite_is_representable_but_not_supported() {
    // The domain can describe it (PQ-1 tests use it); configuration refuses it in this build.
    let set = AcceptedSuites::new([CLASSIC, HFS]).unwrap();
    assert!(set.contains(HFS));
    assert!(!set.all_supported());
}

#[test]
fn the_message_1_cap_is_the_largest_legitimate_message_of_the_set() {
    assert_eq!(AcceptedSuites::only(CLASSIC).max_msg1_len(), 4_424);
    assert_eq!(AcceptedSuites::only(HFS).max_msg1_len(), 5_608);
    assert_eq!(
        AcceptedSuites::new([CLASSIC, HFS]).unwrap().max_msg1_len(),
        5_608
    );
}

#[test]
fn the_relay_accepts_suites_per_role() {
    let policy = SuitePolicy {
        agents: AcceptedSuites::only(CLASSIC),
        clients: AcceptedSuites::new([CLASSIC, HFS]).unwrap(),
    };
    assert_eq!(policy.check(InitiatorRole::Agent, CLASSIC), Ok(()));
    assert_eq!(policy.check(InitiatorRole::Client, HFS), Ok(()));
    assert_eq!(
        policy.check(InitiatorRole::Agent, HFS),
        Err(SuiteError::Unsupported)
    );
    assert_eq!(policy.for_role(InitiatorRole::Agent), policy.agents);
    assert_eq!(policy.for_role(InitiatorRole::Client), policy.clients);
    // Before the role is known, every suite of either set is worth trying.
    assert_eq!(policy.any_role(), policy.agents.union(policy.clients));
    assert!(policy.any_role().contains(HFS));
}

#[test]
fn the_default_policy_is_the_classical_suite_for_both_roles() {
    let policy = SuitePolicy::classical();
    assert_eq!(policy.agents, AcceptedSuites::only(CLASSIC));
    assert_eq!(policy.clients, AcceptedSuites::only(CLASSIC));
}

#[test]
fn a_rejected_suite_is_a_named_security_event() {
    let event = DomainEvent::HandshakeSuiteRejected {
        peer: Fingerprint::from_bytes([7; 32]),
        suite: HFS,
    };
    assert_eq!(event.kind(), "handshake_suite_rejected");
    assert!(event.is_security_alert());
}
