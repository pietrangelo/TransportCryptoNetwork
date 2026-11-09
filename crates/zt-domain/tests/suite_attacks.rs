//! PQ-0 attack catalogue, domain (pq.md §7 PQ-0: parsing of unknown suite values; AP-7 no
//! ordering, no implied suites; AP-11 nothing on the wire).
#![allow(clippy::unwrap_used, missing_docs)]

use zt_domain::{AcceptedSuites, HandshakeSuite, InitiatorRole, SuiteError, SuitePolicy};

const CLASSIC: HandshakeSuite = HandshakeSuite::NoiseIk25519;
const HFS: HandshakeSuite = HandshakeSuite::NoiseIkhfs25519MlKem768;

/// Parsing: every byte that is not a suite id is refused, including the next ones a future
/// version might assign.
#[test]
fn unknown_suite_ids_are_refused() {
    let known: Vec<u8> = HandshakeSuite::ALL.iter().map(|s| s.id()).collect();
    for b in 0..=u8::MAX {
        if !known.contains(&b) {
            assert_eq!(HandshakeSuite::try_from(b), Err(SuiteError::Unknown), "{b}");
        }
    }
}

/// Parsing / malleability: one spelling per suite. No case folding, trimming, aliases,
/// numbers or prefixes, so two configuration files that look different never mean the same.
#[test]
fn a_suite_has_exactly_one_spelling() {
    for text in [
        "",
        "0",
        "1",
        "v1",
        "classic",
        "noise_ik_25519_chachapoly_blake2s",
        "NOISE_IK_25519_CHACHAPOLY_BLAKE2S",
        " Noise_IK_25519_ChaChaPoly_BLAKE2s",
        "Noise_IK_25519_ChaChaPoly_BLAKE2s ",
        "Noise_IK_25519_ChaChaPoly_BLAKE2s\0",
        "Noise_IK_25519_ChaChaPoly_BLAKE2",
        "Noise_IK_25519_ChaChaPoly_BLAKE2b",
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
        "Noise_XX_25519_ChaChaPoly_BLAKE2s",
        "Noise_IKhfs_25519+Kyber1024_ChaChaPoly_BLAKE2s",
        "Noise_IKhfs_25519+MLKEM1024_ChaChaPoly_BLAKE2s",
        "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s,Noise_IK_25519_ChaChaPoly_BLAKE2s",
    ] {
        assert_eq!(
            text.parse::<HandshakeSuite>(),
            Err(SuiteError::Unknown),
            "{text:?}"
        );
    }
}

/// AP-7: accepting one suite never implies accepting another (there is no "at least").
#[test]
fn accepting_a_suite_implies_nothing_about_the_others() {
    let only_hfs = AcceptedSuites::only(HFS);
    assert!(!only_hfs.contains(CLASSIC));
    let policy = SuitePolicy {
        agents: AcceptedSuites::only(HFS),
        clients: AcceptedSuites::only(CLASSIC),
    };
    assert_eq!(
        policy.check(InitiatorRole::Agent, CLASSIC),
        Err(SuiteError::Unsupported)
    );
    assert_eq!(
        policy.check(InitiatorRole::Client, HFS),
        Err(SuiteError::Unsupported)
    );
}

/// Resources: the message 1 cap of a set is never smaller than any member's real maximum,
/// so a legitimate message is never cut, and never larger than the largest member's.
#[test]
fn the_message_1_cap_is_tight() {
    for set in [
        AcceptedSuites::only(CLASSIC),
        AcceptedSuites::only(HFS),
        AcceptedSuites::new([HFS, CLASSIC]).unwrap(),
    ] {
        let max = set.iter().map(HandshakeSuite::max_msg1_len).max().unwrap();
        assert_eq!(set.max_msg1_len(), max);
    }
}

/// The order of a configuration list carries no meaning: no preference, no ranking.
#[test]
fn the_order_of_an_accepted_list_does_not_matter() {
    assert_eq!(
        AcceptedSuites::new([CLASSIC, HFS]).unwrap(),
        AcceptedSuites::new([HFS, CLASSIC]).unwrap()
    );
}
