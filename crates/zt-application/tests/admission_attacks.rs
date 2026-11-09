//! R-1 attack catalogue (resilience §7 R1-A3…A12 as corrected by AP-1, AP-2, AP-3), on the
//! sans-IO admission. Attacker models of review 0007: (a) no credentials, (b) an on-path
//! recorder that replays message 1, (c) the holder of one identity.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use zt_application::admission::{
    Admission, AdmissionConfig, MAX_DISTINCT, PreauthFailure, Refusal, is_known_identity,
};
use zt_domain::trust::{CertTrust, Revocations};
use zt_domain::{
    AccessPolicy, AllowedNodes, AuthFailureReason, CertRejection, ClientGrant, Fingerprint, NodeId,
};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}

fn key(n: u8) -> Fingerprint {
    Fingerprint::from_bytes([n; 32])
}

fn config() -> AdmissionConfig {
    AdmissionConfig {
        max_preauth: 64,
        max_established: 64,
        max_per_identity: 8,
        source_burst: 3,
        source_refill: Duration::from_secs(3),
        ..AdmissionConfig::default()
    }
}

/// AP-1 (b): a replayed message 1 gets message 2 but never confirms. Its token is not given
/// back, so replays from one address stay bounded by the burst.
#[test]
fn replayed_msg1_is_not_refunded() {
    let t0 = Instant::now();
    let mut a = Admission::new(config(), t0);
    for _ in 0..3 {
        // msg2 sent, no authentic transport frame, first-frame deadline: released.
        let t = a.on_accept(ip(1), t0).unwrap();
        a.record(PreauthFailure::Unconfirmed, ip(1), None);
        a.release(t);
    }
    assert_eq!(a.on_accept(ip(1), t0), Err(Refusal::SourceRateLimited));
}

/// AP-1 (b): unconfirmed connections never count against the established pool, so replays of
/// recorded identities cannot fill it.
#[test]
fn replayed_msg1_does_not_enter_the_authenticated_pool() {
    let t0 = Instant::now();
    let mut a = Admission::new(
        AdmissionConfig {
            max_established: 2,
            source_burst: 1_000,
            ..config()
        },
        t0,
    );
    // 60 replays from many addresses, all pending.
    let _replays: Vec<_> = (0..60).map(|n| a.on_accept(ip(n), t0).unwrap()).collect();
    assert_eq!(a.established_count(), 0);
    // The real peers still get both established slots.
    for n in 0..2 {
        let t = a.on_accept(ip(200 + n), t0).unwrap();
        a.on_confirmed(t, key(n), t0).unwrap();
    }
    assert_eq!(a.established_count(), 2);
}

/// AP-1 (b) / AP-2: replays that name a victim's identity never charge that identity, so the
/// victim can always connect.
#[test]
fn replayed_msg1_cannot_drain_the_victims_identity_budget() {
    let t0 = Instant::now();
    let mut a = Admission::new(
        AdmissionConfig {
            source_burst: 1_000,
            ..config()
        },
        t0,
    );
    let victim = key(42);
    for n in 0..50 {
        let t = a.on_accept(ip(n), t0).unwrap();
        a.record(PreauthFailure::Unconfirmed, ip(n), None);
        a.release(t);
    }
    assert_eq!(a.identity_count(&victim), 0);
    let t = a.on_accept(ip(250), t0).unwrap();
    assert!(a.on_confirmed(t, victim, t0).is_ok());
}

/// R1-A5: slow message-1 senders fill only the pre-authentication pool; confirmations of
/// handshakes already in progress and established peers are unaffected.
#[test]
fn slow_handshakes_cannot_starve_established_or_reconnecting_peers() {
    let t0 = Instant::now();
    let mut a = Admission::new(
        AdmissionConfig {
            max_preauth: 4,
            source_burst: 1_000,
            ..config()
        },
        t0,
    );
    // An agent reconnecting: its handshake is in progress.
    let agent = a.on_accept(ip(1), t0).unwrap();
    // Three slowloris connections fill the rest of the pool.
    let _slow: Vec<_> = (2..5).map(|n| a.on_accept(ip(n), t0).unwrap()).collect();
    assert_eq!(a.on_accept(ip(9), t0), Err(Refusal::PreauthPoolFull));
    // The agent completes and confirms: its slot moves to the established pool.
    assert!(a.on_confirmed(agent, key(1), t0).is_ok());
    // That frees one pre-authentication slot for the next peer.
    assert!(a.on_accept(ip(10), t0).is_ok());
}

/// R1-A4: a stolen identity cannot take the established pool, however many addresses it has.
#[test]
fn one_identity_cannot_monopolise_the_established_pool() {
    let t0 = Instant::now();
    let mut a = Admission::new(
        AdmissionConfig {
            max_established: 64,
            max_per_identity: 8,
            ..config()
        },
        t0,
    );
    let thief = key(66);
    let mut admitted = 0;
    for n in 0..100_u8 {
        let t = a.on_accept(ip(n), t0).unwrap();
        if a.on_confirmed(t, thief, t0).is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 8);
    // Neighbours on the same addresses are unaffected.
    let t = a.on_accept(ip(0), t0 + Duration::from_secs(3)).unwrap();
    assert!(a.on_confirmed(t, key(1), t0).is_ok());
}

/// R1-A7: a refused confirmation (identity limit, full pool) is not a refund; a ticket is
/// confirmed at most once and is dead after release.
#[test]
fn refund_only_after_a_successful_confirmation_and_only_once() {
    let t0 = Instant::now();
    let mut a = Admission::new(
        AdmissionConfig {
            max_per_identity: 1,
            ..config()
        },
        t0,
    );
    let first = a.on_accept(ip(1), t0).unwrap();
    a.on_confirmed(first, key(1), t0).unwrap();
    // Refused at confirmation: the token stays spent.
    let second = a.on_accept(ip(1), t0).unwrap();
    assert_eq!(
        a.on_confirmed(second, key(1), t0),
        Err(Refusal::IdentityLimit)
    );
    // Double confirmation: refused, and no second refund.
    assert_eq!(
        a.on_confirmed(first, key(2), t0),
        Err(Refusal::UnknownTicket)
    );
    // Burst 3: one refunded (first), one spent (second); so two more, then refused.
    assert!(a.on_accept(ip(1), t0).is_ok());
    assert!(a.on_accept(ip(1), t0).is_ok());
    assert_eq!(a.on_accept(ip(1), t0), Err(Refusal::SourceRateLimited));
    // After release a ticket cannot be confirmed.
    a.release(second);
    assert_eq!(
        a.on_confirmed(second, key(3), t0),
        Err(Refusal::UnknownTicket)
    );
}

/// Resources: refunds never take a bucket above its burst.
#[test]
fn refunds_never_exceed_the_burst() {
    let t0 = Instant::now();
    let mut a = Admission::new(config(), t0);
    let tickets: Vec<_> = (0..3).map(|_| a.on_accept(ip(1), t0).unwrap()).collect();
    // Long after: the bucket refilled on its own, then three refunds arrive.
    let later = t0 + Duration::from_secs(3_600);
    for (i, t) in tickets.into_iter().enumerate() {
        a.on_confirmed(t, key(i as u8), later).unwrap();
    }
    let ok = (0..10)
        .filter(|_| a.on_accept(ip(1), later).is_ok())
        .count();
    assert_eq!(ok, 3);
}

/// R1-A8 / AP-3: the summary never names an identity or an address, so its volume and its
/// content reveal nothing about which keys are known.
#[test]
fn preauth_refusals_are_aggregated_without_identities() {
    let t0 = Instant::now();
    let mut a = Admission::new(config(), t0);
    let secret_key = Fingerprint::from_bytes([0xa7; 32]);
    a.record(PreauthFailure::UnknownPeer, ip(77), Some(secret_key));
    a.record(PreauthFailure::Unconfirmed, ip(77), None);
    let summary = a.poll_summary(t0 + Duration::from_secs(10)).unwrap();
    let text = format!("{summary:?}");
    assert!(!text.contains("a7a7"), "{text}");
    assert!(!text.contains(&secret_key.to_string()), "{text}");
    assert!(!text.contains("198.51.100.77"), "{text}");
    assert!(!text.contains("[167"), "{text}");
}

/// AP-3: a Noise-speaking scanner with a fresh key per connection produces one summary per
/// interval, whatever its volume; the distinct counters are bounded and say so.
#[test]
fn noise_speaking_scanner_with_fresh_keys_cannot_crowd_out_audit_events() {
    let t0 = Instant::now();
    let mut a = Admission::new(config(), t0);
    let mut summaries = 0;
    for i in 0..100_000_u32 {
        let mut k = [0_u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        let source = IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            (i >> 16) as u16,
            i as u16,
            0,
            0,
            0,
            1,
        ));
        a.record(
            PreauthFailure::UnknownPeer,
            source,
            Some(Fingerprint::from_bytes(k)),
        );
        let now = t0 + Duration::from_millis(u64::from(i) / 10);
        if a.poll_summary(now).is_some() {
            summaries += 1;
        }
    }
    // 100 000 events over 10 s: at most two summaries (one interval ended, maybe a second).
    assert!(summaries <= 2, "{summaries}");
    let last = a.poll_summary(t0 + Duration::from_secs(60)).unwrap();
    assert!(last.distinct_keys <= MAX_DISTINCT);
    assert!(last.distinct_sources <= MAX_DISTINCT);
    assert!(last.saturated);
}

fn policy_with(known_client: Fingerprint, revoked: Fingerprint) -> AccessPolicy {
    let mut p = AccessPolicy::new();
    p.add_client(
        known_client,
        ClientGrant {
            name: NodeId::try_from("ops").unwrap(),
            allowed: AllowedNodes::All,
        },
    )
    .unwrap();
    let mut trust = CertTrust::new();
    trust.set_revocations(Revocations::new([], [revoked]).unwrap());
    p.set_cert_trust(trust).unwrap();
    p
}

/// AP-3: per-event `authentication_failed` lines only for identities the configuration knows
/// (whitelisted, revoked, or bound by a pinned CA's verified signature).
#[test]
fn only_known_identities_get_their_own_audit_line() {
    let (known, revoked, stranger) = (key(1), key(2), key(3));
    let policy = policy_with(known, revoked);
    // A fresh key of a scanner: aggregated.
    assert!(!is_known_identity(
        &policy,
        &stranger,
        AuthFailureReason::UnknownPeer
    ));
    // A certificate that failed before its signature was checked belongs to no one.
    for check in [
        CertRejection::Malformed,
        CertRejection::KeyMismatch,
        CertRejection::UnknownAuthority,
        CertRejection::BadSignature,
    ] {
        assert!(
            !is_known_identity(&policy, &stranger, AuthFailureReason::Certificate(check)),
            "{check:?}"
        );
    }
    // A certificate signed by a pinned CA (rejected after the signature): known.
    assert!(is_known_identity(
        &policy,
        &stranger,
        AuthFailureReason::Certificate(CertRejection::Expired)
    ));
    // A whitelisted or revoked key: known, whatever the reason.
    assert!(is_known_identity(
        &policy,
        &known,
        AuthFailureReason::Certificate(CertRejection::BadSignature)
    ));
    assert!(is_known_identity(
        &policy,
        &revoked,
        AuthFailureReason::KeyRevoked
    ));
}
