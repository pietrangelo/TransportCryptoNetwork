//! Adversary review 0009 (Phase 2, PQ-1): the per-identity line limiter of A8-2 as a value of
//! its own, so that the agent uses the same rule as the relay (finding A9-2,
//! docs/adversary/0009-phase2-pq1-e2e.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    missing_docs
)]

use zt_application::identity_lines::{IdentityEvent, IdentityLines, MAX_LOGGED_IDENTITIES};
use zt_domain::{AuthFailureReason, Fingerprint, HandshakeSuite};

fn key(n: u16) -> Fingerprint {
    let mut b = [0_u8; 32];
    b[..2].copy_from_slice(&n.to_be_bytes());
    Fingerprint::from_bytes(b)
}

/// A9-2: replays of a recorded classical message 1 at a hybrid-only agent give one full line
/// per identity and interval; the rest is counted, and the count is reported once.
#[test]
fn suite_rejections_of_one_identity_are_logged_once_then_counted() {
    let mut lines = IdentityLines::default();
    let rejected = IdentityEvent::SuiteRejected(HandshakeSuite::NoiseIk25519);
    let failed = IdentityEvent::AuthenticationFailed(AuthFailureReason::HandshakeFailed);
    let full = (0..40)
        .filter(|_| lines.note(key(1), rejected))
        .count();
    assert_eq!(full, 1);
    // Another event of the same identity, and the same event of another, are logged too.
    assert!(lines.note(key(1), failed));
    assert!(lines.note(key(2), rejected));
    let ended = lines.take();
    assert_eq!(ended.repeated.len(), 1);
    assert_eq!(
        (ended.repeated[0].peer, ended.repeated[0].event, ended.repeated[0].count),
        (key(1), rejected, 39)
    );
    assert_eq!(ended.suppressed_identities, 0);
    // A new interval starts afresh.
    assert!(lines.note(key(1), rejected));
    assert!(lines.take().repeated.is_empty());
    assert!(lines.take().is_empty());
}

/// A9-2: made-up keys cannot grow the table: beyond [`MAX_LOGGED_IDENTITIES`] identities the
/// events are only counted.
#[test]
fn the_agents_identity_table_is_bounded() {
    let mut lines = IdentityLines::default();
    let ev = IdentityEvent::AuthenticationFailed(AuthFailureReason::UnknownPeer);
    let full = (0..5_000_u16).filter(|n| lines.note(key(*n), ev)).count();
    assert_eq!(full, MAX_LOGGED_IDENTITIES);
    let ended = lines.take();
    assert_eq!(
        ended.suppressed_identities,
        (5_000 - MAX_LOGGED_IDENTITIES) as u64
    );
    assert!(ended.repeated.is_empty());
    assert!(!ended.is_empty());
}
