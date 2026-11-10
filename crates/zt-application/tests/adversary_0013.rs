//! Adversary review 0013, A13-1 (medium): the relay's byte budget shed the *connection* with
//! the largest backlog, so one identity that spread its backlog over many connections
//! (`max_per_identity = 512`) got an honest slow-link download shed first, again and again, and
//! an agent holding its normal credit could be shed before an abuser. Shedding is now fair per
//! authenticated identity: the identity holding the most of the budget is shed, no identity may
//! hold more than its share, and an agent's normal credit is shed only as a last resort.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use zt_application::efficiency::{Backlog, IDENTITY_SHARE, ShedCause, ShedLimits, shed_victim};
use zt_application::relay::ConnId;

const MIB: usize = 1024 * 1024;

fn conn(id: u64, identity: u32, agent: bool, bytes: usize) -> Backlog<u32> {
    Backlog {
        conn: ConnId(id),
        identity,
        agent,
        bytes,
    }
}

/// Production-like limits: the smallest default budget (128 MiB), 32 client streams and 64
/// agent streams of at most 1 MiB each.
fn production() -> ShedLimits {
    ShedLimits::new(128 * MIB, 64 * MIB, 64 * MIB)
}

/// The reproducer of the review, flipped: one honest connection with a 2 MiB backlog, 40
/// attacker connections of one identity with 1.9 MiB each. The attacker's identity is shed,
/// never the honest connection, however many times the relay sheds.
#[test]
fn a_split_backlog_sheds_the_abusing_identity_not_the_honest_connection() {
    let honest = conn(1, 1, false, 2 * MIB);
    let mut backlogs: Vec<_> = (0..40u64)
        .map(|i| conn(100 + i, 666, false, 19 * MIB / 10))
        .collect();
    backlogs.push(honest);
    let limits = ShedLimits::new(64 * MIB, 32 * MIB, 64 * MIB);
    loop {
        let total: usize = backlogs.iter().map(|b| b.bytes).sum();
        let Some(shed) = shed_victim(total, &limits, backlogs.iter().copied()) else {
            break;
        };
        assert_ne!(shed.conn, ConnId(1), "the honest connection was shed");
        assert_eq!(shed.identity, 666);
        backlogs.retain(|b| b.conn != shed.conn);
    }
    assert!(backlogs.iter().any(|b| b.conn == ConnId(1)));
}

/// No identity may hold more than its share of the budget, even while the budget as a whole
/// has room: past the cap the identity is shed at once.
#[test]
fn an_identity_over_its_share_is_shed_within_the_budget() {
    let limits = production();
    assert_eq!(limits.identity_cap, 64 * MIB);
    let backlogs: Vec<_> = (0..40u64)
        .map(|i| conn(10 + i, 7, false, 17 * MIB / 10))
        .chain([conn(1, 1, false, MIB)])
        .collect();
    let total: usize = backlogs.iter().map(|b| b.bytes).sum();
    assert!(total < limits.budget);
    let shed = shed_victim(total, &limits, backlogs).unwrap();
    assert_eq!(shed.identity, 7);
    assert_eq!(shed.cause, ShedCause::IdentityCap);
    assert!(shed.identity_bytes > limits.identity_cap);
}

/// The share is a quarter of the budget, but never less than one connection's full credit: a
/// single well-behaved connection is never over its identity's cap.
#[test]
fn the_identity_cap_is_a_share_of_the_budget_but_at_least_one_connection() {
    assert_eq!(IDENTITY_SHARE, 4);
    assert_eq!(
        ShedLimits::new(1024 * MIB, 64 * MIB, 64 * MIB).identity_cap,
        256 * MIB
    );
    assert_eq!(
        ShedLimits::new(128 * MIB, 64 * MIB, 64 * MIB).identity_cap,
        64 * MIB
    );
    assert_eq!(
        ShedLimits::new(MIB, 64 * MIB, 64 * MIB).identity_cap,
        64 * MIB
    );
}

/// An agent within its normal credit (its streams × 1 MiB) is not shed while a client identity
/// holds more than its own normal share: the old rule shed the agent, the largest connection,
/// and with it every session of that node on this relay.
#[test]
fn an_agent_within_its_normal_credit_is_not_shed_for_a_client() {
    let limits = production();
    let backlogs = [
        conn(1, 1, true, 63 * MIB),
        conn(2, 2, false, 40 * MIB),
        conn(3, 3, false, 30 * MIB),
    ];
    let shed = shed_victim(133 * MIB, &limits, backlogs).unwrap();
    assert_eq!(shed.identity, 2);
    assert!(!shed.agent);
}

/// An agent beyond its normal credit (it granted more than its streams allow, or holds several
/// connections) is shed like anyone else.
#[test]
fn an_agent_beyond_its_normal_credit_can_be_shed() {
    let limits = ShedLimits::new(100 * MIB, 64 * MIB, 32 * MIB);
    let backlogs = [
        conn(1, 1, true, 60 * MIB),
        conn(2, 2, false, 20 * MIB),
        conn(3, 3, false, 25 * MIB),
    ];
    let shed = shed_victim(105 * MIB, &limits, backlogs).unwrap();
    assert_eq!(shed.identity, 1);
    assert!(shed.agent);
}

/// When only agents within their credit hold the budget, the budget still holds: the largest is
/// shed (the last resort, which the minimum budget makes need at least two stalled agents).
#[test]
fn agents_alone_over_the_budget_are_shed_as_a_last_resort() {
    let limits = production();
    let backlogs = [
        conn(1, 1, true, 64 * MIB),
        conn(2, 2, true, 60 * MIB),
        conn(3, 3, true, 10 * MIB),
    ];
    let shed = shed_victim(134 * MIB, &limits, backlogs).unwrap();
    assert_eq!(shed.identity, 1);
}

/// Within the identity that is shed, its largest connection goes first.
#[test]
fn the_largest_connection_of_the_shed_identity_goes_first() {
    let limits = ShedLimits::new(1000, 100, 300);
    let backlogs = [
        Backlog {
            conn: ConnId(1),
            identity: 9_u8,
            agent: false,
            bytes: 90,
        },
        Backlog {
            conn: ConnId(2),
            identity: 9,
            agent: false,
            bytes: 95,
        },
        Backlog {
            conn: ConnId(3),
            identity: 9,
            agent: false,
            bytes: 80,
        },
        Backlog {
            conn: ConnId(4),
            identity: 1,
            agent: false,
            bytes: 99,
        },
    ];
    let shed = shed_victim(364, &limits, backlogs).unwrap();
    assert_eq!(
        (shed.conn, shed.identity_bytes, shed.cause),
        (ConnId(2), 265, ShedCause::IdentityCap)
    );
}
