//! Finding A8-7: the admission state machine under arbitrary event sequences. Whatever the
//! order of accepts, confirmations, releases, failures and summaries, the bookkeeping stays
//! consistent and no limit is exceeded. The `admission` fuzz target drives the same code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    missing_docs
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use proptest::prelude::*;
use zt_application::admission::{
    Admission, AdmissionConfig, IdentityEvent, PreauthFailure, Refusal, Ticket,
};
use zt_domain::{AuthFailureReason, Fingerprint, InitiatorRole};

#[derive(Debug, Clone)]
enum Op {
    Accept { source: u8 },
    Confirm { pick: u8, peer: u8, agent: bool },
    Release { pick: u8 },
    Record { source: u8 },
    Note { peer: u8 },
    Advance { millis: u16 },
    Poll,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => any::<u8>().prop_map(|source| Op::Accept { source }),
        3 => (any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(pick, peer, agent)| Op::Confirm { pick, peer, agent }),
        3 => any::<u8>().prop_map(|pick| Op::Release { pick }),
        1 => any::<u8>().prop_map(|source| Op::Record { source }),
        1 => any::<u8>().prop_map(|peer| Op::Note { peer }),
        1 => any::<u16>().prop_map(|millis| Op::Advance { millis }),
        1 => Just(Op::Poll),
    ]
}

/// Sources in few IPv4 addresses and few IPv6 /48s, so that every cap is reached.
fn source(n: u8) -> IpAddr {
    if n % 2 == 0 {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, n % 8))
    } else {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            u16::from(n % 3),
            u16::from(n),
            0,
            0,
            0,
            1,
        ))
    }
}

fn small() -> AdmissionConfig {
    AdmissionConfig {
        max_preauth: 16,
        max_established: 12,
        max_per_identity: 4,
        source_burst: 6,
        max_pending_per_source: 3,
        max_pending_per_wide: 5,
        identity_refund_burst: 4,
        agent_reserve_percent: 25,
        ..AdmissionConfig::default()
    }
}

proptest! {
    #[test]
    fn admission_bookkeeping_is_consistent(ops in prop::collection::vec(op(), 1..400)) {
        let config = small();
        prop_assert_eq!(config.validate(), Ok(()));
        let t0 = Instant::now();
        let mut now = t0;
        let mut a = Admission::new(config.clone(), t0);
        let mut live: Vec<Ticket> = Vec::new();
        let mut confirmed: HashSet<Ticket> = HashSet::new();
        for op in ops {
            match op {
                Op::Accept { source: s } => {
                    if let Ok(t) = a.on_accept(source(s), now) {
                        prop_assert!(!live.contains(&t), "a ticket is never reused");
                        live.push(t);
                    }
                }
                Op::Confirm { pick, peer, agent } => {
                    if live.is_empty() { continue; }
                    let t = live[usize::from(pick) % live.len()];
                    let role = if agent { InitiatorRole::Agent } else { InitiatorRole::Client };
                    let peer = Fingerprint::from_bytes([peer % 6; 32]);
                    match a.on_confirmed(t, peer, role, now) {
                        Ok(()) => prop_assert!(confirmed.insert(t), "confirmed twice"),
                        // A confirmed ticket is never pending again.
                        Err(refusal) => prop_assert!(
                            !confirmed.contains(&t) || refusal == Refusal::UnknownTicket
                        ),
                    }
                }
                Op::Release { pick } => {
                    if live.is_empty() { continue; }
                    let t = live.swap_remove(usize::from(pick) % live.len());
                    confirmed.remove(&t);
                    a.release(t);
                    // Releasing twice is harmless.
                    a.release(t);
                }
                Op::Record { source: s } => {
                    a.record(PreauthFailure::Unconfirmed, source(s), None);
                }
                Op::Note { peer } => {
                    let ev = IdentityEvent::AuthenticationFailed(AuthFailureReason::KeyRevoked);
                    let _ = a.note_identity_event(Fingerprint::from_bytes([peer; 32]), ev);
                }
                Op::Advance { millis } => now += Duration::from_millis(u64::from(millis)),
                Op::Poll => {
                    let _ = a.poll_summary(now);
                }
            }
            prop_assert_eq!(a.check_invariants(), Ok(()));
            prop_assert!(a.preauth_count() <= config.max_preauth);
            prop_assert!(a.established_count() <= config.max_established);
            prop_assert_eq!(a.established_count(), confirmed.len());
            prop_assert!(a.preauth_count() + a.established_count() <= live.len());
        }
        for t in live {
            a.release(t);
        }
        prop_assert_eq!((a.preauth_count(), a.established_count()), (0, 0));
        prop_assert_eq!(a.check_invariants(), Ok(()));
    }
}
