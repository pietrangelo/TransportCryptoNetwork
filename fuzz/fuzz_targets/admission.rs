//! The relay admission (PROTOCOL §10.1) on arbitrary sequences of accepts, key confirmations
//! of both roles, releases, failures, identity events, clock steps and summaries (finding
//! A8-7 of review 0008). The `admission_props` property test drives the same state machine.
//!
//! Properties: no panic; [`Admission::check_invariants`] holds after every event (pending,
//! per-source, per-/48, per-identity and per-role counters match the live connections, no cap
//! is exceeded); a ticket is never confirmed twice; every connection released leaves the
//! pools empty.
#![no_main]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use zt_application::admission::{
    Admission, AdmissionConfig, IdentityEvent, PreauthFailure, Refusal, Ticket,
};
use zt_domain::{AuthFailureReason, Fingerprint, InitiatorRole};

fn source(n: u8) -> IpAddr {
    if n.is_multiple_of(2) {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, n % 8))
    } else {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, u16::from(n % 3), u16::from(n), 0, 0, 0, 1))
    }
}

fuzz_target!(|data: &[u8]| {
    let config = AdmissionConfig {
        max_preauth: 16,
        max_established: 12,
        max_per_identity: 4,
        source_burst: 6,
        max_pending_per_source: 3,
        max_pending_per_wide: 5,
        identity_refund_burst: 4,
        agent_reserve_percent: 25,
        ..AdmissionConfig::default()
    };
    assert_eq!(config.validate(), Ok(()));
    let t0 = Instant::now();
    let mut now = t0;
    let mut a = Admission::new(config, t0);
    let mut live: Vec<Ticket> = Vec::new();
    let mut confirmed: HashSet<Ticket> = HashSet::new();
    for pair in data.chunks_exact(2) {
        let (op, arg) = match pair {
            [op, arg] => (*op, *arg),
            _ => continue,
        };
        match op % 7 {
            0 | 1 => {
                if let Ok(t) = a.on_accept(source(arg), now) {
                    assert!(!live.contains(&t), "ticket reused");
                    live.push(t);
                }
            }
            2 => {
                if let Some(t) = live.get(usize::from(arg) % live.len().max(1)).copied() {
                    let role = if arg & 0x80 == 0 {
                        InitiatorRole::Client
                    } else {
                        InitiatorRole::Agent
                    };
                    let peer = Fingerprint::from_bytes([arg % 6; 32]);
                    match a.on_confirmed(t, peer, role, now) {
                        Ok(()) => assert!(confirmed.insert(t), "confirmed twice"),
                        Err(refusal) => {
                            assert!(!confirmed.contains(&t) || refusal == Refusal::UnknownTicket);
                        }
                    }
                }
            }
            3 => {
                if !live.is_empty() {
                    let t = live.swap_remove(usize::from(arg) % live.len());
                    confirmed.remove(&t);
                    a.release(t);
                    a.release(t);
                }
            }
            4 => {
                a.record(PreauthFailure::Unconfirmed, source(arg), None);
                let ev = IdentityEvent::AuthenticationFailed(AuthFailureReason::KeyRevoked);
                let _ = a.note_identity_event(Fingerprint::from_bytes([arg; 32]), ev);
            }
            5 => now += Duration::from_millis(u64::from(arg) * 50),
            _ => {
                let _ = a.poll_summary(now);
            }
        }
        assert_eq!(a.check_invariants(), Ok(()));
        assert_eq!(a.established_count(), confirmed.len());
    }
    for t in live {
        a.release(t);
    }
    assert_eq!((a.preauth_count(), a.established_count()), (0, 0));
    assert_eq!(a.check_invariants(), Ok(()));
});
