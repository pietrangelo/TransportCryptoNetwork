//! R-6 efficiency, specification of the sans-IO parts (resilience.md §5.6, review 0007 AP-22,
//! D-13): the receive-window tuner and the choice of the connection the relay's global byte
//! budget sheds.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use zt_application::efficiency::{Backlog, ShedCause, ShedLimits, WindowTuner, shed_victim};
use zt_application::relay::ConnId;
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};

#[test]
fn the_tuner_starts_at_the_initial_window() {
    let t = WindowTuner::new();
    assert_eq!(t.target(), INITIAL_WINDOW);
    assert_eq!(t.update_threshold(), INITIAL_WINDOW / 4);
}

/// A receiver with a backlog (its local reader is the bottleneck) is not window-limited: no
/// growth.
#[test]
fn no_growth_while_the_reader_lags() {
    let mut t = WindowTuner::new();
    t.on_delivered(INITIAL_WINDOW * 4);
    assert_eq!(t.wants_growth(INITIAL_WINDOW / 2), 0);
}

/// A receiver that kept up (it waited on an empty queue) while a full window was delivered is
/// limited by the window, not by its reader: the window doubles, once per full window
/// delivered, up to `MAX_WINDOW`.
#[test]
fn a_stalled_sender_doubles_the_window_up_to_the_maximum() {
    let mut t = WindowTuner::new();
    // Before a full window was delivered, a stall says nothing yet.
    t.on_delivered(INITIAL_WINDOW / 2);
    assert_eq!(t.wants_growth(0), 0);
    t.on_delivered(INITIAL_WINDOW / 2);
    let g = t.wants_growth(1024);
    assert_eq!(g, INITIAL_WINDOW);
    t.grew(g);
    assert_eq!(t.target(), 2 * INITIAL_WINDOW);
    assert_eq!(t.update_threshold(), INITIAL_WINDOW / 2);
    // Not again until another full (larger) window is delivered.
    t.on_delivered(INITIAL_WINDOW);
    assert_eq!(t.wants_growth(0), 0);
    t.on_delivered(INITIAL_WINDOW);
    let g = t.wants_growth(0);
    assert_eq!(g, 2 * INITIAL_WINDOW);
    t.grew(g);
    assert_eq!(t.target(), MAX_WINDOW);
    t.on_delivered(MAX_WINDOW);
    assert_eq!(t.wants_growth(0), 0, "never past MAX_WINDOW");
}

/// A growth the budget refused leaves the window as it is; the tuner may ask again after the
/// next full window.
#[test]
fn a_refused_growth_changes_nothing() {
    let mut t = WindowTuner::new();
    t.on_delivered(INITIAL_WINDOW);
    assert!(t.wants_growth(0) > 0);
    t.refused();
    assert_eq!(t.target(), INITIAL_WINDOW);
    assert_eq!(t.wants_growth(0), 0, "asks again only after another window");
    t.on_delivered(INITIAL_WINDOW);
    assert!(t.wants_growth(0) > 0);
}

proptest! {
    /// Whatever the sequence, the target stays within [INITIAL_WINDOW, MAX_WINDOW] and a
    /// requested growth never takes it past MAX_WINDOW (R6-E4: the receiver never grants
    /// beyond the rules every peer and the relay enforce).
    #[test]
    fn the_target_stays_within_bounds(
        steps in proptest::collection::vec((0_u32..2 * MAX_WINDOW, 0_u32..MAX_WINDOW, any::<bool>()), 0..200)
    ) {
        let mut t = WindowTuner::new();
        for (delivered, backlog, accept) in steps {
            t.on_delivered(delivered);
            let g = t.wants_growth(backlog);
            prop_assert!(t.target().checked_add(g).is_some_and(|w| w <= MAX_WINDOW));
            if g > 0 {
                if accept { t.grew(g) } else { t.refused() }
            }
            prop_assert!(t.target() >= INITIAL_WINDOW && t.target() <= MAX_WINDOW);
            prop_assert!(t.update_threshold() >= INITIAL_WINDOW / 4);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Relay byte budget (D-13): which connection is shed
// ---------------------------------------------------------------------------------------------

/// Limits for the unit tests: a budget of 1000 bytes, a single connection may hold up to 100
/// (so the identity cap is a quarter of the budget, 250), an agent's normal credit is 300.
fn limits() -> ShedLimits {
    ShedLimits::new(1000, 100, 300)
}

fn client(conn: u64, identity: u8, bytes: usize) -> Backlog<u8> {
    Backlog {
        conn: ConnId(conn),
        identity,
        agent: false,
        bytes,
    }
}

#[test]
fn nothing_is_shed_within_the_budget() {
    let backlogs = [client(1, 1, 200), client(2, 2, 200)];
    assert_eq!(shed_victim(400, &limits(), backlogs), None);
    let backlogs = [
        client(1, 1, 250),
        client(2, 2, 250),
        client(3, 3, 250),
        client(4, 4, 250),
    ];
    assert_eq!(shed_victim(1000, &limits(), backlogs), None);
}

/// Over the budget the identity with the largest backlog (the slowest reader) is shed, never
/// one of the others; with one connection per identity this is the largest connection.
#[test]
fn the_largest_backlog_is_shed() {
    let backlogs = [
        client(1, 1, 200),
        client(2, 2, 240),
        client(3, 3, 230),
        client(4, 4, 220),
        client(5, 5, 160),
    ];
    let shed = shed_victim(1050, &limits(), backlogs).unwrap();
    assert_eq!(
        (shed.conn, shed.identity, shed.cause),
        (ConnId(2), 2, ShedCause::Budget)
    );
    assert_eq!(shed.identity_bytes, 240);
}

/// Ties go to the newest connection: a long-lived one is not dropped for a newcomer's equal
/// backlog.
#[test]
fn ties_shed_the_newest_connection() {
    let backlogs = [
        client(7, 1, 240),
        client(3, 2, 240),
        client(4, 3, 240),
        client(5, 4, 240),
        client(6, 5, 240),
    ];
    assert_eq!(
        shed_victim(1200, &limits(), backlogs).unwrap().conn,
        ConnId(7)
    );
}

/// A connection with nothing queued is never shed, even over the budget (the total may lag
/// behind the per-connection counts for an instant).
#[test]
fn an_empty_backlog_is_never_shed() {
    let backlogs = [client(1, 1, 0), client(2, 2, 0)];
    assert_eq!(shed_victim(2000, &limits(), backlogs), None);
}
