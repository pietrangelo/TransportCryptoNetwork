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
use zt_application::efficiency::{WindowTuner, shed_victim};
use zt_application::relay::ConnId;
use zt_domain::flow::{INITIAL_WINDOW, MAX_WINDOW};

#[test]
fn the_tuner_starts_at_the_initial_window() {
    let t = WindowTuner::new();
    assert_eq!(t.target(), INITIAL_WINDOW);
    assert_eq!(t.update_threshold(), INITIAL_WINDOW / 4);
}

/// A sender with plenty of credit left is not window-limited: no growth.
#[test]
fn no_growth_while_the_sender_has_credit() {
    let mut t = WindowTuner::new();
    t.on_delivered(INITIAL_WINDOW * 4);
    assert_eq!(t.wants_growth(INITIAL_WINDOW / 2), 0);
}

/// A sender that ran its window nearly dry while this side kept up is limited by the window:
/// the window doubles, once per full window delivered, up to `MAX_WINDOW`.
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
        for (delivered, peer_credit, accept) in steps {
            t.on_delivered(delivered);
            let g = t.wants_growth(peer_credit);
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

#[test]
fn nothing_is_shed_within_the_budget() {
    let backlogs = [(ConnId(1), 500), (ConnId(2), 400)];
    assert_eq!(shed_victim(900, 1000, backlogs), None);
    assert_eq!(shed_victim(1000, 1000, backlogs), None);
}

/// Over the budget the connection with the largest backlog (the slowest reader) is shed, never
/// one of the others.
#[test]
fn the_largest_backlog_is_shed() {
    let backlogs = [(ConnId(1), 100), (ConnId(2), 900), (ConnId(3), 50)];
    assert_eq!(shed_victim(1050, 1000, backlogs), Some(ConnId(2)));
}

/// Ties go to the newest connection: a long-lived one is not dropped for a newcomer's equal
/// backlog.
#[test]
fn ties_shed_the_newest_connection() {
    let backlogs = [(ConnId(7), 600), (ConnId(3), 600)];
    assert_eq!(shed_victim(1200, 1000, backlogs), Some(ConnId(7)));
}

/// A connection with nothing queued is never shed, even over the budget (the total may lag
/// behind the per-connection counts for an instant).
#[test]
fn an_empty_backlog_is_never_shed() {
    let backlogs = [(ConnId(1), 0), (ConnId(2), 0)];
    assert_eq!(shed_victim(2000, 1000, backlogs), None);
}
