//! Credit-based flow control (HTTP/2 style), rules shared by relay, agent and client.
//!
//! Each direction of each stream has a credit window in bytes. The sender of a `Data` frame
//! consumes credit equal to [`charge`] of the payload length; the receiver returns credit
//! with `WindowUpdate` after delivering the data. The relay enforces the same rules and
//! closes whoever violates them: so the memory queued towards a peer is bounded by
//! construction to `streams × window`, whatever the other peers do.

/// Initial credit of each direction of each stream: 256 KiB.
pub const INITIAL_WINDOW: u32 = 256 * 1024;

/// Maximum credit that can accumulate: 1 MiB. Granting more is a violation.
///
/// Bounds the memory a receiver can get the relay to queue for it to
/// `streams × MAX_WINDOW` (64 MiB for an agent with the default limits).
pub const MAX_WINDOW: u32 = 1024 * 1024;

/// Minimum cost of a `Data` frame, even if it is shorter.
///
/// Without a minimum cost, `INITIAL_WINDOW` one-byte frames would fill the queues with
/// hundreds of thousands of allocations (finding 10 of review 0001). With 512 bytes the number
/// of in-flight frames per stream is at most `INITIAL_WINDOW / MIN_CHARGE = 512`.
pub const MIN_CHARGE: u32 = 512;

/// Minimum credit that can be granted with a single `WindowUpdate`.
///
/// Prevents a flood of `WindowUpdate` frames of one credit each (finding 11).
pub const MIN_WINDOW_UPDATE: u32 = MIN_CHARGE;

/// Credit consumed by a `Data` payload of `len` bytes.
#[must_use]
pub fn charge(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX).max(MIN_CHARGE)
}

/// The credit of one direction of a stream.
///
/// All operations are checked: no overflow, no values beyond [`MAX_WINDOW`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window(u32);

impl Window {
    /// The initial window.
    #[must_use]
    pub const fn initial() -> Self {
        Self(INITIAL_WINDOW)
    }

    /// Bytes still available.
    #[must_use]
    pub const fn available(self) -> u32 {
        self.0
    }

    /// Consumes the credit of a `Data` frame of `len` bytes.
    ///
    /// # Errors
    /// The name of the violated rule if the credit is insufficient.
    pub fn consume(&mut self, len: usize) -> Result<(), &'static str> {
        self.0 = self
            .0
            .checked_sub(charge(len))
            .ok_or("data exceeds flow-control window")?;
        Ok(())
    }

    /// Adds credit received with a `WindowUpdate`.
    ///
    /// # Errors
    /// The name of the violated rule if the update is too small or takes the window
    /// beyond [`MAX_WINDOW`].
    pub fn grant(&mut self, credit: u32) -> Result<(), &'static str> {
        if credit < MIN_WINDOW_UPDATE {
            return Err("window update below minimum");
        }
        self.0 = self
            .0
            .checked_add(credit)
            .filter(|&w| w <= MAX_WINDOW)
            .ok_or("window update exceeds maximum window")?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn small_frames_pay_the_minimum_charge() {
        assert_eq!(charge(0), MIN_CHARGE);
        assert_eq!(charge(1), MIN_CHARGE);
        assert_eq!(charge(4096), 4096);
    }

    #[test]
    fn window_bounds_the_number_of_tiny_frames() {
        let mut w = Window::initial();
        let mut frames = 0_u32;
        while w.consume(1).is_ok() {
            frames += 1;
        }
        assert_eq!(frames, INITIAL_WINDOW / MIN_CHARGE);
    }

    #[test]
    fn consume_beyond_credit_is_rejected_and_leaves_window_unchanged() {
        let mut w = Window::initial();
        w.consume(INITIAL_WINDOW as usize).unwrap();
        assert!(w.consume(1).is_err());
        assert_eq!(w.available(), 0);
    }

    #[test]
    fn grant_rejects_tiny_updates_and_overflow() {
        let mut w = Window::initial();
        assert!(w.grant(1).is_err());
        assert!(w.grant(MAX_WINDOW).is_err());
        assert!(w.grant(u32::MAX).is_err());
        assert_eq!(w.available(), INITIAL_WINDOW);
        w.grant(MAX_WINDOW - INITIAL_WINDOW).unwrap();
        assert_eq!(w.available(), MAX_WINDOW);
    }
}
