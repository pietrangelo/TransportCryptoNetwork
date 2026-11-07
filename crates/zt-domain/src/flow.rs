//! Controllo di flusso a credito (stile HTTP/2), regole condivise da relay, agent e client.
//!
//! Ogni direzione di ogni stream ha una finestra di credito in byte. Chi invia un `Data`
//! consuma credito pari a [`charge`] della lunghezza del payload; chi riceve restituisce
//! credito con `WindowUpdate` dopo aver consegnato i dati. Il relay applica le stesse regole
//! e chiude chi le viola: così la memoria in coda verso un peer è limitata per costruzione a
//! `stream × finestra`, qualunque cosa facciano gli altri peer.

/// Credito iniziale di ogni direzione di ogni stream: 256 KiB.
pub const INITIAL_WINDOW: u32 = 256 * 1024;

/// Credito massimo accumulabile: 16 MiB. Concederne di più è una violazione.
pub const MAX_WINDOW: u32 = 16 * 1024 * 1024;

/// Costo minimo di un frame `Data`, anche se più corto.
///
/// Senza costo minimo, `INITIAL_WINDOW` frame da un byte riempirebbero le code con
/// centinaia di migliaia di allocazioni (finding 10 della review 0001). Con 512 byte il numero
/// di frame in volo per stream è al più `INITIAL_WINDOW / MIN_CHARGE = 512`.
pub const MIN_CHARGE: u32 = 512;

/// Credito minimo concedibile con un singolo `WindowUpdate`.
///
/// Impedisce il flood di `WindowUpdate` da un credito ciascuno (finding 11).
pub const MIN_WINDOW_UPDATE: u32 = MIN_CHARGE;

/// Credito consumato da un payload `Data` lungo `len` byte.
#[must_use]
pub fn charge(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX).max(MIN_CHARGE)
}

/// Il credito di una direzione di uno stream.
///
/// Tutte le operazioni sono controllate: niente overflow, niente valori oltre [`MAX_WINDOW`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window(u32);

impl Window {
    /// La finestra iniziale.
    #[must_use]
    pub const fn initial() -> Self {
        Self(INITIAL_WINDOW)
    }

    /// Byte ancora disponibili.
    #[must_use]
    pub const fn available(self) -> u32 {
        self.0
    }

    /// Consuma il credito di un frame `Data` da `len` byte.
    ///
    /// # Errors
    /// Il nome della regola violata se il credito non basta.
    pub fn consume(&mut self, len: usize) -> Result<(), &'static str> {
        self.0 = self
            .0
            .checked_sub(charge(len))
            .ok_or("data exceeds flow-control window")?;
        Ok(())
    }

    /// Aggiunge credito ricevuto con un `WindowUpdate`.
    ///
    /// # Errors
    /// Il nome della regola violata se l'aggiornamento è troppo piccolo o porta la finestra
    /// oltre [`MAX_WINDOW`].
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
