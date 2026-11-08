//! Le chiavi di un responder durante una rotazione: la corrente e, facoltativa, la precedente.

use crate::error::CryptoError;
use crate::identity::Identity;

/// Chiave corrente e chiave precedente di un responder (PROTOCOL §14).
///
/// Come initiator si usa sempre la corrente; come responder si accetta un `msg1` cifrato
/// verso l'una o l'altra. Non è `Clone`: contiene segreti.
#[derive(Debug)]
pub struct Keyring {
    current: Identity,
    previous: Option<Identity>,
}

impl Keyring {
    /// Un keyring con una sola chiave.
    #[must_use]
    pub const fn single(current: Identity) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Chiave corrente più quella precedente.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] se le due chiavi coincidono: una rotazione verso la stessa
    /// chiave è quasi sempre un errore di configurazione (file sbagliato).
    pub fn rotating(current: Identity, previous: Identity) -> Result<Self, CryptoError> {
        if current.fingerprint() == previous.fingerprint() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            current,
            previous: Some(previous),
        })
    }

    /// La chiave corrente.
    #[must_use]
    pub const fn current(&self) -> &Identity {
        &self.current
    }

    /// La chiave precedente, se c'è una rotazione in corso.
    #[must_use]
    pub const fn previous(&self) -> Option<&Identity> {
        self.previous.as_ref()
    }
}

impl From<Identity> for Keyring {
    fn from(current: Identity) -> Self {
        Self::single(current)
    }
}
