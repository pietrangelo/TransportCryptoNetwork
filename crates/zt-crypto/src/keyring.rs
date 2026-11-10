//! The keys of a responder during a rotation: the current one and, optionally, the previous one.

use crate::error::CryptoError;
use crate::identity::Identity;

/// Current key and previous key of a responder (PROTOCOL §14).
///
/// As initiator the current one is always used; as responder a `msg1` encrypted to either
/// one is accepted. It is not `Clone`: it contains secrets.
#[derive(Debug)]
pub struct Keyring {
    current: Identity,
    previous: Option<Identity>,
}

impl Keyring {
    /// A keyring with a single key.
    #[must_use]
    pub const fn single(current: Identity) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Current key plus the previous one.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] if the two keys are the same: a rotation to the same key
    /// is almost always a configuration error (wrong file).
    pub fn rotating(current: Identity, previous: Identity) -> Result<Self, CryptoError> {
        if current.fingerprint() == previous.fingerprint() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            current,
            previous: Some(previous),
        })
    }

    /// The current key.
    #[must_use]
    pub const fn current(&self) -> &Identity {
        &self.current
    }

    /// The previous key, if a rotation is in progress.
    #[must_use]
    pub const fn previous(&self) -> Option<&Identity> {
        self.previous.as_ref()
    }

    /// The keys a responder tries, in order: the current one, then the previous one.
    pub fn identities(&self) -> impl Iterator<Item = &Identity> {
        std::iter::once(&self.current).chain(self.previous.as_ref())
    }
}

impl From<Identity> for Keyring {
    fn from(current: Identity) -> Self {
        Self::single(current)
    }
}
