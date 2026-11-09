//! Hot-swappable configuration values (revocation without restart).

use std::sync::Arc;

use tokio::sync::watch;

/// Read side of a value that can be replaced while the process is running (relay policy,
/// authorized clients of an agent). Cloneable; every copy sees the latest value.
#[derive(Debug)]
pub struct Revocable<T> {
    rx: watch::Receiver<Arc<T>>,
}

// Implemented by hand: the copy shares the value, so `T` need not be `Clone` (e.g. `Keyring`).
impl<T> Clone for Revocable<T> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
        }
    }
}

/// Write side: replaces the value and wakes up whoever is watching it.
#[derive(Debug)]
pub struct Updater<T> {
    tx: watch::Sender<Arc<T>>,
}

impl From<zt_crypto::Identity> for Revocable<zt_crypto::Keyring> {
    fn from(identity: zt_crypto::Identity) -> Self {
        Self::fixed(zt_crypto::Keyring::single(identity))
    }
}

impl<T> Revocable<T> {
    /// A replaceable value and its [`Updater`].
    #[must_use]
    pub fn new(value: T) -> (Self, Updater<T>) {
        let (tx, rx) = watch::channel(Arc::new(value));
        (Self { rx }, Updater { tx })
    }

    /// A value that will never change.
    #[must_use]
    pub fn fixed(value: T) -> Self {
        Self::new(value).0
    }

    /// An already shared value that will never change.
    #[must_use]
    pub fn fixed_shared(value: Arc<T>) -> Self {
        let (_tx, rx) = watch::channel(value);
        Self { rx }
    }

    /// The current value.
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        Arc::clone(&self.rx.borrow())
    }

    /// Waits for the next replacement. For a fixed value (or if the [`Updater`] has been
    /// dropped) it never returns.
    pub async fn changed(&mut self) {
        if self.rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl<T> From<T> for Revocable<T> {
    fn from(value: T) -> Self {
        Self::fixed(value)
    }
}

impl<T> Updater<T> {
    /// Replaces the value.
    pub fn replace(&self, value: T) {
        self.tx.send_replace(Arc::new(value));
    }
}
