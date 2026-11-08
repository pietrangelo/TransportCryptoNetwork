//! Valori di configurazione sostituibili a caldo (revoca senza riavvio).

use std::sync::Arc;

use tokio::sync::watch;

/// Lato di lettura di un valore che può essere sostituito mentre il processo gira (policy del
/// relay, client autorizzati di un agent). Clonabile; ogni copia vede l'ultimo valore.
#[derive(Debug, Clone)]
pub struct Revocable<T> {
    rx: watch::Receiver<Arc<T>>,
}

/// Lato di scrittura: sostituisce il valore e sveglia chi lo osserva.
#[derive(Debug)]
pub struct Updater<T> {
    tx: watch::Sender<Arc<T>>,
}

impl<T> Revocable<T> {
    /// Un valore sostituibile e il suo [`Updater`].
    #[must_use]
    pub fn new(value: T) -> (Self, Updater<T>) {
        let (tx, rx) = watch::channel(Arc::new(value));
        (Self { rx }, Updater { tx })
    }

    /// Un valore che non cambierà mai.
    #[must_use]
    pub fn fixed(value: T) -> Self {
        Self::new(value).0
    }

    /// Il valore attuale.
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        Arc::clone(&self.rx.borrow())
    }

    /// Attende la prossima sostituzione. Per un valore fisso (o se l'[`Updater`] è stato
    /// eliminato) non ritorna mai.
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
    /// Sostituisce il valore.
    pub fn replace(&self, value: T) {
        self.tx.send_replace(Arc::new(value));
    }
}
