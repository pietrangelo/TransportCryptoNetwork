//! Visibilità delle chiavi in uso (PROTOCOL §14, finding 0005-3).
//!
//! Una chiave precedente lasciata attiva per errore allunga la vita di una chiave che si voleva
//! ritirare: per questo il processo dichiara all'avvio (e a ogni ricarica) quali fingerprint
//! accetta, e ricorda periodicamente finché una precedente è ancora accettata.

use std::time::Duration;

use zt_crypto::Keyring;

use crate::Revocable;

/// Ogni quanto si ricorda che una chiave precedente è ancora accettata.
pub const ROTATION_REMINDER: Duration = Duration::from_secs(60 * 60);

/// Registra le fingerprint delle chiavi accettate (evento `keys_in_use`).
pub fn announce(role: &'static str, keys: &Keyring) {
    let current = keys.current().fingerprint().to_string();
    if let Some(previous) = keys.previous() {
        tracing::warn!(
            target: "zt_audit",
            event_kind = "keys_in_use",
            role,
            current_fingerprint = %current,
            previous_fingerprint = %previous.fingerprint(),
            "keys in use: a previous key is still accepted; drop it when the rotation is complete"
        );
    } else {
        tracing::info!(
            target: "zt_audit",
            event_kind = "keys_in_use",
            role,
            current_fingerprint = %current,
            previous_fingerprint = "none",
            "keys in use"
        );
    }
}

/// Annuncia le chiavi, poi le riannuncia a ogni sostituzione; finché c'è una chiave precedente,
/// ogni `every` registra `previous_key_still_accepted`. Non ritorna.
pub async fn watch(role: &'static str, mut keys: Revocable<Keyring>, every: Duration) {
    loop {
        let current = keys.current();
        announce(role, &current);
        let reminders = async {
            let Some(previous) = current.previous() else {
                return std::future::pending::<()>().await;
            };
            let previous = previous.fingerprint().to_string();
            loop {
                tokio::time::sleep(every).await;
                tracing::warn!(
                    target: "zt_audit",
                    event_kind = "previous_key_still_accepted",
                    role,
                    previous_fingerprint = %previous,
                    "a previous key is still accepted: complete the rotation and remove it"
                );
            }
        };
        tokio::select! {
            () = keys.changed() => {}
            () = reminders => {}
        }
    }
}
