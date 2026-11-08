//! Visibilità delle chiavi in uso (PROTOCOL §14, finding 0005-3).
//!
//! Una chiave precedente lasciata attiva per errore allunga la vita di una chiave che si voleva
//! ritirare: per questo il processo dichiara all'avvio (e a ogni ricarica) quali fingerprint
//! accetta, e ricorda periodicamente finché una precedente è ancora accettata.
//!
//! Lo stesso vale per le chiavi di agent nella policy del relay: un nodo con due chiavi
//! (`public_keys = [nuova, vecchia]`) ha una rotazione non completata, e la chiave vecchia
//! resta valida per registrarsi come quel nodo (finding 0005b-2).

use std::time::Duration;

use zt_crypto::Keyring;
use zt_domain::trust::CertTrust;
use zt_domain::{AccessPolicy, AuthorizedClients};

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

/// Registra un `agent_rotation_pending` per ogni nodo della policy con due chiavi di agent.
/// Restituisce quanti sono.
pub fn announce_agent_rotations(policy: &AccessPolicy) -> usize {
    let mut pending: usize = 0;
    for (node, keys) in policy.agent_keys() {
        if keys.len() < 2 {
            continue;
        }
        // Ordine stabile nei log: le fingerprint non hanno un ordine proprio.
        let mut fingerprints: Vec<String> = keys.iter().map(ToString::to_string).collect();
        fingerprints.sort_unstable();
        tracing::warn!(
            target: "zt_audit",
            event_kind = "agent_rotation_pending",
            %node,
            fingerprints = %fingerprints.join(","),
            "an agent key rotation is not complete: remove the old key from the policy"
        );
        pending = pending.saturating_add(1);
    }
    pending
}

/// Segnala le rotazioni di agent non completate nella policy all'avvio e a ogni ricarica;
/// finché ne resta una, le ripete ogni `every`. Non ritorna.
pub async fn watch_agent_rotations(mut policy: Revocable<AccessPolicy>, every: Duration) {
    loop {
        let current = policy.current();
        let reminders = async {
            if announce_agent_rotations(&current) == 0 {
                return std::future::pending::<()>().await;
            }
            loop {
                tokio::time::sleep(every).await;
                announce_agent_rotations(&current);
            }
        };
        tokio::select! {
            () = policy.changed() => {}
            () = reminders => {}
        }
    }
}

/// Una configurazione che pinna CA: la policy del relay o i client autorizzati di un agent.
pub trait CertTrustSource {
    /// Le CA pinnate e la denylist.
    fn cert_trust(&self) -> &CertTrust;
}

impl CertTrustSource for CertTrust {
    fn cert_trust(&self) -> &CertTrust {
        self
    }
}

impl CertTrustSource for AccessPolicy {
    fn cert_trust(&self) -> &CertTrust {
        AccessPolicy::cert_trust(self)
    }
}

impl CertTrustSource for AuthorizedClients {
    fn cert_trust(&self) -> &CertTrust {
        AuthorizedClients::cert_trust(self)
    }
}

/// Le fingerprint delle chiavi di una CA, in ordine stabile.
fn fingerprints(keys: &[zt_domain::trust::TrustedCaKey]) -> String {
    let mut all: Vec<String> = keys.iter().map(|k| k.fingerprint.to_string()).collect();
    all.sort_unstable();
    all.join(",")
}

/// Registra `authorities_in_use` per ogni CA e `revocations_in_use` con i conteggi della
/// denylist (PROTOCOL §15.11). Solo nomi, fingerprint e conteggi: mai chiavi, serie o
/// certificati.
pub fn announce_authorities(role: &'static str, trust: &CertTrust) {
    for authority in trust.authorities() {
        let fingerprints = fingerprints(authority.keys());
        let max_lifetime = authority.max_lifetime_secs();
        if authority.keys().len() > 1 {
            tracing::warn!(
                target: "zt_audit",
                event_kind = "authorities_in_use",
                role,
                authority = %authority.name(),
                fingerprints = %fingerprints,
                max_lifetime,
                "certificate authority in use with two keys: complete the rotation"
            );
        } else {
            tracing::info!(
                target: "zt_audit",
                event_kind = "authorities_in_use",
                role,
                authority = %authority.name(),
                fingerprints = %fingerprints,
                max_lifetime,
                "certificate authority in use"
            );
        }
    }
    if let Some(revocations) = trust.revocations() {
        let (serials, keys) = revocations.counts();
        tracing::info!(
            target: "zt_audit",
            event_kind = "revocations_in_use",
            role,
            serials,
            keys,
            "revocation list in use"
        );
    }
}

/// Registra un `ca_rotation_pending` per ogni CA con due chiavi. Restituisce quante sono.
fn announce_ca_rotations(role: &'static str, trust: &CertTrust) -> usize {
    let mut pending: usize = 0;
    for (name, keys) in trust.rotations_pending() {
        tracing::warn!(
            target: "zt_audit",
            event_kind = "ca_rotation_pending",
            role,
            authority = %name,
            fingerprints = %fingerprints(keys),
            "a certificate authority rotation is not complete: remove the old key"
        );
        pending = pending.saturating_add(1);
    }
    pending
}

/// Annuncia CA e denylist all'avvio e a ogni sostituzione; finché una CA ha due chiavi
/// registra `ca_rotation_pending` subito e ogni `every`. Non ritorna.
pub async fn watch_authorities<T: CertTrustSource>(
    role: &'static str,
    mut config: Revocable<T>,
    every: Duration,
) {
    loop {
        let current = config.current();
        let trust = current.cert_trust();
        announce_authorities(role, trust);
        let reminders = async {
            if announce_ca_rotations(role, trust) == 0 {
                return std::future::pending::<()>().await;
            }
            loop {
                tokio::time::sleep(every).await;
                announce_ca_rotations(role, trust);
            }
        };
        tokio::select! {
            () = config.changed() => {}
            () = reminders => {}
        }
    }
}
