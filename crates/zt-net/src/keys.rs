//! Visibility of the keys in use (PROTOCOL §14, finding 0005-3).
//!
//! A previous key left active by mistake extends the life of a key that was meant to be
//! retired: for this reason the process declares at startup (and on every reload) which
//! fingerprints it accepts, and periodically reminds while a previous one is still accepted.
//!
//! The same applies to agent keys in the relay policy: a node with two keys
//! (`public_keys = [new, old]`) has an incomplete rotation, and the old key remains valid for
//! registering as that node (finding 0005b-2).

use std::time::Duration;

use zt_crypto::Keyring;
use zt_domain::trust::CertTrust;
use zt_domain::{AccessPolicy, AuthorizedClients};

use crate::Revocable;

/// How often to remind that a previous key is still accepted.
pub const ROTATION_REMINDER: Duration = Duration::from_secs(60 * 60);

/// Logs the fingerprints of the accepted keys (`keys_in_use` event).
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

/// Announces the keys, then re-announces them on every replacement; while there is a previous
/// key, logs `previous_key_still_accepted` every `every`. Never returns.
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

/// Logs an `agent_rotation_pending` for every node in the policy with two agent keys.
/// Returns how many there are.
pub fn announce_agent_rotations(policy: &AccessPolicy) -> usize {
    let mut pending: usize = 0;
    for (node, keys) in policy.agent_keys() {
        if keys.len() < 2 {
            continue;
        }
        // Stable order in the logs: fingerprints have no natural order.
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

/// Reports incomplete agent rotations in the policy at startup and on every reload; while one
/// remains, repeats them every `every`. Never returns.
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

/// A configuration that pins CAs: the relay policy or the authorized clients of an agent.
pub trait CertTrustSource {
    /// The pinned CAs and the denylist.
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

/// The fingerprints of a CA's keys, in a stable order.
fn fingerprints(keys: &[zt_domain::trust::TrustedCaKey]) -> String {
    let mut all: Vec<String> = keys.iter().map(|k| k.fingerprint.to_string()).collect();
    all.sort_unstable();
    all.join(",")
}

/// Logs `authorities_in_use` for every CA and `revocations_in_use` with the denylist counts
/// (PROTOCOL §15.11). Only names, fingerprints and counts: never keys, serials or certificates.
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

/// Logs a `ca_rotation_pending` for every CA with two keys. Returns how many there are.
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

/// Announces CAs and denylist at startup and on every replacement; while a CA has two keys,
/// logs `ca_rotation_pending` immediately and every `every`. Never returns.
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
