//! The clients an agent accepts end-to-end: per-key whitelist and pinned CAs
//! (PROTOCOL §15.4, §15.5).

use std::collections::HashSet;
use std::sync::Arc;

use crate::cert::{CertClaims, CertRejection, UnixTime};
use crate::crypto::{Fingerprint, HybridFingerprint};
use crate::error::DomainError;
use crate::events::AuthFailureReason;
use crate::ids::NodeId;
use crate::policy::{ClientCredential, HybridPins};
use crate::trust::CertTrust;

/// Authorized clients of an agent.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedClients {
    keys: HashSet<Fingerprint>,
    trust: CertTrust,
    /// v2 pins (PQ-AUTH), keyed by the X25519-level fingerprint.
    hybrid: HybridPins,
}

impl AuthorizedClients {
    /// No clients.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key to the whitelist.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] if the key is already present or is a CA key.
    pub fn add_client(&mut self, key: Fingerprint) -> Result<(), DomainError> {
        if self.trust.ca_fingerprints().any(|ca| ca == key) || !self.keys.insert(key) {
            return Err(DomainError::DuplicatePeer(key));
        }
        Ok(())
    }

    /// Sets the pinned CAs and the denylist.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] if a CA key is also a client key.
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError> {
        if let Some(ca) = trust.ca_fingerprints().find(|ca| self.keys.contains(ca)) {
            return Err(DomainError::DuplicatePeer(ca));
        }
        self.trust = trust;
        Ok(())
    }

    /// The pinned CAs and the denylist.
    #[must_use]
    pub const fn cert_trust(&self) -> &CertTrust {
        &self.trust
    }

    /// `true` if the key is in the whitelist (without considering the denylist).
    #[must_use]
    pub fn contains_key(&self, key: &Fingerprint) -> bool {
        self.keys.contains(key)
    }

    /// Pins the v2 identity of a whitelisted key (PQ-AUTH): from then on it is admitted only
    /// through a hybrid IK handshake that proved `hybrid`.
    ///
    /// # Errors
    /// [`DomainError::UnknownPeer`] if the key is not in the whitelist,
    /// [`DomainError::DuplicatePeer`] if it is already pinned or `hybrid` is another key's.
    pub fn pin_hybrid(
        &mut self,
        key: Fingerprint,
        hybrid: HybridFingerprint,
    ) -> Result<(), DomainError> {
        if !self.keys.contains(&key) {
            return Err(DomainError::UnknownPeer(key));
        }
        self.hybrid.pin(key, hybrid)
    }

    /// The v2 identity pinned for `key`, if any.
    #[must_use]
    pub fn hybrid_identity(&self, key: &Fingerprint) -> Option<&HybridFingerprint> {
        self.hybrid.get(key)
    }

    /// [`Self::admit_hybrid`] for a handshake that proved no hybrid identity.
    ///
    /// # Errors
    /// The rejection reason, for the audit.
    pub fn admit(
        &self,
        peer: &Fingerprint,
        cert: Option<&Arc<CertClaims>>,
        node: &NodeId,
        now: UnixTime,
    ) -> Result<ClientCredential, AuthFailureReason> {
        self.admit_hybrid(peer, None, cert, node, now)
    }

    /// Steps 1, 2, 5, 7–10 and 12 of PROTOCOL §15.4, with the v2 pin of PQ-AUTH: `hybrid` is
    /// the hybrid identity the handshake proved, if any.
    ///
    /// # Errors
    /// The rejection reason, for the audit.
    pub fn admit_hybrid(
        &self,
        peer: &Fingerprint,
        hybrid: Option<&HybridFingerprint>,
        cert: Option<&Arc<CertClaims>>,
        node: &NodeId,
        now: UnixTime,
    ) -> Result<ClientCredential, AuthFailureReason> {
        // Step 1.
        if self.trust.is_key_revoked(peer) {
            return Err(AuthFailureReason::KeyRevoked);
        }
        self.hybrid.check(peer, hybrid)?;
        let Some(claims) = cert else {
            // Step 2: only the whitelist decides.
            return if self.keys.contains(peer) {
                Ok(ClientCredential::Key)
            } else {
                Err(AuthFailureReason::UnknownPeer)
            };
        };
        if claims.subject() != peer {
            return Err(AuthFailureReason::Certificate(CertRejection::KeyMismatch));
        }
        // Steps 5 and 7–10, even for a whitelisted key (fail closed).
        let authority = self
            .trust
            .check(claims, now)
            .map_err(AuthFailureReason::Certificate)?;
        // The whitelist takes precedence: the certificate is only verified.
        if self.keys.contains(peer) {
            return Ok(ClientCredential::Key);
        }
        // Step 12.
        if !authority.permits(claims, node) {
            return Err(AuthFailureReason::Certificate(
                CertRejection::NodeOutOfScope,
            ));
        }
        Ok(ClientCredential::Certificate(Arc::clone(claims)))
    }

    /// [`Self::still_admits_hybrid`] for a session without a hybrid identity.
    #[must_use]
    pub fn still_admits(
        &self,
        peer: &Fingerprint,
        credential: &ClientCredential,
        node: &NodeId,
        now: UnixTime,
    ) -> bool {
        self.still_admits_hybrid(peer, None, credential, node, now)
    }

    /// For hot revocation and expiry: is the credential still valid, and does the session's
    /// hybrid identity still satisfy the v2 pin (a reload may add one)?
    #[must_use]
    pub fn still_admits_hybrid(
        &self,
        peer: &Fingerprint,
        hybrid: Option<&HybridFingerprint>,
        credential: &ClientCredential,
        node: &NodeId,
        now: UnixTime,
    ) -> bool {
        if self.trust.is_key_revoked(peer) || self.hybrid.check(peer, hybrid).is_err() {
            return false;
        }
        match credential {
            ClientCredential::Key => self.keys.contains(peer),
            ClientCredential::Certificate(claims) => {
                claims.subject() == peer
                    && self
                        .trust
                        .check(claims, now)
                        .is_ok_and(|authority| authority.permits(claims, node))
            }
        }
    }
}

impl FromIterator<Fingerprint> for AuthorizedClients {
    /// A whitelist from a list of keys (duplicates ignored), without CAs.
    fn from_iter<I: IntoIterator<Item = Fingerprint>>(keys: I) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            trust: CertTrust::default(),
            hybrid: HybridPins::default(),
        }
    }
}
