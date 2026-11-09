//! The clients an agent accepts end-to-end: per-key whitelist and pinned CAs
//! (PROTOCOL §15.4, §15.5).

use std::collections::HashSet;
use std::sync::Arc;

use crate::cert::{CertClaims, CertRejection, UnixTime};
use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::events::AuthFailureReason;
use crate::ids::NodeId;
use crate::policy::ClientCredential;
use crate::trust::CertTrust;

/// Authorized clients of an agent.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedClients {
    keys: HashSet<Fingerprint>,
    trust: CertTrust,
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

    /// Steps 1, 2, 5, 7–10 and 12 of PROTOCOL §15.4.
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
        // Step 1.
        if self.trust.is_key_revoked(peer) {
            return Err(AuthFailureReason::KeyRevoked);
        }
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

    /// For hot revocation and expiry: is the credential still valid?
    #[must_use]
    pub fn still_admits(
        &self,
        peer: &Fingerprint,
        credential: &ClientCredential,
        node: &NodeId,
        now: UnixTime,
    ) -> bool {
        if self.trust.is_key_revoked(peer) {
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
        }
    }
}
