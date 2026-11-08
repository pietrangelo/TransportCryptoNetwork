//! I client che un agent accetta end-to-end: whitelist per chiave e CA pinnate
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

/// Client autorizzati di un agent.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedClients {
    keys: HashSet<Fingerprint>,
    trust: CertTrust,
}

impl AuthorizedClients {
    /// Nessun client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Aggiunge una chiave alla whitelist.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] se la chiave è già presente o è la chiave di una CA.
    pub fn add_client(&mut self, key: Fingerprint) -> Result<(), DomainError> {
        if self.trust.ca_fingerprints().any(|ca| ca == key) || !self.keys.insert(key) {
            return Err(DomainError::DuplicatePeer(key));
        }
        Ok(())
    }

    /// Imposta le CA pinnate e la denylist.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] se una chiave di CA è anche una chiave di client.
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError> {
        if let Some(ca) = trust.ca_fingerprints().find(|ca| self.keys.contains(ca)) {
            return Err(DomainError::DuplicatePeer(ca));
        }
        self.trust = trust;
        Ok(())
    }

    /// Le CA pinnate e la denylist.
    #[must_use]
    pub const fn cert_trust(&self) -> &CertTrust {
        &self.trust
    }

    /// `true` se la chiave è nella whitelist (senza considerare la denylist).
    #[must_use]
    pub fn contains_key(&self, key: &Fingerprint) -> bool {
        self.keys.contains(key)
    }

    /// Passi 1, 2, 5, 7–10 e 12 di PROTOCOL §15.4.
    ///
    /// # Errors
    /// Il motivo del rifiuto, per l'audit.
    pub fn admit(
        &self,
        peer: &Fingerprint,
        cert: Option<&Arc<CertClaims>>,
        node: &NodeId,
        now: UnixTime,
    ) -> Result<ClientCredential, AuthFailureReason> {
        // Passo 1.
        if self.trust.is_key_revoked(peer) {
            return Err(AuthFailureReason::KeyRevoked);
        }
        let Some(claims) = cert else {
            // Passo 2: solo la whitelist decide.
            return if self.keys.contains(peer) {
                Ok(ClientCredential::Key)
            } else {
                Err(AuthFailureReason::UnknownPeer)
            };
        };
        if claims.subject() != peer {
            return Err(AuthFailureReason::Certificate(CertRejection::KeyMismatch));
        }
        // Passi 5 e 7–10, anche per una chiave della whitelist (fail closed).
        let authority = self
            .trust
            .check(claims, now)
            .map_err(AuthFailureReason::Certificate)?;
        // La whitelist ha la precedenza: il certificato è solo verificato.
        if self.keys.contains(peer) {
            return Ok(ClientCredential::Key);
        }
        // Passo 12.
        if !authority.permits(claims, node) {
            return Err(AuthFailureReason::Certificate(
                CertRejection::NodeOutOfScope,
            ));
        }
        Ok(ClientCredential::Certificate(Arc::clone(claims)))
    }

    /// Per la revoca a caldo e la scadenza: la credenziale vale ancora?
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
    /// Una whitelist da un elenco di chiavi (duplicati ignorati), senza CA.
    fn from_iter<I: IntoIterator<Item = Fingerprint>>(keys: I) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            trust: CertTrust::default(),
        }
    }
}
