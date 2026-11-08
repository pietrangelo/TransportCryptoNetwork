//! I client che un agent accetta end-to-end: whitelist per chiave e CA pinnate
//! (PROTOCOL §15.4, §15.5).
//!
//! **Fase 6, RED**: la whitelist per chiave funziona come prima (era un
//! `HashSet<Fingerprint>`); tutto ciò che riguarda i certificati è uno stub che rifiuta.

use std::collections::HashSet;
use std::sync::Arc;

use crate::cert::{CertClaims, UnixTime};
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
    /// [`DomainError::DuplicatePeer`] se la chiave è già presente.
    pub fn add_client(&mut self, key: Fingerprint) -> Result<(), DomainError> {
        if !self.keys.insert(key) {
            return Err(DomainError::DuplicatePeer(key));
        }
        Ok(())
    }

    /// Imposta le CA pinnate e la denylist.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] se una chiave di CA è anche una chiave di client.
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError> {
        // RED: stub, rifiuta sempre.
        drop(trust);
        Err(DomainError::TooManyAuthorities)
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
        // RED: stub, rifiuta sempre.
        let _ = (peer, cert, node, now);
        Err(AuthFailureReason::UnknownPeer)
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
        // RED: stub, fail closed.
        let _ = (peer, credential, node, now);
        false
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
