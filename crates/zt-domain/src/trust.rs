//! Fiducia nei certificati: CA pinnate, denylist, controlli 5 e 7–10 di PROTOCOL §15.4.
//!
//! **Fase 6, RED**: stub che rifiutano sempre (fail closed).

use std::collections::HashSet;

use crate::cert::{CertClaims, CertKey, CertRejection, CertSerial, UnixTime};
use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::ids::NodeId;
use crate::policy::AllowedNodes;

/// Una chiave pubblica di CA pinnata: i 32 byte (confronto byte per byte con `ca_key`) e la
/// fingerprint (forma X25519, per i conflitti con le chiavi dei peer e per i log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedCaKey {
    /// I 32 byte Ed25519, già validati come punto canonico e non debole da `zt-crypto`.
    pub key: CertKey,
    /// La fingerprint della chiave.
    pub fingerprint: Fingerprint,
}

/// Una voce `[[authorities]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    name: NodeId,
    keys: Vec<TrustedCaKey>,
    allowed: AllowedNodes,
    max_lifetime_secs: u64,
}

impl Authority {
    /// Nome della CA (solo per i log).
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// Una o due chiavi.
    #[must_use]
    pub fn keys(&self) -> &[TrustedCaKey] {
        &self.keys
    }

    /// I nodi che la CA può concedere.
    #[must_use]
    pub const fn allowed(&self) -> &AllowedNodes {
        &self.allowed
    }

    /// Durata massima dei certificati di questa CA.
    #[must_use]
    pub const fn max_lifetime_secs(&self) -> u64 {
        self.max_lifetime_secs
    }

    /// `true` se `node` è in `ambito(cert) ∩ allow` (PROTOCOL §15.5).
    #[must_use]
    pub fn permits(&self, claims: &CertClaims, node: &NodeId) -> bool {
        // RED: stub, non concede nulla.
        let _ = (claims, node);
        false
    }
}

/// La denylist (`revoked.toml`, PROTOCOL §15.8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    serials: HashSet<CertSerial>,
    keys: HashSet<Fingerprint>,
}

impl Revocations {
    /// Una denylist entro i limiti.
    ///
    /// # Errors
    /// [`DomainError::TooManyRevocations`] oltre `MAX_REVOKED_SERIALS` o `MAX_REVOKED_KEYS`.
    pub fn new(
        serials: impl IntoIterator<Item = CertSerial>,
        keys: impl IntoIterator<Item = Fingerprint>,
    ) -> Result<Self, DomainError> {
        // RED: stub, rifiuta sempre.
        let _ = (serials.into_iter(), keys.into_iter());
        Err(DomainError::TooManyRevocations { what: "serials" })
    }

    /// `true` se la chiave è revocata.
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        // RED: stub, tutto revocato.
        let _ = (key, &self.keys);
        true
    }

    /// `true` se il numero di serie è revocato.
    #[must_use]
    pub fn is_serial_revoked(&self, serial: &CertSerial) -> bool {
        // RED: stub, tutto revocato.
        let _ = (serial, &self.serials);
        true
    }

    /// `(serials, keys)`: quante voci.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        // RED: stub.
        (0, 0)
    }
}

/// Le CA pinnate di una configurazione e la sua denylist.
#[derive(Debug, Clone, Default)]
pub struct CertTrust {
    authorities: Vec<Authority>,
    revocations: Option<Revocations>,
}

impl CertTrust {
    /// Nessuna CA, nessuna denylist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Aggiunge una CA (PROTOCOL §15.9: vincoli di caricamento).
    ///
    /// # Errors
    /// [`DomainError::AuthorityKeys`], [`DomainError::DuplicateAuthority`],
    /// [`DomainError::AuthorityLifetime`], [`DomainError::TooManyAuthorities`],
    /// [`DomainError::DuplicatePeer`] per una chiave già in un'altra CA.
    pub fn add_authority(
        &mut self,
        name: NodeId,
        keys: &[TrustedCaKey],
        allowed: AllowedNodes,
        max_lifetime_secs: u64,
    ) -> Result<(), DomainError> {
        // RED: stub, rifiuta sempre.
        let _ = (keys, allowed, max_lifetime_secs);
        Err(DomainError::AuthorityKeys(name))
    }

    /// Imposta la denylist.
    pub fn set_revocations(&mut self, revocations: Revocations) {
        // RED: stub, la denylist non entra.
        drop(revocations);
    }

    /// `true` se non c'è nessuna CA.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    /// `true` se ci sono CA ma nessuna denylist: la configurazione non è avviabile.
    #[must_use]
    pub fn needs_revocations(&self) -> bool {
        // RED: stub, fail closed.
        let _ = &self.revocations;
        true
    }

    /// La CA che pinna esattamente questi 32 byte.
    #[must_use]
    pub fn authority_for_key(&self, key: &CertKey) -> Option<&Authority> {
        // RED: stub.
        let _ = key;
        None
    }

    /// Le fingerprint di tutte le chiavi di CA.
    pub fn ca_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        // RED: stub.
        core::iter::empty()
    }

    /// `true` se la chiave è nella denylist (`keys`).
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        // RED: stub, fail closed.
        let _ = key;
        true
    }

    /// Passi 5 e 7–10 di PROTOCOL §15.4, nell'ordine.
    ///
    /// # Errors
    /// Il primo controllo che fallisce.
    pub fn check(&self, claims: &CertClaims, now: UnixTime) -> Result<&Authority, CertRejection> {
        // RED: stub, rifiuta sempre.
        let _ = (claims, now);
        Err(CertRejection::Malformed)
    }

    /// Le CA con due chiavi (rotazione non completata).
    pub fn rotations_pending(&self) -> impl Iterator<Item = (&NodeId, &[TrustedCaKey])> {
        // RED: stub.
        core::iter::empty()
    }

    /// Le CA, in ordine d'inserimento.
    pub fn authorities(&self) -> impl Iterator<Item = &Authority> {
        self.authorities.iter()
    }

    /// La denylist, se impostata.
    #[must_use]
    pub const fn revocations(&self) -> Option<&Revocations> {
        self.revocations.as_ref()
    }
}
