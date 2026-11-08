//! Fiducia nei certificati: CA pinnate, denylist, controlli 5 e 7–10 di PROTOCOL §15.4.

use std::collections::HashSet;

use crate::cert::{CertClaims, CertKey, CertRejection, CertScope, CertSerial, UnixTime};
use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::ids::NodeId;
use crate::limits::{
    CERT_CLOCK_SKEW_SECS, MAX_AUTHORITIES, MAX_AUTHORITY_KEYS, MAX_CERT_LIFETIME_SECS,
    MAX_REVOKED_KEYS, MAX_REVOKED_SERIALS, MIN_AUTHORITY_LIFETIME_SECS,
};
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
        let in_cert = match claims.scope() {
            CertScope::All => true,
            CertScope::Only(nodes) => nodes.contains(node),
        };
        in_cert && self.allowed.permits(node)
    }

    /// `true` se `key` è una delle chiavi pinnate di questa CA (byte per byte).
    fn pins(&self, key: &CertKey) -> bool {
        self.keys.iter().any(|k| k.key == *key)
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
        // L'insieme non supera mai il limite di più di una voce: memoria limitata qualunque
        // sia l'iteratore.
        let mut set_serials = HashSet::new();
        for serial in serials {
            set_serials.insert(serial);
            if set_serials.len() > MAX_REVOKED_SERIALS {
                return Err(DomainError::TooManyRevocations { what: "serials" });
            }
        }
        let mut set_keys = HashSet::new();
        for key in keys {
            set_keys.insert(key);
            if set_keys.len() > MAX_REVOKED_KEYS {
                return Err(DomainError::TooManyRevocations { what: "keys" });
            }
        }
        Ok(Self {
            serials: set_serials,
            keys: set_keys,
        })
    }

    /// `true` se la chiave è revocata.
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        self.keys.contains(key)
    }

    /// `true` se il numero di serie è revocato.
    #[must_use]
    pub fn is_serial_revoked(&self, serial: &CertSerial) -> bool {
        self.serials.contains(serial)
    }

    /// `(serials, keys)`: quante voci.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.serials.len(), self.keys.len())
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
        // Tutti i controlli prima di qualsiasi modifica: nessun effetto parziale.
        let distinct = match keys {
            [_] => true,
            [a, b] => a.key != b.key && a.fingerprint != b.fingerprint,
            _ => false,
        };
        if !distinct || keys.len() > MAX_AUTHORITY_KEYS {
            return Err(DomainError::AuthorityKeys(name));
        }
        if !(MIN_AUTHORITY_LIFETIME_SECS..=MAX_CERT_LIFETIME_SECS).contains(&max_lifetime_secs) {
            return Err(DomainError::AuthorityLifetime {
                secs: max_lifetime_secs,
            });
        }
        if self.authorities.len() >= MAX_AUTHORITIES {
            return Err(DomainError::TooManyAuthorities);
        }
        if self.authorities.iter().any(|a| a.name == name) {
            return Err(DomainError::DuplicateAuthority(name));
        }
        // Una chiave di CA in una sola voce, confrontata sia per byte sia per fingerprint
        // (`P` e `−P` hanno la stessa fingerprint).
        for key in keys {
            let taken = self
                .authorities
                .iter()
                .flat_map(|a| a.keys.iter())
                .any(|k| k.key == key.key || k.fingerprint == key.fingerprint);
            if taken {
                return Err(DomainError::DuplicatePeer(key.fingerprint));
            }
        }
        self.authorities.push(Authority {
            name,
            keys: keys.to_vec(),
            allowed,
            max_lifetime_secs,
        });
        Ok(())
    }

    /// Imposta la denylist.
    pub fn set_revocations(&mut self, revocations: Revocations) {
        self.revocations = Some(revocations);
    }

    /// `true` se non c'è nessuna CA.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    /// `true` se ci sono CA ma nessuna denylist: la configurazione non è avviabile.
    #[must_use]
    pub fn needs_revocations(&self) -> bool {
        !self.authorities.is_empty() && self.revocations.is_none()
    }

    /// La CA che pinna esattamente questi 32 byte.
    #[must_use]
    pub fn authority_for_key(&self, key: &CertKey) -> Option<&Authority> {
        self.authorities.iter().find(|a| a.pins(key))
    }

    /// Le fingerprint di tutte le chiavi di CA.
    pub fn ca_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.authorities
            .iter()
            .flat_map(|a| a.keys.iter().map(|k| k.fingerprint))
    }

    /// `true` se la chiave è nella denylist (`keys`).
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|r| r.is_key_revoked(key))
    }

    /// Passi 5 e 7–10 di PROTOCOL §15.4, nell'ordine.
    ///
    /// # Errors
    /// Il primo controllo che fallisce.
    pub fn check(&self, claims: &CertClaims, now: UnixTime) -> Result<&Authority, CertRejection> {
        // Passo 5: la CA che pinna esattamente `ca_key`.
        let authority = self
            .authority_for_key(claims.ca_key())
            .ok_or(CertRejection::UnknownAuthority)?;
        // Passo 7. Senza denylist (configurazione non avviabile, `needs_revocations`) nessuna
        // serie si può dire non revocata: fail closed.
        let serial_revoked = self
            .revocations
            .as_ref()
            .is_none_or(|r| r.is_serial_revoked(&claims.serial()));
        if serial_revoked {
            return Err(CertRejection::SerialRevoked);
        }
        // Passo 8: tolleranza solo su `not_before`, senza underflow.
        if now < claims.not_before().saturating_sub(CERT_CLOCK_SKEW_SECS) {
            return Err(CertRejection::NotYetValid);
        }
        // Passo 9: `not_after` escluso, mai esteso.
        if now >= claims.not_after() {
            return Err(CertRejection::Expired);
        }
        // Passo 10.
        let lifetime = claims
            .not_after()
            .as_secs()
            .saturating_sub(claims.not_before().as_secs());
        if lifetime > authority.max_lifetime_secs {
            return Err(CertRejection::LifetimeExceedsAuthority);
        }
        Ok(authority)
    }

    /// Le CA con due chiavi (rotazione non completata).
    pub fn rotations_pending(&self) -> impl Iterator<Item = (&NodeId, &[TrustedCaKey])> {
        self.authorities
            .iter()
            .filter(|a| a.keys.len() > 1)
            .map(|a| (&a.name, a.keys.as_slice()))
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
