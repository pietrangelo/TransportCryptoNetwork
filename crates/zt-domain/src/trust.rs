//! Certificate trust: pinned CAs, denylist, checks 5 and 7–10 of PROTOCOL §15.4.

use std::collections::HashSet;
use std::sync::Arc;

use crate::cert::{
    CaFingerprint, CaKeyRef, CertClaims, CertKey, CertRejection, CertScope, CertSerial,
    MLDSA65_PUBLIC_KEY_LEN, UnixTime,
};
use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::ids::NodeId;
use crate::limits::{
    CERT_CLOCK_SKEW_SECS, MAX_AUTHORITIES, MAX_AUTHORITY_KEYS, MAX_CERT_LIFETIME_SECS,
    MAX_REVOKED_KEYS, MAX_REVOKED_SERIALS, MIN_AUTHORITY_LIFETIME_SECS,
};
use crate::policy::AllowedNodes;

/// A pinned CA public key: the 32 Ed25519 bytes (byte-by-byte comparison with `ca_key`, or
/// the Ed25519 component of a composite key) and their fingerprint (X25519 form, for conflicts
/// with peer keys and for the logs). A composite (v2) key also carries its ML-DSA-65 half and
/// its [`CaFingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCaKey {
    /// The 32 Ed25519 bytes, already validated by `zt-crypto` as a canonical, non-weak point.
    pub key: CertKey,
    /// The fingerprint of the key.
    pub fingerprint: Fingerprint,
    /// The ML-DSA-65 half of a composite (v2) key; `None` for a v1 (Ed25519) key.
    pub composite: Option<CompositeCaPin>,
}

/// The ML-DSA-65 half of a pinned composite CA key and the key's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeCaPin {
    ca_fp: CaFingerprint,
    mldsa_key: Arc<[u8]>,
}

impl CompositeCaPin {
    /// A composite pin. `ca_fp` is computed by `zt-crypto` over the whole key.
    ///
    /// # Errors
    /// [`DomainError::InvalidLength`] for an ML-DSA-65 key of the wrong length.
    pub fn new(ca_fp: CaFingerprint, mldsa_key: &[u8]) -> Result<Self, DomainError> {
        if mldsa_key.len() != MLDSA65_PUBLIC_KEY_LEN {
            return Err(DomainError::InvalidLength {
                what: "ML-DSA-65 public key",
                expected: MLDSA65_PUBLIC_KEY_LEN,
                actual: mldsa_key.len(),
            });
        }
        Ok(Self {
            ca_fp,
            mldsa_key: Arc::from(mldsa_key),
        })
    }

    /// The fingerprint of the composite key, as certificates v2 name it.
    #[must_use]
    pub const fn ca_fp(&self) -> &CaFingerprint {
        &self.ca_fp
    }

    /// The 1 952 bytes of the ML-DSA-65 public key.
    #[must_use]
    pub fn mldsa_key(&self) -> &[u8] {
        &self.mldsa_key
    }
}

impl TrustedCaKey {
    /// `true` if this pin is the key `reference` names, **with its algorithm**: an Ed25519
    /// reference never matches a composite pin, even with the same Ed25519 bytes, and vice
    /// versa (finding AP-13).
    #[must_use]
    pub fn matches(&self, reference: &CaKeyRef) -> bool {
        match (reference, &self.composite) {
            (CaKeyRef::Ed25519(key), None) => self.key == *key,
            (CaKeyRef::Composite(fp), Some(pin)) => pin.ca_fp == *fp,
            _ => false,
        }
    }

    /// The certificate version this key signs: 1 or 2.
    #[must_use]
    pub const fn version(&self) -> u8 {
        if self.composite.is_some() { 2 } else { 1 }
    }
}

/// An `[[authorities]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    name: NodeId,
    keys: Vec<TrustedCaKey>,
    allowed: AllowedNodes,
    max_lifetime_secs: u64,
}

impl Authority {
    /// Name of the CA (for the logs only).
    #[must_use]
    pub const fn name(&self) -> &NodeId {
        &self.name
    }

    /// One or two keys.
    #[must_use]
    pub fn keys(&self) -> &[TrustedCaKey] {
        &self.keys
    }

    /// The nodes the CA may grant.
    #[must_use]
    pub const fn allowed(&self) -> &AllowedNodes {
        &self.allowed
    }

    /// Maximum lifetime of this CA's certificates.
    #[must_use]
    pub const fn max_lifetime_secs(&self) -> u64 {
        self.max_lifetime_secs
    }

    /// `true` if `node` is in `scope(cert) ∩ allow` (PROTOCOL §15.5).
    #[must_use]
    pub fn permits(&self, claims: &CertClaims, node: &NodeId) -> bool {
        let in_cert = match claims.scope() {
            CertScope::All => true,
            CertScope::Only(nodes) => nodes.contains(node),
        };
        in_cert && self.allowed.permits(node)
    }

    /// The pinned key that `reference` names, with its algorithm.
    #[must_use]
    pub fn pin_for(&self, reference: &CaKeyRef) -> Option<&TrustedCaKey> {
        self.keys.iter().find(|k| k.matches(reference))
    }
}

/// The denylist (`revoked.toml`, PROTOCOL §15.8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    serials: HashSet<CertSerial>,
    keys: HashSet<Fingerprint>,
}

impl Revocations {
    /// A denylist within the limits.
    ///
    /// # Errors
    /// [`DomainError::TooManyRevocations`] beyond `MAX_REVOKED_SERIALS` or `MAX_REVOKED_KEYS`.
    pub fn new(
        serials: impl IntoIterator<Item = CertSerial>,
        keys: impl IntoIterator<Item = Fingerprint>,
    ) -> Result<Self, DomainError> {
        // The set never exceeds the limit by more than one entry: bounded memory whatever
        // the iterator.
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

    /// `true` if the key is revoked.
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        self.keys.contains(key)
    }

    /// `true` if the serial number is revoked.
    #[must_use]
    pub fn is_serial_revoked(&self, serial: &CertSerial) -> bool {
        self.serials.contains(serial)
    }

    /// `(serials, keys)`: how many entries.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.serials.len(), self.keys.len())
    }
}

/// The pinned CAs of a configuration and its denylist.
#[derive(Debug, Clone, Default)]
pub struct CertTrust {
    authorities: Vec<Authority>,
    revocations: Option<Revocations>,
}

impl CertTrust {
    /// No CAs, no denylist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a CA (PROTOCOL §15.9: loading constraints).
    ///
    /// # Errors
    /// [`DomainError::AuthorityKeys`], [`DomainError::DuplicateAuthority`],
    /// [`DomainError::AuthorityLifetime`], [`DomainError::TooManyAuthorities`],
    /// [`DomainError::DuplicatePeer`] for a key already in another CA.
    pub fn add_authority(
        &mut self,
        name: NodeId,
        keys: &[TrustedCaKey],
        allowed: AllowedNodes,
        max_lifetime_secs: u64,
    ) -> Result<(), DomainError> {
        // All checks before any modification: no partial effects. The Ed25519 bytes are
        // compared whatever the algorithm: a composite key never reuses the Ed25519 key of the
        // v1 key it replaces, even in the same entry (finding AP-13).
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
        // A CA key in a single entry only, compared both by bytes and by fingerprint
        // (`P` and `−P` have the same fingerprint).
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

    /// Sets the denylist.
    pub fn set_revocations(&mut self, revocations: Revocations) {
        self.revocations = Some(revocations);
    }

    /// `true` if there is no CA.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    /// `true` if there are CAs but no denylist: the configuration cannot be started.
    #[must_use]
    pub fn needs_revocations(&self) -> bool {
        !self.authorities.is_empty() && self.revocations.is_none()
    }

    /// The CA that pins exactly these 32 bytes as a v1 (Ed25519) key.
    #[must_use]
    pub fn authority_for_key(&self, key: &CertKey) -> Option<&Authority> {
        self.authority_for(&CaKeyRef::Ed25519(*key))
    }

    /// The CA that pins the key `reference` names, with its algorithm (finding AP-13).
    #[must_use]
    pub fn authority_for(&self, reference: &CaKeyRef) -> Option<&Authority> {
        self.authorities
            .iter()
            .find(|a| a.pin_for(reference).is_some())
    }

    /// The fingerprints of all CA keys.
    pub fn ca_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.authorities
            .iter()
            .flat_map(|a| a.keys.iter().map(|k| k.fingerprint))
    }

    /// `true` if the key is in the denylist (`keys`).
    #[must_use]
    pub fn is_key_revoked(&self, key: &Fingerprint) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|r| r.is_key_revoked(key))
    }

    /// Steps 5 and 7–10 of PROTOCOL §15.4, in order.
    ///
    /// # Errors
    /// The first check that fails.
    pub fn check(&self, claims: &CertClaims, now: UnixTime) -> Result<&Authority, CertRejection> {
        // Step 5: the CA that pins exactly the key the certificate names, with its algorithm.
        let authority = self
            .authority_for(claims.authority_key())
            .ok_or(CertRejection::UnknownAuthority)?;
        // Step 7. Without a denylist (configuration cannot be started, `needs_revocations`) no
        // serial can be said to be unrevoked: fail closed.
        let serial_revoked = self
            .revocations
            .as_ref()
            .is_none_or(|r| r.is_serial_revoked(&claims.serial()));
        if serial_revoked {
            return Err(CertRejection::SerialRevoked);
        }
        // Step 8: tolerance on `not_before` only, without underflow.
        if now < claims.not_before().saturating_sub(CERT_CLOCK_SKEW_SECS) {
            return Err(CertRejection::NotYetValid);
        }
        // Step 9: `not_after` excluded, never extended.
        if now >= claims.not_after() {
            return Err(CertRejection::Expired);
        }
        // Step 10.
        let lifetime = claims
            .not_after()
            .as_secs()
            .saturating_sub(claims.not_before().as_secs());
        if lifetime > authority.max_lifetime_secs {
            return Err(CertRejection::LifetimeExceedsAuthority);
        }
        Ok(authority)
    }

    /// The CAs with two keys (rotation not completed).
    pub fn rotations_pending(&self) -> impl Iterator<Item = (&NodeId, &[TrustedCaKey])> {
        self.authorities
            .iter()
            .filter(|a| a.keys.len() > 1)
            .map(|a| (&a.name, a.keys.as_slice()))
    }

    /// The CAs, in insertion order.
    pub fn authorities(&self) -> impl Iterator<Item = &Authority> {
        self.authorities.iter()
    }

    /// The denylist, if set.
    #[must_use]
    pub const fn revocations(&self) -> Option<&Revocations> {
        self.revocations.as_ref()
    }
}
