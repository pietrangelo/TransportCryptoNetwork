//! ML-DSA-65 (FIPS 204), the post-quantum half of the composite CA signature (PQ-AUTH,
//! PROTOCOL §15.14). Only the offline CA signs; the fleet only verifies.
//!
//! The provider is `RustCrypto` `ml-dsa`, pinned to one exact version: `zt-ca` verifies every
//! signature it makes with [`verify`], the very function the relays and agents run (finding
//! AP-5), so a divergence between signer and verifier is caught at issuance, not in the field.
//! The independent `libcrux-ml-dsa` is a test-only differential oracle (`tests/mldsa.rs`, with
//! the Wycheproof and NIST ACVP vectors).
//!
//! The functions are **sans-IO**: key generation takes the 32-byte seed `ξ` and signing takes
//! the 32-byte `rnd` of FIPS 204 Algorithm 2 (hedged signing when `rnd` comes from the CSPRNG),
//! so every operation is deterministic for given inputs and checkable against vectors.

use core::fmt;

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// Length of an ML-DSA-65 public key.
pub const PUBLIC_KEY_LEN: usize = 1_952;
/// Length of an ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3_309;
/// Length of the key-generation seed `ξ`.
pub const SEED_LEN: usize = 32;
/// Length of the signing randomness `rnd`.
pub const RANDOMNESS_LEN: usize = 32;
/// Longest FIPS 204 context string.
pub const MAX_CONTEXT_LEN: usize = 255;

// The domain's copies of the sizes (certificate format) agree with the provider's.
const _: () = {
    assert!(PUBLIC_KEY_LEN == zt_domain::cert::MLDSA65_PUBLIC_KEY_LEN);
    assert!(SIGNATURE_LEN == zt_domain::cert::MLDSA65_SIGNATURE_LEN);
};

/// An ML-DSA-65 signing key. Secret: no `Clone`, zeroized on drop (the `zeroize` feature of
/// `ml-dsa` wipes the seed and the expanded key), redacted `Debug`. Boxed: the expanded key is
/// large, and moving it would leave copies on the stack.
pub struct MlDsa65SigningKey(Box<SigningKey<MlDsa65>>);

impl MlDsa65SigningKey {
    /// `ML-DSA.KeyGen_internal(ξ)` (FIPS 204 Algorithm 6).
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let xi = Zeroizing::new(ml_dsa::B32::from(*seed));
        Self(Box::new(SigningKey::<MlDsa65>::from_seed(&xi)))
    }

    /// The encoded public key (1 952 bytes).
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.expanded_key().verifying_key().encode().to_vec()
    }

    /// `ML-DSA.Sign(sk, message, context)` (FIPS 204 Algorithm 2) with the caller's `rnd`:
    /// `M' = 0 ‖ |ctx| ‖ ctx ‖ message`. Pass CSPRNG output for the hedged variant.
    ///
    /// # Errors
    /// [`crate::CryptoError::InvalidKey`] for a context over 255 bytes.
    pub fn sign(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; RANDOMNESS_LEN],
    ) -> Result<Vec<u8>, crate::CryptoError> {
        let ctx_len = u8::try_from(context.len()).map_err(|_| crate::CryptoError::InvalidKey)?;
        let rnd = Zeroizing::new(ml_dsa::B32::from(*randomness));
        let header = [0_u8, ctx_len];
        let signature = self
            .0
            .expanded_key()
            .sign_internal(&[&header, context, message], &rnd);
        Ok(signature.encode().to_vec())
    }
}

impl fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa65SigningKey(<redacted>)")
    }
}

/// `ML-DSA.Verify(pk, message, signature, context)` (FIPS 204 Algorithm 3).
///
/// `false` for a key or signature of the wrong length, a context over 255 bytes, a signature
/// whose encoding is not canonical (hint indices repeated, out of order or out of bounds,
/// `z` out of range: `sigDecode` refuses it) and of course a signature that does not verify.
/// Every input is public.
#[must_use]
pub fn verify(public_key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LEN
        || signature.len() != SIGNATURE_LEN
        || context.len() > MAX_CONTEXT_LEN
    {
        return false;
    }
    let Ok(encoded) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
        return false;
    };
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    key.verify_with_context(message, context, &signature)
}
