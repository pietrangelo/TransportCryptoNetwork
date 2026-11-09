//! The responder's pre-filter of message 1 (finding A12-6 of review 0012).
//!
//! Nothing on the wire names the suite or the responder key (AP-11), so a responder that
//! accepts several suites, during a rotation with two keys, used to run a full `snow` trial for
//! every suite and key whose length bounds fit. An invalid message 1 then cost the union of
//! every trial, and the attacker chooses the length.
//!
//! This module replays, with the same primitives as the vendored `snow` (X25519,
//! `ChaChaPoly`, `BLAKE2s`), the first steps a `snow` responder takes on message 1, up to its
//! **first authenticated decryption**, and nothing else:
//!
//! ```text
//! IK, IKhfs   h = HASH(name); ck = h; MixHash(prologue); MixHash(s_r)
//!             e: MixHash(e); es: MixKey(DH(s_r, e)); DecryptAndHash(s or e1)   ← the test
//! hybrid IK   ... MixHash(s_r); psk0: MixKeyAndHash(psk0)
//!             e: MixHash(e), MixKey(e); es: MixKey(DH(s_r, e)); DecryptAndHash(e1) ← the test
//! ```
//!
//! A message 1 that fails this test would fail `snow` at the same step with the same keys,
//! so the filter only ever saves work; `snow` still runs, in full, on the one suite and key
//! that pass. The two pre-PQ-AUTH suites carry `e` at offset 0, so one X25519 multiplication
//! per key serves both. A legitimate message 1 passes the test of its own suite and key only
//! (another would need a 128-bit tag collision); a message crafted to pass several tests gets
//! one `snow` trial anyway, the first in a fixed order.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use curve25519_dalek::montgomery::MontgomeryPoint;
use zeroize::Zeroizing;

/// `HASHLEN` of `BLAKE2s`.
const HASH_LEN: usize = 32;
/// The block length of `BLAKE2s`, for HMAC.
const BLOCK_LEN: usize = 64;
/// The AEAD tag.
const TAG_LEN: usize = 16;

/// X25519 as `snow`'s default resolver computes it: `MontgomeryPoint(e) · clamp(secret)`.
pub(crate) fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    crate::noise::ops::dh();
    Zeroizing::new(MontgomeryPoint(*public).mul_clamped(*secret).to_bytes())
}

fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// HMAC-BLAKE2s, as `snow`'s `Hash::hmac` (a key shorter than the block, zero-padded).
fn hmac(key: &[u8; HASH_LEN], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut ipad = Zeroizing::new([0x36_u8; BLOCK_LEN]);
    let mut opad = Zeroizing::new([0x5c_u8; BLOCK_LEN]);
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *i ^= k;
        *o ^= k;
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad.as_ref());
    for part in parts {
        inner.update(part);
    }
    let inner = Zeroizing::new(<[u8; HASH_LEN]>::from(inner.finalize()));
    let mut outer = Blake2s256::new();
    outer.update(opad.as_ref());
    outer.update(inner.as_ref());
    Zeroizing::new(outer.finalize().into())
}

/// Noise's `HKDF(ck, ikm)`: the temporary key and the first two outputs.
fn hkdf2(
    ck: &[u8; HASH_LEN],
    ikm: &[u8],
) -> (Zeroizing<[u8; HASH_LEN]>, [Zeroizing<[u8; HASH_LEN]>; 2]) {
    let temp = hmac(ck, &[ikm]);
    let one = hmac(&temp, &[&[1]]);
    let two = hmac(&temp, &[one.as_ref(), &[2]]);
    (temp, [one, two])
}

/// The symmetric state of a responder that has not yet decrypted anything.
pub(crate) struct Symmetric {
    h: [u8; HASH_LEN],
    ck: Zeroizing<[u8; HASH_LEN]>,
    k: Zeroizing<[u8; 32]>,
}

impl Symmetric {
    /// `Initialize(name)`, `MixHash(prologue)` and the responder's pre-message `MixHash(s_r)`.
    pub(crate) fn new(name: &str, prologue: &[u8], responder_static: &[u8; 32]) -> Self {
        let mut h = [0_u8; HASH_LEN];
        match h.get_mut(..name.len()) {
            Some(head) => head.copy_from_slice(name.as_bytes()),
            None => h = hash(&[name.as_bytes()]),
        }
        let mut state = Self {
            h,
            ck: Zeroizing::new(h),
            k: Zeroizing::new([0; 32]),
        };
        state.mix_hash(prologue);
        state.mix_hash(responder_static);
        state
    }

    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    pub(crate) fn mix_key(&mut self, ikm: &[u8]) {
        let (_, [ck, k]) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = k;
    }

    pub(crate) fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (temp, [ck, temp_h]) = hkdf2(&self.ck, ikm);
        let k = hmac(&temp, &[temp_h.as_ref(), &[3]]);
        self.ck = ck;
        self.mix_hash(temp_h.as_ref());
        self.k = k;
    }

    /// `true` if `ciphertext` (with its tag) decrypts under the current key, nonce 0 and
    /// `ad = h`: the first `DecryptAndHash` of message 1.
    pub(crate) fn decrypts(&self, ciphertext: &[u8]) -> bool {
        let Some(split) = ciphertext.len().checked_sub(TAG_LEN) else {
            return false;
        };
        let (body, tag) = ciphertext.split_at(split);
        let mut plain = Zeroizing::new(body.to_vec());
        ChaCha20Poly1305::new(self.k.as_ref().into())
            .decrypt_in_place_detached(
                &Nonce::default(),
                &self.h,
                plain.as_mut_slice(),
                Tag::from_slice(tag),
            )
            .is_ok()
    }
}
