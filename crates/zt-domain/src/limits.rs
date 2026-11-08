//! Limiti del protocollo, fissati a compile-time.
//!
//! Ogni limite ha una motivazione di sicurezza (OWASP A03/A04): un peer non può mai
//! costringerci ad allocare più di [`MAX_FRAME_LEN`] byte per frame, qualunque cosa dichiari.

/// Lunghezza massima di un messaggio di trasporto Noise (specifica Noise, §3).
pub const NOISE_MAX_MESSAGE_LEN: usize = 65_535;

/// Lunghezza del tag AEAD aggiunto da Noise a ogni messaggio cifrato.
pub const NOISE_TAG_LEN: usize = 16;

/// Lunghezza fissa dell'header di un frame sul filo (vedi `docs/PROTOCOL.md`).
pub const FRAME_HEADER_LEN: usize = 8;

/// Strati di cifratura annidati che un frame `Data` deve attraversare:
/// tunnel end-to-end client↔agent dentro il canale peer↔relay.
pub const ENCRYPTION_LAYERS: usize = 2;

/// Dimensione massima del payload di un singolo frame: 60 KiB.
pub const MAX_PAYLOAD_LEN: usize = 60 * 1024;

/// Dimensione massima di un frame completo (header + payload).
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD_LEN;

/// Lunghezza massima di un [`NodeId`](crate::NodeId) (un'etichetta DNS, RFC 1035 §2.3.4).
pub const MAX_NODE_ID_LEN: usize = 63;

/// Lunghezza massima di un certificato client (PROTOCOL §15.12): 64 nodi da 63 byte e un nome
/// da 63 byte.
pub const MAX_CERT_LEN: usize = 4_328;

/// Lunghezza minima di un certificato client: `scope = 0x01` e nome di 1 byte.
pub const MIN_CERT_LEN: usize = 170;

/// Nodi al massimo in un certificato con `scope = 0x00`.
pub const MAX_CERT_NODES: usize = 64;

/// Durata massima di un certificato, regola del formato (24 ore).
pub const MAX_CERT_LIFETIME_SECS: u64 = 86_400;

/// Tolleranza sull'orologio, solo su `not_before` (PROTOCOL §15.6).
pub const CERT_CLOCK_SKEW_SECS: u64 = 120;

/// `max_lifetime` minimo di una CA.
pub const MIN_AUTHORITY_LIFETIME_SECS: u64 = 60;

/// `max_lifetime` di default di una CA (8 ore).
pub const DEFAULT_AUTHORITY_LIFETIME_SECS: u64 = 28_800;

/// Voci `[[authorities]]` al massimo per file.
pub const MAX_AUTHORITIES: usize = 16;

/// Chiavi per CA: la corrente e, durante una rotazione, la nuova.
pub const MAX_AUTHORITY_KEYS: usize = 2;

/// Numeri di serie al massimo nella denylist.
pub const MAX_REVOKED_SERIALS: usize = 16_384;

/// Chiavi al massimo nella denylist.
pub const MAX_REVOKED_KEYS: usize = 4_096;

/// Byte del messaggio 1 di Noise IK oltre il payload: `e` (32) + `s` cifrata (32 + 16) + tag
/// del payload (16).
pub const NOISE_MSG1_OVERHEAD: usize = 96;

// Prove a compile-time: se qualcuno alza un limite in modo incoerente, il build fallisce.
const _: () = {
    // Un payload massimo, incapsulato due volte (header + tag per strato), sta in un messaggio Noise.
    let overhead = ENCRYPTION_LAYERS * (FRAME_HEADER_LEN + NOISE_TAG_LEN);
    assert!(MAX_PAYLOAD_LEN + overhead <= NOISE_MAX_MESSAGE_LEN);
    // Il campo `length` dell'header è un u16: il limite deve essere esprimibile sul filo.
    assert!(MAX_PAYLOAD_LEN <= u16::MAX as usize);
    assert!(MAX_NODE_ID_LEN <= MAX_PAYLOAD_LEN);
    // Il messaggio 1 con il certificato più grande sta in un `Data` e in un messaggio Noise
    // (PROTOCOL §15.3).
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= MAX_PAYLOAD_LEN);
    assert!(NOISE_MSG1_OVERHEAD + MAX_CERT_LEN + NOISE_TAG_LEN <= NOISE_MAX_MESSAGE_LEN);
    assert!(MIN_CERT_LEN <= MAX_CERT_LEN);
};
