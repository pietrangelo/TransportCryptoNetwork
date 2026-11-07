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

// Prove a compile-time: se qualcuno alza un limite in modo incoerente, il build fallisce.
const _: () = {
    // Un payload massimo, incapsulato due volte (header + tag per strato), sta in un messaggio Noise.
    let overhead = ENCRYPTION_LAYERS * (FRAME_HEADER_LEN + NOISE_TAG_LEN);
    assert!(MAX_PAYLOAD_LEN + overhead <= NOISE_MAX_MESSAGE_LEN);
    // Il campo `length` dell'header è un u16: il limite deve essere esprimibile sul filo.
    assert!(MAX_PAYLOAD_LEN <= u16::MAX as usize);
    assert!(MAX_NODE_ID_LEN <= MAX_PAYLOAD_LEN);
};
