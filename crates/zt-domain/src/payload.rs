use core::fmt;

use bytes::Bytes;

use crate::error::DomainError;
use crate::limits::MAX_PAYLOAD_LEN;

/// Payload opaco di un frame `Data`: byte cifrati end-to-end che il relay inoltra senza leggerli.
///
/// Invariante: lunghezza in `1..=MAX_PAYLOAD_LEN`. Il payload vuoto è vietato perché un frame
/// `Data` vuoto non trasporta nulla e sarebbe solo un vettore di amplificazione/DoS.
///
/// Internamente usa [`Bytes`]: il decoder può consegnare il payload senza copiarlo
/// (zero-copy) e l'inoltro sul relay condivide lo stesso buffer.
#[derive(Clone, PartialEq, Eq)]
pub struct FramePayload(Bytes);

impl FramePayload {
    /// Lunghezza in byte (sempre in `1..=MAX_PAYLOAD_LEN`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Sempre `false`: un payload vuoto non è costruibile.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// I byte del payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consuma il payload restituendo il buffer sottostante.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl TryFrom<Bytes> for FramePayload {
    type Error = DomainError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        match bytes.len() {
            0 => Err(DomainError::PayloadEmpty),
            len if len > MAX_PAYLOAD_LEN => Err(DomainError::PayloadTooLarge {
                len,
                max: MAX_PAYLOAD_LEN,
            }),
            _ => Ok(Self(bytes)),
        }
    }
}

impl TryFrom<&[u8]> for FramePayload {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::copy_from_slice(bytes))
    }
}

impl TryFrom<Vec<u8>> for FramePayload {
    type Error = DomainError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(bytes))
    }
}

impl fmt::Debug for FramePayload {
    /// Mostra solo la lunghezza: il contenuto (traffico SSH) non deve mai finire nei log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FramePayload({} bytes)", self.0.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_bounds_are_enforced() {
        assert_eq!(
            FramePayload::try_from(&[][..]),
            Err(DomainError::PayloadEmpty)
        );
        assert!(FramePayload::try_from(vec![0; 1]).is_ok());
        assert!(FramePayload::try_from(vec![0; MAX_PAYLOAD_LEN]).is_ok());
        assert_eq!(
            FramePayload::try_from(vec![0; MAX_PAYLOAD_LEN + 1]),
            Err(DomainError::PayloadTooLarge {
                len: MAX_PAYLOAD_LEN + 1,
                max: MAX_PAYLOAD_LEN
            })
        );
    }

    #[test]
    fn payload_debug_hides_content() {
        let payload = FramePayload::try_from(&b"SSH-2.0-secret"[..]).unwrap();
        assert_eq!(format!("{payload:?}"), "FramePayload(14 bytes)");
    }
}
