use core::fmt;
use core::num::NonZeroU32;

use crate::error::DomainError;
use crate::limits::MAX_NODE_ID_LEN;

/// Nome logico di un nodo target, usato come alias nell'inventory Ansible.
///
/// Invarianti (etichetta DNS ristretta, RFC 1035 §2.3.4, solo minuscole):
/// - lunghezza `1..=63`;
/// - alfabeto `[a-z0-9-]`, quindi solo ASCII stampabile e nessun byte di controllo;
/// - non inizia né finisce con `-`.
///
/// L'alfabeto ristretto elimina alla radice attacchi di omografia Unicode, injection nei log
/// e ambiguità di confronto (niente case folding).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(Box<str>);

impl NodeId {
    /// Il nome come stringa.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Il nome come byte (forma usata sul filo).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Lunghezza in byte (sempre in `1..=63`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Sempre `false`: un `NodeId` vuoto non è costruibile. Presente per coerenza con `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        if len == 0 {
            return Err(DomainError::NodeIdEmpty);
        }
        if len > MAX_NODE_ID_LEN {
            return Err(DomainError::NodeIdTooLong {
                len,
                max: MAX_NODE_ID_LEN,
            });
        }
        if let Some(position) = bytes
            .iter()
            .position(|b| !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        {
            return Err(DomainError::NodeIdInvalidByte { position });
        }
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(DomainError::NodeIdHyphenAtEdge);
        }
        // Tutti i byte sono ASCII: la conversione non può fallire, ma la gestiamo senza panic.
        let text = core::str::from_utf8(bytes).map_err(|e| DomainError::NodeIdInvalidByte {
            position: e.valid_up_to(),
        })?;
        Ok(Self(text.into()))
    }
}

impl TryFrom<&str> for NodeId {
    type Error = DomainError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        Self::try_from(text.as_bytes())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

/// Identificativo di una sessione end-to-end client↔agent.
///
/// 128 bit generati da un CSPRNG nell'adapter (il dominio non genera casualità).
/// Il valore tutto-zero è riservato e rifiutato.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; Self::LEN]);

impl SessionId {
    /// Lunghezza in byte.
    pub const LEN: usize = 16;

    /// Costruisce un `SessionId` da 16 byte casuali.
    ///
    /// # Errors
    /// [`DomainError::SessionIdZero`] se tutti i byte sono zero.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, DomainError> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(DomainError::SessionIdZero);
        }
        Ok(Self(bytes))
    }

    /// I byte dell'identificativo.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SessionId {
    type Error = DomainError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; Self::LEN] = bytes.try_into().map_err(|_| DomainError::InvalidLength {
            what: "session id",
            expected: Self::LEN,
            actual: bytes.len(),
        })?;
        Self::from_bytes(array)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// Identificativo di un flusso multiplexato su una connessione.
///
/// Lo stream `0` è riservato ai frame di controllo della connessione, quindi un `StreamId`
/// è sempre diverso da zero (garantito dal tipo [`NonZeroU32`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(NonZeroU32);

impl StreamId {
    /// Il valore numerico (sempre `> 0`).
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for StreamId {
    type Error = DomainError;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        NonZeroU32::new(raw)
            .map(Self)
            .ok_or(DomainError::StreamIdZero)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    #[test]
    fn node_id_accepts_dns_labels() {
        for ok in ["a", "web-01", "db0", "x".repeat(63).as_str()] {
            assert!(NodeId::try_from(ok).is_ok(), "{ok} should be valid");
        }
    }

    #[test]
    fn node_id_rejects_empty() {
        assert_eq!(NodeId::try_from(""), Err(DomainError::NodeIdEmpty));
    }

    #[test]
    fn node_id_rejects_too_long() {
        let long = "a".repeat(64);
        assert_eq!(
            NodeId::try_from(long.as_str()),
            Err(DomainError::NodeIdTooLong { len: 64, max: 63 })
        );
    }

    #[test]
    fn node_id_rejects_forbidden_bytes() {
        let cases: [(&[u8], usize); 7] = [
            (b"Web", 0),        // maiuscole: niente case folding ambiguo
            (b"web.01", 3),     // niente FQDN: un'etichetta sola
            (b"web 01", 3),     // spazi
            (b"web\n01", 3),    // log injection
            (b"web\x0001", 3),  // NUL byte
            (b"w\xc3\xa9b", 1), // UTF-8 non ASCII (omografie)
            (b"../etc", 0),     // path traversal se usato in un path
        ];
        for (input, position) in cases {
            assert_eq!(
                NodeId::try_from(input),
                Err(DomainError::NodeIdInvalidByte { position }),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn node_id_rejects_hyphen_at_edges() {
        for bad in ["-web", "web-", "-"] {
            assert_eq!(NodeId::try_from(bad), Err(DomainError::NodeIdHyphenAtEdge));
        }
    }

    #[test]
    fn session_id_rejects_all_zeros_and_wrong_length() {
        assert_eq!(
            SessionId::from_bytes([0; 16]),
            Err(DomainError::SessionIdZero)
        );
        assert_eq!(
            SessionId::try_from(&[1_u8; 15][..]),
            Err(DomainError::InvalidLength {
                what: "session id",
                expected: 16,
                actual: 15
            })
        );
        assert!(SessionId::try_from(&[7_u8; 16][..]).is_ok());
    }

    #[test]
    fn stream_id_zero_is_reserved() {
        assert_eq!(StreamId::try_from(0), Err(DomainError::StreamIdZero));
        assert_eq!(StreamId::try_from(42).map(StreamId::get), Ok(42));
    }
}
