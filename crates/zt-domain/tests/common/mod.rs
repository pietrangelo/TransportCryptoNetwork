//! Codificatore indipendente dei certificati per i test (PROTOCOL §15.1): scrive i byte a mano,
//! campo per campo, così i test non dipendono dall'encoder che stanno verificando.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use zt_domain::{CertBody, CertKey, CertScope, CertSerial, NodeId, UnixTime};

/// Il vettore di riferimento di PROTOCOL §15.13 (187 byte), trascritto dal documento.
pub const REFERENCE_CERT_HEX: &str = concat!(
    "54434e4301018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf374",
    "8801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df6",
    "0f5b8fc9b3940102030405060708090a0b0c0d0e0f10000000006b49d2000000",
    "00006b49e01005616c69636500020564622d3031067765622d3031659fa00c94",
    "7c7c513c256db9673ba40a895ee8adba9e4da97e578f6743f976ac5301b6aad1",
    "203e4a03a87dd2cffca22d964126ae7d5b26a9d16067697e5b530f",
);

/// I byte del vettore di riferimento.
pub fn reference_cert() -> Vec<u8> {
    hex_decode(REFERENCE_CERT_HEX)
}

pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub const REF_CA_KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
pub const REF_SUBJECT_KEY: &str =
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
pub const REF_NOT_BEFORE: u64 = 1_800_000_000;
pub const REF_NOT_AFTER: u64 = 1_800_003_600;
pub const REF_SERIAL: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

pub fn key32(text: &str) -> [u8; 32] {
    hex_decode(text).try_into().unwrap()
}

pub fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

/// Un certificato scritto a mano. I campi sono byte grezzi, così si possono rendere
/// incoerenti a piacere.
#[derive(Debug, Clone)]
pub struct Raw {
    pub magic: [u8; 4],
    pub version: u8,
    pub sig_alg: u8,
    pub ca_key: [u8; 32],
    pub subject_key: [u8; 32],
    pub serial: [u8; 16],
    pub not_before: u64,
    pub not_after: u64,
    /// `None`: la lunghezza vera di `name`.
    pub name_len: Option<u8>,
    pub name: Vec<u8>,
    pub scope: u8,
    /// `None`: il numero vero di `nodes`.
    pub node_count: Option<u8>,
    pub nodes: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl Raw {
    /// Il vettore di riferimento di PROTOCOL §15.13, firma compresa.
    pub fn reference() -> Self {
        let cert = reference_cert();
        Self {
            magic: *b"TCNC",
            version: 1,
            sig_alg: 1,
            ca_key: key32(REF_CA_KEY),
            subject_key: key32(REF_SUBJECT_KEY),
            serial: REF_SERIAL,
            not_before: REF_NOT_BEFORE,
            not_after: REF_NOT_AFTER,
            name_len: None,
            name: b"alice".to_vec(),
            scope: 0,
            node_count: None,
            nodes: vec![b"db-01".to_vec(), b"web-01".to_vec()],
            signature: cert[cert.len() - 64..].to_vec(),
        }
    }

    /// Un certificato valido per il formato (chiavi e firma arbitrarie).
    pub fn valid() -> Self {
        Self {
            ca_key: [0xca; 32],
            subject_key: [0x5b; 32],
            signature: vec![0x5a; 64],
            ..Self::reference()
        }
    }

    /// Il più corto: `scope = 0x01`, nome di 1 byte (170 byte).
    pub fn smallest() -> Self {
        Self {
            name: b"a".to_vec(),
            scope: 1,
            nodes: Vec::new(),
            ..Self::valid()
        }
    }

    /// Il più lungo: nome di 63 byte e 64 nodi da 63 byte (4 328 byte).
    pub fn largest() -> Self {
        Self {
            name: vec![b'n'; 63],
            nodes: largest_nodes(64),
            ..Self::valid()
        }
    }

    pub fn tbs(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.magic);
        b.push(self.version);
        b.push(self.sig_alg);
        b.extend_from_slice(&self.ca_key);
        b.extend_from_slice(&self.subject_key);
        b.extend_from_slice(&self.serial);
        b.extend_from_slice(&self.not_before.to_be_bytes());
        b.extend_from_slice(&self.not_after.to_be_bytes());
        b.push(self.name_len.unwrap_or(self.name.len() as u8));
        b.extend_from_slice(&self.name);
        b.push(self.scope);
        b.push(self.node_count.unwrap_or(self.nodes.len() as u8));
        for n in &self.nodes {
            b.push(n.len() as u8);
            b.extend_from_slice(n);
        }
        b
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut b = self.tbs();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Il `CertBody` atteso per questo certificato (solo per certificati validi).
    pub fn body(&self) -> CertBody {
        let scope = if self.scope == 1 {
            CertScope::All
        } else {
            CertScope::Only(
                self.nodes
                    .iter()
                    .map(|n| NodeId::try_from(n.as_slice()).unwrap())
                    .collect(),
            )
        };
        CertBody::new(
            CertKey::from_bytes(self.ca_key),
            CertKey::from_bytes(self.subject_key),
            CertSerial::try_from(self.serial).unwrap(),
            UnixTime::from_secs(self.not_before),
            UnixTime::from_secs(self.not_after),
            NodeId::try_from(self.name.as_slice()).unwrap(),
            scope,
        )
        .unwrap()
    }
}

/// `count` nodi distinti da 63 byte, in ordine crescente di byte.
pub fn largest_nodes(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut n = vec![b'a'; 61];
            n.extend_from_slice(format!("{i:02}").as_bytes());
            n
        })
        .collect()
}

/// `count` nodi distinti corti, in ordine crescente di byte.
pub fn short_nodes(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| format!("n{i:03}").into_bytes())
        .collect()
}
