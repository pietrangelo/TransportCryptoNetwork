//! Più chiavi per lo stesso agent durante una rotazione (Fase 5, PROTOCOL §14).
#![allow(clippy::unwrap_used)]

use zt_domain::{
    AccessPolicy, AllowedNodes, ClientGrant, DomainError, Fingerprint, MAX_AGENT_KEYS, NodeId,
    PeerRole,
};

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}
fn node(n: &str) -> NodeId {
    NodeId::try_from(n).unwrap()
}

// ---------- specifica ----------

#[test]
fn both_keys_of_a_rotating_agent_map_to_its_node() {
    let mut p = AccessPolicy::new();
    p.add_agent_keys(node("web-01"), &[fp(1), fp(2)]).unwrap();
    for k in [fp(1), fp(2)] {
        assert!(matches!(p.role(&k), Some(PeerRole::Agent { node: n }) if *n == node("web-01")));
    }
    p.add_client(
        fp(10),
        ClientGrant {
            name: node("ansible"),
            allowed: AllowedNodes::All,
        },
    )
    .unwrap();
    assert!(p.may_open(&fp(10), &node("web-01")));
}

#[test]
fn a_single_key_is_the_same_as_add_agent() {
    let mut p = AccessPolicy::new();
    p.add_agent_keys(node("web-01"), &[fp(1)]).unwrap();
    assert!(p.role(&fp(1)).is_some());
    assert_eq!(MAX_AGENT_KEYS, 2);
}

// ---------- attacchi ----------

#[test]
fn more_than_two_keys_or_none_are_refused() {
    let mut p = AccessPolicy::new();
    assert!(matches!(
        p.add_agent_keys(node("web-01"), &[fp(1), fp(2), fp(3)]),
        Err(DomainError::AgentKeys(_))
    ));
    assert!(matches!(
        p.add_agent_keys(node("web-01"), &[]),
        Err(DomainError::AgentKeys(_))
    ));
    // Nessun effetto parziale.
    assert!(p.role(&fp(1)).is_none());
    p.add_agent_keys(node("web-01"), &[fp(1)]).unwrap();
}

#[test]
fn the_same_key_twice_is_refused() {
    let mut p = AccessPolicy::new();
    assert!(matches!(
        p.add_agent_keys(node("web-01"), &[fp(1), fp(1)]),
        Err(DomainError::AgentKeys(_))
    ));
}

#[test]
fn a_key_of_another_peer_cannot_be_smuggled_in_as_a_second_key() {
    let mut p = AccessPolicy::new();
    p.add_agent(fp(1), node("db-01")).unwrap();
    p.add_client(
        fp(10),
        ClientGrant {
            name: node("ansible"),
            allowed: AllowedNodes::All,
        },
    )
    .unwrap();
    // La chiave di un altro agent o di un client non diventa la seconda chiave di web-01.
    for stolen in [fp(1), fp(10)] {
        assert!(matches!(
            p.add_agent_keys(node("web-01"), &[fp(2), stolen]),
            Err(DomainError::DuplicatePeer(_))
        ));
        assert!(p.role(&fp(2)).is_none(), "partial insert left behind");
    }
    assert!(matches!(
        p.add_agent_keys(node("db-01"), &[fp(3), fp(4)]),
        Err(DomainError::DuplicateNode(_))
    ));
}
