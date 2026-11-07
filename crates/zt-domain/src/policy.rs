use std::collections::{BTreeSet, HashMap};

use crate::crypto::Fingerprint;
use crate::error::DomainError;
use crate::ids::NodeId;

/// Nodi che un client può raggiungere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedNodes {
    /// Tutti i nodi registrati (da usare solo per l'amministratore della flotta).
    All,
    /// Solo questi nodi. Un insieme vuoto non concede nulla.
    Only(BTreeSet<NodeId>),
}

impl AllowedNodes {
    /// `true` se `node` è concesso.
    #[must_use]
    pub fn permits(&self, node: &NodeId) -> bool {
        match self {
            Self::All => true,
            Self::Only(nodes) => nodes.contains(node),
        }
    }
}

/// Ciò che la policy concede a un client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    /// Nome leggibile per gli audit log (stesse regole di un [`NodeId`]).
    pub name: NodeId,
    /// I nodi raggiungibili.
    pub allowed: AllowedNodes,
}

/// Il ruolo di un peer autenticato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole<'a> {
    /// Un agent, che può registrarsi solo con questo nome.
    Agent {
        /// Il nome assegnato alla chiave.
        node: &'a NodeId,
    },
    /// Un client, con i suoi permessi.
    Client {
        /// I permessi.
        grant: &'a ClientGrant,
    },
}

/// Whitelist del relay: chi può connettersi, con quale ruolo, e verso quali nodi.
///
/// Principio del minimo privilegio: una chiave ha **un solo** ruolo, un agent ha **un solo**
/// nome, un client vede solo i nodi elencati. Tutto ciò che non è concesso è negato.
#[derive(Debug, Clone, Default)]
pub struct AccessPolicy {
    agents: HashMap<Fingerprint, NodeId>,
    nodes: BTreeSet<NodeId>,
    clients: HashMap<Fingerprint, ClientGrant>,
}

impl AccessPolicy {
    /// Una policy vuota, che nega tutto.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_new_peer(&self, peer: &Fingerprint) -> Result<(), DomainError> {
        if self.agents.contains_key(peer) || self.clients.contains_key(peer) {
            return Err(DomainError::DuplicatePeer(*peer));
        }
        Ok(())
    }

    /// Autorizza la chiave `peer` a registrarsi come agent del nodo `node`.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] se la chiave ha già un ruolo,
    /// [`DomainError::DuplicateNode`] se il nodo ha già un agent.
    pub fn add_agent(&mut self, peer: Fingerprint, node: NodeId) -> Result<(), DomainError> {
        self.ensure_new_peer(&peer)?;
        if !self.nodes.insert(node.clone()) {
            return Err(DomainError::DuplicateNode(node));
        }
        self.agents.insert(peer, node);
        Ok(())
    }

    /// Autorizza la chiave `peer` come client con i permessi `grant`.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] se la chiave ha già un ruolo.
    pub fn add_client(&mut self, peer: Fingerprint, grant: ClientGrant) -> Result<(), DomainError> {
        self.ensure_new_peer(&peer)?;
        self.clients.insert(peer, grant);
        Ok(())
    }

    /// Il ruolo di una chiave, o `None` se sconosciuta.
    #[must_use]
    pub fn role(&self, peer: &Fingerprint) -> Option<PeerRole<'_>> {
        if let Some(node) = self.agents.get(peer) {
            return Some(PeerRole::Agent { node });
        }
        self.clients.get(peer).map(|grant| PeerRole::Client { grant })
    }

    /// `true` se il client `peer` può aprire uno stream verso `target`.
    ///
    /// Un nodo che non esiste nella policy non è mai concesso, nemmeno con [`AllowedNodes::All`].
    #[must_use]
    pub fn may_open(&self, peer: &Fingerprint, target: &NodeId) -> bool {
        self.nodes.contains(target)
            && self.clients.get(peer).is_some_and(|grant| grant.allowed.permits(target))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint::from_bytes([b; 32])
    }
    fn node(n: &str) -> NodeId {
        NodeId::try_from(n).unwrap()
    }
    fn only(nodes: &[&str]) -> AllowedNodes {
        AllowedNodes::Only(nodes.iter().map(|n| node(n)).collect())
    }

    fn policy() -> AccessPolicy {
        let mut p = AccessPolicy::new();
        p.add_agent(fp(1), node("web-01")).unwrap();
        p.add_agent(fp(2), node("db-01")).unwrap();
        p.add_client(fp(10), ClientGrant { name: node("ansible"), allowed: only(&["web-01"]) })
            .unwrap();
        p.add_client(fp(11), ClientGrant { name: node("admin"), allowed: AllowedNodes::All })
            .unwrap();
        p
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = AccessPolicy::new();
        assert_eq!(p.role(&fp(1)), None);
        assert!(!p.may_open(&fp(1), &node("web-01")));
    }

    #[test]
    fn roles_are_resolved_by_key() {
        let p = policy();
        assert_eq!(p.role(&fp(1)), Some(PeerRole::Agent { node: &node("web-01") }));
        assert!(matches!(p.role(&fp(10)), Some(PeerRole::Client { .. })));
        assert_eq!(p.role(&fp(99)), None);
    }

    #[test]
    fn clients_reach_only_granted_existing_nodes() {
        let p = policy();
        assert!(p.may_open(&fp(10), &node("web-01")));
        assert!(!p.may_open(&fp(10), &node("db-01")));
        assert!(p.may_open(&fp(11), &node("db-01")));
        // `All` non inventa nodi inesistenti.
        assert!(!p.may_open(&fp(11), &node("ghost")));
    }

    #[test]
    fn agents_cannot_open_streams() {
        let p = policy();
        assert!(!p.may_open(&fp(1), &node("db-01")));
    }

    #[test]
    fn a_key_has_exactly_one_role_and_a_node_one_agent() {
        let mut p = policy();
        assert_eq!(
            p.add_client(fp(1), ClientGrant { name: node("x"), allowed: AllowedNodes::All }),
            Err(DomainError::DuplicatePeer(fp(1)))
        );
        assert_eq!(p.add_agent(fp(10), node("new")), Err(DomainError::DuplicatePeer(fp(10))));
        assert_eq!(p.add_agent(fp(3), node("web-01")), Err(DomainError::DuplicateNode(node("web-01"))));
    }
}
