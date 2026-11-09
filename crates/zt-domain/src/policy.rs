use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::cert::{CertClaims, CertRejection, UnixTime};
use crate::crypto::{Fingerprint, HybridFingerprint};
use crate::error::DomainError;
use crate::events::AuthFailureReason;
use crate::ids::NodeId;
use crate::trust::CertTrust;

/// Nodes a client can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedNodes {
    /// All registered nodes (to be used only for the fleet administrator).
    All,
    /// Only these nodes. An empty set grants nothing.
    Only(BTreeSet<NodeId>),
}

impl AllowedNodes {
    /// `true` if `node` is granted.
    #[must_use]
    pub fn permits(&self, node: &NodeId) -> bool {
        match self {
            Self::All => true,
            Self::Only(nodes) => nodes.contains(node),
        }
    }
}

/// What the policy grants a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    /// Human-readable name for the audit logs (same rules as a [`NodeId`]).
    pub name: NodeId,
    /// The reachable nodes.
    pub allowed: AllowedNodes,
}

/// The role of an authenticated peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole<'a> {
    /// An agent, which can register only under this name.
    Agent {
        /// The name assigned to the key.
        node: &'a NodeId,
    },
    /// A client, with its permissions.
    Client {
        /// The permissions.
        grant: &'a ClientGrant,
    },
}

/// With which credential a client was admitted (PROTOCOL §15.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCredential {
    /// The per-key whitelist: no in-session expiry.
    Key,
    /// A verified certificate: valid until `not_after`.
    Certificate(Arc<CertClaims>),
}

/// Successful outcome of [`AccessPolicy::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission<'a> {
    /// An agent, which can register only under this name.
    Agent {
        /// The name assigned to the key.
        node: &'a NodeId,
    },
    /// A client, with the credential that admitted it.
    Client {
        /// The credential.
        credential: ClientCredential,
    },
}

/// Agent keys admitted for a node: the current one and, during a rotation, the new one.
pub const MAX_AGENT_KEYS: usize = 2;

/// The relay's whitelist: who may connect, with which role, and towards which nodes.
///
/// Principle of least privilege: a key has **exactly one** role, an agent has **exactly one**
/// name, a client sees only the listed nodes. Everything not granted is denied.
#[derive(Debug, Clone, Default)]
pub struct AccessPolicy {
    agents: HashMap<Fingerprint, NodeId>,
    nodes: BTreeSet<NodeId>,
    clients: HashMap<Fingerprint, ClientGrant>,
    cert_trust: CertTrust,
    /// v2 pins (PQ-AUTH): the hybrid identity a key must prove, keyed by its X25519-level
    /// fingerprint (the one identity and revocation unit, finding AP-6).
    hybrid: HybridPins,
}

/// v2 pins: X25519-level fingerprint → the fingerprint v2 its handshake must prove.
#[derive(Debug, Clone, Default)]
pub(crate) struct HybridPins(HashMap<Fingerprint, HybridFingerprint>);

impl HybridPins {
    /// Pins `hybrid` for `peer`. A key has one v2 identity, and a v2 identity one key.
    pub(crate) fn pin(
        &mut self,
        peer: Fingerprint,
        hybrid: HybridFingerprint,
    ) -> Result<(), DomainError> {
        if self.0.contains_key(&peer) || self.0.values().any(|h| *h == hybrid) {
            return Err(DomainError::DuplicatePeer(peer));
        }
        self.0.insert(peer, hybrid);
        Ok(())
    }

    pub(crate) fn get(&self, peer: &Fingerprint) -> Option<&HybridFingerprint> {
        self.0.get(peer)
    }

    /// `Ok` if `peer` has no v2 pin, or the handshake proved exactly the pinned identity.
    /// Fingerprint v2 comparison is constant-time.
    pub(crate) fn check(
        &self,
        peer: &Fingerprint,
        proved: Option<&HybridFingerprint>,
    ) -> Result<(), AuthFailureReason> {
        match (self.0.get(peer), proved) {
            (None, _) => Ok(()),
            (Some(pinned), Some(proved)) if pinned == proved => Ok(()),
            (Some(_), _) => Err(AuthFailureReason::IdentityDowngrade),
        }
    }
}

impl AccessPolicy {
    /// An empty policy, which denies everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_new_peer(&self, peer: &Fingerprint) -> Result<(), DomainError> {
        if self.agents.contains_key(peer)
            || self.clients.contains_key(peer)
            || self.cert_trust.ca_fingerprints().any(|ca| ca == *peer)
        {
            return Err(DomainError::DuplicatePeer(*peer));
        }
        Ok(())
    }

    /// Authorizes the key `peer` to register as the agent of node `node`.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] if the key already has a role,
    /// [`DomainError::DuplicateNode`] if the node already has an agent.
    pub fn add_agent(&mut self, peer: Fingerprint, node: NodeId) -> Result<(), DomainError> {
        self.ensure_new_peer(&peer)?;
        if !self.nodes.insert(node.clone()) {
            return Err(DomainError::DuplicateNode(node));
        }
        self.agents.insert(peer, node);
        Ok(())
    }

    /// Authorizes one or two keys as the agent of node `node`: two during the rotation of the
    /// agent key (PROTOCOL §14). Whichever registers last wins.
    ///
    /// # Errors
    /// [`DomainError::AgentKeys`] if there are zero keys, more than [`MAX_AGENT_KEYS`], or
    /// duplicate keys; [`DomainError::DuplicatePeer`] and [`DomainError::DuplicateNode`] as in
    /// [`Self::add_agent`]. On error the policy is unchanged.
    pub fn add_agent_keys(
        &mut self,
        node: NodeId,
        keys: &[Fingerprint],
    ) -> Result<(), DomainError> {
        let distinct = match keys {
            [_] => true,
            [a, b] => a != b,
            _ => false,
        };
        if !distinct || keys.len() > MAX_AGENT_KEYS {
            return Err(DomainError::AgentKeys(node));
        }
        // All checks before any modification: no partial effects.
        for key in keys {
            self.ensure_new_peer(key)?;
        }
        if self.nodes.contains(&node) {
            return Err(DomainError::DuplicateNode(node));
        }
        self.nodes.insert(node.clone());
        for key in keys {
            self.agents.insert(*key, node.clone());
        }
        Ok(())
    }

    /// Authorizes the key `peer` as a client with the permissions `grant`.
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] if the key already has a role.
    pub fn add_client(&mut self, peer: Fingerprint, grant: ClientGrant) -> Result<(), DomainError> {
        self.ensure_new_peer(&peer)?;
        self.clients.insert(peer, grant);
        Ok(())
    }

    /// Pins the v2 identity of a key that already has a role (PQ-AUTH, PROTOCOL §7.5.3): from
    /// then on the key is admitted only through a hybrid IK handshake that proved `hybrid`.
    ///
    /// # Errors
    /// [`DomainError::UnknownPeer`] if the key has no role, [`DomainError::DuplicatePeer`] if
    /// it is already pinned or `hybrid` is another key's.
    pub fn pin_hybrid(
        &mut self,
        peer: Fingerprint,
        hybrid: HybridFingerprint,
    ) -> Result<(), DomainError> {
        if self.role(&peer).is_none() {
            return Err(DomainError::UnknownPeer(peer));
        }
        self.hybrid.pin(peer, hybrid)
    }

    /// The v2 identity pinned for `peer`, if any.
    #[must_use]
    pub fn hybrid_identity(&self, peer: &Fingerprint) -> Option<&HybridFingerprint> {
        self.hybrid.get(peer)
    }

    /// The role of a key, or `None` if unknown.
    #[must_use]
    pub fn role(&self, peer: &Fingerprint) -> Option<PeerRole<'_>> {
        if let Some(node) = self.agents.get(peer) {
            return Some(PeerRole::Agent { node });
        }
        self.clients
            .get(peer)
            .map(|grant| PeerRole::Client { grant })
    }

    /// The agent keys admitted for each node, in node order: two for the nodes whose
    /// rotation has not yet completed (PROTOCOL §14). The order of the keys is not
    /// significant.
    #[must_use]
    pub fn agent_keys(&self) -> BTreeMap<&NodeId, Vec<Fingerprint>> {
        let mut by_node: BTreeMap<&NodeId, Vec<Fingerprint>> = BTreeMap::new();
        for (key, node) in &self.agents {
            by_node.entry(node).or_default().push(*key);
        }
        by_node
    }

    /// Sets the pinned CAs and the denylist (PROTOCOL §15.8, §15.9).
    ///
    /// # Errors
    /// [`DomainError::DuplicatePeer`] if a CA key is also a peer's key.
    pub fn set_cert_trust(&mut self, trust: CertTrust) -> Result<(), DomainError> {
        for ca in trust.ca_fingerprints() {
            if self.agents.contains_key(&ca) || self.clients.contains_key(&ca) {
                return Err(DomainError::DuplicatePeer(ca));
            }
        }
        self.cert_trust = trust;
        Ok(())
    }

    /// The pinned CAs and the denylist.
    #[must_use]
    pub const fn cert_trust(&self) -> &CertTrust {
        &self.cert_trust
    }

    /// [`Self::admit_hybrid`] for a handshake that proved no hybrid identity.
    ///
    /// # Errors
    /// The rejection reason, for the audit.
    pub fn admit(
        &self,
        peer: &Fingerprint,
        cert: Option<&Arc<CertClaims>>,
        now: UnixTime,
    ) -> Result<Admission<'_>, AuthFailureReason> {
        self.admit_hybrid(peer, None, cert, now)
    }

    /// Steps 1, 2, 5, 7–11 of PROTOCOL §15.4 and the table in §15.5, for a handshake that
    /// proved the X25519-level identity `peer` and, with the hybrid IK suite, the hybrid
    /// identity `hybrid` (PQ-AUTH). A key pinned in v2 needs exactly that hybrid identity.
    ///
    /// # Errors
    /// The rejection reason, for the audit.
    pub fn admit_hybrid(
        &self,
        peer: &Fingerprint,
        hybrid: Option<&HybridFingerprint>,
        cert: Option<&Arc<CertClaims>>,
        now: UnixTime,
    ) -> Result<Admission<'_>, AuthFailureReason> {
        // Step 1: the denylist applies to any credential, any role and any handshake.
        if self.cert_trust.is_key_revoked(peer) {
            return Err(AuthFailureReason::KeyRevoked);
        }
        // The v2 pin, before any certificate: no downgrade to a classical handshake.
        self.hybrid.check(peer, hybrid)?;
        // Steps 5 and 7–10: a presented certificate is always verified (fail closed), even
        // for a whitelisted key.
        if let Some(claims) = cert {
            // Defense in depth: the binding (step 4) has already been verified in `zt-crypto`.
            if claims.subject() != peer {
                return Err(AuthFailureReason::Certificate(CertRejection::KeyMismatch));
            }
            self.cert_trust
                .check(claims, now)
                .map_err(AuthFailureReason::Certificate)?;
        }
        match self.role(peer) {
            // Step 11: a key has exactly one role.
            Some(PeerRole::Agent { .. }) if cert.is_some() => {
                Err(AuthFailureReason::Certificate(CertRejection::RoleConflict))
            }
            Some(PeerRole::Agent { node }) => Ok(Admission::Agent { node }),
            // The whitelist takes precedence: no union of permissions.
            Some(PeerRole::Client { .. }) => Ok(Admission::Client {
                credential: ClientCredential::Key,
            }),
            None => match cert {
                Some(claims) => Ok(Admission::Client {
                    credential: ClientCredential::Certificate(Arc::clone(claims)),
                }),
                None => Err(AuthFailureReason::UnknownPeer),
            },
        }
    }

    /// [`Self::may_open`] generalized: policy nodes ∩ effective scope of the credential.
    #[must_use]
    pub fn may_open_with(
        &self,
        peer: &Fingerprint,
        credential: &ClientCredential,
        target: &NodeId,
        now: UnixTime,
    ) -> bool {
        if self.cert_trust.is_key_revoked(peer) || !self.nodes.contains(target) {
            return false;
        }
        match credential {
            ClientCredential::Key => self.may_open(peer, target),
            ClientCredential::Certificate(claims) => {
                claims.subject() == peer
                    && !self.agents.contains_key(peer)
                    && self
                        .cert_trust
                        .check(claims, now)
                        .is_ok_and(|authority| authority.permits(claims, target))
            }
        }
    }

    /// `true` if the client `peer` may open a stream towards `target`.
    ///
    /// A node that does not exist in the policy is never granted, not even with
    /// [`AllowedNodes::All`].
    #[must_use]
    pub fn may_open(&self, peer: &Fingerprint, target: &NodeId) -> bool {
        self.nodes.contains(target)
            && self
                .clients
                .get(peer)
                .is_some_and(|grant| grant.allowed.permits(target))
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
        p.add_client(
            fp(10),
            ClientGrant {
                name: node("ansible"),
                allowed: only(&["web-01"]),
            },
        )
        .unwrap();
        p.add_client(
            fp(11),
            ClientGrant {
                name: node("admin"),
                allowed: AllowedNodes::All,
            },
        )
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
        assert_eq!(
            p.role(&fp(1)),
            Some(PeerRole::Agent {
                node: &node("web-01")
            })
        );
        assert!(matches!(p.role(&fp(10)), Some(PeerRole::Client { .. })));
        assert_eq!(p.role(&fp(99)), None);
    }

    #[test]
    fn clients_reach_only_granted_existing_nodes() {
        let p = policy();
        assert!(p.may_open(&fp(10), &node("web-01")));
        assert!(!p.may_open(&fp(10), &node("db-01")));
        assert!(p.may_open(&fp(11), &node("db-01")));
        // `All` does not invent nonexistent nodes.
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
            p.add_client(
                fp(1),
                ClientGrant {
                    name: node("x"),
                    allowed: AllowedNodes::All
                }
            ),
            Err(DomainError::DuplicatePeer(fp(1)))
        );
        assert_eq!(
            p.add_agent(fp(10), node("new")),
            Err(DomainError::DuplicatePeer(fp(10)))
        );
        assert_eq!(
            p.add_agent(fp(3), node("web-01")),
            Err(DomainError::DuplicateNode(node("web-01")))
        );
    }

    #[test]
    fn agent_keys_lists_both_keys_of_a_node_in_rotation() {
        let mut p = policy();
        p.add_agent_keys(node("app-01"), &[fp(20), fp(21)]).unwrap();
        let keys = p.agent_keys();
        assert_eq!(
            keys.keys().map(|n| n.as_str()).collect::<Vec<_>>(),
            ["app-01", "db-01", "web-01"]
        );
        assert_eq!(keys.get(&node("web-01")).unwrap(), &[fp(1)]);
        let app = keys.get(&node("app-01")).unwrap();
        assert_eq!(app.len(), 2);
        assert!(app.contains(&fp(20)) && app.contains(&fp(21)));
    }
}
