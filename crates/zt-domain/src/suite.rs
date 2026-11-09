//! Handshake suites: which Noise construction a handshake uses (PROTOCOL §7.5).
//!
//! RED stub (PQ-0): every operation fails closed until the implementation lands.

use std::fmt;
use std::str::FromStr;

/// A handshake suite: one Noise protocol name, one prologue, one set of message sizes.
///
/// A suite is identified by a **single** id (finding AP-7). Suites are deliberately not
/// ordered: there is no "minimum suite", only explicit accepted sets per role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandshakeSuite {
    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s` with the `TCN/1` prologues: the classical suite.
    NoiseIk25519,
    /// `Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`: reserved for PQ-1, not supported by
    /// this build.
    NoiseIkhfs25519MlKem768,
}

/// Why a suite name, id or set was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SuiteError {
    /// Not the name or id of any suite.
    #[error("unknown handshake suite")]
    Unknown,
    /// A known suite that this build cannot run.
    #[error("handshake suite not supported by this build")]
    Unsupported,
    /// An accepted set must name at least one suite.
    #[error("the accepted handshake suites must not be empty")]
    Empty,
    /// The same suite twice in one set.
    #[error("a handshake suite is listed twice")]
    Duplicate,
}

impl HandshakeSuite {
    /// Every suite this version of the protocol knows, supported or not.
    pub const ALL: [Self; 2] = [Self::NoiseIk25519, Self::NoiseIkhfs25519MlKem768];

    /// The suite id (stub).
    #[must_use]
    pub const fn id(self) -> u8 {
        0xff
    }

    /// The Noise protocol name (stub).
    #[must_use]
    pub const fn protocol_name(self) -> &'static str {
        ""
    }

    /// `true` if this build can run the suite (stub).
    #[must_use]
    pub const fn is_supported(self) -> bool {
        false
    }

    /// Bytes of message 1 beyond its payload (stub).
    #[must_use]
    pub const fn msg1_overhead(self) -> usize {
        0
    }

    /// The longest legitimate message 1 (stub).
    #[must_use]
    pub const fn max_msg1_len(self) -> usize {
        0
    }

    /// The length of message 2 (stub).
    #[must_use]
    pub const fn msg2_len(self) -> usize {
        0
    }
}

impl fmt::Display for HandshakeSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.protocol_name())
    }
}

impl FromStr for HandshakeSuite {
    type Err = SuiteError;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        Err(SuiteError::Unknown)
    }
}

impl TryFrom<u8> for HandshakeSuite {
    type Error = SuiteError;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Err(SuiteError::Unknown)
    }
}

/// A non-empty set of suites a responder accepts for one role (stub).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSuites {
    bits: u8,
}

impl AcceptedSuites {
    /// The set of the listed suites (stub).
    ///
    /// # Errors
    /// Always (stub).
    pub fn new(_: impl IntoIterator<Item = HandshakeSuite>) -> Result<Self, SuiteError> {
        Err(SuiteError::Empty)
    }

    /// The set with one suite (stub).
    #[must_use]
    pub const fn only(_: HandshakeSuite) -> Self {
        Self { bits: 0 }
    }

    /// `true` if `suite` is in the set (stub).
    #[must_use]
    pub const fn contains(self, _: HandshakeSuite) -> bool {
        false
    }

    /// The suites of the set (stub).
    pub fn iter(self) -> impl Iterator<Item = HandshakeSuite> {
        std::iter::empty()
    }

    /// The union of two sets (stub).
    #[must_use]
    pub const fn union(self, _: Self) -> Self {
        self
    }

    /// The longest legitimate message 1 over the set (stub).
    #[must_use]
    pub const fn max_msg1_len(self) -> usize {
        0
    }

    /// `true` if every suite of the set is supported by this build (stub).
    #[must_use]
    pub const fn all_supported(self) -> bool {
        false
    }
}

/// The two kinds of initiator a relay distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InitiatorRole {
    /// An agent (outer channel).
    Agent,
    /// A client (outer or end-to-end channel).
    Client,
}

/// The suites a relay accepts, per role (finding AP-7: agents and clients separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuitePolicy {
    /// Suites accepted from agents.
    pub agents: AcceptedSuites,
    /// Suites accepted from clients.
    pub clients: AcceptedSuites,
}

impl SuitePolicy {
    /// The classical suite only, for both roles (stub).
    #[must_use]
    pub const fn classical() -> Self {
        Self {
            agents: AcceptedSuites { bits: 0 },
            clients: AcceptedSuites { bits: 0 },
        }
    }

    /// The set for `role` (stub).
    #[must_use]
    pub const fn for_role(self, _: InitiatorRole) -> AcceptedSuites {
        self.agents
    }

    /// Suites worth trying on a message 1, before the role is known (stub).
    #[must_use]
    pub const fn any_role(self) -> AcceptedSuites {
        self.agents
    }

    /// `Ok` if `role` may use `suite` (stub).
    ///
    /// # Errors
    /// Always (stub).
    pub const fn check(self, _: InitiatorRole, _: HandshakeSuite) -> Result<(), SuiteError> {
        Err(SuiteError::Unsupported)
    }
}
