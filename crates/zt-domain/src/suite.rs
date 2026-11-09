//! Handshake suites: which Noise construction a handshake uses (PROTOCOL §7.5).
//!
//! A suite fixes the Noise protocol name, the prologue and the message sizes. There is
//! **one** identifier per suite (finding AP-7) and suites are deliberately **not ordered**:
//! there is no "minimum suite", only explicit accepted sets, configured per role. Nothing about
//! the suite travels in the clear (finding AP-11): a responder finds the suite by trying the
//! ones it accepts, as it already tries its current and previous key.
//!
//! Adding a suite (PQ-1) means a new variant, its sizes, and flipping
//! [`HandshakeSuite::is_supported`] once `zt-crypto` can run it.

use std::fmt;
use std::str::FromStr;

use crate::limits::{MAX_CERT_LEN, NOISE_MSG1_OVERHEAD, NOISE_TAG_LEN};

/// Length of an X25519 public key (Noise `e`, `s`).
const DH_LEN: usize = 32;
/// ML-KEM-768 encapsulation key (FIPS 203).
const MLKEM768_EK_LEN: usize = 1_184;
/// ML-KEM-768 ciphertext (FIPS 203).
const MLKEM768_CT_LEN: usize = 1_088;

/// A handshake suite: one Noise protocol name, one prologue, one set of message sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandshakeSuite {
    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s` with the `TCN/1` prologues: the classical suite,
    /// byte for byte the handshake of every release so far.
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
    /// A known suite that this build cannot run, or that a role does not accept.
    #[error("handshake suite not supported or not accepted")]
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

    /// The suite id. It never travels in the clear: from PQ-1 on it is mixed into the prologue
    /// of the suites that have one (the classical suite keeps the `TCN/1` prologue).
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::NoiseIk25519 => 0x00,
            Self::NoiseIkhfs25519MlKem768 => 0x01,
        }
    }

    /// The Noise protocol name, which is also the suite's only spelling in configuration.
    #[must_use]
    pub const fn protocol_name(self) -> &'static str {
        match self {
            Self::NoiseIk25519 => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            Self::NoiseIkhfs25519MlKem768 => "Noise_IKhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s",
        }
    }

    /// `true` if this build can run the suite. Configuration refuses the others.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        match self {
            Self::NoiseIk25519 => true,
            Self::NoiseIkhfs25519MlKem768 => false,
        }
    }

    /// Bytes of message 1 beyond its payload. The payload tag is included.
    #[must_use]
    pub const fn msg1_overhead(self) -> usize {
        match self {
            // e + encrypted s + payload tag.
            Self::NoiseIk25519 => NOISE_MSG1_OVERHEAD,
            // e + encrypted e1 + encrypted s + payload tag. In IK the HFS modifier puts `e1`
            // after `es` (HFS §5), so it is encrypted: the spike test checks it against snow.
            Self::NoiseIkhfs25519MlKem768 => {
                DH_LEN + MLKEM768_EK_LEN + NOISE_TAG_LEN + DH_LEN + NOISE_TAG_LEN + NOISE_TAG_LEN
            }
        }
    }

    /// The longest legitimate message 1: the one carrying the largest certificate
    /// (PROTOCOL §15.3).
    #[must_use]
    pub const fn max_msg1_len(self) -> usize {
        self.msg1_overhead().saturating_add(MAX_CERT_LEN)
    }

    /// The length of message 2, whose payload is always empty.
    #[must_use]
    pub const fn msg2_len(self) -> usize {
        match self {
            // e + empty payload tag.
            Self::NoiseIk25519 => DH_LEN + NOISE_TAG_LEN,
            // e + encrypted ekem1 + empty payload tag.
            Self::NoiseIkhfs25519MlKem768 => {
                DH_LEN + MLKEM768_CT_LEN + NOISE_TAG_LEN + NOISE_TAG_LEN
            }
        }
    }

    const fn bit(self) -> u8 {
        1 << self.id()
    }
}

// Every suite's largest message 1 fits a Noise message and a `Data` frame (it is the first
// `Data` payload on the end-to-end channel), so no legitimate handshake is ever cut.
const _: () = {
    let mut rest = HandshakeSuite::ALL.as_slice();
    while let [suite, tail @ ..] = rest {
        assert!(suite.max_msg1_len() <= crate::limits::MAX_PAYLOAD_LEN);
        assert!(suite.max_msg1_len() <= crate::limits::NOISE_MAX_MESSAGE_LEN);
        assert!(suite.msg2_len() <= crate::limits::NOISE_MAX_MESSAGE_LEN);
        assert!(suite.id() < 8);
        rest = tail;
    }
};

impl fmt::Display for HandshakeSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.protocol_name())
    }
}

impl FromStr for HandshakeSuite {
    type Err = SuiteError;

    /// Exactly the Noise protocol name: no case folding, trimming or aliases.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|s| s.protocol_name() == text)
            .ok_or(SuiteError::Unknown)
    }
}

impl TryFrom<u8> for HandshakeSuite {
    type Error = SuiteError;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .into_iter()
            .find(|s| s.id() == id)
            .ok_or(SuiteError::Unknown)
    }
}

/// A non-empty set of suites a responder accepts for one role. The order in which a
/// configuration lists them carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSuites {
    bits: u8,
}

impl AcceptedSuites {
    /// The set of the listed suites.
    ///
    /// # Errors
    /// [`SuiteError::Empty`] for no suite, [`SuiteError::Duplicate`] for a repeated one.
    /// Whether the build supports them is checked by the configuration
    /// ([`AcceptedSuites::all_supported`]), so that tests can describe future sets.
    pub fn new(suites: impl IntoIterator<Item = HandshakeSuite>) -> Result<Self, SuiteError> {
        let mut bits = 0_u8;
        for suite in suites {
            if bits & suite.bit() != 0 {
                return Err(SuiteError::Duplicate);
            }
            bits |= suite.bit();
        }
        if bits == 0 {
            return Err(SuiteError::Empty);
        }
        Ok(Self { bits })
    }

    /// The set with one suite.
    #[must_use]
    pub const fn only(suite: HandshakeSuite) -> Self {
        Self { bits: suite.bit() }
    }

    /// `true` if `suite` is in the set.
    #[must_use]
    pub const fn contains(self, suite: HandshakeSuite) -> bool {
        self.bits & suite.bit() != 0
    }

    /// The suites of the set, in the fixed order of [`HandshakeSuite::ALL`].
    pub fn iter(self) -> impl Iterator<Item = HandshakeSuite> {
        HandshakeSuite::ALL
            .into_iter()
            .filter(move |s| self.contains(*s))
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// The longest legitimate message 1 over the set: the pre-authentication buffer cap.
    #[must_use]
    pub const fn max_msg1_len(self) -> usize {
        let mut max = 0;
        let mut rest = HandshakeSuite::ALL.as_slice();
        while let [suite, tail @ ..] = rest {
            if self.contains(*suite) && suite.max_msg1_len() > max {
                max = suite.max_msg1_len();
            }
            rest = tail;
        }
        max
    }

    /// `true` if every suite of the set is supported by this build.
    #[must_use]
    pub const fn all_supported(self) -> bool {
        let mut rest = HandshakeSuite::ALL.as_slice();
        while let [suite, tail @ ..] = rest {
            if self.contains(*suite) && !suite.is_supported() {
                return false;
            }
            rest = tail;
        }
        true
    }

    /// The protocol names of the set, comma-separated (for audit events).
    #[must_use]
    pub fn names(self) -> String {
        self.iter()
            .map(HandshakeSuite::protocol_name)
            .collect::<Vec<_>>()
            .join(",")
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

/// The suites a relay accepts, per role (finding AP-7: agents and clients separately, because
/// laptops are the long tail of any upgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuitePolicy {
    /// Suites accepted from agents.
    pub agents: AcceptedSuites,
    /// Suites accepted from clients.
    pub clients: AcceptedSuites,
}

impl SuitePolicy {
    /// The classical suite only, for both roles: the fixed default, which never changes between
    /// releases (AP-7). A release that adds a suite does not accept it until configured.
    #[must_use]
    pub const fn classical() -> Self {
        Self {
            agents: AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
            clients: AcceptedSuites::only(HandshakeSuite::NoiseIk25519),
        }
    }

    /// The set for `role`.
    #[must_use]
    pub const fn for_role(self, role: InitiatorRole) -> AcceptedSuites {
        match role {
            InitiatorRole::Agent => self.agents,
            InitiatorRole::Client => self.clients,
        }
    }

    /// Suites worth trying on a message 1, before the role is known.
    #[must_use]
    pub const fn any_role(self) -> AcceptedSuites {
        self.agents.union(self.clients)
    }

    /// `Ok` if `role` may use `suite`.
    ///
    /// # Errors
    /// [`SuiteError::Unsupported`] if the suite is not in the role's set.
    pub const fn check(self, role: InitiatorRole, suite: HandshakeSuite) -> Result<(), SuiteError> {
        if self.for_role(role).contains(suite) {
            Ok(())
        } else {
            Err(SuiteError::Unsupported)
        }
    }
}
