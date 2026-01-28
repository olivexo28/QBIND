//! Core primitives and enums for qbind post-quantum blockchain.

pub type AccountId = [u8; 32];
pub type ProgramId = [u8; 32];
pub type Hash32 = [u8; 32];

// ============================================================================
// ChainId - T159: Chain ID for domain separation
// ============================================================================

/// Unique identifier for a QBIND network (DevNet, TestNet, MainNet).
///
/// The `ChainId` is used in all signing preimages to prevent cross-chain replay attacks.
/// Signatures created on one network cannot be valid on another network because the
/// chain ID is part of the signed data.
///
/// # Design Notes
///
/// - The `u64` value is intentionally non-trivial to avoid accidental collisions.
/// - Each environment (DevNet, TestNet, MainNet) has a unique constant value.
/// - Custom networks can derive their own ChainId, but should avoid values that
///   could collide with the official constants.
///
/// # Security Properties
///
/// - All signed objects (transactions, batches, votes, proposals, timeouts) include
///   the chain ID in their signing preimage.
/// - This prevents cross-chain replay attacks between different QBIND networks.
/// - See `QBIND_CHAIN_ID_AND_DOMAINS.md` for the full domain-separation scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ChainId(pub u64);

impl ChainId {
    /// Create a new ChainId from a raw u64 value.
    pub const fn new(id: u64) -> Self {
        ChainId(id)
    }

    /// Get the raw u64 value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chain_{:016x}", self.0)
    }
}

/// ChainId constant for QBIND DevNet.
///
/// Value: `0x51424E44_44455600` (encoded form of "QBND" + "DEV" + null byte)
///
/// This is the chain ID for the development network. It should be used for:
/// - Local development and testing
/// - CI/CD pipelines
/// - Pre-release testing
///
/// **NOT FOR PRODUCTION USE**
pub const QBIND_DEVNET_CHAIN_ID: ChainId = ChainId(0x51424E44_44455600);

/// ChainId constant for QBIND TestNet.
///
/// Value: `0x51424E44_54535400` (encoded form of "QBND" + "TST" + null byte)
///
/// This is the chain ID for the public test network. It should be used for:
/// - Public testing before mainnet launch
/// - Integration testing with external services
/// - Community testing and feedback
///
/// **NOT FOR PRODUCTION VALUE TRANSFER**
pub const QBIND_TESTNET_CHAIN_ID: ChainId = ChainId(0x51424E44_54535400);

/// ChainId constant for QBIND MainNet.
///
/// Value: `0x51424E44_4D41494E` (encoded form of "QBND" + "MAIN")
///
/// This is the chain ID for the production main network. It should be used for:
/// - Production deployments
/// - Real value transfer
///
/// **PRODUCTION USE ONLY**
pub const QBIND_MAINNET_CHAIN_ID: ChainId = ChainId(0x51424E44_4D41494E);

// ============================================================================
// NetworkEnvironment - T159: Network environment classification
// ============================================================================

/// Classification of the network environment.
///
/// This enum represents the three standard QBIND network environments:
/// - `Devnet`: Development network for testing and development
/// - `Testnet`: Public test network for pre-production testing
/// - `Mainnet`: Production network for real value transfer
///
/// The environment is used to:
/// - Select the appropriate `ChainId` constant
/// - Configure network-specific parameters
/// - Enable/disable certain features based on environment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum NetworkEnvironment {
    /// Development network (default for local testing).
    #[default]
    Devnet,
    /// Public test network.
    Testnet,
    /// Production main network.
    Mainnet,
}

impl NetworkEnvironment {
    /// Get the canonical ChainId for this network environment.
    pub const fn chain_id(&self) -> ChainId {
        match self {
            NetworkEnvironment::Devnet => QBIND_DEVNET_CHAIN_ID,
            NetworkEnvironment::Testnet => QBIND_TESTNET_CHAIN_ID,
            NetworkEnvironment::Mainnet => QBIND_MAINNET_CHAIN_ID,
        }
    }

    /// Get a short ASCII scope string for this environment.
    ///
    /// Used in domain-separation tags:
    /// - Devnet: "DEV"
    /// - Testnet: "TST"
    /// - Mainnet: "MAIN"
    pub const fn scope(&self) -> &'static str {
        match self {
            NetworkEnvironment::Devnet => "DEV",
            NetworkEnvironment::Testnet => "TST",
            NetworkEnvironment::Mainnet => "MAIN",
        }
    }
}

impl std::fmt::Display for NetworkEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkEnvironment::Devnet => write!(f, "DevNet"),
            NetworkEnvironment::Testnet => write!(f, "TestNet"),
            NetworkEnvironment::Mainnet => write!(f, "MainNet"),
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteFamily {
    Lattice = 0x00,
    HashBased = 0x01,
    CodeBased = 0x02,
    Isogeny = 0x03,
    Reserved = 0xFF,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecurityCategory {
    Cat1 = 0x01,
    Cat3 = 0x03,
    Cat5 = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteTier {
    Core = 0x00,
    Experimental = 0x01,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteStatus {
    Active = 0x00,
    Legacy = 0x01,
    Disabled = 0x02,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    ValidatorOwner = 0x00,
    ValidatorConsensus = 0x01,
    ValidatorNetwork = 0x02,
    Governance = 0x03,
    BridgeOperator = 0x04,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MainnetStatus {
    PreGenesis = 0x00,
    Ready = 0x01,
    Activated = 0x02,
}
