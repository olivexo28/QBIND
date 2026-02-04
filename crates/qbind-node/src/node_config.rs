//! T162: Node configuration with network environment selection.
//!
//! This module provides the top-level node configuration struct that includes
//! network environment selection (DevNet/TestNet/MainNet) and chain-id plumbing.
//!
//! # Environment Selection
//!
//! The `NodeConfig` struct contains a `NetworkEnvironment` field that determines:
//! - The chain ID used for all signing/verification operations
//! - The domain scope for domain-separated signatures
//! - Environment-specific logging and metrics
//!
//! # CLI Integration
//!
//! The module provides helper functions for parsing CLI arguments:
//! - `parse_environment()` - Parse environment from string
//! - `NodeConfig::log_startup_info()` - Log startup information
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::node_config::{NodeConfig, parse_environment};
//! use qbind_types::NetworkEnvironment;
//!
//! // Parse from CLI argument
//! let env = parse_environment("testnet").unwrap();
//!
//! // Create config
//! let config = NodeConfig::new(env);
//!
//! // Log startup info
//! config.log_startup_info("my-validator-id");
//!
//! // Get chain ID for signing
//! let chain_id = config.chain_id();
//! ```

use qbind_ledger::{FeeDistributionPolicy, MonetaryAccounts, MonetaryMode, SeigniorageSplit};
use qbind_types::{ChainId, NetworkEnvironment};
use std::path::PathBuf;

// ============================================================================
// T165: DAG Availability Configuration
// ============================================================================

/// Configuration for DAG availability certificates (T165).
///
/// This struct controls the behavior of the DAG availability protocol,
/// including whether it's enabled and the quorum threshold for certificates.
///
/// # Environments
///
/// - **DevNet**: Disabled by default (DevNet is frozen at DAG v0)
/// - **TestNet Alpha**: Enabled when running with DAG mempool
/// - **MainNet**: Enabled by default (future)
///
/// # Quorum Calculation
///
/// For BFT consensus with `n = 3f + 1` validators, the quorum is `2f + 1`.
/// For example:
/// - 4 validators (f=1): quorum = 3
/// - 7 validators (f=2): quorum = 5
/// - 10 validators (f=3): quorum = 7
#[derive(Clone, Debug, PartialEq)]
pub struct DagAvailabilityConfig {
    /// Whether DAG availability certificates are enabled.
    ///
    /// When `false`, the DAG mempool operates in v0 mode (no acks/certs).
    /// When `true`, validators issue BatchAcks and form BatchCertificates.
    pub enabled: bool,

    /// Quorum fraction for certificate formation.
    ///
    /// Default: `2.0 / 3.0` (i.e., 2f+1 for n=3f+1)
    ///
    /// The actual quorum size is computed as:
    /// `quorum_size = ceil(quorum_fraction * num_validators)`
    pub quorum_fraction: f32,
}

impl Default for DagAvailabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default (DevNet compatibility)
            quorum_fraction: 2.0 / 3.0,
        }
    }
}

impl DagAvailabilityConfig {
    /// Create a disabled configuration (DevNet default).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create an enabled configuration for TestNet/MainNet.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            quorum_fraction: 2.0 / 3.0,
        }
    }

    /// Compute the quorum size for a given number of validators.
    ///
    /// # Arguments
    ///
    /// * `num_validators` - Total number of validators in the network
    ///
    /// # Returns
    ///
    /// The quorum size (number of acks required for a certificate).
    /// Returns 1 if `num_validators` is 0 (edge case for single-node testing).
    pub fn compute_quorum_size(&self, num_validators: usize) -> usize {
        if num_validators == 0 {
            return 1;
        }
        let quorum = (self.quorum_fraction * num_validators as f32).ceil() as usize;
        quorum.max(1) // At least 1 ack required
    }

    /// Create a configuration with a specific quorum size (for testing).
    pub fn with_fixed_quorum(quorum_size: usize) -> Self {
        // We don't store a fixed quorum, but this helps with testing
        // where we want a specific quorum regardless of validator count
        Self {
            enabled: true,
            // Use a fraction that will give the desired quorum for typical validator counts
            quorum_fraction: quorum_size as f32 / 4.0, // Assumes ~4 validators in tests
        }
    }
}

// ============================================================================
// T170: NetworkTransportConfig
// ============================================================================

/// Configuration for the P2P network transport layer (T170).
///
/// This struct controls the behavior of the P2P networking stack.
/// For DevNet and TestNet Alpha, P2P is disabled by default (static mesh).
/// For TestNet Beta and MainNet, P2P will be enabled.
///
/// # Phased Rollout
///
/// - **DevNet v0**: `enable_p2p = false` — Uses static KEMTLS mesh
/// - **TestNet Alpha**: `enable_p2p = false` — Config-driven static mesh
/// - **TestNet Beta**: `enable_p2p = true` — Basic peer discovery + gossip
/// - **MainNet**: `enable_p2p = true` — Full P2P with DoS protection
///
/// # Connection Limits
///
/// - `max_outbound`: Maximum outbound connections (default: 16)
/// - `max_inbound`: Maximum inbound connections (default: 64)
/// - `gossip_fanout`: Number of peers to forward gossip messages (default: 6)
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::NetworkTransportConfig;
///
/// // Default config (P2P disabled, static mesh)
/// let config = NetworkTransportConfig::default();
/// assert!(!config.enable_p2p);
///
/// // Enable P2P for TestNet Beta
/// let testnet_beta = NetworkTransportConfig::testnet_beta();
/// assert!(testnet_beta.enable_p2p);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTransportConfig {
    /// Whether the P2P overlay is enabled.
    ///
    /// - `false` (default): Uses static mesh (DevNet, TestNet Alpha)
    /// - `true`: Uses dynamic P2P overlay (TestNet Beta, MainNet)
    pub enable_p2p: bool,

    /// Maximum number of outbound connections.
    ///
    /// Default: 16. For validators, this should be at least 2f+1 for liveness.
    pub max_outbound: usize,

    /// Maximum number of inbound connections.
    ///
    /// Default: 64. Higher than outbound to allow full nodes to connect.
    pub max_inbound: usize,

    /// Gossip fanout for DAG/mempool overlay.
    ///
    /// Default: 6. Number of peers to forward gossip messages to.
    pub gossip_fanout: usize,

    /// Local address to listen on for P2P connections (T172).
    /// e.g. "0.0.0.0:9000"
    pub listen_addr: Option<String>,

    /// Public address to advertise to peers (T172).
    pub advertised_addr: Option<String>,

    /// List of static peers to dial at startup (T172).
    /// Format: "host:port"
    pub static_peers: Vec<String>,
}

impl Default for NetworkTransportConfig {
    fn default() -> Self {
        Self {
            enable_p2p: false, // Static mesh by default (DevNet/TestNet Alpha)
            max_outbound: 16,  // Suggested default for validators
            max_inbound: 64,   // Allow more inbound for full nodes
            gossip_fanout: 6,  // Standard gossip fanout
            listen_addr: None,
            advertised_addr: None,
            static_peers: Vec::new(),
        }
    }
}

impl NetworkTransportConfig {
    /// Create a disabled configuration (DevNet/TestNet Alpha default).
    ///
    /// Uses static mesh networking without dynamic P2P.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create an enabled configuration for TestNet Beta.
    ///
    /// Enables basic P2P with peer discovery and gossip.
    pub fn testnet_beta() -> Self {
        Self {
            enable_p2p: true,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 6,
            listen_addr: Some("0.0.0.0:9000".to_string()),
            advertised_addr: None,
            static_peers: Vec::new(),
        }
    }

    /// Create a configuration for MainNet with production values.
    ///
    /// Enables full P2P with DoS protection settings.
    pub fn mainnet() -> Self {
        Self {
            enable_p2p: true,
            max_outbound: 16,
            max_inbound: 64,
            gossip_fanout: 8,
            listen_addr: Some("0.0.0.0:9000".to_string()),
            advertised_addr: None,
            static_peers: Vec::new(),
        }
    }

    /// Check if the P2P overlay is enabled.
    pub fn is_p2p_enabled(&self) -> bool {
        self.enable_p2p
    }
}

// ============================================================================
// T173: NetworkMode – Consensus/DAG networking mode selection
// ============================================================================

/// Network mode for consensus and DAG message transport (T173).
///
/// This enum determines how consensus and DAG messages are transported
/// between validators:
///
/// - **LocalMesh**: Uses existing local/loopback networking (default for DevNet/TestNet Alpha)
/// - **P2p**: Uses `TcpKemTlsP2pService` for P2P transport (opt-in for TestNet Alpha)
///
/// # Phased Rollout
///
/// - **DevNet v0**: `LocalMesh` default; P2P disabled
/// - **TestNet Alpha**: `LocalMesh` default; `P2p` opt-in for testing
/// - **TestNet Beta**: `P2p` default for dynamic peer discovery
/// - **MainNet**: `P2p` required with full DoS protection
///
/// # Usage
///
/// ```rust,ignore
/// use qbind_node::node_config::{NetworkMode, NodeConfig};
///
/// // Default uses LocalMesh (DevNet compatibility)
/// let config = NodeConfig::default();
/// assert_eq!(config.network_mode, NetworkMode::LocalMesh);
///
/// // Opt-in to P2P mode for TestNet testing
/// let p2p_config = config.with_network_mode(NetworkMode::P2p);
/// assert_eq!(p2p_config.network_mode, NetworkMode::P2p);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// Local mesh networking (existing behavior).
    ///
    /// Uses the existing `PeerManager` / `AsyncPeerManager` based networking
    /// with direct KEMTLS connections. This is the default for DevNet and
    /// TestNet Alpha for backward compatibility.
    #[default]
    LocalMesh,

    /// P2P networking via `TcpKemTlsP2pService` (T172/T173).
    ///
    /// Uses the new P2P transport layer with:
    /// - `P2pMessage` framing for consensus/DAG messages
    /// - Static peer connections via `NetworkTransportConfig.static_peers`
    /// - Broadcast and direct messaging via `P2pService` trait
    ///
    /// Requires `enable_p2p = true` in `NetworkTransportConfig`.
    P2p,
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkMode::LocalMesh => write!(f, "local-mesh"),
            NetworkMode::P2p => write!(f, "p2p"),
        }
    }
}

/// Parse a network mode from a string.
///
/// Valid values: "local-mesh" | "localmesh" | "mesh" | "p2p"
///
/// # Fallback Behavior
///
/// Returns `NetworkMode::LocalMesh` for unrecognized values. This is intentional
/// to preserve backward compatibility - new config values default to the safe
/// existing behavior. Users should verify their configuration takes effect by
/// checking `NodeConfig::network_mode` after parsing.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_network_mode;
///
/// assert_eq!(parse_network_mode("p2p"), NetworkMode::P2p);
/// assert_eq!(parse_network_mode("local-mesh"), NetworkMode::LocalMesh);
/// assert_eq!(parse_network_mode("unknown"), NetworkMode::LocalMesh); // Fallback
/// ```
pub fn parse_network_mode(s: &str) -> NetworkMode {
    match s.to_lowercase().as_str() {
        "p2p" => NetworkMode::P2p,
        "local-mesh" | "localmesh" | "mesh" => NetworkMode::LocalMesh,
        _ => {
            // Log the fallback for debugging purposes
            eprintln!(
                "[T173] Warning: Unrecognized network mode '{}', defaulting to LocalMesh",
                s
            );
            NetworkMode::LocalMesh
        }
    }
}

// ============================================================================
// ExecutionProfile (T163)
// ============================================================================

/// Execution profile for selecting the transaction execution mode.
///
/// # T163: VM v0 Introduction
///
/// This enum allows the node to choose between different execution modes:
/// - `NonceOnly`: DevNet default, uses Stage A sender-partitioned parallel execution
/// - `VmV0`: TestNet Alpha, uses sequential VM v0 execution with account balances
///
/// DevNet v0 behavior is preserved by defaulting to `NonceOnly`.
/// TestNet Alpha will use `VmV0` for the new VM-based execution.
///
/// # Usage
///
/// ```rust,ignore
/// use qbind_node::node_config::{ExecutionProfile, parse_execution_profile};
///
/// // Parse from CLI argument
/// let profile = parse_execution_profile("vm-v0");
/// assert_eq!(profile, ExecutionProfile::VmV0);
///
/// // Default is NonceOnly
/// let default_profile = parse_execution_profile("unknown");
/// assert_eq!(default_profile, ExecutionProfile::NonceOnly);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExecutionProfile {
    /// Nonce-only execution (DevNet default).
    ///
    /// Uses Stage A sender-partitioned parallel execution.
    /// Transactions only validate and increment nonces.
    #[default]
    NonceOnly,

    /// VM v0 execution (TestNet Alpha).
    ///
    /// Uses sequential execution with account state:
    /// - AccountState { nonce, balance }
    /// - Transfer transaction semantics
    /// - Deterministic state transitions
    VmV0,
}

impl std::fmt::Display for ExecutionProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionProfile::NonceOnly => write!(f, "nonce-only"),
            ExecutionProfile::VmV0 => write!(f, "vm-v0"),
        }
    }
}

// ============================================================================
// NodeConfig
// ============================================================================

/// Top-level node configuration for qbind-node.
///
/// This struct holds the environment-level configuration for a node,
/// including the network environment selection that determines chain-id
/// and domain separation behavior.
///
/// # Environment Selection (T162)
///
/// The `environment` field determines:
/// - **Chain ID**: Used in all signing preimages to prevent cross-chain replay
/// - **Domain Scope**: DEV, TST, or MAIN for domain-separated signatures
/// - **Logging**: Environment is included in startup logs and metrics
///
/// # Execution Profile (T163)
///
/// The `execution_profile` field determines:
/// - **NonceOnly**: DevNet default, Stage A parallel nonce execution
/// - **VmV0**: TestNet Alpha, sequential VM v0 with account balances
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::{NodeConfig, ExecutionProfile};
/// use qbind_types::NetworkEnvironment;
///
/// let config = NodeConfig::new(NetworkEnvironment::Testnet);
/// assert_eq!(config.environment, NetworkEnvironment::Testnet);
/// assert_eq!(config.chain_id().as_u64(), 0x51424E44_54535400);
///
/// // Create config with VM v0 profile for TestNet
/// let vm_config = NodeConfig::with_profile(
///     NetworkEnvironment::Testnet,
///     ExecutionProfile::VmV0
/// );
/// assert_eq!(vm_config.execution_profile, ExecutionProfile::VmV0);
/// ```
// ============================================================================
// T180: MempoolMode – Selects between FIFO and DAG mempool
// ============================================================================

/// Mempool mode for transaction management (T180).
///
/// This enum determines which mempool implementation is used:
///
/// - **Fifo**: Traditional FIFO mempool (default for DevNet/TestNet Alpha)
/// - **Dag**: DAG-based mempool with availability certificates (default for TestNet Beta)
///
/// # Phased Rollout
///
/// - **DevNet v0**: `Fifo` (default and only option)
/// - **TestNet Alpha**: `Fifo` default; DAG opt-in
/// - **TestNet Beta**: `Dag` default; FIFO fallback for testing
/// - **MainNet**: `Dag` required
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MempoolMode {
    /// FIFO mempool (traditional queue-based).
    ///
    /// Transactions are ordered by arrival time.
    /// Simple and deterministic, suitable for dev/test.
    #[default]
    Fifo,

    /// DAG mempool with availability certificates.
    ///
    /// Validators create batches that form a DAG structure.
    /// Provides improved throughput and fairness.
    Dag,
}

impl std::fmt::Display for MempoolMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolMode::Fifo => write!(f, "fifo"),
            MempoolMode::Dag => write!(f, "dag"),
        }
    }
}

/// Parse a mempool mode from a string.
///
/// Valid values: "fifo" | "dag"
///
/// # Fallback Behavior
///
/// Returns `MempoolMode::Fifo` for unrecognized values. This is intentional
/// to provide a safe default when parsing user input. Callers should validate
/// input before calling this function if strict validation is needed.
///
/// # Example
///
/// ```rust,ignore
/// assert_eq!(parse_mempool_mode("dag"), MempoolMode::Dag);
/// assert_eq!(parse_mempool_mode("fifo"), MempoolMode::Fifo);
/// assert_eq!(parse_mempool_mode("invalid"), MempoolMode::Fifo); // Falls back to Fifo
/// ```
pub fn parse_mempool_mode(s: &str) -> MempoolMode {
    match s.to_lowercase().as_str() {
        "dag" => MempoolMode::Dag,
        "fifo" => MempoolMode::Fifo,
        other => {
            eprintln!(
                "[T180] Warning: Unrecognized mempool mode '{}', defaulting to Fifo",
                other
            );
            MempoolMode::Fifo
        }
    }
}

// ============================================================================
// T189: DagCouplingMode – DAG–consensus coupling configuration
// ============================================================================

/// DAG–consensus coupling mode (T189).
///
/// Controls how the consensus layer interacts with DAG availability certificates.
/// See QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md §6 for detailed semantics.
///
/// # Phased Rollout
///
/// - **DevNet v0**: `Off` (coupling disabled)
/// - **TestNet Alpha**: `Off` (coupling disabled)
/// - **TestNet Beta**: `Off` (optionally `Warn` for testing/transition)
/// - **MainNet v0**: `Enforce` (coupling required)
///
/// # Mode Semantics
///
/// | Mode | Proposal Construction | Vote Validation | Commit |
/// | :--- | :--- | :--- | :--- |
/// | `Off` | No restrictions | No DAG checks | Normal |
/// | `Warn` | No restrictions | Log warnings for uncertified batches | Normal |
/// | `Enforce` | Only certified batches | Reject uncertified batches | Only certified |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DagCouplingMode {
    /// Off: No coupling; consensus ignores DAG certificates.
    ///
    /// Used in: DevNet v0, TestNet Alpha, TestNet Beta (default).
    /// Proposals and votes do not require batch certificates.
    #[default]
    Off,

    /// Warn: Log warnings for uncertified batches but don't reject.
    ///
    /// Used in: Testing/transition scenarios.
    /// Proposals can include uncertified batches, but warnings are logged.
    /// Validators vote normally but log warnings for missing certs.
    Warn,

    /// Enforce: Reject proposals with uncertified batches.
    ///
    /// Used in: MainNet v0.
    /// Proposals must only include certified batches.
    /// Validators reject proposals with uncertified or invalid certificates.
    /// All committed transactions must belong to certified batches.
    Enforce,
}

impl std::fmt::Display for DagCouplingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagCouplingMode::Off => write!(f, "off"),
            DagCouplingMode::Warn => write!(f, "warn"),
            DagCouplingMode::Enforce => write!(f, "enforce"),
        }
    }
}

/// Parse a DAG coupling mode from a string (T189).
///
/// Valid values: "off" | "warn" | "enforce" (case-insensitive)
///
/// # Returns
///
/// `Some(DagCouplingMode)` if valid, `None` for unrecognized values.
/// Unlike `parse_mempool_mode`, this function does NOT fall back to a default
/// because coupling mode is a critical configuration that should be explicit.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_dag_coupling_mode;
///
/// assert_eq!(parse_dag_coupling_mode("off"), Some(DagCouplingMode::Off));
/// assert_eq!(parse_dag_coupling_mode("warn"), Some(DagCouplingMode::Warn));
/// assert_eq!(parse_dag_coupling_mode("enforce"), Some(DagCouplingMode::Enforce));
/// assert_eq!(parse_dag_coupling_mode("invalid"), None);
/// ```
pub fn parse_dag_coupling_mode(s: &str) -> Option<DagCouplingMode> {
    match s.to_lowercase().as_str() {
        "off" => Some(DagCouplingMode::Off),
        "warn" => Some(DagCouplingMode::Warn),
        "enforce" => Some(DagCouplingMode::Enforce),
        _ => None,
    }
}

/// Valid DAG coupling mode values for CLI help text.
pub const VALID_DAG_COUPLING_MODES: &[&str] = &["off", "warn", "enforce"];

// ============================================================================
// T180: Configuration Profile – Preset configurations for different network phases
// ============================================================================

/// Configuration profile for preset network configurations (T180, T185).
///
/// This enum represents canonical configurations for different network phases:
///
/// - **DevNetV0**: Frozen DevNet configuration (NonceOnly, FIFO, LocalMesh)
/// - **TestNetAlpha**: TestNet Alpha configuration (VmV0, FIFO default, LocalMesh default)
/// - **TestNetBeta**: TestNet Beta configuration (VmV0, gas-on, DAG default, P2P default)
/// - **MainNet**: MainNet v0 configuration (VmV0, gas-on mandatory, DAG mandatory, P2P required)
///
/// Using a profile ensures consistent configuration across deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigProfile {
    /// DevNet v0 frozen configuration.
    ///
    /// - Environment: DevNet
    /// - Execution: NonceOnly
    /// - Gas: Disabled
    /// - Mempool: FIFO
    /// - Network: LocalMesh
    DevNetV0,

    /// TestNet Alpha configuration.
    ///
    /// - Environment: TestNet
    /// - Execution: VmV0
    /// - Gas: Disabled (opt-in)
    /// - Mempool: FIFO (DAG opt-in)
    /// - Network: LocalMesh (P2P opt-in)
    TestNetAlpha,

    /// TestNet Beta v0 configuration (T180).
    ///
    /// - Environment: TestNet
    /// - Execution: VmV0
    /// - Gas: Enabled by default
    /// - Fee Priority: Enabled by default
    /// - Mempool: DAG by default (FIFO fallback)
    /// - Network: P2P by default (LocalMesh fallback)
    TestNetBeta,

    /// MainNet v0 configuration (T185).
    ///
    /// - Environment: MainNet (QBIND_MAINNET_CHAIN_ID)
    /// - Execution: VmV0
    /// - Gas: Enabled (**cannot be disabled**)
    /// - Fee Priority: Enabled (**cannot be disabled**)
    /// - Mempool: DAG (**required** for validators)
    /// - Network: P2P (**required** for validators)
    /// - DAG Availability: Enabled (**required**)
    /// - Data Dir: **Required** (no in-memory validators)
    ///
    /// See QBIND_MAINNET_V0_SPEC.md for full specification.
    MainNet,
}

impl std::fmt::Display for ConfigProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigProfile::DevNetV0 => write!(f, "devnet-v0"),
            ConfigProfile::TestNetAlpha => write!(f, "testnet-alpha"),
            ConfigProfile::TestNetBeta => write!(f, "testnet-beta"),
            ConfigProfile::MainNet => write!(f, "mainnet"),
        }
    }
}

/// Parse a configuration profile from a string.
///
/// Valid values: "devnet-v0" | "testnet-alpha" | "testnet-beta" | "mainnet"
///
/// Returns `None` for unrecognized values.
pub fn parse_config_profile(s: &str) -> Option<ConfigProfile> {
    match s.to_lowercase().as_str() {
        "devnet-v0" | "devnet" => Some(ConfigProfile::DevNetV0),
        "testnet-alpha" | "alpha" => Some(ConfigProfile::TestNetAlpha),
        "testnet-beta" | "beta" => Some(ConfigProfile::TestNetBeta),
        "mainnet" | "mainnet-v0" => Some(ConfigProfile::MainNet),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    /// The network environment for this node.
    ///
    /// Determines the chain ID and domain scope used for all
    /// signing and verification operations.
    pub environment: NetworkEnvironment,

    /// The execution profile for this node (T163).
    ///
    /// Determines the transaction execution mode:
    /// - NonceOnly: Stage A parallel nonce execution (DevNet default)
    /// - VmV0: Sequential VM v0 with account balances (TestNet Alpha)
    pub execution_profile: ExecutionProfile,

    /// The data directory for persistent state (T164).
    ///
    /// When set and `execution_profile` is `VmV0`, the VM v0 state will be
    /// persisted to disk at `<data_dir>/state_vm_v0`.
    ///
    /// When `None`, VM v0 uses in-memory state only (not persistent).
    pub data_dir: Option<PathBuf>,

    /// P2P network transport configuration (T170/T172).
    pub network: NetworkTransportConfig,

    /// Network mode for consensus/DAG message transport (T173).
    ///
    /// Determines whether consensus and DAG messages use:
    /// - `LocalMesh`: Existing local/loopback networking (default)
    /// - `P2p`: New P2P transport via `TcpKemTlsP2pService`
    pub network_mode: NetworkMode,

    // ========================================================================
    // T180: Additional configuration fields for TestNet Beta
    // ========================================================================
    /// Whether gas enforcement is enabled (T180).
    ///
    /// - DevNet / TestNet Alpha: `false` (disabled)
    /// - TestNet Beta / MainNet: `true` (enabled)
    pub gas_enabled: bool,

    /// Whether fee-priority mempool ordering is enabled (T180).
    ///
    /// When `true`, transactions are ordered by `max_fee_per_gas` and `effective_fee`.
    /// Requires `gas_enabled = true` to be meaningful.
    ///
    /// - DevNet / TestNet Alpha: `false` (disabled)
    /// - TestNet Beta / MainNet: `true` (enabled)
    pub enable_fee_priority: bool,

    /// Mempool mode selection (T180).
    ///
    /// - DevNet / TestNet Alpha: `MempoolMode::Fifo` (default)
    /// - TestNet Beta / MainNet: `MempoolMode::Dag` (default)
    pub mempool_mode: MempoolMode,

    /// Whether DAG availability certificates are enabled (T180).
    ///
    /// Only meaningful when `mempool_mode == MempoolMode::Dag`.
    ///
    /// - DevNet: `false` (disabled)
    /// - TestNet Alpha: `false` (opt-in)
    /// - TestNet Beta / MainNet: `true` (enabled)
    pub dag_availability_enabled: bool,

    // ========================================================================
    // T189: DAG–Consensus Coupling Configuration
    // ========================================================================
    /// DAG–consensus coupling mode (T189).
    ///
    /// Controls how the consensus layer interacts with DAG availability certificates.
    /// See QBIND_DAG_CONSENSUS_COUPLING_DESIGN.md §6 for detailed semantics.
    ///
    /// - DevNet v0: `Off` (coupling disabled)
    /// - TestNet Alpha: `Off` (coupling disabled)
    /// - TestNet Beta: `Off` (optionally `Warn` for testing/transition)
    /// - MainNet v0: `Enforce` (coupling required; cannot be changed)
    pub dag_coupling_mode: DagCouplingMode,

    // ========================================================================
    // T186: Stage B Parallel Execution Configuration
    // ========================================================================
    /// Whether Stage B conflict-graph parallel execution is enabled (T186).
    ///
    /// When `true` and `execution_profile == ExecutionProfile::VmV0`, the node
    /// uses the Stage B conflict-graph scheduler to execute blocks in parallel.
    /// When `false`, blocks are executed sequentially (existing behavior).
    ///
    /// Stage B produces identical state and receipts as sequential execution
    /// but uses multiple cores for improved throughput.
    ///
    /// - DevNet v0: `false` (disabled)
    /// - TestNet Alpha: `false` (disabled)
    /// - TestNet Beta: `false` (disabled by default; opt-in available)
    /// - MainNet v0: `true` (enabled by default; operators can override)
    pub stage_b_enabled: bool,

    // ========================================================================
    // T193: Fee Distribution Policy Configuration
    // ========================================================================
    /// Fee distribution policy for transaction fees (T193).
    ///
    /// Determines how fees are split between burning (deflationary pressure)
    /// and proposer rewards (incentive to include transactions).
    ///
    /// - DevNet v0: `burn_only()` (all fees burned, no proposer rewards)
    /// - TestNet Alpha: `burn_only()` (all fees burned)
    /// - TestNet Beta: `burn_only()` (all fees burned)
    /// - MainNet v0: `mainnet_default()` (50% burn, 50% proposer)
    ///
    /// Only meaningful when `gas_enabled = true`.
    pub fee_distribution_policy: FeeDistributionPolicy,

    // ========================================================================
    // T197: Monetary Mode Configuration
    // ========================================================================
    /// Monetary engine mode (T197).
    ///
    /// Controls whether the monetary engine is active, in shadow mode, or off.
    ///
    /// - DevNet v0: `Off` (no issuance, no decisions)
    /// - TestNet Alpha: `Shadow` (decisions + metrics only)
    /// - TestNet Beta: `Shadow` (decisions + metrics only)
    /// - MainNet v0: `Shadow` (governance can flip to Active later)
    pub monetary_mode: MonetaryMode,

    /// Seigniorage accounts for Active mode (T197).
    ///
    /// When `monetary_mode == Active`, these accounts receive newly minted tokens.
    /// Must be `Some(..)` for Active mode on MainNet.
    /// Can be `None` for Off/Shadow modes.
    pub monetary_accounts: Option<MonetaryAccounts>,

    /// Seigniorage split configuration (T197).
    ///
    /// Determines how newly minted tokens are distributed among
    /// validators, treasury, insurance, and community.
    /// Only meaningful when `monetary_mode == Active`.
    pub seigniorage_split: SeigniorageSplit,
}

impl Default for NodeConfig {
    /// Default configuration uses DevNet environment and NonceOnly profile.
    ///
    /// This ensures backward compatibility with existing code and scripts
    /// that don't explicitly specify an environment or profile.
    fn default() -> Self {
        Self {
            environment: NetworkEnvironment::Devnet,
            execution_profile: ExecutionProfile::NonceOnly,
            data_dir: None,
            network: NetworkTransportConfig::default(),
            network_mode: NetworkMode::LocalMesh,
            // T180: DevNet defaults (gas/fee/DAG disabled)
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            // T189: DAG coupling disabled for DevNet
            dag_coupling_mode: DagCouplingMode::Off,
            // T186: Stage B disabled by default
            stage_b_enabled: false,
            // T193: Burn-only fee distribution for DevNet
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
            // T197: Monetary mode off for DevNet
            monetary_mode: MonetaryMode::Off,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }
}

impl NodeConfig {
    /// Create a new node configuration with the specified environment.
    ///
    /// Uses the default execution profile (NonceOnly) for backward compatibility.
    pub fn new(environment: NetworkEnvironment) -> Self {
        Self {
            environment,
            execution_profile: ExecutionProfile::NonceOnly,
            data_dir: None,
            network: NetworkTransportConfig::default(),
            network_mode: NetworkMode::LocalMesh,
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            dag_coupling_mode: DagCouplingMode::Off,
            stage_b_enabled: false,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
            // T197: Default to Off for backward compatibility
            monetary_mode: MonetaryMode::Off,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a new node configuration with environment and execution profile.
    pub fn with_profile(
        environment: NetworkEnvironment,
        execution_profile: ExecutionProfile,
    ) -> Self {
        Self {
            environment,
            execution_profile,
            data_dir: None,
            network: NetworkTransportConfig::default(),
            network_mode: NetworkMode::LocalMesh,
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            dag_coupling_mode: DagCouplingMode::Off,
            stage_b_enabled: false,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
            // T197: Default to Off for backward compatibility
            monetary_mode: MonetaryMode::Off,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a DevNet configuration.
    ///
    /// Convenience method for the most common test/dev case.
    /// Uses NonceOnly profile (DevNet default).
    pub fn devnet() -> Self {
        Self::new(NetworkEnvironment::Devnet)
    }

    /// Create a TestNet configuration.
    ///
    /// Uses NonceOnly profile by default. For VM v0, use `testnet_vm_v0()`.
    pub fn testnet() -> Self {
        Self::new(NetworkEnvironment::Testnet)
    }

    /// Create a TestNet configuration with VM v0 profile (T163).
    ///
    /// This is the recommended configuration for TestNet Alpha.
    pub fn testnet_vm_v0() -> Self {
        Self::with_profile(NetworkEnvironment::Testnet, ExecutionProfile::VmV0)
    }

    // ========================================================================
    // T180: Configuration Profile Presets
    // ========================================================================

    /// Create a DevNet v0 preset configuration (T180).
    ///
    /// This is the canonical frozen DevNet configuration:
    /// - Environment: DevNet
    /// - Execution: NonceOnly
    /// - Gas: Disabled
    /// - Fee Priority: Disabled
    /// - Mempool: FIFO
    /// - Network: LocalMesh
    /// - P2P: Disabled
    /// - DAG Coupling: Off (T189)
    /// - Stage B: Disabled (T186)
    /// - Fee Distribution: Burn-only (T193)
    /// - Monetary Mode: Off (T197)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::NodeConfig;
    ///
    /// let config = NodeConfig::devnet_v0_preset();
    /// assert!(!config.gas_enabled);
    /// assert_eq!(config.mempool_mode, MempoolMode::Fifo);
    /// ```
    pub fn devnet_v0_preset() -> Self {
        Self {
            environment: NetworkEnvironment::Devnet,
            execution_profile: ExecutionProfile::NonceOnly,
            data_dir: None,
            network: NetworkTransportConfig::disabled(),
            network_mode: NetworkMode::LocalMesh,
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            dag_coupling_mode: DagCouplingMode::Off, // T189: Coupling disabled for DevNet
            stage_b_enabled: false,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(), // T193
            // T197: Monetary mode off for DevNet
            monetary_mode: MonetaryMode::Off,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a TestNet Alpha preset configuration (T180).
    ///
    /// This is the canonical TestNet Alpha configuration:
    /// - Environment: TestNet (QBIND_TESTNET_CHAIN_ID)
    /// - Execution: VmV0
    /// - Gas: Disabled (opt-in)
    /// - Fee Priority: Disabled (opt-in)
    /// - Mempool: FIFO (DAG opt-in)
    /// - Network: LocalMesh (P2P opt-in)
    /// - P2P: Disabled
    /// - DAG Coupling: Off (T189)
    /// - Stage B: Disabled (T186)
    /// - Fee Distribution: Burn-only (T193)
    /// - Monetary Mode: Shadow (T197)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::NodeConfig;
    /// use qbind_types::NetworkEnvironment;
    ///
    /// let config = NodeConfig::testnet_alpha_preset();
    /// assert_eq!(config.environment, NetworkEnvironment::Testnet);
    /// assert!(!config.gas_enabled);
    /// ```
    pub fn testnet_alpha_preset() -> Self {
        Self {
            environment: NetworkEnvironment::Testnet,
            execution_profile: ExecutionProfile::VmV0,
            data_dir: None,
            network: NetworkTransportConfig::disabled(),
            network_mode: NetworkMode::LocalMesh,
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            dag_coupling_mode: DagCouplingMode::Off, // T189: Coupling disabled for Alpha
            stage_b_enabled: false,
            fee_distribution_policy: FeeDistributionPolicy::burn_only(), // T193
            // T197: Shadow mode for TestNet Alpha
            monetary_mode: MonetaryMode::Shadow,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a TestNet Beta v0 preset configuration (T180).
    ///
    /// This is the canonical TestNet Beta configuration as defined in
    /// QBIND_TESTNET_BETA_SPEC.md:
    ///
    /// - Environment: TestNet (QBIND_TESTNET_CHAIN_ID - same as Alpha)
    /// - Execution: VmV0 (same as Alpha)
    /// - Gas: **Enabled by default**
    /// - Fee Priority: **Enabled by default**
    /// - Mempool: **DAG by default** (FIFO fallback for dev/harness)
    /// - Network: **P2P by default** (LocalMesh for dev/harness)
    /// - P2P: **Enabled by default**
    /// - DAG Availability: **Enabled by default**
    /// - DAG Coupling: **Off** (T189: optionally Warn for experiments)
    /// - Stage B: **Disabled by default** (T186: opt-in available for testing)
    /// - Fee Distribution: **Burn-only** (T193: testing uses burn-only for simplicity)
    /// - Monetary Mode: **Shadow** (T197: decisions + metrics only)
    ///
    /// **Note**: Callers should supply `data_dir` via `with_data_dir()` before
    /// starting nodes, as Beta requires persistent state.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::NodeConfig;
    /// use qbind_types::NetworkEnvironment;
    ///
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_data_dir("/data/qbind");
    ///
    /// assert_eq!(config.environment, NetworkEnvironment::Testnet);
    /// assert!(config.gas_enabled);
    /// assert!(config.enable_fee_priority);
    /// assert_eq!(config.mempool_mode, MempoolMode::Dag);
    /// assert_eq!(config.network_mode, NetworkMode::P2p);
    /// assert!(config.network.enable_p2p);
    /// assert!(config.dag_availability_enabled);
    /// ```
    pub fn testnet_beta_preset() -> Self {
        Self {
            environment: NetworkEnvironment::Testnet,
            execution_profile: ExecutionProfile::VmV0,
            data_dir: None, // Caller should set via with_data_dir()
            network: NetworkTransportConfig::testnet_beta(),
            network_mode: NetworkMode::P2p,
            gas_enabled: true,
            enable_fee_priority: true,
            mempool_mode: MempoolMode::Dag,
            dag_availability_enabled: true,
            dag_coupling_mode: DagCouplingMode::Off, // T189: Off for Beta (optionally Warn)
            stage_b_enabled: false,                  // T186: Disabled by default for Beta
            fee_distribution_policy: FeeDistributionPolicy::burn_only(), // T193
            // T197: Shadow mode for TestNet Beta
            monetary_mode: MonetaryMode::Shadow,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a MainNet v0 preset configuration (T185).
    ///
    /// This is the canonical MainNet configuration as defined in
    /// QBIND_MAINNET_V0_SPEC.md:
    ///
    /// - Environment: MainNet (QBIND_MAINNET_CHAIN_ID)
    /// - Execution: VmV0
    /// - Gas: **Enabled (cannot be disabled)**
    /// - Fee Priority: **Enabled (cannot be disabled)**
    /// - Mempool: **DAG (required for validators)**
    /// - Network: **P2P (required for validators)**
    /// - P2P: **Enabled (required)**
    /// - DAG Availability: **Enabled (required)**
    /// - DAG Coupling: **Enforce (required)** (T189)
    /// - Stage B: **Enabled by default** (T186: parallel execution available)
    /// - Fee Distribution: **50% burn / 50% proposer** (T193: MainNet default)
    /// - Monetary Mode: **Shadow** (T197: governance can flip to Active later)
    ///
    /// **Note**: Callers MUST supply `data_dir` via `with_data_dir()` before
    /// starting nodes. MainNet validators cannot use in-memory-only storage.
    ///
    /// # Safety Rails
    ///
    /// After constructing a MainNet config, you should call
    /// `validate_mainnet_invariants()` before startup to ensure all
    /// MainNet-required invariants are satisfied. This validation is
    /// automatically performed when using the CLI with `--profile mainnet`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::NodeConfig;
    /// use qbind_types::NetworkEnvironment;
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_data_dir("/data/qbind");
    ///
    /// // Validate before startup
    /// config.validate_mainnet_invariants().expect("MainNet config invalid");
    ///
    /// assert_eq!(config.environment, NetworkEnvironment::Mainnet);
    /// assert!(config.gas_enabled);
    /// assert!(config.enable_fee_priority);
    /// assert_eq!(config.mempool_mode, MempoolMode::Dag);
    /// assert_eq!(config.network_mode, NetworkMode::P2p);
    /// assert!(config.network.enable_p2p);
    /// assert!(config.dag_availability_enabled);
    /// assert!(config.stage_b_enabled);
    /// assert_eq!(config.dag_coupling_mode, DagCouplingMode::Enforce);
    /// ```
    pub fn mainnet_preset() -> Self {
        Self {
            environment: NetworkEnvironment::Mainnet,
            execution_profile: ExecutionProfile::VmV0,
            data_dir: None, // Caller MUST set via with_data_dir()
            network: NetworkTransportConfig::mainnet(),
            network_mode: NetworkMode::P2p,
            gas_enabled: true,
            enable_fee_priority: true,
            mempool_mode: MempoolMode::Dag,
            dag_availability_enabled: true,
            dag_coupling_mode: DagCouplingMode::Enforce, // T189: Required for MainNet
            stage_b_enabled: true,                       // T186: Enabled by default for MainNet
            fee_distribution_policy: FeeDistributionPolicy::mainnet_default(), // T193: 50/50 split
            // T197: Shadow mode by default, governance can flip to Active later
            monetary_mode: MonetaryMode::Shadow,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
        }
    }

    /// Create a MainNet preset with LocalMesh for single-machine testing (T185).
    ///
    /// This is the same as `mainnet_preset()` but forces:
    /// - `network_mode = LocalMesh`
    /// - `enable_p2p = false`
    ///
    /// **WARNING**: This configuration is **NOT** valid for real MainNet
    /// validators. It is provided only for single-machine development/testing
    /// scenarios where P2P transport is impractical.
    ///
    /// This configuration will **fail** `validate_mainnet_invariants()`.
    /// Use only for local harness tests.
    pub fn mainnet_preset_localmesh() -> Self {
        Self {
            network: NetworkTransportConfig::disabled(),
            network_mode: NetworkMode::LocalMesh,
            ..Self::mainnet_preset()
        }
    }

    /// Create a configuration from a profile enum (T180, T185).
    ///
    /// This is the recommended way to create configurations when using the
    /// `--profile` CLI flag.
    ///
    /// # Arguments
    ///
    /// * `profile` - The configuration profile to use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, ConfigProfile};
    ///
    /// let config = NodeConfig::from_profile(ConfigProfile::TestNetBeta);
    /// assert!(config.gas_enabled);
    ///
    /// let mainnet = NodeConfig::from_profile(ConfigProfile::MainNet);
    /// assert_eq!(mainnet.environment, NetworkEnvironment::Mainnet);
    /// ```
    pub fn from_profile(profile: ConfigProfile) -> Self {
        match profile {
            ConfigProfile::DevNetV0 => Self::devnet_v0_preset(),
            ConfigProfile::TestNetAlpha => Self::testnet_alpha_preset(),
            ConfigProfile::TestNetBeta => Self::testnet_beta_preset(),
            ConfigProfile::MainNet => Self::mainnet_preset(),
        }
    }

    // ========================================================================
    // T180: Builder methods for new configuration fields
    // ========================================================================

    /// Enable or disable gas enforcement (T180).
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether gas enforcement should be enabled
    pub fn with_gas_enabled(mut self, enabled: bool) -> Self {
        self.gas_enabled = enabled;
        self
    }

    /// Enable or disable fee-priority mempool ordering (T180).
    ///
    /// Note: Fee priority requires gas enforcement to be meaningful.
    /// If you enable fee priority without gas, the configuration may
    /// be automatically adjusted during enforcement.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether fee priority should be enabled
    pub fn with_fee_priority(mut self, enabled: bool) -> Self {
        self.enable_fee_priority = enabled;
        self
    }

    /// Set the mempool mode (T180).
    ///
    /// # Arguments
    ///
    /// * `mode` - The mempool mode (Fifo or Dag)
    pub fn with_mempool_mode(mut self, mode: MempoolMode) -> Self {
        self.mempool_mode = mode;
        self
    }

    /// Enable or disable DAG availability certificates (T180).
    ///
    /// Only meaningful when `mempool_mode == MempoolMode::Dag`.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether DAG availability certificates should be enabled
    pub fn with_dag_availability(mut self, enabled: bool) -> Self {
        self.dag_availability_enabled = enabled;
        self
    }

    /// Set the DAG–consensus coupling mode (T189).
    ///
    /// Controls how the consensus layer interacts with DAG availability certificates.
    ///
    /// # Arguments
    ///
    /// * `mode` - The DAG coupling mode to use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_dag_coupling_mode(DagCouplingMode::Warn);  // Enable warnings for testing
    /// assert_eq!(config.dag_coupling_mode, DagCouplingMode::Warn);
    /// ```
    pub fn with_dag_coupling_mode(mut self, mode: DagCouplingMode) -> Self {
        self.dag_coupling_mode = mode;
        self
    }

    /// Enable or disable Stage B parallel execution (T186).
    ///
    /// When enabled and `execution_profile == ExecutionProfile::VmV0`, the node
    /// uses conflict-graph-based parallel execution for improved throughput.
    ///
    /// Stage B produces identical state and receipts as sequential execution.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether Stage B parallel execution should be enabled
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_stage_b_enabled(true);  // Opt-in for testing
    /// assert!(config.stage_b_enabled);
    /// ```
    pub fn with_stage_b_enabled(mut self, enabled: bool) -> Self {
        self.stage_b_enabled = enabled;
        self
    }

    /// Set the fee distribution policy (T193).
    ///
    /// Determines how transaction fees are split between burning and
    /// proposer rewards.
    ///
    /// # Arguments
    ///
    /// * `policy` - The fee distribution policy to use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::FeeDistributionPolicy;
    ///
    /// // Custom 70% burn, 30% proposer
    /// let policy = FeeDistributionPolicy::new(7_000, 3_000);
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_fee_distribution_policy(policy);
    /// ```
    pub fn with_fee_distribution_policy(mut self, policy: FeeDistributionPolicy) -> Self {
        self.fee_distribution_policy = policy;
        self
    }

    /// Set the monetary mode (T197).
    ///
    /// # Arguments
    ///
    /// * `mode` - The monetary mode to use (Off, Shadow, or Active)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::MonetaryMode;
    ///
    /// let config = NodeConfig::testnet_alpha_preset()
    ///     .with_monetary_mode(MonetaryMode::Active);
    /// ```
    pub fn with_monetary_mode(mut self, mode: MonetaryMode) -> Self {
        self.monetary_mode = mode;
        self
    }

    /// Set the monetary accounts for Active mode (T197).
    ///
    /// # Arguments
    ///
    /// * `accounts` - The accounts to receive seigniorage
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::MonetaryAccounts;
    ///
    /// let accounts = MonetaryAccounts::test_accounts();
    /// let config = NodeConfig::testnet_alpha_preset()
    ///     .with_monetary_accounts(accounts);
    /// ```
    pub fn with_monetary_accounts(mut self, accounts: MonetaryAccounts) -> Self {
        self.monetary_accounts = Some(accounts);
        self
    }

    /// Set the seigniorage split configuration (T197).
    ///
    /// # Arguments
    ///
    /// * `split` - The seigniorage split in basis points
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::SeigniorageSplit;
    ///
    /// let split = SeigniorageSplit::new(6_000, 2_000, 1_000, 1_000);
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_seigniorage_split(split);
    /// ```
    pub fn with_seigniorage_split(mut self, split: SeigniorageSplit) -> Self {
        self.seigniorage_split = split;
        self
    }

    /// Create a TestNet Beta preset with LocalMesh for CI-friendly testing (T180).
    ///
    /// This is the same as `testnet_beta_preset()` but forces:
    /// - `network_mode = LocalMesh`
    /// - `enable_p2p = false`
    ///
    /// Useful for cluster harness tests that need Beta configuration
    /// without requiring actual P2P transport.
    pub fn testnet_beta_preset_localmesh() -> Self {
        Self {
            network: NetworkTransportConfig::disabled(),
            network_mode: NetworkMode::LocalMesh,
            ..Self::testnet_beta_preset()
        }
    }

    /// Create a MainNet configuration.
    pub fn mainnet() -> Self {
        Self::new(NetworkEnvironment::Mainnet)
    }

    /// Set the network mode for consensus/DAG transport (T173).
    ///
    /// # Arguments
    ///
    /// * `mode` - The network mode to use (LocalMesh or P2p)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::testnet_vm_v0()
    ///     .with_network_mode(NetworkMode::P2p);
    /// ```
    pub fn with_network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Set the data directory for persistent state (T164).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the data directory.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::testnet_vm_v0()
    ///     .with_data_dir("/data/qbind");
    /// ```
    pub fn with_data_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    /// Get the path to the VM v0 state directory (T164).
    ///
    /// Returns `Some(<data_dir>/state_vm_v0)` if `data_dir` is set,
    /// otherwise returns `None`.
    pub fn vm_v0_state_dir(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join("state_vm_v0"))
    }

    /// Get the chain ID for this node's environment.
    ///
    /// This chain ID should be used in all signing preimages:
    /// - Transaction signing/verification
    /// - Vote signing/verification
    /// - Block proposal signing/verification
    /// - Timeout message signing/verification
    /// - DAG batch signing/verification
    pub fn chain_id(&self) -> ChainId {
        self.environment.chain_id()
    }

    /// Get the domain scope string for this node's environment.
    ///
    /// Returns:
    /// - "DEV" for DevNet
    /// - "TST" for TestNet
    /// - "MAIN" for MainNet
    pub fn scope(&self) -> &'static str {
        self.environment.scope()
    }

    /// Log startup information for this node configuration.
    ///
    /// This should be called at node startup to provide visibility
    /// into the environment configuration.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - Optional validator identifier for logging
    ///
    /// # Output
    ///
    /// Prints to stdout:
    /// ```text
    /// qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=local-mesh p2p=disabled
    /// ```
    pub fn log_startup_info(&self, validator_id: Option<&str>) {
        println!("{}", self.startup_info_string(validator_id));
    }

    /// Format startup information as a string (for use in custom logging).
    ///
    /// # Arguments
    ///
    /// * `validator_id` - Optional validator identifier for logging
    ///
    /// # Returns
    ///
    /// A formatted string with environment and P2P information.
    ///
    /// # T175 Additions
    ///
    /// The startup info string now includes:
    /// - Network mode (local-mesh / p2p)
    /// - P2P state (enabled/disabled)
    /// - Listen address (when P2P enabled)
    /// - Number of static peers
    ///
    /// # T180 Additions
    ///
    /// The startup info string now also includes:
    /// - Gas enforcement state (gas=on/off)
    /// - Fee priority state (fee-priority=on/off)
    /// - Mempool mode (mempool=fifo/dag)
    ///
    /// # T185 Additions
    ///
    /// The startup info string now also includes:
    /// - DAG availability state (dag_availability=enabled/disabled)
    ///
    /// # T186 Additions
    ///
    /// The startup info string now also includes:
    /// - Stage B parallel execution state (stage_b=enabled/disabled)
    ///
    /// # T189 Additions
    ///
    /// The startup info string now also includes:
    /// - DAG coupling mode (dag_coupling=off/warn/enforce)
    ///
    /// # T193 Additions
    ///
    /// The startup info string now also includes:
    /// - Fee distribution policy (fee_distribution=burn-only or burn=X% proposer=Y%)
    pub fn startup_info_string(&self, validator_id: Option<&str>) -> String {
        let validator_str = validator_id.unwrap_or("none");
        let chain_id_hex = format!("0x{:016x}", self.chain_id().as_u64());

        // Build P2P info string (T175)
        let p2p_info = if self.network_mode == NetworkMode::P2p && self.network.enable_p2p {
            let listen_str = self
                .network
                .listen_addr
                .as_ref()
                .map(|a| a.as_str())
                .unwrap_or("default");
            let peer_count = self.network.static_peers.len();
            format!("p2p=enabled listen={} peers={}", listen_str, peer_count)
        } else {
            "p2p=disabled".to_string()
        };

        // Build T180 config info
        let gas_str = if self.gas_enabled { "on" } else { "off" };
        let fee_priority_str = if self.enable_fee_priority {
            "on"
        } else {
            "off"
        };
        let dag_availability_str = if self.dag_availability_enabled {
            "enabled"
        } else {
            "disabled"
        };

        // T186: Stage B parallel execution state
        let stage_b_str = if self.stage_b_enabled {
            "enabled"
        } else {
            "disabled"
        };

        // T193: Fee distribution policy
        let fee_dist_str = if self.fee_distribution_policy.is_burn_only() {
            "burn-only".to_string()
        } else {
            format!("{}", self.fee_distribution_policy)
        };

        format!(
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={} profile={} network={} {} gas={} fee-priority={} fee_distribution={} mempool={} dag_availability={} dag_coupling={} stage_b={}",
            validator_str,
            self.environment,
            chain_id_hex,
            self.scope(),
            self.execution_profile,
            self.network_mode,
            p2p_info,
            gas_str,
            fee_priority_str,
            fee_dist_str,
            self.mempool_mode,
            dag_availability_str,
            self.dag_coupling_mode,
            stage_b_str
        )
    }

    /// Validate and normalize P2P configuration (T175).
    ///
    /// This method checks the P2P configuration and logs warnings for
    /// common misconfigurations. It should be called after building
    /// the NodeConfig from CLI arguments.
    ///
    /// # Behavior
    ///
    /// - If `network_mode == LocalMesh` or `enable_p2p == false`:
    ///   P2P flags are ignored with a warning log.
    /// - If `network_mode == P2p && enable_p2p == true`:
    ///   - If `listen_addr` is missing, uses default (127.0.0.1:0)
    ///   - If zero peers, logs a warning about single-node operation
    /// - DevNet with P2P enabled logs a warning about violating freeze
    ///
    /// # Returns
    ///
    /// `true` if P2P should be enabled, `false` otherwise.
    pub fn validate_p2p_config(&mut self) -> bool {
        // Case 1: LocalMesh mode - P2P is disabled regardless of enable_p2p
        if self.network_mode == NetworkMode::LocalMesh {
            if self.network.enable_p2p {
                eprintln!(
                    "[T175] Warning: enable_p2p=true ignored because network_mode=local-mesh"
                );
            }
            return false;
        }

        // Case 2: P2p mode but enable_p2p is false - warn and use LocalMesh
        if self.network_mode == NetworkMode::P2p && !self.network.enable_p2p {
            eprintln!(
                "[T175] Warning: network_mode=p2p but enable_p2p=false; \
                 P2P will not be started. Set --enable-p2p to enable P2P transport."
            );
            return false;
        }

        // Case 3: P2p mode and enable_p2p - validate and proceed
        if self.network_mode == NetworkMode::P2p && self.network.enable_p2p {
            // Warn if DevNet with P2P (violates freeze)
            if self.environment == NetworkEnvironment::Devnet {
                eprintln!(
                    "[T175] Warning: P2P enabled in DevNet environment. \
                     DevNet v0 freeze recommends LocalMesh. \
                     Use --env testnet for P2P experimentation."
                );
            }

            // Ensure listen_addr has a default
            if self.network.listen_addr.is_none() {
                eprintln!(
                    "[T175] Warning: P2P enabled but no listen address specified. \
                     Using default: 127.0.0.1:0 (OS-assigned port)"
                );
                self.network.listen_addr = Some("127.0.0.1:0".to_string());
            }

            // Warn if no peers
            if self.network.static_peers.is_empty() {
                eprintln!(
                    "[T175] Warning: P2P enabled with zero static peers. \
                     Node will operate in single-node loopback mode."
                );
            }

            return true;
        }

        false
    }

    /// Check if P2P mode is effectively enabled.
    ///
    /// Returns `true` if both `network_mode == P2p` and `enable_p2p == true`.
    pub fn is_p2p_mode(&self) -> bool {
        self.network_mode == NetworkMode::P2p && self.network.enable_p2p
    }

    // ========================================================================
    // T185: MainNet Safety Rails
    // ========================================================================

    /// Validate that this configuration satisfies MainNet invariants (T185).
    ///
    /// MainNet v0 requires strict configuration to ensure validator safety.
    /// This method checks all mandatory invariants and returns an error
    /// describing the first violation found.
    ///
    /// # MainNet Invariants
    ///
    /// 1. `environment` == `NetworkEnvironment::Mainnet`
    /// 2. `gas_enabled` == `true` (cannot be disabled)
    /// 3. `enable_fee_priority` == `true` (cannot be disabled)
    /// 4. `mempool_mode` == `MempoolMode::Dag` (required for validators)
    /// 5. `dag_availability_enabled` == `true` (required)
    /// 6. `network_mode` == `NetworkMode::P2p` (required for validators)
    /// 7. `network.enable_p2p` == `true` (required)
    /// 8. `data_dir` is set (no in-memory-only validators)
    ///
    /// # Usage
    ///
    /// This method should be called during node startup when
    /// `--profile mainnet` is specified. If validation fails, the node
    /// should refuse to start.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all invariants are satisfied.
    /// `Err(MainnetConfigError)` describing the first violation.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_data_dir("/data/qbind");
    ///
    /// match config.validate_mainnet_invariants() {
    ///     Ok(()) => println!("MainNet config valid"),
    ///     Err(e) => {
    ///         eprintln!("MainNet config invalid: {}", e);
    ///         std::process::exit(1);
    ///     }
    /// }
    /// ```
    pub fn validate_mainnet_invariants(&self) -> Result<(), MainnetConfigError> {
        // 1. Environment must be MainNet
        if self.environment != NetworkEnvironment::Mainnet {
            return Err(MainnetConfigError::WrongEnvironment {
                expected: NetworkEnvironment::Mainnet,
                actual: self.environment,
            });
        }

        // 2. Gas must be enabled
        if !self.gas_enabled {
            return Err(MainnetConfigError::GasDisabled);
        }

        // 3. Fee priority must be enabled
        if !self.enable_fee_priority {
            return Err(MainnetConfigError::FeePriorityDisabled);
        }

        // 4. Mempool mode must be DAG
        if self.mempool_mode != MempoolMode::Dag {
            return Err(MainnetConfigError::WrongMempoolMode {
                expected: MempoolMode::Dag,
                actual: self.mempool_mode,
            });
        }

        // 5. DAG availability must be enabled
        if !self.dag_availability_enabled {
            return Err(MainnetConfigError::DagAvailabilityDisabled);
        }

        // 6. DAG coupling must be Enforce (T189)
        if self.dag_coupling_mode != DagCouplingMode::Enforce {
            return Err(MainnetConfigError::DagCouplingNotEnforced {
                actual: self.dag_coupling_mode,
            });
        }

        // 7. Network mode must be P2P
        if self.network_mode != NetworkMode::P2p {
            return Err(MainnetConfigError::WrongNetworkMode {
                expected: NetworkMode::P2p,
                actual: self.network_mode,
            });
        }

        // 8. P2P must be enabled
        if !self.network.enable_p2p {
            return Err(MainnetConfigError::P2pDisabled);
        }

        // 9. Data directory must be set (no in-memory validators)
        if self.data_dir.is_none() {
            return Err(MainnetConfigError::MissingDataDir);
        }

        // 10. Fee distribution must be MainNet default (T193)
        let mainnet_policy = FeeDistributionPolicy::mainnet_default();
        if self.fee_distribution_policy != mainnet_policy {
            return Err(MainnetConfigError::WrongFeeDistributionPolicy {
                expected: mainnet_policy,
                actual: self.fee_distribution_policy,
            });
        }

        // T186: Stage B is allowed but not required for MainNet.
        // Log a warning if disabled, but do not fail startup.
        // Stage B is compiled and available; operators can choose to enable/disable it.
        if !self.stage_b_enabled {
            eprintln!(
                "[T186] MainNet: stage_b_enabled=false -- allowed, but parallel execution \
                 is recommended once fully audited."
            );
        }

        // 11. Monetary mode must not be Off (T197)
        // MainNet must at least compute + expose decisions.
        if self.monetary_mode == MonetaryMode::Off {
            return Err(MainnetConfigError::MonetaryModeOff);
        }

        // 12. If monetary mode is Active, accounts and split must be valid (T197)
        if self.monetary_mode == MonetaryMode::Active {
            if self.monetary_accounts.is_none() {
                return Err(MainnetConfigError::MonetaryAccountsMissing);
            }
            if let Err(e) = self.seigniorage_split.validate() {
                return Err(MainnetConfigError::SeigniorageSplitInvalid(e));
            }

            // T201: Verify monetary accounts are properly configured
            if let Some(ref accounts) = self.monetary_accounts {
                if !accounts.is_valid_for_mainnet() {
                    return Err(MainnetConfigError::MonetaryAccountsInvalid);
                }
            }
        }

        // TODO(future): Add stricter rules for validators vs non-validators
        // when the code has a way to distinguish between them.
        // For now, all invariants are enforced unconditionally.

        // TODO(future): Enforce HSM signer mode for validators.
        // Currently deferred to a dedicated HSM task.

        Ok(())
    }
}

// ============================================================================
// T185: MainNet Configuration Error
// ============================================================================

/// Error indicating a MainNet configuration invariant violation (T185).
///
/// These errors are returned by `NodeConfig::validate_mainnet_invariants()`
/// when the configuration violates one of the MainNet v0 requirements.
///
/// MainNet nodes MUST refuse to start if any of these invariants are violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainnetConfigError {
    /// The network environment is not MainNet.
    WrongEnvironment {
        expected: NetworkEnvironment,
        actual: NetworkEnvironment,
    },

    /// Gas enforcement is disabled.
    ///
    /// MainNet requires gas enforcement to be enabled. Transactions
    /// without gas metering could allow DoS attacks or infinite loops.
    GasDisabled,

    /// Fee-priority mempool ordering is disabled.
    ///
    /// MainNet requires fee-priority ordering for fair transaction
    /// inclusion and economic sustainability.
    FeePriorityDisabled,

    /// Mempool mode is not DAG.
    ///
    /// MainNet validators must use DAG mempool for availability
    /// certificates and consensus coupling.
    WrongMempoolMode {
        expected: MempoolMode,
        actual: MempoolMode,
    },

    /// DAG availability certificates are disabled.
    ///
    /// MainNet requires availability certificates for data availability
    /// guarantees and consensus safety.
    DagAvailabilityDisabled,

    /// DAG coupling mode is not Enforce (T189).
    ///
    /// MainNet requires DAG–consensus coupling to be enforced.
    /// Proposals with uncertified batches must be rejected.
    DagCouplingNotEnforced { actual: DagCouplingMode },

    /// Network mode is not P2P.
    ///
    /// MainNet validators must use P2P transport. LocalMesh is only
    /// allowed for DevNet/TestNet harness testing.
    WrongNetworkMode {
        expected: NetworkMode,
        actual: NetworkMode,
    },

    /// P2P transport is disabled.
    ///
    /// MainNet validators must have P2P enabled for production networking.
    P2pDisabled,

    /// Data directory is not configured.
    ///
    /// MainNet validators must use persistent storage. In-memory-only
    /// nodes cannot safely participate in consensus.
    MissingDataDir,

    /// Fee distribution policy is not the MainNet default (T193).
    ///
    /// MainNet requires the 50% burn / 50% proposer fee distribution
    /// policy for economic integrity.
    WrongFeeDistributionPolicy {
        expected: FeeDistributionPolicy,
        actual: FeeDistributionPolicy,
    },

    /// Monetary mode is Off (T197).
    ///
    /// MainNet must at least compute and expose monetary decisions.
    /// Off mode is not allowed for MainNet.
    MonetaryModeOff,

    /// Monetary accounts missing when Active mode (T197).
    ///
    /// When monetary mode is Active, valid seigniorage accounts must
    /// be configured to receive newly minted tokens.
    MonetaryAccountsMissing,

    /// Seigniorage split is invalid (T197).
    ///
    /// The seigniorage split must sum to 10,000 basis points (100%).
    SeigniorageSplitInvalid(String),

    /// Monetary accounts are invalid for MainNet (T201).
    ///
    /// When monetary mode is Active, all four monetary accounts must:
    /// - Be distinct (no duplicates)
    /// - Be non-zero addresses
    MonetaryAccountsInvalid,
}

impl std::fmt::Display for MainnetConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainnetConfigError::WrongEnvironment { expected, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: environment must be {} but is {}",
                    expected, actual
                )
            }
            MainnetConfigError::GasDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: gas enforcement must be enabled (--enable-gas=true)"
                )
            }
            MainnetConfigError::FeePriorityDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: fee-priority ordering must be enabled (--enable-fee-priority=true)"
                )
            }
            MainnetConfigError::WrongMempoolMode { expected, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: mempool mode must be {} but is {} (--mempool-mode=dag)",
                    expected, actual
                )
            }
            MainnetConfigError::DagAvailabilityDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: DAG availability certificates must be enabled (--enable-dag-availability=true)"
                )
            }
            MainnetConfigError::DagCouplingNotEnforced { actual } => {
                write!(
                    f,
                    "MainNet invariant violated: dag_coupling_mode must be Enforce but is {} (--dag-coupling-mode=enforce)",
                    actual
                )
            }
            MainnetConfigError::WrongNetworkMode { expected, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: network mode must be {} but is {} (--network-mode=p2p)",
                    expected, actual
                )
            }
            MainnetConfigError::P2pDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: P2P transport must be enabled (--enable-p2p=true)"
                )
            }
            MainnetConfigError::MissingDataDir => {
                write!(
                    f,
                    "MainNet invariant violated: data directory must be configured (--data-dir=/path/to/data)"
                )
            }
            MainnetConfigError::WrongFeeDistributionPolicy { expected, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: fee distribution policy must be {} but is {} (T193)",
                    expected, actual
                )
            }
            MainnetConfigError::MonetaryModeOff => {
                write!(
                    f,
                    "MainNet invariant violated: monetary mode must not be 'off' (--monetary-mode=shadow or --monetary-mode=active)"
                )
            }
            MainnetConfigError::MonetaryAccountsMissing => {
                write!(
                    f,
                    "MainNet invariant violated: monetary accounts must be configured when monetary mode is 'active'"
                )
            }
            MainnetConfigError::SeigniorageSplitInvalid(e) => {
                write!(
                    f,
                    "MainNet invariant violated: seigniorage split is invalid: {}",
                    e
                )
            }
            MainnetConfigError::MonetaryAccountsInvalid => {
                write!(
                    f,
                    "MainNet invariant violated: monetary accounts must be distinct non-zero addresses when monetary mode is 'active' (T201)"
                )
            }
        }
    }
}

impl std::error::Error for MainnetConfigError {}

// ============================================================================
// CLI Parsing Helpers
// ============================================================================

/// Error returned when parsing an invalid environment string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnvironmentError {
    /// The invalid environment string that was provided.
    pub invalid_value: String,
}

impl std::fmt::Display for ParseEnvironmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid environment '{}': expected 'devnet', 'testnet', or 'mainnet'",
            self.invalid_value
        )
    }
}

impl std::error::Error for ParseEnvironmentError {}

/// Parse a network environment from a CLI argument string.
///
/// Accepts case-insensitive values:
/// - "devnet" → `NetworkEnvironment::Devnet`
/// - "testnet" → `NetworkEnvironment::Testnet`
/// - "mainnet" → `NetworkEnvironment::Mainnet`
///
/// # Arguments
///
/// * `s` - The environment string from CLI
///
/// # Returns
///
/// `Ok(NetworkEnvironment)` if valid, `Err(ParseEnvironmentError)` otherwise.
///
/// # Examples
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_environment;
/// use qbind_types::NetworkEnvironment;
///
/// assert_eq!(parse_environment("devnet").unwrap(), NetworkEnvironment::Devnet);
/// assert_eq!(parse_environment("TESTNET").unwrap(), NetworkEnvironment::Testnet);
/// assert_eq!(parse_environment("MainNet").unwrap(), NetworkEnvironment::Mainnet);
/// assert!(parse_environment("invalid").is_err());
/// ```
pub fn parse_environment(s: &str) -> Result<NetworkEnvironment, ParseEnvironmentError> {
    match s.to_lowercase().as_str() {
        "devnet" => Ok(NetworkEnvironment::Devnet),
        "testnet" => Ok(NetworkEnvironment::Testnet),
        "mainnet" => Ok(NetworkEnvironment::Mainnet),
        _ => Err(ParseEnvironmentError {
            invalid_value: s.to_string(),
        }),
    }
}

/// Default environment string for CLI parsing.
pub const DEFAULT_ENVIRONMENT: &str = "devnet";

/// Valid environment values for CLI help text.
pub const VALID_ENVIRONMENTS: &[&str] = &["devnet", "testnet", "mainnet"];

// ============================================================================
// Execution Profile CLI Parsing (T163)
// ============================================================================

/// Parse an execution profile from a CLI argument string.
///
/// Accepts case-insensitive values:
/// - "nonce-only" → `ExecutionProfile::NonceOnly` (default)
/// - "vm-v0" → `ExecutionProfile::VmV0`
///
/// Unknown values default to `NonceOnly` for backward compatibility.
///
/// # Arguments
///
/// * `s` - The execution profile string from CLI
///
/// # Returns
///
/// The parsed `ExecutionProfile`. Unknown values return `NonceOnly`.
///
/// # Examples
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_execution_profile;
/// use qbind_node::node_config::ExecutionProfile;
///
/// assert_eq!(parse_execution_profile("nonce-only"), ExecutionProfile::NonceOnly);
/// assert_eq!(parse_execution_profile("vm-v0"), ExecutionProfile::VmV0);
/// assert_eq!(parse_execution_profile("VM-V0"), ExecutionProfile::VmV0);
/// assert_eq!(parse_execution_profile("unknown"), ExecutionProfile::NonceOnly); // fallback
/// ```
pub fn parse_execution_profile(s: &str) -> ExecutionProfile {
    match s.to_ascii_lowercase().as_str() {
        "nonce-only" => ExecutionProfile::NonceOnly,
        "vm-v0" => ExecutionProfile::VmV0,
        _ => ExecutionProfile::NonceOnly,
    }
}

/// Default execution profile string for CLI parsing.
pub const DEFAULT_EXECUTION_PROFILE: &str = "nonce-only";

/// Valid execution profile values for CLI help text.
pub const VALID_EXECUTION_PROFILES: &[&str] = &["nonce-only", "vm-v0"];

// ============================================================================
// T175: Address Parsing Helpers
// ============================================================================

use std::net::SocketAddr;

/// Error returned when parsing an invalid socket address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAddrError {
    /// The invalid address string that was provided.
    pub invalid_value: String,
    /// The reason for the parse failure.
    pub reason: String,
}

impl std::fmt::Display for ParseAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid address '{}': {}",
            self.invalid_value, self.reason
        )
    }
}

impl std::error::Error for ParseAddrError {}

/// Parse a socket address from a CLI argument string (T175).
///
/// Accepts `host:port` format, e.g., "127.0.0.1:19000" or "0.0.0.0:9000".
///
/// # Arguments
///
/// * `s` - The address string from CLI
///
/// # Returns
///
/// `Ok(SocketAddr)` if valid, `Err(ParseAddrError)` otherwise.
///
/// # Examples
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_socket_addr;
///
/// let addr = parse_socket_addr("127.0.0.1:19000").unwrap();
/// assert_eq!(addr.port(), 19000);
///
/// let result = parse_socket_addr("invalid:addr");
/// assert!(result.is_err());
/// ```
pub fn parse_socket_addr(s: &str) -> Result<SocketAddr, ParseAddrError> {
    s.parse().map_err(|e| ParseAddrError {
        invalid_value: s.to_string(),
        reason: format!("{}", e),
    })
}

/// Default P2P listen address for CLI parsing.
pub const DEFAULT_P2P_LISTEN_ADDR: &str = "127.0.0.1:0";

/// Default network mode for CLI parsing.
pub const DEFAULT_NETWORK_MODE: &str = "local-mesh";

/// Valid network mode values for CLI help text.
pub const VALID_NETWORK_MODES: &[&str] = &["local-mesh", "p2p"];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_types::{QBIND_DEVNET_CHAIN_ID, QBIND_MAINNET_CHAIN_ID, QBIND_TESTNET_CHAIN_ID};

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert_eq!(config.chain_id(), QBIND_DEVNET_CHAIN_ID);
        assert_eq!(config.scope(), "DEV");
        assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
    }

    #[test]
    fn test_node_config_devnet() {
        let config = NodeConfig::devnet();
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert_eq!(config.chain_id(), QBIND_DEVNET_CHAIN_ID);
        assert_eq!(config.scope(), "DEV");
        assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::testnet();
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.chain_id(), QBIND_TESTNET_CHAIN_ID);
        assert_eq!(config.scope(), "TST");
        assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
    }

    #[test]
    fn test_node_config_mainnet() {
        let config = NodeConfig::mainnet();
        assert_eq!(config.environment, NetworkEnvironment::Mainnet);
        assert_eq!(config.chain_id(), QBIND_MAINNET_CHAIN_ID);
        assert_eq!(config.scope(), "MAIN");
        assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);
    }

    #[test]
    fn test_parse_environment_valid() {
        // Case-insensitive matching
        assert_eq!(
            parse_environment("devnet").unwrap(),
            NetworkEnvironment::Devnet
        );
        assert_eq!(
            parse_environment("DEVNET").unwrap(),
            NetworkEnvironment::Devnet
        );
        assert_eq!(
            parse_environment("DevNet").unwrap(),
            NetworkEnvironment::Devnet
        );
        assert_eq!(
            parse_environment("testnet").unwrap(),
            NetworkEnvironment::Testnet
        );
        assert_eq!(
            parse_environment("TESTNET").unwrap(),
            NetworkEnvironment::Testnet
        );
        assert_eq!(
            parse_environment("mainnet").unwrap(),
            NetworkEnvironment::Mainnet
        );
        assert_eq!(
            parse_environment("MAINNET").unwrap(),
            NetworkEnvironment::Mainnet
        );
    }

    #[test]
    fn test_parse_environment_invalid() {
        let result = parse_environment("invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.invalid_value, "invalid");
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn test_startup_info_string() {
        let config = NodeConfig::testnet();
        let info = config.startup_info_string(Some("V1"));
        assert!(info.contains("environment=TestNet"));
        assert!(info.contains("chain_id=0x51424e4454535400"));
        assert!(info.contains("scope=TST"));
        assert!(info.contains("validator=V1"));
    }

    #[test]
    fn test_startup_info_string_no_validator() {
        let config = NodeConfig::devnet();
        let info = config.startup_info_string(None);
        assert!(info.contains("validator=none"));
        assert!(info.contains("environment=DevNet"));
    }

    #[test]
    fn test_chain_ids_are_unique() {
        let devnet = NodeConfig::devnet().chain_id();
        let testnet = NodeConfig::testnet().chain_id();
        let mainnet = NodeConfig::mainnet().chain_id();

        assert_ne!(devnet, testnet);
        assert_ne!(devnet, mainnet);
        assert_ne!(testnet, mainnet);
    }

    #[test]
    fn test_scopes_are_unique() {
        let devnet = NodeConfig::devnet().scope();
        let testnet = NodeConfig::testnet().scope();
        let mainnet = NodeConfig::mainnet().scope();

        assert_ne!(devnet, testnet);
        assert_ne!(devnet, mainnet);
        assert_ne!(testnet, mainnet);
    }

    // ========================================================================
    // T163: ExecutionProfile Tests
    // ========================================================================

    #[test]
    fn test_execution_profile_default() {
        let profile = ExecutionProfile::default();
        assert_eq!(profile, ExecutionProfile::NonceOnly);
    }

    #[test]
    fn test_execution_profile_display() {
        assert_eq!(format!("{}", ExecutionProfile::NonceOnly), "nonce-only");
        assert_eq!(format!("{}", ExecutionProfile::VmV0), "vm-v0");
    }

    #[test]
    fn test_node_config_with_profile() {
        let config = NodeConfig::with_profile(NetworkEnvironment::Testnet, ExecutionProfile::VmV0);
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    }

    #[test]
    fn test_node_config_testnet_vm_v0() {
        let config = NodeConfig::testnet_vm_v0();
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.execution_profile, ExecutionProfile::VmV0);
    }

    #[test]
    fn test_parse_execution_profile_valid() {
        // Case-insensitive matching
        assert_eq!(
            parse_execution_profile("nonce-only"),
            ExecutionProfile::NonceOnly
        );
        assert_eq!(
            parse_execution_profile("NONCE-ONLY"),
            ExecutionProfile::NonceOnly
        );
        assert_eq!(
            parse_execution_profile("Nonce-Only"),
            ExecutionProfile::NonceOnly
        );
        assert_eq!(parse_execution_profile("vm-v0"), ExecutionProfile::VmV0);
        assert_eq!(parse_execution_profile("VM-V0"), ExecutionProfile::VmV0);
    }

    #[test]
    fn test_parse_execution_profile_fallback() {
        // Unknown values should fallback to NonceOnly
        assert_eq!(
            parse_execution_profile("invalid"),
            ExecutionProfile::NonceOnly
        );
        assert_eq!(parse_execution_profile(""), ExecutionProfile::NonceOnly);
        assert_eq!(
            parse_execution_profile("vm-v1"),
            ExecutionProfile::NonceOnly
        );
    }

    #[test]
    fn test_execution_profile_constants() {
        assert_eq!(DEFAULT_EXECUTION_PROFILE, "nonce-only");
        assert_eq!(VALID_EXECUTION_PROFILES, &["nonce-only", "vm-v0"]);
    }

    #[test]
    fn test_startup_info_includes_profile() {
        let config = NodeConfig::testnet_vm_v0();
        let info = config.startup_info_string(Some("V1"));
        assert!(info.contains("profile=vm-v0"));
    }

    // ========================================================================
    // T165: DagAvailabilityConfig Tests
    // ========================================================================

    #[test]
    fn test_dag_availability_config_default() {
        let config = DagAvailabilityConfig::default();
        assert!(!config.enabled, "should be disabled by default");
        assert!((config.quorum_fraction - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_dag_availability_config_disabled() {
        let config = DagAvailabilityConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_dag_availability_config_enabled() {
        let config = DagAvailabilityConfig::enabled();
        assert!(config.enabled);
        assert!((config.quorum_fraction - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_dag_availability_quorum_computation() {
        let config = DagAvailabilityConfig::enabled();

        // n=4 (f=1): quorum = ceil(4 * 2/3) = ceil(2.67) = 3
        assert_eq!(config.compute_quorum_size(4), 3);

        // n=7 (f=2): quorum = ceil(7 * 2/3) = ceil(4.67) = 5
        assert_eq!(config.compute_quorum_size(7), 5);

        // n=10 (f=3): quorum = ceil(10 * 2/3) = ceil(6.67) = 7
        assert_eq!(config.compute_quorum_size(10), 7);

        // n=1: quorum = ceil(1 * 2/3) = ceil(0.67) = 1
        assert_eq!(config.compute_quorum_size(1), 1);

        // n=0: edge case, returns 1
        assert_eq!(config.compute_quorum_size(0), 1);
    }

    #[test]
    fn test_dag_availability_with_fixed_quorum() {
        let config = DagAvailabilityConfig::with_fixed_quorum(3);
        assert!(config.enabled);
        // For 4 validators, should give quorum ~= 3
        // quorum_fraction = 3/4 = 0.75
        // ceil(4 * 0.75) = 3
        assert_eq!(config.compute_quorum_size(4), 3);
    }

    // ========================================================================
    // T170: NetworkTransportConfig Tests
    // ========================================================================

    #[test]
    fn test_network_transport_config_default() {
        let config = NetworkTransportConfig::default();
        assert!(!config.enable_p2p, "P2P should be disabled by default");
        assert_eq!(config.max_outbound, 16);
        assert_eq!(config.max_inbound, 64);
        assert_eq!(config.gossip_fanout, 6);
    }

    #[test]
    fn test_network_transport_config_disabled() {
        let config = NetworkTransportConfig::disabled();
        assert!(!config.enable_p2p);
        assert!(!config.is_p2p_enabled());
    }

    #[test]
    fn test_network_transport_config_testnet_beta() {
        let config = NetworkTransportConfig::testnet_beta();
        assert!(config.enable_p2p);
        assert!(config.is_p2p_enabled());
        assert_eq!(config.max_outbound, 16);
        assert_eq!(config.max_inbound, 64);
        assert_eq!(config.gossip_fanout, 6);
    }

    #[test]
    fn test_network_transport_config_mainnet() {
        let config = NetworkTransportConfig::mainnet();
        assert!(config.enable_p2p);
        assert!(config.is_p2p_enabled());
        assert_eq!(config.max_outbound, 16);
        assert_eq!(config.max_inbound, 64);
        assert_eq!(config.gossip_fanout, 8); // Higher fanout for MainNet
    }

    #[test]
    fn test_network_transport_config_is_p2p_enabled() {
        let disabled = NetworkTransportConfig::disabled();
        assert!(!disabled.is_p2p_enabled());

        let enabled = NetworkTransportConfig::testnet_beta();
        assert!(enabled.is_p2p_enabled());
    }

    // ========================================================================
    // T180: TestNet Beta Preset Tests
    // ========================================================================

    #[test]
    fn test_devnet_v0_preset() {
        let config = NodeConfig::devnet_v0_preset();

        // Environment
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert_eq!(config.chain_id(), QBIND_DEVNET_CHAIN_ID);
        assert_eq!(config.scope(), "DEV");

        // Execution
        assert_eq!(config.execution_profile, ExecutionProfile::NonceOnly);

        // Gas (disabled)
        assert!(!config.gas_enabled, "DevNet v0 should have gas disabled");

        // Fee priority (disabled)
        assert!(
            !config.enable_fee_priority,
            "DevNet v0 should have fee priority disabled"
        );

        // Mempool (FIFO)
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Fifo,
            "DevNet v0 should use FIFO mempool"
        );

        // DAG availability (disabled)
        assert!(
            !config.dag_availability_enabled,
            "DevNet v0 should have DAG availability disabled"
        );

        // Network (LocalMesh, P2P disabled)
        assert_eq!(config.network_mode, NetworkMode::LocalMesh);
        assert!(!config.network.enable_p2p);
    }

    #[test]
    fn test_testnet_alpha_preset() {
        let config = NodeConfig::testnet_alpha_preset();

        // Environment
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.chain_id(), QBIND_TESTNET_CHAIN_ID);
        assert_eq!(config.scope(), "TST");

        // Execution
        assert_eq!(
            config.execution_profile,
            ExecutionProfile::VmV0,
            "TestNet Alpha should use VmV0"
        );

        // Gas (disabled by default in Alpha)
        assert!(
            !config.gas_enabled,
            "TestNet Alpha should have gas disabled by default"
        );

        // Fee priority (disabled by default in Alpha)
        assert!(
            !config.enable_fee_priority,
            "TestNet Alpha should have fee priority disabled"
        );

        // Mempool (FIFO by default in Alpha)
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Fifo,
            "TestNet Alpha should use FIFO mempool by default"
        );

        // DAG availability (disabled by default in Alpha)
        assert!(
            !config.dag_availability_enabled,
            "TestNet Alpha should have DAG availability disabled by default"
        );

        // Network (LocalMesh by default, P2P disabled)
        assert_eq!(config.network_mode, NetworkMode::LocalMesh);
        assert!(!config.network.enable_p2p);
    }

    #[test]
    fn test_testnet_beta_preset() {
        let config = NodeConfig::testnet_beta_preset();

        // Environment: Same chain ID as Alpha
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.chain_id(), QBIND_TESTNET_CHAIN_ID);
        assert_eq!(config.scope(), "TST");

        // Execution: VmV0
        assert_eq!(
            config.execution_profile,
            ExecutionProfile::VmV0,
            "TestNet Beta should use VmV0"
        );

        // Gas: Enabled by default in Beta
        assert!(
            config.gas_enabled,
            "TestNet Beta should have gas ENABLED by default"
        );

        // Fee priority: Enabled by default in Beta
        assert!(
            config.enable_fee_priority,
            "TestNet Beta should have fee priority ENABLED by default"
        );

        // Mempool: DAG by default in Beta
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Dag,
            "TestNet Beta should use DAG mempool by default"
        );

        // DAG availability: Enabled by default in Beta
        assert!(
            config.dag_availability_enabled,
            "TestNet Beta should have DAG availability ENABLED by default"
        );

        // Network: P2P by default in Beta
        assert_eq!(
            config.network_mode,
            NetworkMode::P2p,
            "TestNet Beta should use P2P network mode by default"
        );
        assert!(
            config.network.enable_p2p,
            "TestNet Beta should have P2P ENABLED by default"
        );
    }

    #[test]
    fn test_testnet_beta_preset_localmesh() {
        let config = NodeConfig::testnet_beta_preset_localmesh();

        // Should have all Beta features
        assert!(config.gas_enabled);
        assert!(config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Dag);
        assert!(config.dag_availability_enabled);

        // But with LocalMesh networking for CI-friendly tests
        assert_eq!(
            config.network_mode,
            NetworkMode::LocalMesh,
            "testnet_beta_preset_localmesh should use LocalMesh"
        );
        assert!(
            !config.network.enable_p2p,
            "testnet_beta_preset_localmesh should have P2P disabled"
        );
    }

    #[test]
    fn test_from_profile() {
        // DevNet v0
        let devnet = NodeConfig::from_profile(ConfigProfile::DevNetV0);
        assert_eq!(devnet.environment, NetworkEnvironment::Devnet);
        assert!(!devnet.gas_enabled);

        // TestNet Alpha
        let alpha = NodeConfig::from_profile(ConfigProfile::TestNetAlpha);
        assert_eq!(alpha.environment, NetworkEnvironment::Testnet);
        assert_eq!(alpha.execution_profile, ExecutionProfile::VmV0);
        assert!(!alpha.gas_enabled);

        // TestNet Beta
        let beta = NodeConfig::from_profile(ConfigProfile::TestNetBeta);
        assert_eq!(beta.environment, NetworkEnvironment::Testnet);
        assert!(beta.gas_enabled);
        assert!(beta.enable_fee_priority);
        assert_eq!(beta.mempool_mode, MempoolMode::Dag);
    }

    #[test]
    fn test_parse_config_profile() {
        assert_eq!(
            parse_config_profile("devnet-v0"),
            Some(ConfigProfile::DevNetV0)
        );
        assert_eq!(
            parse_config_profile("devnet"),
            Some(ConfigProfile::DevNetV0)
        );
        assert_eq!(
            parse_config_profile("testnet-alpha"),
            Some(ConfigProfile::TestNetAlpha)
        );
        assert_eq!(
            parse_config_profile("alpha"),
            Some(ConfigProfile::TestNetAlpha)
        );
        assert_eq!(
            parse_config_profile("testnet-beta"),
            Some(ConfigProfile::TestNetBeta)
        );
        assert_eq!(
            parse_config_profile("beta"),
            Some(ConfigProfile::TestNetBeta)
        );
        assert_eq!(parse_config_profile("invalid"), None);
        assert_eq!(
            parse_config_profile("TESTNET-BETA"),
            Some(ConfigProfile::TestNetBeta)
        );
    }

    #[test]
    fn test_parse_mempool_mode() {
        assert_eq!(parse_mempool_mode("fifo"), MempoolMode::Fifo);
        assert_eq!(parse_mempool_mode("FIFO"), MempoolMode::Fifo);
        assert_eq!(parse_mempool_mode("dag"), MempoolMode::Dag);
        assert_eq!(parse_mempool_mode("DAG"), MempoolMode::Dag);
        assert_eq!(parse_mempool_mode("unknown"), MempoolMode::Fifo); // Default fallback
    }

    #[test]
    fn test_presets_preserve_existing_behavior() {
        // Verify that existing constructors still produce the same results
        // (DevNet/TestNet Alpha defaults remain unchanged)

        let default = NodeConfig::default();
        assert_eq!(default.environment, NetworkEnvironment::Devnet);
        assert_eq!(default.execution_profile, ExecutionProfile::NonceOnly);
        assert!(!default.gas_enabled);
        assert!(!default.enable_fee_priority);
        assert_eq!(default.mempool_mode, MempoolMode::Fifo);
        assert!(!default.dag_availability_enabled);
        assert_eq!(default.network_mode, NetworkMode::LocalMesh);
        assert!(!default.network.enable_p2p);

        let devnet = NodeConfig::devnet();
        assert_eq!(devnet.environment, NetworkEnvironment::Devnet);
        assert!(!devnet.gas_enabled);

        let testnet = NodeConfig::testnet();
        assert_eq!(testnet.environment, NetworkEnvironment::Testnet);
        assert!(!testnet.gas_enabled);

        let testnet_vm_v0 = NodeConfig::testnet_vm_v0();
        assert_eq!(testnet_vm_v0.environment, NetworkEnvironment::Testnet);
        assert_eq!(testnet_vm_v0.execution_profile, ExecutionProfile::VmV0);
        assert!(!testnet_vm_v0.gas_enabled); // Alpha default: gas off
    }

    #[test]
    fn test_builder_methods() {
        let config = NodeConfig::testnet_alpha_preset()
            .with_gas_enabled(true)
            .with_fee_priority(true)
            .with_mempool_mode(MempoolMode::Dag)
            .with_dag_availability(true);

        assert!(config.gas_enabled);
        assert!(config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Dag);
        assert!(config.dag_availability_enabled);
    }

    #[test]
    fn test_startup_info_includes_t180_fields() {
        let config = NodeConfig::testnet_beta_preset();
        let info = config.startup_info_string(Some("V1"));

        assert!(info.contains("gas=on"), "Should show gas=on for Beta");
        assert!(
            info.contains("fee-priority=on"),
            "Should show fee-priority=on for Beta"
        );
        assert!(
            info.contains("mempool=dag"),
            "Should show mempool=dag for Beta"
        );
    }

    #[test]
    fn test_mempool_mode_display() {
        assert_eq!(format!("{}", MempoolMode::Fifo), "fifo");
        assert_eq!(format!("{}", MempoolMode::Dag), "dag");
    }

    #[test]
    fn test_config_profile_display() {
        assert_eq!(format!("{}", ConfigProfile::DevNetV0), "devnet-v0");
        assert_eq!(format!("{}", ConfigProfile::TestNetAlpha), "testnet-alpha");
        assert_eq!(format!("{}", ConfigProfile::TestNetBeta), "testnet-beta");
    }

    // ========================================================================
    // T186: Stage B Parallel Execution Tests
    // ========================================================================

    #[test]
    fn test_stage_b_disabled_by_default() {
        let config = NodeConfig::default();
        assert!(
            !config.stage_b_enabled,
            "Stage B should be disabled by default"
        );
    }

    #[test]
    fn test_stage_b_devnet_preset() {
        let config = NodeConfig::devnet_v0_preset();
        assert!(
            !config.stage_b_enabled,
            "DevNet v0 preset should have Stage B disabled"
        );
    }

    #[test]
    fn test_stage_b_testnet_alpha_preset() {
        let config = NodeConfig::testnet_alpha_preset();
        assert!(
            !config.stage_b_enabled,
            "TestNet Alpha preset should have Stage B disabled"
        );
    }

    #[test]
    fn test_stage_b_testnet_beta_preset() {
        let config = NodeConfig::testnet_beta_preset();
        assert!(
            !config.stage_b_enabled,
            "TestNet Beta preset should have Stage B disabled (opt-in available)"
        );
    }

    #[test]
    fn test_stage_b_mainnet_preset() {
        let config = NodeConfig::mainnet_preset();
        assert!(
            config.stage_b_enabled,
            "MainNet preset should have Stage B enabled by default"
        );
    }

    #[test]
    fn test_stage_b_builder_method() {
        let config = NodeConfig::testnet_beta_preset().with_stage_b_enabled(true);
        assert!(
            config.stage_b_enabled,
            "with_stage_b_enabled(true) should enable Stage B"
        );

        let config2 = NodeConfig::mainnet_preset().with_stage_b_enabled(false);
        assert!(
            !config2.stage_b_enabled,
            "with_stage_b_enabled(false) should disable Stage B"
        );
    }

    #[test]
    fn test_stage_b_in_startup_info() {
        let config_enabled = NodeConfig::mainnet_preset();
        let info_enabled = config_enabled.startup_info_string(Some("V1"));
        assert!(
            info_enabled.contains("stage_b=enabled"),
            "Startup info should show stage_b=enabled for MainNet"
        );

        let config_disabled = NodeConfig::testnet_alpha_preset();
        let info_disabled = config_disabled.startup_info_string(Some("V1"));
        assert!(
            info_disabled.contains("stage_b=disabled"),
            "Startup info should show stage_b=disabled for TestNet Alpha"
        );
    }

    #[test]
    fn test_mainnet_validates_with_stage_b_disabled() {
        // Create a MainNet config but with Stage B disabled via override
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_stage_b_enabled(false);

        // MainNet validation should still pass (Stage B is allowed but not required)
        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_ok(),
            "MainNet validation should pass even with Stage B disabled (it's allowed, not required)"
        );
    }

    #[test]
    fn test_mainnet_validates_with_stage_b_enabled() {
        let config = NodeConfig::mainnet_preset().with_data_dir("/tmp/test");

        // MainNet validation should pass
        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_ok(),
            "MainNet validation should pass with Stage B enabled"
        );
    }

    // ========================================================================
    // T189: DAG Coupling Mode Tests
    // ========================================================================

    #[test]
    fn test_dag_coupling_mode_default() {
        let mode = DagCouplingMode::default();
        assert_eq!(mode, DagCouplingMode::Off);
    }

    #[test]
    fn test_dag_coupling_mode_display() {
        assert_eq!(format!("{}", DagCouplingMode::Off), "off");
        assert_eq!(format!("{}", DagCouplingMode::Warn), "warn");
        assert_eq!(format!("{}", DagCouplingMode::Enforce), "enforce");
    }

    #[test]
    fn test_parse_dag_coupling_mode_valid() {
        // Case-insensitive matching
        assert_eq!(parse_dag_coupling_mode("off"), Some(DagCouplingMode::Off));
        assert_eq!(parse_dag_coupling_mode("OFF"), Some(DagCouplingMode::Off));
        assert_eq!(parse_dag_coupling_mode("Off"), Some(DagCouplingMode::Off));
        assert_eq!(parse_dag_coupling_mode("warn"), Some(DagCouplingMode::Warn));
        assert_eq!(parse_dag_coupling_mode("WARN"), Some(DagCouplingMode::Warn));
        assert_eq!(
            parse_dag_coupling_mode("enforce"),
            Some(DagCouplingMode::Enforce)
        );
        assert_eq!(
            parse_dag_coupling_mode("ENFORCE"),
            Some(DagCouplingMode::Enforce)
        );
    }

    #[test]
    fn test_parse_dag_coupling_mode_invalid() {
        assert_eq!(parse_dag_coupling_mode("invalid"), None);
        assert_eq!(parse_dag_coupling_mode(""), None);
        assert_eq!(parse_dag_coupling_mode("on"), None);
        assert_eq!(parse_dag_coupling_mode("enabled"), None);
    }

    #[test]
    fn test_dag_coupling_mode_devnet_preset() {
        let config = NodeConfig::devnet_v0_preset();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Off,
            "DevNet v0 preset should have dag_coupling_mode = Off"
        );
    }

    #[test]
    fn test_dag_coupling_mode_testnet_alpha_preset() {
        let config = NodeConfig::testnet_alpha_preset();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Off,
            "TestNet Alpha preset should have dag_coupling_mode = Off"
        );
    }

    #[test]
    fn test_dag_coupling_mode_testnet_beta_preset() {
        let config = NodeConfig::testnet_beta_preset();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Off,
            "TestNet Beta preset should have dag_coupling_mode = Off (optionally Warn)"
        );
    }

    #[test]
    fn test_dag_coupling_mode_mainnet_preset() {
        let config = NodeConfig::mainnet_preset();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Enforce,
            "MainNet preset should have dag_coupling_mode = Enforce"
        );
    }

    #[test]
    fn test_dag_coupling_mode_builder_method() {
        let config =
            NodeConfig::testnet_beta_preset().with_dag_coupling_mode(DagCouplingMode::Warn);
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Warn,
            "with_dag_coupling_mode(Warn) should set mode to Warn"
        );

        let config2 = NodeConfig::mainnet_preset().with_dag_coupling_mode(DagCouplingMode::Off);
        assert_eq!(
            config2.dag_coupling_mode,
            DagCouplingMode::Off,
            "with_dag_coupling_mode(Off) should set mode to Off"
        );
    }

    #[test]
    fn test_dag_coupling_mode_in_startup_info() {
        let config_enforce = NodeConfig::mainnet_preset();
        let info_enforce = config_enforce.startup_info_string(Some("V1"));
        assert!(
            info_enforce.contains("dag_coupling=enforce"),
            "Startup info should show dag_coupling=enforce for MainNet"
        );

        let config_off = NodeConfig::testnet_alpha_preset();
        let info_off = config_off.startup_info_string(Some("V1"));
        assert!(
            info_off.contains("dag_coupling=off"),
            "Startup info should show dag_coupling=off for TestNet Alpha"
        );

        let config_warn =
            NodeConfig::testnet_beta_preset().with_dag_coupling_mode(DagCouplingMode::Warn);
        let info_warn = config_warn.startup_info_string(Some("V1"));
        assert!(
            info_warn.contains("dag_coupling=warn"),
            "Startup info should show dag_coupling=warn when set"
        );
    }

    #[test]
    fn test_mainnet_validation_rejects_coupling_not_enforce() {
        // Create a MainNet config but with coupling mode set to Off
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_dag_coupling_mode(DagCouplingMode::Off);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when dag_coupling_mode != Enforce"
        );
        match result {
            Err(MainnetConfigError::DagCouplingNotEnforced { actual }) => {
                assert_eq!(actual, DagCouplingMode::Off);
            }
            _ => panic!("Expected DagCouplingNotEnforced error, got: {:?}", result),
        }
    }

    #[test]
    fn test_mainnet_validation_rejects_coupling_warn() {
        // Create a MainNet config but with coupling mode set to Warn
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_dag_coupling_mode(DagCouplingMode::Warn);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when dag_coupling_mode = Warn"
        );
        match result {
            Err(MainnetConfigError::DagCouplingNotEnforced { actual }) => {
                assert_eq!(actual, DagCouplingMode::Warn);
            }
            _ => panic!("Expected DagCouplingNotEnforced error, got: {:?}", result),
        }
    }

    #[test]
    fn test_mainnet_validation_accepts_coupling_enforce() {
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_dag_coupling_mode(DagCouplingMode::Enforce);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_ok(),
            "MainNet validation should pass when dag_coupling_mode = Enforce"
        );
    }

    #[test]
    fn test_dag_coupling_error_display() {
        let error = MainnetConfigError::DagCouplingNotEnforced {
            actual: DagCouplingMode::Off,
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("dag_coupling_mode"));
        assert!(error_str.contains("Enforce"));
        assert!(error_str.contains("off"));
        assert!(error_str.contains("--dag-coupling-mode=enforce"));
    }

    // ========================================================================
    // T201: Monetary Accounts Validation Tests
    // ========================================================================

    #[test]
    fn test_mainnet_validation_rejects_monetary_accounts_with_zero_address() {
        // Create a MainNet config with Active mode and zero treasury address
        let mut accounts = MonetaryAccounts::test_accounts();
        accounts.treasury = [0u8; 32]; // Zero address

        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_monetary_mode(MonetaryMode::Active)
            .with_monetary_accounts(accounts);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when monetary accounts contain zero address"
        );
        match result {
            Err(MainnetConfigError::MonetaryAccountsInvalid) => (),
            _ => panic!(
                "Expected MonetaryAccountsInvalid error, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_mainnet_validation_rejects_monetary_accounts_with_duplicates() {
        // Create a MainNet config with Active mode and duplicate addresses
        let test_addr = [1u8; 32];
        let accounts = MonetaryAccounts::new(
            test_addr, // validator_pool
            test_addr, // treasury (duplicate!)
            [2u8; 32], // insurance
            [3u8; 32], // community
        );

        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_monetary_mode(MonetaryMode::Active)
            .with_monetary_accounts(accounts);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when monetary accounts have duplicates"
        );
        match result {
            Err(MainnetConfigError::MonetaryAccountsInvalid) => (),
            _ => panic!(
                "Expected MonetaryAccountsInvalid error, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_mainnet_validation_accepts_valid_monetary_accounts() {
        // Create a MainNet config with Active mode and valid accounts
        let accounts = MonetaryAccounts::new(
            [1u8; 32], // validator_pool
            [2u8; 32], // treasury
            [3u8; 32], // insurance
            [4u8; 32], // community
        );

        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_monetary_mode(MonetaryMode::Active)
            .with_monetary_accounts(accounts);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_ok(),
            "MainNet validation should pass with valid monetary accounts: {:?}",
            result
        );
    }

    #[test]
    fn test_monetary_accounts_is_valid_for_mainnet() {
        // Test the is_valid_for_mainnet method directly
        let valid_accounts = MonetaryAccounts::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        );
        assert!(valid_accounts.is_valid_for_mainnet());

        // Zero address should fail
        let accounts_with_zero = MonetaryAccounts::new(
            [0u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
        );
        assert!(!accounts_with_zero.is_valid_for_mainnet());

        // Duplicates should fail
        let accounts_with_dup = MonetaryAccounts::new(
            [1u8; 32],
            [1u8; 32],
            [3u8; 32],
            [4u8; 32],
        );
        assert!(!accounts_with_dup.is_valid_for_mainnet());
    }

    #[test]
    fn test_monetary_accounts_invalid_error_display() {
        let error = MainnetConfigError::MonetaryAccountsInvalid;
        let error_str = format!("{}", error);
        assert!(error_str.contains("monetary accounts"));
        assert!(error_str.contains("distinct"));
        assert!(error_str.contains("non-zero"));
        assert!(error_str.contains("T201"));
    }
}