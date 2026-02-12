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

use qbind_ledger::{
    FeeDistributionPolicy, GenesisHash, MonetaryAccounts, MonetaryMode, SeigniorageSplit,
};
use qbind_types::{ChainId, NetworkEnvironment};
use std::path::PathBuf;

// ============================================================================
// T208: State Retention Configuration
// ============================================================================

/// Mode for state retention and pruning (T208).
///
/// Determines how historical state data is managed by the node.
/// Pruning is purely local node behavior and does not affect consensus.
///
/// # Environments
///
/// - **DevNet v0**: `Disabled` (full history retained)
/// - **TestNet Alpha**: `Disabled` (full history retained)
/// - **TestNet Beta**: `Height` with retain_height ~100_000
/// - **MainNet v0**: `Height` with retain_height ~500_000 (~30 days of history)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StateRetentionMode {
    /// State pruning is disabled. All historical state is retained.
    ///
    /// This is the default for DevNet and TestNet Alpha to preserve
    /// full history for debugging and testing.
    #[default]
    Disabled,

    /// Prune state based on block height.
    ///
    /// State data below `current_height - retain_height` may be pruned.
    /// This is the recommended mode for production validators to manage
    /// disk space while maintaining sufficient history for reorganizations.
    Height,
    // Epochs mode can be added in the future:
    // Epochs,
}

impl std::fmt::Display for StateRetentionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateRetentionMode::Disabled => write!(f, "disabled"),
            StateRetentionMode::Height => write!(f, "height"),
        }
    }
}

/// Parse a state retention mode from a string.
///
/// Valid values: "disabled", "height"
///
/// Returns `None` for unrecognized values.
pub fn parse_state_retention_mode(s: &str) -> Option<StateRetentionMode> {
    match s.to_lowercase().as_str() {
        "disabled" | "off" => Some(StateRetentionMode::Disabled),
        "height" | "blocks" => Some(StateRetentionMode::Height),
        _ => None,
    }
}

/// Valid state retention mode strings for documentation and error messages.
pub const VALID_STATE_RETENTION_MODES: &[&str] = &["disabled", "height"];

/// Configuration for state retention and pruning (T208).
///
/// Controls how the node manages historical state data to balance disk usage
/// against the ability to verify historical blocks and handle reorganizations.
///
/// # Pruning Behavior
///
/// When `mode = Height` and `retain_height = Some(N)`:
/// - State below `current_height - N` may be pruned
/// - Pruning runs every `prune_interval_blocks` committed blocks
/// - Current account state is never pruned (only historical snapshots)
///
/// # Thread Safety
///
/// Pruning runs in a background task and does not block consensus or execution.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::{StateRetentionConfig, StateRetentionMode};
///
/// // MainNet configuration: keep ~30 days of history
/// let config = StateRetentionConfig {
///     mode: StateRetentionMode::Height,
///     retain_height: Some(500_000),  // ~30 days at 5s blocks
///     retain_epochs: None,
///     prune_interval_blocks: 1_000,
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRetentionConfig {
    /// The retention mode.
    pub mode: StateRetentionMode,

    /// Number of blocks of history to retain when `mode = Height`.
    ///
    /// State below `current_height - retain_height` may be pruned.
    /// Set to `None` to retain all history (equivalent to `mode = Disabled`).
    ///
    /// Recommended values:
    /// - TestNet Beta: 100_000 (~6 days at 5s blocks)
    /// - MainNet: 500_000 (~30 days at 5s blocks)
    pub retain_height: Option<u64>,

    /// Number of epochs of history to retain when `mode = Epochs`.
    ///
    /// Reserved for future use when epoch-based pruning is implemented.
    /// Currently ignored.
    pub retain_epochs: Option<u64>,

    /// Interval (in committed blocks) between pruning runs.
    ///
    /// Pruning is triggered every N blocks to amortize the cost.
    /// Recommended: 1_000 blocks (~83 minutes at 5s blocks).
    pub prune_interval_blocks: u64,
}

impl Default for StateRetentionConfig {
    fn default() -> Self {
        Self {
            mode: StateRetentionMode::Disabled,
            retain_height: None,
            retain_epochs: None,
            prune_interval_blocks: 1_000,
        }
    }
}

impl StateRetentionConfig {
    /// Create a disabled state retention configuration.
    ///
    /// All historical state is retained. This is the default for DevNet.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create a height-based state retention configuration.
    ///
    /// # Arguments
    ///
    /// * `retain_height` - Number of blocks of history to retain
    /// * `prune_interval_blocks` - Blocks between pruning runs
    pub fn height_based(retain_height: u64, prune_interval_blocks: u64) -> Self {
        Self {
            mode: StateRetentionMode::Height,
            retain_height: Some(retain_height),
            retain_epochs: None,
            prune_interval_blocks,
        }
    }

    /// Create the TestNet Beta default configuration.
    ///
    /// - Mode: Height
    /// - Retain height: 100_000 blocks (~6 days at 5s blocks)
    /// - Prune interval: 1_000 blocks
    pub fn testnet_beta_default() -> Self {
        Self::height_based(100_000, 1_000)
    }

    /// Create the MainNet default configuration.
    ///
    /// - Mode: Height
    /// - Retain height: 500_000 blocks (~30 days at 5s blocks)
    /// - Prune interval: 1_000 blocks
    pub fn mainnet_default() -> Self {
        Self::height_based(500_000, 1_000)
    }

    /// Check if pruning is enabled.
    pub fn is_enabled(&self) -> bool {
        self.mode != StateRetentionMode::Disabled
    }

    /// Compute the prune-below height for a given current height.
    ///
    /// Returns `None` if:
    /// - Pruning is disabled (mode != Height)
    /// - retain_height is not set
    /// - current_height <= retain_height (nothing to prune yet)
    pub fn prune_below_height(&self, current_height: u64) -> Option<u64> {
        if self.mode != StateRetentionMode::Height {
            return None;
        }
        let retain = self.retain_height?;
        if current_height > retain {
            Some(current_height - retain)
        } else {
            None // Nothing to prune yet
        }
    }

    /// Check if pruning should run at the given height.
    ///
    /// Returns `true` if pruning is enabled and the height is a multiple
    /// of `prune_interval_blocks`.
    pub fn should_prune_at_height(&self, height: u64) -> bool {
        self.is_enabled()
            && self.prune_interval_blocks > 0
            && height.is_multiple_of(self.prune_interval_blocks)
    }
}

// ============================================================================
// T215: State Snapshot Configuration
// ============================================================================

/// Configuration for state snapshots (T215).
///
/// Controls periodic snapshot creation for fast sync and recovery.
/// Snapshots are local-only and do not affect consensus.
///
/// # Behavior
///
/// When enabled, snapshots are created at configured intervals:
/// - `snapshot_interval_blocks`: Create snapshot every N committed blocks
/// - `snapshot_dir`: Directory to store snapshots
/// - `max_snapshots`: Maximum number of snapshots to retain (oldest pruned)
///
/// # Thread Safety
///
/// Snapshot creation runs in a background task and does not block consensus.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::SnapshotConfig;
/// use std::path::PathBuf;
///
/// // MainNet configuration: snapshot every 50k blocks
/// let config = SnapshotConfig::enabled(
///     PathBuf::from("/data/qbind/snapshots"),
///     50_000,  // Every ~3.5 days at 5s blocks
///     3,       // Keep last 3 snapshots
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Whether snapshot creation is enabled.
    ///
    /// When false, no periodic snapshots are created.
    /// Fast-sync restore is still possible from operator-provided snapshots.
    pub enabled: bool,

    /// Directory to store snapshots.
    ///
    /// Each snapshot is stored in a subdirectory named by height:
    /// `{snapshot_dir}/{height}/`
    ///
    /// Must be set when `enabled = true`.
    pub snapshot_dir: Option<PathBuf>,

    /// Interval (in committed blocks) between snapshot creation.
    ///
    /// A snapshot is created when `current_height % snapshot_interval_blocks == 0`.
    ///
    /// Recommended values:
    /// - TestNet Beta: 100_000 blocks (~6 days at 5s blocks)
    /// - MainNet v0: 50_000 blocks (~3.5 days at 5s blocks)
    pub snapshot_interval_blocks: u64,

    /// Maximum number of snapshots to retain.
    ///
    /// When a new snapshot is created and this limit is exceeded,
    /// the oldest snapshot is deleted to free space.
    ///
    /// Recommended: 3-5 snapshots for recovery flexibility.
    pub max_snapshots: u32,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            snapshot_dir: None,
            snapshot_interval_blocks: 50_000,
            max_snapshots: 3,
        }
    }
}

impl SnapshotConfig {
    /// Create a disabled snapshot configuration.
    ///
    /// No periodic snapshots are created. This is the default for DevNet.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create an enabled snapshot configuration.
    ///
    /// # Arguments
    ///
    /// * `snapshot_dir` - Directory to store snapshots
    /// * `interval_blocks` - Blocks between snapshots
    /// * `max_snapshots` - Maximum snapshots to retain
    pub fn enabled(snapshot_dir: PathBuf, interval_blocks: u64, max_snapshots: u32) -> Self {
        Self {
            enabled: true,
            snapshot_dir: Some(snapshot_dir),
            snapshot_interval_blocks: interval_blocks,
            max_snapshots,
        }
    }

    /// Create the TestNet Beta default configuration.
    ///
    /// - Enabled with 100,000 block interval (~6 days at 5s blocks)
    /// - Retains 3 snapshots
    /// - Snapshot directory must be set by operator
    pub fn testnet_beta_default() -> Self {
        Self {
            enabled: true,
            snapshot_dir: None, // Must be configured by operator
            snapshot_interval_blocks: 100_000,
            max_snapshots: 3,
        }
    }

    /// Create the MainNet default configuration.
    ///
    /// - Enabled with 50,000 block interval (~3.5 days at 5s blocks)
    /// - Retains 5 snapshots for better recovery options
    /// - Snapshot directory must be set by operator
    pub fn mainnet_default() -> Self {
        Self {
            enabled: true,
            snapshot_dir: None, // Must be configured by operator
            snapshot_interval_blocks: 50_000,
            max_snapshots: 5,
        }
    }

    /// Check if snapshots are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.snapshot_dir.is_some()
    }

    /// Check if a snapshot should be created at the given height.
    ///
    /// Returns `true` if snapshots are enabled and the height is a multiple
    /// of `snapshot_interval_blocks`.
    pub fn should_snapshot_at_height(&self, height: u64) -> bool {
        self.enabled
            && self.snapshot_dir.is_some()
            && self.snapshot_interval_blocks > 0
            && height > 0
            && height.is_multiple_of(self.snapshot_interval_blocks)
    }

    /// Get the snapshot path for a given height.
    ///
    /// Returns `None` if snapshots are disabled or no directory is configured.
    pub fn snapshot_path_for_height(&self, height: u64) -> Option<PathBuf> {
        self.snapshot_dir
            .as_ref()
            .map(|dir| dir.join(height.to_string()))
    }
}

// ============================================================================
// T215: Fast Sync Configuration
// ============================================================================

/// Configuration for fast-sync from local snapshots (T215).
///
/// Controls startup behavior when a local snapshot is available.
/// Fast-sync allows a node to boot from a snapshot instead of replaying
/// all blocks from genesis.
///
/// # Workflow
///
/// 1. Node checks `fast_sync_snapshot_dir` for valid snapshot
/// 2. Validates snapshot metadata (height, chain ID)
/// 3. Restores state from snapshot
/// 4. Replays blocks from snapshot height → current tip
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::FastSyncConfig;
/// use std::path::PathBuf;
///
/// let config = FastSyncConfig::from_snapshot(
///     PathBuf::from("/data/qbind/snapshots/100000"),
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FastSyncConfig {
    /// Whether fast-sync from snapshot is enabled.
    ///
    /// When true and a valid snapshot exists at `fast_sync_snapshot_dir`,
    /// the node will boot from the snapshot instead of replaying from genesis.
    pub enabled: bool,

    /// Path to snapshot directory to restore from.
    ///
    /// Must contain a valid snapshot with:
    /// - `meta.json`: Snapshot metadata
    /// - `state/`: RocksDB checkpoint files
    ///
    /// If `None` or the path doesn't exist, normal sync from genesis is used.
    pub fast_sync_snapshot_dir: Option<PathBuf>,
}

impl FastSyncConfig {
    /// Create a disabled fast-sync configuration (default).
    ///
    /// Node will sync normally from genesis or existing state.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create a fast-sync configuration to restore from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot_dir` - Path to the snapshot directory to restore from
    pub fn from_snapshot(snapshot_dir: PathBuf) -> Self {
        Self {
            enabled: true,
            fast_sync_snapshot_dir: Some(snapshot_dir),
        }
    }

    /// Check if fast-sync is configured and should be attempted.
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.fast_sync_snapshot_dir.is_some()
    }
}

// ============================================================================
// T210: Signer Mode Configuration
// ============================================================================

/// Signer mode for validator key management (T210).
///
/// Determines how the validator signing key is stored and accessed.
/// This configuration affects security posture and operational requirements.
///
/// # Environments
///
/// - **DevNet v0**: `LoopbackTesting` (default for development)
/// - **TestNet Alpha**: `EncryptedFsV1` (recommended, must provide keystore path)
/// - **TestNet Beta**: `EncryptedFsV1` (recommended, must provide keystore path)
/// - **MainNet v0**: `EncryptedFsV1` or `HsmPkcs11` (**LoopbackTesting forbidden**)
///
/// # Security Notes
///
/// - `LoopbackTesting` is **FORBIDDEN** on MainNet (enforced by `validate_mainnet_invariants`)
/// - `EncryptedFsV1` stores keys encrypted at rest (ChaCha20-Poly1305 + PBKDF2)
/// - `RemoteSigner` communicates with external signer service (future HSM support)
/// - `HsmPkcs11` uses Hardware Security Module via PKCS#11 interface
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SignerMode {
    /// Loopback testing mode (DevNet only).
    ///
    /// Uses in-memory keys with loopback transport for testing remote signer flows.
    /// **NOT allowed for MainNet** – `validate_mainnet_invariants()` will reject this.
    ///
    /// Use only for:
    /// - Development and debugging
    /// - CI/CD testing pipelines
    /// - Single-machine harness tests
    #[default]
    LoopbackTesting,

    /// Encrypted filesystem keystore (TestNet/MainNet).
    ///
    /// Keys are stored on disk encrypted using ChaCha20-Poly1305 AEAD with
    /// PBKDF2-derived encryption keys. Requires `signer_keystore_path` to be set.
    ///
    /// Recommended for:
    /// - TestNet Alpha/Beta validators
    /// - MainNet validators without HSM access (acceptable with strong passphrase)
    EncryptedFsV1,

    /// Remote signer service (future HSM support).
    ///
    /// Communicates with an external signer service over gRPC or Unix socket.
    /// The signer service manages keys and performs signing operations.
    /// Requires `remote_signer_url` to be set.
    ///
    /// Use for:
    /// - Production validators with dedicated signing infrastructure
    /// - Multi-node signing architectures
    /// - Future HSM integration via signer proxy
    RemoteSigner,

    /// Hardware Security Module via PKCS#11 interface.
    ///
    /// Keys are stored in and never leave the HSM. Signing operations are
    /// performed by the HSM hardware. Requires `hsm_config_path` to be set.
    ///
    /// **Recommended for MainNet validators** for maximum key security.
    ///
    /// Supported HSMs (planned):
    /// - YubiHSM 2
    /// - AWS CloudHSM
    /// - Azure Key Vault Managed HSM
    HsmPkcs11,
}

impl std::fmt::Display for SignerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerMode::LoopbackTesting => write!(f, "loopback-testing"),
            SignerMode::EncryptedFsV1 => write!(f, "encrypted-fs"),
            SignerMode::RemoteSigner => write!(f, "remote-signer"),
            SignerMode::HsmPkcs11 => write!(f, "hsm-pkcs11"),
        }
    }
}

/// Parse a signer mode from a CLI argument string (T210).
///
/// Valid values (case-insensitive):
/// - "loopback-testing" | "loopback" | "testing" → `SignerMode::LoopbackTesting`
/// - "encrypted-fs" | "encrypted-fs-v1" | "encrypted" → `SignerMode::EncryptedFsV1`
/// - "remote-signer" | "remote" → `SignerMode::RemoteSigner`
/// - "hsm-pkcs11" | "hsm" | "pkcs11" → `SignerMode::HsmPkcs11`
///
/// # Returns
///
/// `Some(SignerMode)` if valid, `None` for unrecognized values.
/// Unlike some other parsers, this does NOT fall back to a default because
/// signer mode is a critical security configuration that must be explicit.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_signer_mode;
///
/// assert_eq!(parse_signer_mode("encrypted-fs"), Some(SignerMode::EncryptedFsV1));
/// assert_eq!(parse_signer_mode("hsm"), Some(SignerMode::HsmPkcs11));
/// assert_eq!(parse_signer_mode("invalid"), None);
/// ```
pub fn parse_signer_mode(s: &str) -> Option<SignerMode> {
    match s.to_lowercase().as_str() {
        "loopback-testing" | "loopback" | "testing" => Some(SignerMode::LoopbackTesting),
        "encrypted-fs" | "encrypted-fs-v1" | "encrypted" => Some(SignerMode::EncryptedFsV1),
        "remote-signer" | "remote" => Some(SignerMode::RemoteSigner),
        "hsm-pkcs11" | "hsm" | "pkcs11" => Some(SignerMode::HsmPkcs11),
        _ => None,
    }
}

/// Valid signer mode values for CLI help text.
pub const VALID_SIGNER_MODES: &[&str] = &[
    "loopback-testing",
    "encrypted-fs",
    "remote-signer",
    "hsm-pkcs11",
];

/// Check if a signer mode is allowed for production (MainNet) use.
///
/// Returns `true` for production-ready signer modes:
/// - `EncryptedFsV1`
/// - `RemoteSigner`
/// - `HsmPkcs11`
///
/// Returns `false` for development-only modes:
/// - `LoopbackTesting`
pub fn is_production_signer_mode(mode: SignerMode) -> bool {
    match mode {
        SignerMode::LoopbackTesting => false,
        SignerMode::EncryptedFsV1 => true,
        SignerMode::RemoteSigner => true,
        SignerMode::HsmPkcs11 => true,
    }
}

// ============================================================================
// T214: Signer Failure Mode Configuration
// ============================================================================

/// Signer failure mode for HSM/remote signer errors (T214).
///
/// Controls how the node reacts to signer/HSM failures during consensus operations.
/// This is critical for "fail-closed" behavior on MainNet to prevent signing with
/// degraded or unavailable signers.
///
/// # MainNet Requirement
///
/// MainNet validators **MUST** use `ExitOnFailure` to ensure fail-closed behavior.
/// This is enforced by `validate_mainnet_invariants()`.
///
/// # TestNet/DevNet Flexibility
///
/// Non-MainNet environments may use `LogAndContinue` for chaos testing, debugging,
/// or development scenarios where immediate node exit is undesirable.
///
/// # Security Notes
///
/// - `ExitOnFailure` ensures signing failures are immediately visible and addressed
/// - `LogAndContinue` should **NEVER** be used on MainNet (enforced by config validation)
/// - Redundancy is achieved via external orchestration, not automatic failover
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SignerFailureMode {
    /// Exit the node on signer failure (default, MainNet required).
    ///
    /// When an HSM or remote signer error occurs, the node logs the error
    /// at `error!` level, increments failure metrics, and terminates the process.
    /// This "fail-closed" behavior ensures that validators do not continue
    /// operating with potentially degraded or unavailable signing capability.
    ///
    /// Operators should use external orchestration (systemd, k8s, etc.) to
    /// restart the node or failover to a backup signer host.
    ///
    /// **This is the only mode allowed on MainNet.**
    #[default]
    ExitOnFailure,

    /// Log the error and continue (allowed only in dev/test profiles).
    ///
    /// When an HSM or remote signer error occurs, the node logs the error
    /// and propagates it to the caller without terminating. This allows
    /// testing failure scenarios and observing degraded behavior.
    ///
    /// **WARNING**: This mode must NOT be used on MainNet. It is intended
    /// for chaos testing, debugging, and development only.
    LogAndContinue,
}

impl std::fmt::Display for SignerFailureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerFailureMode::ExitOnFailure => write!(f, "exit-on-failure"),
            SignerFailureMode::LogAndContinue => write!(f, "log-and-continue"),
        }
    }
}

/// Parse a signer failure mode from a CLI argument string (T214).
///
/// Valid values (case-insensitive):
/// - "exit-on-failure" | "exit" | "fail" → `SignerFailureMode::ExitOnFailure`
/// - "log-and-continue" | "log" | "continue" → `SignerFailureMode::LogAndContinue`
///
/// # Returns
///
/// `Some(SignerFailureMode)` if valid, `None` for unrecognized values.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::parse_signer_failure_mode;
///
/// assert_eq!(parse_signer_failure_mode("exit-on-failure"), Some(SignerFailureMode::ExitOnFailure));
/// assert_eq!(parse_signer_failure_mode("log-and-continue"), Some(SignerFailureMode::LogAndContinue));
/// assert_eq!(parse_signer_failure_mode("invalid"), None);
/// ```
pub fn parse_signer_failure_mode(s: &str) -> Option<SignerFailureMode> {
    match s.to_lowercase().as_str() {
        "exit-on-failure" | "exit" | "fail" => Some(SignerFailureMode::ExitOnFailure),
        "log-and-continue" | "log" | "continue" => Some(SignerFailureMode::LogAndContinue),
        _ => None,
    }
}

/// Valid signer failure mode values for CLI help text.
pub const VALID_SIGNER_FAILURE_MODES: &[&str] = &["exit-on-failure", "log-and-continue"];

// ============================================================================
// T218: Mempool DoS Configuration
// ============================================================================

/// Configuration for DAG mempool DoS protections (T218).
///
/// Controls per-sender rate limits and batch size limits to prevent
/// malicious senders from overwhelming the mempool.
///
/// # Environments
///
/// - **DevNet v0**: Very loose limits (debugging-friendly)
/// - **TestNet Alpha**: Disabled / neutral (FIFO or DAG in proto mode)
/// - **TestNet Beta**: Moderate protection (testable limits)
/// - **MainNet v0**: Tighter defaults (conservative; can refine post-benchmark)
///
/// # Per-Sender Quotas
///
/// Each sender can only have a bounded number of pending (unbatched + batched-not-committed)
/// transactions in the mempool at any time. This prevents a single sender from
/// monopolizing mempool resources.
///
/// # Batch Size Limits
///
/// Each DAG batch is capped at a maximum number of transactions and a maximum
/// byte size. This ensures batches can be efficiently verified and propagated.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::MempoolDosConfig;
///
/// // MainNet configuration
/// let config = MempoolDosConfig::mainnet_default();
/// assert_eq!(config.max_pending_per_sender, 1_000);
/// assert_eq!(config.max_txs_per_batch, 4_000);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolDosConfig {
    /// Maximum number of *pending* txs per sender allowed in mempool.
    ///
    /// A sender exceeding this limit will have their new transactions rejected
    /// until existing transactions are committed or evicted.
    ///
    /// Set to 0 to disable this limit (not recommended for production).
    ///
    /// Recommended values:
    /// - DevNet: 10,000 (very loose)
    /// - TestNet Beta: 2,000 (moderate)
    /// - MainNet: 1,000 (conservative)
    pub max_pending_per_sender: u32,

    /// Maximum total pending bytes per sender.
    ///
    /// A sender exceeding this limit will have their new transactions rejected
    /// until existing transactions are committed or evicted.
    ///
    /// Set to 0 to disable this limit (not recommended for production).
    ///
    /// Recommended values:
    /// - DevNet: 64 MiB
    /// - TestNet Beta: 16 MiB
    /// - MainNet: 8 MiB
    pub max_pending_bytes_per_sender: u64,

    /// Maximum transactions per DAG batch.
    ///
    /// Batches with more transactions than this limit will be rejected
    /// or truncated at batch construction time.
    ///
    /// Set to 0 to disable this limit (not recommended for production).
    ///
    /// Recommended values:
    /// - DevNet: 10,000
    /// - TestNet Beta: 5,000
    /// - MainNet: 4,000
    pub max_txs_per_batch: u32,

    /// Maximum total serialized bytes per DAG batch.
    ///
    /// Batches exceeding this byte limit will be rejected or truncated
    /// at batch construction time.
    ///
    /// Set to 0 to disable this limit (not recommended for production).
    ///
    /// Recommended values:
    /// - DevNet: 4 MiB
    /// - TestNet Beta: 2 MiB
    /// - MainNet: 2 MiB
    pub max_batch_bytes: u64,
}

impl Default for MempoolDosConfig {
    fn default() -> Self {
        // Default to DevNet-style loose limits
        Self::devnet_default()
    }
}

impl MempoolDosConfig {
    /// Create a disabled configuration (all limits at maximum).
    ///
    /// Use only for development/debugging. Not recommended for production.
    pub fn disabled() -> Self {
        Self {
            max_pending_per_sender: u32::MAX,
            max_pending_bytes_per_sender: u64::MAX,
            max_txs_per_batch: u32::MAX,
            max_batch_bytes: u64::MAX,
        }
    }

    /// Create a DevNet default configuration.
    ///
    /// Very loose limits to avoid interfering with debugging:
    /// - max_pending_per_sender: 10,000
    /// - max_pending_bytes_per_sender: 64 MiB
    /// - max_txs_per_batch: 10,000
    /// - max_batch_bytes: 4 MiB
    pub fn devnet_default() -> Self {
        Self {
            max_pending_per_sender: 10_000,
            max_pending_bytes_per_sender: 64 * 1024 * 1024, // 64 MiB
            max_txs_per_batch: 10_000,
            max_batch_bytes: 4 * 1024 * 1024, // 4 MiB
        }
    }

    /// Create a TestNet Beta default configuration.
    ///
    /// Moderate protection for exercising limits in tests:
    /// - max_pending_per_sender: 2,000
    /// - max_pending_bytes_per_sender: 16 MiB
    /// - max_txs_per_batch: 5,000
    /// - max_batch_bytes: 2 MiB
    pub fn testnet_beta_default() -> Self {
        Self {
            max_pending_per_sender: 2_000,
            max_pending_bytes_per_sender: 16 * 1024 * 1024, // 16 MiB
            max_txs_per_batch: 5_000,
            max_batch_bytes: 2 * 1024 * 1024, // 2 MiB
        }
    }

    /// Create a MainNet v0 default configuration.
    ///
    /// Tighter defaults for production (conservative; can refine post-benchmark):
    /// - max_pending_per_sender: 1,000
    /// - max_pending_bytes_per_sender: 8 MiB
    /// - max_txs_per_batch: 4,000
    /// - max_batch_bytes: 2 MiB
    pub fn mainnet_default() -> Self {
        Self {
            max_pending_per_sender: 1_000,
            max_pending_bytes_per_sender: 8 * 1024 * 1024, // 8 MiB
            max_txs_per_batch: 4_000,
            max_batch_bytes: 2 * 1024 * 1024, // 2 MiB
        }
    }

    /// Check if any limits are enabled.
    ///
    /// Returns `true` if at least one limit is not set to MAX.
    pub fn is_enabled(&self) -> bool {
        self.max_pending_per_sender < u32::MAX
            || self.max_pending_bytes_per_sender < u64::MAX
            || self.max_txs_per_batch < u32::MAX
            || self.max_batch_bytes < u64::MAX
    }

    /// Check if per-sender limits are enabled.
    pub fn sender_limits_enabled(&self) -> bool {
        self.max_pending_per_sender < u32::MAX || self.max_pending_bytes_per_sender < u64::MAX
    }

    /// Check if batch limits are enabled.
    pub fn batch_limits_enabled(&self) -> bool {
        self.max_txs_per_batch < u32::MAX || self.max_batch_bytes < u64::MAX
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - All limits must be > 0
    /// - max_pending_per_sender must be reasonable (< 100,000)
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if self.max_pending_per_sender == 0 {
            return Err("max_pending_per_sender must be > 0".to_string());
        }
        if self.max_pending_bytes_per_sender == 0 {
            return Err("max_pending_bytes_per_sender must be > 0".to_string());
        }
        if self.max_txs_per_batch == 0 {
            return Err("max_txs_per_batch must be > 0".to_string());
        }
        if self.max_batch_bytes == 0 {
            return Err("max_batch_bytes must be > 0".to_string());
        }
        // Sanity checks to prevent effectively disabled limits on MainNet
        if self.max_pending_per_sender > 100_000 {
            return Err(format!(
                "max_pending_per_sender {} is too high for MainNet (max 100,000)",
                self.max_pending_per_sender
            ));
        }
        Ok(())
    }
}

// ============================================================================
// T219: Mempool Eviction Rate Limiting Configuration
// ============================================================================

/// Mode for mempool eviction rate limiting (T219).
///
/// Controls how the mempool handles eviction rate limiting:
/// - **Off**: No limit; record metrics but still evict normally
/// - **Warn**: Log warnings when limit would be exceeded but still evict
/// - **Enforce**: Reject new transactions instead of exceeding eviction rate
///
/// # Environments
///
/// - **DevNet v0**: `Off` (no rate limiting, debugging-friendly)
/// - **TestNet Alpha**: `Warn` (observe limits but don't enforce)
/// - **TestNet Beta**: `Enforce` (test enforcement behavior)
/// - **MainNet v0**: `Enforce` (required for production)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EvictionRateMode {
    /// No rate limiting. Evictions proceed normally.
    /// Metrics are still recorded for observability.
    #[default]
    Off,
    /// Log warnings when eviction rate exceeds limit.
    /// Evictions still proceed. Useful for observability.
    Warn,
    /// Enforce eviction rate limit.
    /// New transactions are rejected instead of exceeding the limit.
    Enforce,
}

impl std::fmt::Display for EvictionRateMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvictionRateMode::Off => write!(f, "off"),
            EvictionRateMode::Warn => write!(f, "warn"),
            EvictionRateMode::Enforce => write!(f, "enforce"),
        }
    }
}

/// Parse an eviction rate mode from a string.
///
/// Valid values: "off" (or "disabled"), "warn" (or "warning"), "enforce" (or "enforced")
///
/// Returns `None` for unrecognized values.
pub fn parse_eviction_rate_mode(s: &str) -> Option<EvictionRateMode> {
    match s.to_lowercase().as_str() {
        "off" | "disabled" => Some(EvictionRateMode::Off),
        "warn" | "warning" => Some(EvictionRateMode::Warn),
        "enforce" | "enforced" => Some(EvictionRateMode::Enforce),
        _ => None,
    }
}

/// Valid eviction rate mode strings for documentation and error messages.
pub const VALID_EVICTION_RATE_MODES: &[&str] = &["off", "warn", "enforce"];

/// Configuration for DAG mempool eviction rate limiting (T219).
///
/// Controls the rate at which transactions can be evicted from the mempool
/// to prevent excessive churn under adversarial conditions.
///
/// This sits on top of existing protections:
/// - Fee-priority mempool (T169)
/// - Per-sender quotas and batch caps (T218)
///
/// # Environments
///
/// - **DevNet v0**: `mode = Off`, loose limits (debugging-friendly)
/// - **TestNet Alpha**: `mode = Warn`, moderate limits (observability)
/// - **TestNet Beta**: `mode = Enforce`, tighter limits (testing enforcement)
/// - **MainNet v0**: `mode = Enforce`, conservative limits (production)
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::MempoolEvictionConfig;
///
/// // MainNet configuration
/// let config = MempoolEvictionConfig::mainnet_default();
/// assert_eq!(config.max_evictions_per_interval, 1_000);
/// assert_eq!(config.interval_secs, 10);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolEvictionConfig {
    /// Eviction rate mode (Off/Warn/Enforce).
    ///
    /// - Off: No rate limiting (DevNet default)
    /// - Warn: Log warnings but still evict (TestNet Alpha)
    /// - Enforce: Reject new txs instead of exceeding limit (MainNet required)
    pub mode: EvictionRateMode,

    /// Maximum evictions allowed per interval (across all senders).
    ///
    /// When the eviction count reaches this limit within the interval,
    /// behavior depends on `mode`:
    /// - Off: Continue evicting, record metric
    /// - Warn: Continue evicting, log warning
    /// - Enforce: Reject incoming tx instead of evicting
    ///
    /// Recommended values:
    /// - DevNet: 10,000 (very loose)
    /// - TestNet Alpha: 5,000 (moderate)
    /// - TestNet Beta: 2,000 (tighter)
    /// - MainNet: 1,000 (conservative)
    pub max_evictions_per_interval: u32,

    /// Length of the measurement interval in seconds.
    ///
    /// The eviction counter is reset when the interval elapses.
    ///
    /// Recommended value: 10 seconds for all environments.
    pub interval_secs: u32,
}

impl Default for MempoolEvictionConfig {
    fn default() -> Self {
        // Default to DevNet-style loose limits
        Self::devnet_default()
    }
}

impl MempoolEvictionConfig {
    /// Create a disabled configuration (no rate limiting).
    ///
    /// Use only for development/debugging. Not recommended for production.
    pub fn disabled() -> Self {
        Self {
            mode: EvictionRateMode::Off,
            max_evictions_per_interval: u32::MAX,
            interval_secs: 10,
        }
    }

    /// Create a DevNet default configuration.
    ///
    /// Very loose limits to avoid interfering with debugging:
    /// - mode: Off
    /// - max_evictions_per_interval: 10,000
    /// - interval_secs: 10
    pub fn devnet_default() -> Self {
        Self {
            mode: EvictionRateMode::Off,
            max_evictions_per_interval: 10_000,
            interval_secs: 10,
        }
    }

    /// Create a TestNet Alpha default configuration.
    ///
    /// Warn mode for observability without enforcement:
    /// - mode: Warn
    /// - max_evictions_per_interval: 5,000
    /// - interval_secs: 10
    pub fn testnet_alpha_default() -> Self {
        Self {
            mode: EvictionRateMode::Warn,
            max_evictions_per_interval: 5_000,
            interval_secs: 10,
        }
    }

    /// Create a TestNet Beta default configuration.
    ///
    /// Enforce mode for testing enforcement behavior:
    /// - mode: Enforce
    /// - max_evictions_per_interval: 2,000
    /// - interval_secs: 10
    pub fn testnet_beta_default() -> Self {
        Self {
            mode: EvictionRateMode::Enforce,
            max_evictions_per_interval: 2_000,
            interval_secs: 10,
        }
    }

    /// Create a MainNet v0 default configuration.
    ///
    /// Conservative limits for production:
    /// - mode: Enforce (required)
    /// - max_evictions_per_interval: 1,000
    /// - interval_secs: 10
    pub fn mainnet_default() -> Self {
        Self {
            mode: EvictionRateMode::Enforce,
            max_evictions_per_interval: 1_000,
            interval_secs: 10,
        }
    }

    /// Check if rate limiting is enabled.
    ///
    /// Returns `true` if mode is not Off.
    pub fn is_enabled(&self) -> bool {
        self.mode != EvictionRateMode::Off
    }

    /// Check if enforcement is enabled.
    ///
    /// Returns `true` if mode is Enforce.
    pub fn is_enforcing(&self) -> bool {
        self.mode == EvictionRateMode::Enforce
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - mode must be Enforce
    /// - max_evictions_per_interval must be > 0
    /// - interval_secs must be >= 1
    /// - max_evictions_per_interval must be reasonable (< 1,000,000)
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if self.mode != EvictionRateMode::Enforce {
            return Err(format!(
                "eviction mode must be 'enforce' for MainNet but is '{}'",
                self.mode
            ));
        }
        if self.max_evictions_per_interval == 0 {
            return Err("max_evictions_per_interval must be > 0".to_string());
        }
        if self.interval_secs < 1 {
            return Err("interval_secs must be >= 1".to_string());
        }
        // Sanity check to prevent effectively disabled limits
        if self.max_evictions_per_interval > 1_000_000 {
            return Err(format!(
                "max_evictions_per_interval {} is too high for MainNet (max 1,000,000)",
                self.max_evictions_per_interval
            ));
        }
        Ok(())
    }
}

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
// T226: P2P Discovery Configuration
// ============================================================================

/// Configuration for dynamic peer discovery (T226).
///
/// Controls how the node discovers and maintains connections to peers
/// beyond static bootstrap peers. Discovery is essential for MainNet
/// to ensure a healthy, diverse peer set.
///
/// # Environments
///
/// - **DevNet v0**: Enabled with fast intervals (10s) for testing
/// - **TestNet Alpha/Beta**: Enabled with standard intervals (30s)
/// - **MainNet v0**: **Required** - validation rejects `enabled = false`
///
/// # Discovery Behavior
///
/// When enabled, the discovery manager:
/// 1. Periodically asks connected peers for their known peers (gossip-style)
/// 2. Maintains an in-memory peer store of candidates
/// 3. Picks random candidates to fill outbound slots up to `outbound_target`
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::P2pDiscoveryConfig;
///
/// // MainNet configuration
/// let config = P2pDiscoveryConfig::mainnet_default();
/// assert!(config.enabled);
/// assert_eq!(config.outbound_target, 8);
/// assert_eq!(config.max_known_peers, 300);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pDiscoveryConfig {
    /// Whether dynamic peer discovery is enabled.
    ///
    /// When `false`, the node only connects to static/bootstrap peers.
    /// MainNet validators **must** have this set to `true`.
    pub enabled: bool,

    /// Interval between discovery exchanges (seconds).
    ///
    /// Controls how often the node exchanges peer lists with connected peers
    /// and attempts new outbound connections to fill the peer set.
    ///
    /// Recommended values:
    /// - DevNet: 10 seconds (fast discovery for testing)
    /// - TestNet Alpha/Beta: 30 seconds
    /// - MainNet: 30 seconds
    pub interval_secs: u32,

    /// Maximum number of known peers to track.
    ///
    /// Enforces a cap on memory usage from peer discovery. Excess peers
    /// are evicted based on age and liveness score.
    ///
    /// Recommended values:
    /// - DevNet: 200
    /// - TestNet Alpha/Beta: 200
    /// - MainNet: 300
    pub max_known_peers: u32,

    /// Target number of outbound peer connections.
    ///
    /// The discovery manager attempts to maintain at least this many
    /// outbound connections. When below target, it dials candidates from
    /// the peer store.
    ///
    /// MainNet requires at least 4 outbound peers for network resilience.
    ///
    /// Recommended values:
    /// - DevNet: 4
    /// - TestNet Alpha/Beta: 8
    /// - MainNet: 8
    pub outbound_target: u32,
}

impl Default for P2pDiscoveryConfig {
    fn default() -> Self {
        Self::devnet_default()
    }
}

impl P2pDiscoveryConfig {
    /// Create a disabled discovery configuration.
    ///
    /// Only for use in single-node testing. Not allowed on MainNet.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            interval_secs: 30,
            max_known_peers: 200,
            outbound_target: 8,
        }
    }

    /// Create a DevNet discovery configuration (T226).
    ///
    /// - enabled: true
    /// - interval_secs: 10 (fast discovery for testing)
    /// - max_known_peers: 200
    /// - outbound_target: 4
    pub fn devnet_default() -> Self {
        Self {
            enabled: true,
            interval_secs: 10,
            max_known_peers: 200,
            outbound_target: 4,
        }
    }

    /// Create a TestNet Alpha configuration (T226).
    ///
    /// - enabled: true
    /// - interval_secs: 30
    /// - max_known_peers: 200
    /// - outbound_target: 8
    pub fn testnet_alpha_default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            max_known_peers: 200,
            outbound_target: 8,
        }
    }

    /// Create a TestNet Beta configuration (T226).
    ///
    /// Same as TestNet Alpha:
    /// - enabled: true
    /// - interval_secs: 30
    /// - max_known_peers: 200
    /// - outbound_target: 8
    pub fn testnet_beta_default() -> Self {
        Self::testnet_alpha_default()
    }

    /// Create a MainNet discovery configuration (T226).
    ///
    /// - enabled: true (required)
    /// - interval_secs: 30
    /// - max_known_peers: 300 (higher for MainNet)
    /// - outbound_target: 8
    pub fn mainnet_default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            max_known_peers: 300,
            outbound_target: 8,
        }
    }

    /// Check if discovery is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - enabled must be true
    /// - outbound_target must be >= 4
    /// - max_known_peers must be >= outbound_target
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if !self.enabled {
            return Err("discovery must be enabled for MainNet".to_string());
        }
        if self.outbound_target < 4 {
            return Err(format!(
                "outbound_target must be >= 4 for MainNet but is {}",
                self.outbound_target
            ));
        }
        if self.max_known_peers < self.outbound_target {
            return Err(format!(
                "max_known_peers ({}) must be >= outbound_target ({}) for MainNet",
                self.max_known_peers, self.outbound_target
            ));
        }
        Ok(())
    }
}

// ============================================================================
// T226: P2P Liveness Configuration
// ============================================================================

/// Configuration for peer liveness scoring (T226).
///
/// Controls periodic heartbeat probes to connected peers and scoring
/// behavior. Peers that fail heartbeats are scored down and eventually
/// evicted, maintaining a healthy peer set.
///
/// # Liveness Scoring
///
/// Each peer has a score from 0-100:
/// - Initial score: 80
/// - Successful heartbeat response: +5 (capped at 100)
/// - Missed heartbeat: -15
/// - Score below minimum threshold: peer is evicted
///
/// # Environments
///
/// - **DevNet v0**: Fast heartbeats (10s interval, 5s timeout, 5 failures)
/// - **TestNet Alpha/Beta**: Standard (15s interval, 10s timeout, 4 failures)
/// - **MainNet v0**: Conservative (15s interval, 10s timeout, 3 failures)
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::P2pLivenessConfig;
///
/// // MainNet configuration
/// let config = P2pLivenessConfig::mainnet_default();
/// assert_eq!(config.heartbeat_interval_secs, 15);
/// assert_eq!(config.heartbeat_timeout_secs, 10);
/// assert_eq!(config.max_heartbeat_failures, 3);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pLivenessConfig {
    /// Interval between heartbeat probes (seconds).
    ///
    /// Controls how often the node sends Ping messages to connected peers.
    /// Must be > 0 for MainNet.
    ///
    /// Recommended values:
    /// - DevNet: 10 seconds
    /// - TestNet Alpha/Beta: 15 seconds
    /// - MainNet: 15 seconds
    pub heartbeat_interval_secs: u32,

    /// Timeout for heartbeat responses (seconds).
    ///
    /// If a peer doesn't respond to a Ping within this time,
    /// the heartbeat is considered missed.
    ///
    /// Should be less than `heartbeat_interval_secs`.
    ///
    /// Recommended values:
    /// - DevNet: 5 seconds
    /// - TestNet Alpha/Beta: 10 seconds
    /// - MainNet: 10 seconds
    pub heartbeat_timeout_secs: u32,

    /// Maximum consecutive heartbeat failures before eviction.
    ///
    /// When a peer misses this many consecutive heartbeats,
    /// it is evicted and marked as unhealthy.
    /// Must be > 0 for MainNet.
    ///
    /// Recommended values:
    /// - DevNet: 5
    /// - TestNet Alpha/Beta: 4
    /// - MainNet: 3 (stricter for production)
    pub max_heartbeat_failures: u32,
}

impl Default for P2pLivenessConfig {
    fn default() -> Self {
        Self::devnet_default()
    }
}

impl P2pLivenessConfig {
    /// Create a disabled/permissive liveness configuration.
    ///
    /// Very long intervals and high failure threshold.
    /// Only for use in testing. Not recommended for production.
    pub fn disabled() -> Self {
        Self {
            heartbeat_interval_secs: 3600, // 1 hour
            heartbeat_timeout_secs: 1800,  // 30 minutes
            max_heartbeat_failures: 100,   // Effectively disabled
        }
    }

    /// Create a DevNet liveness configuration (T226).
    ///
    /// Fast heartbeats for quick failure detection in dev:
    /// - heartbeat_interval_secs: 10
    /// - heartbeat_timeout_secs: 5
    /// - max_heartbeat_failures: 5
    pub fn devnet_default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            heartbeat_timeout_secs: 5,
            max_heartbeat_failures: 5,
        }
    }

    /// Create a TestNet Alpha liveness configuration (T226).
    ///
    /// - heartbeat_interval_secs: 15
    /// - heartbeat_timeout_secs: 10
    /// - max_heartbeat_failures: 4
    pub fn testnet_alpha_default() -> Self {
        Self {
            heartbeat_interval_secs: 15,
            heartbeat_timeout_secs: 10,
            max_heartbeat_failures: 4,
        }
    }

    /// Create a TestNet Beta liveness configuration (T226).
    ///
    /// Same as TestNet Alpha:
    /// - heartbeat_interval_secs: 15
    /// - heartbeat_timeout_secs: 10
    /// - max_heartbeat_failures: 4
    pub fn testnet_beta_default() -> Self {
        Self::testnet_alpha_default()
    }

    /// Create a MainNet liveness configuration (T226).
    ///
    /// Conservative settings for production:
    /// - heartbeat_interval_secs: 15
    /// - heartbeat_timeout_secs: 10
    /// - max_heartbeat_failures: 3 (stricter than testnet)
    pub fn mainnet_default() -> Self {
        Self {
            heartbeat_interval_secs: 15,
            heartbeat_timeout_secs: 10,
            max_heartbeat_failures: 3,
        }
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - heartbeat_interval_secs must be > 0
    /// - max_heartbeat_failures must be > 0
    /// - heartbeat_timeout_secs should be < heartbeat_interval_secs (warning only)
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if self.heartbeat_interval_secs == 0 {
            return Err("heartbeat_interval_secs must be > 0 for MainNet".to_string());
        }
        if self.max_heartbeat_failures == 0 {
            return Err("max_heartbeat_failures must be > 0 for MainNet".to_string());
        }
        // Timeout should be less than interval for sensible behavior
        if self.heartbeat_timeout_secs >= self.heartbeat_interval_secs {
            eprintln!(
                "[T226] Warning: heartbeat_timeout_secs ({}) >= heartbeat_interval_secs ({}); \
                 this may cause unnecessary false positives",
                self.heartbeat_timeout_secs, self.heartbeat_interval_secs
            );
        }
        Ok(())
    }
}

// ============================================================================
// T231: P2P Anti-Eclipse Configuration
// ============================================================================

/// Configuration for P2P anti-eclipse constraints (T231).
///
/// Controls additional diversity and outbound peer requirements beyond the
/// basic IP-prefix diversity provided by `NetworkTransportConfig`. This config
/// adds MainNet-grade protection against eclipse attacks by enforcing:
///
/// - Maximum peers from the same IPv4 /24 prefix
/// - Minimum outbound peers to maintain network connectivity
/// - Minimum ASN diversity for outbound connections
///
/// # Environments
///
/// - **DevNet v0**: Loose limits (`enforce=false`), for easy local testing
/// - **TestNet Alpha/Beta**: Moderate limits (`enforce=false`), for observability
/// - **MainNet v0**: Strict limits (`enforce=true`), required for production
///
/// # Integration
///
/// The anti-eclipse configuration is checked alongside the existing
/// `DiversityState` in the P2P layer. When `enforce=true`, connections
/// that would violate these limits are rejected.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::P2pAntiEclipseConfig;
///
/// // MainNet configuration
/// let config = P2pAntiEclipseConfig::mainnet_default();
/// assert!(config.enforce);
/// assert_eq!(config.max_peers_per_ipv4_prefix, 8);
/// assert_eq!(config.min_outbound_peers, 8);
/// assert_eq!(config.min_asn_diversity, 2);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pAntiEclipseConfig {
    /// Maximum number of peers allowed from the same IPv4 /24 prefix.
    ///
    /// This limits connections from peers in the same network segment to
    /// prevent a single ISP or network operator from eclipsing the node.
    ///
    /// Recommended values:
    /// - DevNet: 64 (permissive for local testing)
    /// - TestNet Alpha/Beta: 16 (moderate)
    /// - MainNet: 8 (strict for production)
    pub max_peers_per_ipv4_prefix: u32,

    /// Minimum number of outbound peer connections to maintain.
    ///
    /// The node will attempt to establish at least this many outbound
    /// connections to ensure network connectivity isn't dependent solely
    /// on inbound connections (which could be controlled by an attacker).
    ///
    /// Recommended values:
    /// - DevNet: 4 (minimum viable)
    /// - TestNet Alpha/Beta: 6 (moderate)
    /// - MainNet: 8 (robust connectivity)
    pub min_outbound_peers: u32,

    /// Minimum number of distinct Autonomous System Numbers (ASNs) for outbound peers.
    ///
    /// This ensures outbound connections are spread across different network
    /// operators, making it harder for a single entity to eclipse the node.
    ///
    /// Recommended values:
    /// - DevNet: 1 (disabled effectively)
    /// - TestNet Alpha/Beta: 2 (minimal diversity)
    /// - MainNet: 2 (required diversity)
    pub min_asn_diversity: u32,

    /// Whether to enforce anti-eclipse constraints.
    ///
    /// When `false`, violations are logged/metriced but connections are allowed.
    /// When `true`, connections that violate limits are rejected.
    ///
    /// - DevNet: `false` (warning only)
    /// - TestNet Alpha/Beta: `false` (warning only)
    /// - MainNet: `true` (required for validators)
    pub enforce: bool,
}

impl Default for P2pAntiEclipseConfig {
    fn default() -> Self {
        Self::devnet_default()
    }
}

impl P2pAntiEclipseConfig {
    /// Create a disabled/permissive anti-eclipse configuration.
    ///
    /// Only for use in testing where anti-eclipse is not needed.
    pub fn disabled() -> Self {
        Self {
            max_peers_per_ipv4_prefix: 128,
            min_outbound_peers: 1,
            min_asn_diversity: 1,
            enforce: false,
        }
    }

    /// Create a DevNet anti-eclipse configuration (T231).
    ///
    /// - max_peers_per_ipv4_prefix: 64 (permissive for local testing)
    /// - min_outbound_peers: 4
    /// - min_asn_diversity: 1 (effectively disabled)
    /// - enforce: false
    pub fn devnet_default() -> Self {
        Self {
            max_peers_per_ipv4_prefix: 64,
            min_outbound_peers: 4,
            min_asn_diversity: 1,
            enforce: false,
        }
    }

    /// Create a TestNet Alpha anti-eclipse configuration (T231).
    ///
    /// - max_peers_per_ipv4_prefix: 16
    /// - min_outbound_peers: 6
    /// - min_asn_diversity: 2
    /// - enforce: false
    pub fn testnet_alpha_default() -> Self {
        Self {
            max_peers_per_ipv4_prefix: 16,
            min_outbound_peers: 6,
            min_asn_diversity: 2,
            enforce: false,
        }
    }

    /// Create a TestNet Beta anti-eclipse configuration (T231).
    ///
    /// Same as TestNet Alpha:
    /// - max_peers_per_ipv4_prefix: 16
    /// - min_outbound_peers: 6
    /// - min_asn_diversity: 2
    /// - enforce: false
    pub fn testnet_beta_default() -> Self {
        Self::testnet_alpha_default()
    }

    /// Create a MainNet anti-eclipse configuration (T231).
    ///
    /// Strict settings for production:
    /// - max_peers_per_ipv4_prefix: 8
    /// - min_outbound_peers: 8
    /// - min_asn_diversity: 2
    /// - enforce: true (required for MainNet)
    pub fn mainnet_default() -> Self {
        Self {
            max_peers_per_ipv4_prefix: 8,
            min_outbound_peers: 8,
            min_asn_diversity: 2,
            enforce: true,
        }
    }

    /// Check if enforcement is enabled.
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - enforce must be true
    /// - max_peers_per_ipv4_prefix must be > 0
    /// - min_outbound_peers must be >= 4
    /// - min_asn_diversity must be >= 2
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if !self.enforce {
            return Err("enforce must be true for MainNet".to_string());
        }
        if self.max_peers_per_ipv4_prefix == 0 {
            return Err("max_peers_per_ipv4_prefix must be > 0 for MainNet".to_string());
        }
        if self.min_outbound_peers < 4 {
            return Err(format!(
                "min_outbound_peers must be >= 4 for MainNet but is {}",
                self.min_outbound_peers
            ));
        }
        if self.min_asn_diversity < 2 {
            return Err(format!(
                "min_asn_diversity must be >= 2 for MainNet but is {}",
                self.min_asn_diversity
            ));
        }
        Ok(())
    }
}

// ============================================================================
// T229: Slashing Configuration
// ============================================================================

/// Slashing mode for evidence processing and penalty enforcement (T229).
///
/// Determines how the slashing engine processes evidence and whether
/// penalties (stake burning, jailing) are applied.
///
/// # Environments
///
/// - **DevNet v0**: `EnforceCritical` (see actual penalties for testing)
/// - **TestNet Alpha**: `RecordOnly` (evidence + metrics only)
/// - **TestNet Beta**: `RecordOnly` by default (opt-in to EnforceCritical)
/// - **MainNet v0**: `RecordOnly` by default (governance can flip to EnforceCritical)
///
/// # Slashing Modes
///
/// - `Off`: No evidence processing at all. Only for dev tools.
/// - `RecordOnly`: Record evidence + emit metrics, but no stake changes.
/// - `EnforceCritical`: Apply penalties for O1 (double-sign) and O2 (invalid proposer sig).
/// - `EnforceAll`: Apply penalties for all offenses (O1–O5). Reserved for future use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SlashingMode {
    /// No evidence processing at all. Only for DevNet/dev tools.
    ///
    /// **Not allowed for MainNet** – `validate_mainnet_invariants()` will reject this.
    Off,

    /// Record evidence + metrics only. No stake changes, no jailing.
    ///
    /// Allowed for TestNet (with warning) and DevNet only.
    ///
    /// **Not allowed for MainNet (M4)** – `validate_mainnet_invariants()` will reject this.
    /// MainNet requires enforcement to deter Byzantine behavior.
    #[default]
    RecordOnly,

    /// Enforce penalties for critical offenses only (O1, O2).
    ///
    /// - O1: Classical double-signing → slash + jail
    /// - O2: Invalid consensus signature as proposer → slash + jail
    ///
    /// O3/O4/O5 remain in evidence-only mode.
    ///
    /// **Required for MainNet (M4)** – This is the minimum enforcement level.
    EnforceCritical,

    /// Enforce penalties for all offenses (O1–O5).
    ///
    /// Reserved for future use when O3/O4/O5 penalties are finalized.
    /// Not yet enabled in any environment.
    ///
    /// **Allowed for MainNet** – Strictest enforcement level.
    EnforceAll,
}

impl std::fmt::Display for SlashingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingMode::Off => write!(f, "off"),
            SlashingMode::RecordOnly => write!(f, "record_only"),
            SlashingMode::EnforceCritical => write!(f, "enforce_critical"),
            SlashingMode::EnforceAll => write!(f, "enforce_all"),
        }
    }
}

/// Parse a slashing mode from a string.
///
/// Valid values: "off", "record_only", "enforce_critical", "enforce_all"
///
/// Returns `None` for unrecognized values.
pub fn parse_slashing_mode(s: &str) -> Option<SlashingMode> {
    match s.to_lowercase().as_str() {
        "off" | "disabled" => Some(SlashingMode::Off),
        "record_only" | "record" | "recordonly" => Some(SlashingMode::RecordOnly),
        "enforce_critical" | "enforcecritical" | "critical" => Some(SlashingMode::EnforceCritical),
        "enforce_all" | "enforceall" | "all" => Some(SlashingMode::EnforceAll),
        _ => None,
    }
}

/// Valid slashing mode strings for documentation and error messages.
pub const VALID_SLASHING_MODES: &[&str] =
    &["off", "record_only", "enforce_critical", "enforce_all"];

/// Configuration for the slashing penalty engine (T229).
///
/// Controls how the node processes slashing evidence and applies penalties.
/// Penalty parameters are expressed in basis points (1 bps = 0.01%).
///
/// # T227 Offense Ranges (for reference)
///
/// | Offense | Severity | Slash Range |
/// |---------|----------|-------------|
/// | O1 | Critical | 5–10% (500–1000 bps) |
/// | O2 | High | 5% (500 bps) |
/// | O3a | Medium | 0–0.5% (0–50 bps) |
/// | O3b | Medium-High | 1–3% (100–300 bps) |
/// | O4 | High | 5–10% (500–1000 bps) |
/// | O5 | Medium-High | 1–5% (100–500 bps) |
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::{SlashingConfig, SlashingMode};
///
/// // DevNet configuration (EnforceCritical mode)
/// let config = SlashingConfig::devnet_default();
/// assert_eq!(config.mode, SlashingMode::EnforceCritical);
/// assert_eq!(config.slash_bps_o1_double_sign, 750); // 7.5%
///
/// // MainNet configuration (EnforceCritical mode, M4 requirement)
/// let mainnet = SlashingConfig::mainnet_default();
/// assert_eq!(mainnet.mode, SlashingMode::EnforceCritical);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingConfig {
    /// The slashing mode for this node.
    pub mode: SlashingMode,

    // ========================================================================
    // Slash Percentages (in basis points)
    // ========================================================================
    /// Slash percentage for O1 (double-signing) in basis points.
    ///
    /// T227 range: 500–1000 bps (5–10%).
    /// Default: 750 bps (7.5%).
    pub slash_bps_o1_double_sign: u16,

    /// Slash percentage for O2 (invalid proposer signature) in basis points.
    ///
    /// T227 range: 500 bps (5%).
    /// Validation allows 450-550 bps tolerance for operational flexibility.
    /// Default: 500 bps (5%).
    pub slash_bps_o2_invalid_proposer_sig: u16,

    // ========================================================================
    // Jailing Configuration
    // ========================================================================
    /// Whether to jail validator on O1 offense (double-signing).
    pub jail_on_o1: bool,

    /// Number of epochs to jail validator for O1 offense.
    ///
    /// Default: 10 epochs.
    pub jail_epochs_o1: u32,

    /// Whether to jail validator on O2 offense (invalid proposer sig).
    pub jail_on_o2: bool,

    /// Number of epochs to jail validator for O2 offense.
    ///
    /// Default: 5 epochs.
    pub jail_epochs_o2: u32,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self::devnet_default()
    }
}

impl SlashingConfig {
    /// Create a disabled slashing configuration.
    ///
    /// No evidence processing at all. Only for dev tools.
    pub fn disabled() -> Self {
        Self {
            mode: SlashingMode::Off,
            slash_bps_o1_double_sign: 750,
            slash_bps_o2_invalid_proposer_sig: 500,
            jail_on_o1: false,
            jail_epochs_o1: 0,
            jail_on_o2: false,
            jail_epochs_o2: 0,
        }
    }

    /// Create the DevNet default configuration (T229).
    ///
    /// - mode: EnforceCritical (so we can see actual penalties easily)
    /// - slash_bps_o1_double_sign: 750 (7.5%, midpoint of T227 range)
    /// - slash_bps_o2_invalid_proposer_sig: 500 (5%)
    /// - jail_on_o1: true, jail_epochs_o1: 10
    /// - jail_on_o2: true, jail_epochs_o2: 5
    pub fn devnet_default() -> Self {
        Self {
            mode: SlashingMode::EnforceCritical,
            slash_bps_o1_double_sign: 750, // 7.5% - midpoint of 5-10% range
            slash_bps_o2_invalid_proposer_sig: 500, // 5%
            jail_on_o1: true,
            jail_epochs_o1: 10,
            jail_on_o2: true,
            jail_epochs_o2: 5,
        }
    }

    /// Create the TestNet Alpha default configuration (T229).
    ///
    /// - mode: EnforceCritical (recommended per M4)
    /// - Same slash/jail parameters as DevNet
    ///
    /// **M4 Recommendation**: TestNet Alpha defaults to enforcement mode to
    /// validate penalty mechanics. RecordOnly is allowed with explicit opt-in.
    pub fn testnet_alpha_default() -> Self {
        Self {
            mode: SlashingMode::EnforceCritical,
            slash_bps_o1_double_sign: 750,
            slash_bps_o2_invalid_proposer_sig: 500,
            jail_on_o1: true,
            jail_epochs_o1: 10,
            jail_on_o2: true,
            jail_epochs_o2: 5,
        }
    }

    /// Create the TestNet Beta default configuration (T229, M4).
    ///
    /// - mode: EnforceCritical (recommended per M4)
    /// - Same slash/jail parameters as TestNet Alpha
    ///
    /// **M4 Recommendation**: TestNet Beta defaults to enforcement mode.
    /// RecordOnly is allowed with explicit opt-in (and logs a warning).
    pub fn testnet_beta_default() -> Self {
        Self::testnet_alpha_default()
    }

    /// Create the MainNet default configuration (T229, M4).
    ///
    /// - mode: EnforceCritical (required for MainNet per M4)
    /// - Slash parameters at T227-compliant values
    /// - Jail parameters enabled for critical offenses
    ///
    /// **M4 Requirement**: MainNet cannot run with slashing disabled (RecordOnly/Off).
    /// Validators must have enforcement enabled to deter Byzantine behavior.
    pub fn mainnet_default() -> Self {
        Self {
            mode: SlashingMode::EnforceCritical,
            slash_bps_o1_double_sign: 750, // 7.5% - conservative within T227 range
            slash_bps_o2_invalid_proposer_sig: 500, // 5%
            jail_on_o1: true,
            jail_epochs_o1: 10,
            jail_on_o2: true,
            jail_epochs_o2: 5,
        }
    }

    /// Check if slashing is enabled (not Off mode).
    pub fn is_enabled(&self) -> bool {
        self.mode != SlashingMode::Off
    }

    /// Check if penalty enforcement is enabled (EnforceCritical or EnforceAll).
    pub fn is_enforcing(&self) -> bool {
        matches!(
            self.mode,
            SlashingMode::EnforceCritical | SlashingMode::EnforceAll
        )
    }

    /// Check if O1/O2 penalties should be applied.
    pub fn should_enforce_critical(&self) -> bool {
        matches!(
            self.mode,
            SlashingMode::EnforceCritical | SlashingMode::EnforceAll
        )
    }

    /// Check if O3/O4/O5 penalties should be applied.
    ///
    /// Currently only true for EnforceAll mode (reserved for future use).
    pub fn should_enforce_all(&self) -> bool {
        self.mode == SlashingMode::EnforceAll
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements (M4):
    /// - mode must be EnforceCritical or EnforceAll (Off and RecordOnly are forbidden)
    /// - slash_bps_o1_double_sign must be in T227 range (500–1000 bps)
    /// - slash_bps_o2_invalid_proposer_sig must be ~500 bps (±50 tolerance)
    /// - jail_epochs must be > 0 and <= 1,000,000
    ///
    /// **M4 Security Requirement**: MainNet cannot run with slashing disabled.
    /// RecordOnly mode only logs evidence without applying penalties, which provides
    /// no economic deterrent for Byzantine behavior.
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        // M4: Mode must be enforcing (EnforceCritical or EnforceAll) for MainNet
        // Off and RecordOnly are forbidden to ensure economic security
        match self.mode {
            SlashingMode::Off => {
                return Err("slashing mode 'off' is forbidden for MainNet; \
                            use 'enforce_critical' or 'enforce_all'"
                    .to_string());
            }
            SlashingMode::RecordOnly => {
                return Err("slashing mode 'record_only' is forbidden for MainNet (M4); \
                            MainNet requires enforcement to deter Byzantine behavior; \
                            use 'enforce_critical' or 'enforce_all'"
                    .to_string());
            }
            SlashingMode::EnforceCritical | SlashingMode::EnforceAll => {
                // Valid modes for MainNet
            }
        }

        // Validate parameters (mode is guaranteed to be enforcing at this point)
        // O1 slash range: 500-1000 bps (5-10%)
        if self.slash_bps_o1_double_sign < 500 || self.slash_bps_o1_double_sign > 1000 {
            return Err(format!(
                "slash_bps_o1_double_sign ({}) must be in range 500-1000 for MainNet",
                self.slash_bps_o1_double_sign
            ));
        }

        // O2 slash: ~500 bps (5%), allow some tolerance
        if self.slash_bps_o2_invalid_proposer_sig < 450
            || self.slash_bps_o2_invalid_proposer_sig > 550
        {
            return Err(format!(
                "slash_bps_o2_invalid_proposer_sig ({}) must be in range 450-550 for MainNet",
                self.slash_bps_o2_invalid_proposer_sig
            ));
        }

        // Jail epochs must be reasonable if jailing is enabled
        if self.jail_on_o1 {
            if self.jail_epochs_o1 == 0 {
                return Err("jail_epochs_o1 must be > 0 when jail_on_o1 is enabled".to_string());
            }
            if self.jail_epochs_o1 > 1_000_000 {
                return Err(format!(
                    "jail_epochs_o1 ({}) exceeds maximum of 1,000,000",
                    self.jail_epochs_o1
                ));
            }
        }

        if self.jail_on_o2 {
            if self.jail_epochs_o2 == 0 {
                return Err("jail_epochs_o2 must be > 0 when jail_on_o2 is enabled".to_string());
            }
            if self.jail_epochs_o2 > 1_000_000 {
                return Err(format!(
                    "jail_epochs_o2 ({}) exceeds maximum of 1,000,000",
                    self.jail_epochs_o2
                ));
            }
        }

        Ok(())
    }

    /// Validate the configuration for TestNet and emit warnings if needed (M4).
    ///
    /// Returns `Ok(())` if valid. If RecordOnly mode is used, logs a warning
    /// but does not fail.
    ///
    /// TestNet requirements (M4):
    /// - mode must not be Off
    /// - EnforceCritical or EnforceAll is preferred
    /// - RecordOnly is allowed but generates a warning (explicitly opted-in for testing)
    /// - If enforcing, parameters are validated for correctness
    ///
    /// # Returns
    ///
    /// `Ok(true)` if using preferred mode (EnforceCritical/EnforceAll)
    /// `Ok(false)` if using RecordOnly (warning logged)
    /// `Err(String)` if Off mode or invalid parameters
    pub fn validate_for_testnet(&self) -> Result<bool, String> {
        match self.mode {
            SlashingMode::Off => {
                return Err("slashing mode 'off' is forbidden for TestNet; \
                            use 'enforce_critical' (recommended) or 'record_only' (for testing)"
                    .to_string());
            }
            SlashingMode::RecordOnly => {
                // Allowed but warn loudly
                eprintln!(
                    "[M4 WARNING] TestNet: slashing mode is 'record_only'. \
                     Enforcement is RECOMMENDED to validate penalty mechanics. \
                     Set --slashing-mode=enforce_critical for production-like behavior."
                );
                return Ok(false);
            }
            SlashingMode::EnforceCritical | SlashingMode::EnforceAll => {
                // Preferred modes for TestNet
            }
        }

        // Validate parameters if enforcing
        if self.is_enforcing() {
            // O1 slash range: 500-1000 bps (5-10%)
            if self.slash_bps_o1_double_sign < 500 || self.slash_bps_o1_double_sign > 1000 {
                return Err(format!(
                    "slash_bps_o1_double_sign ({}) must be in range 500-1000 for TestNet",
                    self.slash_bps_o1_double_sign
                ));
            }

            // O2 slash: ~500 bps (5%), allow some tolerance
            if self.slash_bps_o2_invalid_proposer_sig < 450
                || self.slash_bps_o2_invalid_proposer_sig > 550
            {
                return Err(format!(
                    "slash_bps_o2_invalid_proposer_sig ({}) must be in range 450-550 for TestNet",
                    self.slash_bps_o2_invalid_proposer_sig
                ));
            }
        }

        Ok(true)
    }

    /// Validate the configuration for DevNet (M4).
    ///
    /// DevNet has no restrictions on slashing mode (all modes allowed).
    /// This allows testing various slashing scenarios including Off and RecordOnly.
    ///
    /// Returns `Ok(())` always for DevNet.
    pub fn validate_for_devnet(&self) -> Result<(), String> {
        // DevNet allows all modes for testing flexibility
        Ok(())
    }
}

// ============================================================================
// M2: Validator Stake Configuration
// ============================================================================

/// Minimum stake required for validator registration in microQBIND.
///
/// All internal stake values are stored in microQBIND (1 QBIND = 1,000,000 microQBIND).
///
/// | Network | Minimum Stake (microQBIND) | Equivalent (QBIND) | Rationale |
/// |---------|----------------------------|--------------------| ----------|
/// | DevNet  | 1,000,000                  | 1 QBIND            | Low barrier for testing |
/// | TestNet | 10,000,000                 | 10 QBIND           | Moderate barrier for realistic testing |
/// | MainNet | 100,000,000,000            | 100,000 QBIND      | Economic security threshold |

/// Minimum validator stake for DevNet (1 QBIND = 1,000,000 microQBIND).
pub const MIN_VALIDATOR_STAKE_DEVNET: u64 = 1_000_000;

/// Minimum validator stake for TestNet (10 QBIND = 10,000,000 microQBIND).
pub const MIN_VALIDATOR_STAKE_TESTNET: u64 = 10_000_000;

/// Minimum validator stake for MainNet (100,000 QBIND = 100,000,000,000 microQBIND).
pub const MIN_VALIDATOR_STAKE_MAINNET: u64 = 100_000_000_000;

/// Configuration for validator stake requirements (M2).
///
/// Controls minimum stake enforcement at validator registration and epoch transitions.
/// Validators must have at least `min_validator_stake` to:
/// 1. Register as a validator
/// 2. Remain eligible for the validator set at epoch boundaries
///
/// # Environments
///
/// - **DevNet v0**: 1,000,000 microQBIND (1 QBIND) — low barrier for testing
/// - **TestNet Alpha/Beta**: 10,000,000 microQBIND (10 QBIND) — moderate barrier
/// - **MainNet v0**: 100,000,000,000 microQBIND (100,000 QBIND) — economic security
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::ValidatorStakeConfig;
///
/// // DevNet configuration
/// let config = ValidatorStakeConfig::devnet_default();
/// assert_eq!(config.min_validator_stake, 1_000_000);
///
/// // MainNet configuration
/// let mainnet = ValidatorStakeConfig::mainnet_default();
/// assert_eq!(mainnet.min_validator_stake, 100_000_000_000);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorStakeConfig {
    /// Minimum stake required for validator registration and eligibility (in microQBIND).
    ///
    /// Validators with stake below this threshold:
    /// - Cannot register as new validators
    /// - Are excluded from the validator set at epoch boundaries
    pub min_validator_stake: u64,

    /// Whether to fail-fast at startup if active validators are below threshold.
    ///
    /// - `true` (MainNet default): Fail startup if any active validator is below min
    /// - `false` (DevNet/TestNet): Exclude below-threshold validators but continue
    pub fail_fast_on_startup: bool,
}

impl Default for ValidatorStakeConfig {
    fn default() -> Self {
        Self::devnet_default()
    }
}

impl ValidatorStakeConfig {
    /// Create the DevNet default configuration (M2).
    ///
    /// - min_validator_stake: 1,000,000 microQBIND (1 QBIND)
    /// - fail_fast_on_startup: false (exclude below-threshold but continue)
    pub fn devnet_default() -> Self {
        Self {
            min_validator_stake: MIN_VALIDATOR_STAKE_DEVNET,
            fail_fast_on_startup: false,
        }
    }

    /// Create the TestNet Alpha/Beta default configuration (M2).
    ///
    /// - min_validator_stake: 10,000,000 microQBIND (10 QBIND)
    /// - fail_fast_on_startup: false (exclude below-threshold but continue)
    pub fn testnet_default() -> Self {
        Self {
            min_validator_stake: MIN_VALIDATOR_STAKE_TESTNET,
            fail_fast_on_startup: false,
        }
    }

    /// Create the MainNet default configuration (M2).
    ///
    /// - min_validator_stake: 100,000,000,000 microQBIND (100,000 QBIND)
    /// - fail_fast_on_startup: true (fail startup if any validator below min)
    pub fn mainnet_default() -> Self {
        Self {
            min_validator_stake: MIN_VALIDATOR_STAKE_MAINNET,
            fail_fast_on_startup: true,
        }
    }

    /// Check if a stake amount meets the minimum threshold.
    pub fn is_stake_sufficient(&self, stake: u64) -> bool {
        stake >= self.min_validator_stake
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - min_validator_stake must be at least MIN_VALIDATOR_STAKE_MAINNET
    /// - fail_fast_on_startup should be true
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if self.min_validator_stake < MIN_VALIDATOR_STAKE_MAINNET {
            return Err(format!(
                "min_validator_stake ({}) must be at least {} for MainNet",
                self.min_validator_stake, MIN_VALIDATOR_STAKE_MAINNET
            ));
        }
        if !self.fail_fast_on_startup {
            return Err("fail_fast_on_startup must be true for MainNet".to_string());
        }
        Ok(())
    }
}

// ============================================================================
// T232: Genesis Source Configuration
// ============================================================================

/// Source for genesis configuration (T232).
///
/// Determines where the genesis configuration is loaded from.
/// MainNet requires an external genesis file; DevNet/TestNet can use embedded genesis.
///
/// # Environments
///
/// - **DevNet v0**: `Embedded` (default) — uses built-in test genesis
/// - **TestNet Alpha/Beta**: `Embedded` (default) or `External` with file path
/// - **MainNet v0**: `External` (**required**) — must specify `genesis_path`
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::GenesisSourceConfig;
/// use std::path::PathBuf;
///
/// // DevNet: use embedded genesis
/// let devnet = GenesisSourceConfig::embedded();
///
/// // MainNet: require external genesis file
/// let mainnet = GenesisSourceConfig::external(
///     PathBuf::from("/etc/qbind/genesis.json")
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisSourceConfig {
    /// Whether to use an external genesis file.
    ///
    /// - `false` (default): Use embedded/default genesis (DevNet/TestNet)
    /// - `true`: Load genesis from external file (MainNet required)
    pub use_external: bool,

    /// Path to external genesis file.
    ///
    /// Required when `use_external = true`.
    /// The file must be a valid JSON file conforming to the GenesisConfig schema.
    ///
    /// Example: `/etc/qbind/genesis.json`
    pub genesis_path: Option<PathBuf>,
}

impl Default for GenesisSourceConfig {
    fn default() -> Self {
        Self::embedded()
    }
}

impl GenesisSourceConfig {
    /// Create an embedded genesis configuration (default).
    ///
    /// Uses built-in test genesis for DevNet and TestNet.
    /// Not valid for MainNet.
    pub fn embedded() -> Self {
        Self {
            use_external: false,
            genesis_path: None,
        }
    }

    /// Create an external genesis configuration.
    ///
    /// Loads genesis from the specified file path.
    /// Required for MainNet.
    pub fn external(genesis_path: PathBuf) -> Self {
        Self {
            use_external: true,
            genesis_path: Some(genesis_path),
        }
    }

    /// Create the DevNet default configuration.
    ///
    /// - Uses embedded genesis (no external file required)
    pub fn devnet_default() -> Self {
        Self::embedded()
    }

    /// Create the TestNet Alpha/Beta default configuration.
    ///
    /// - Uses embedded genesis by default
    /// - Operators can override with --genesis-path
    pub fn testnet_default() -> Self {
        Self::embedded()
    }

    /// Create the MainNet default configuration.
    ///
    /// - Requires external genesis file (must be set via --genesis-path)
    /// - Returns a config that will fail validation until path is set
    pub fn mainnet_default() -> Self {
        // MainNet requires external genesis, but path must be provided by operator
        // This will fail validate_for_mainnet() until a path is set
        Self {
            use_external: true,
            genesis_path: None,
        }
    }

    /// Check if the genesis source is configured.
    ///
    /// Returns true if:
    /// - Using embedded genesis, or
    /// - Using external genesis with a valid path
    pub fn is_configured(&self) -> bool {
        !self.use_external || self.genesis_path.is_some()
    }

    /// Validate that the configuration is suitable for MainNet.
    ///
    /// Returns `Ok(())` if valid, or an error message if invalid.
    ///
    /// MainNet requirements:
    /// - Must use external genesis file (`use_external = true`)
    /// - Must have a genesis path configured
    pub fn validate_for_mainnet(&self) -> Result<(), String> {
        if !self.use_external {
            return Err("MainNet requires external genesis file (--genesis-path)".to_string());
        }
        if self.genesis_path.is_none() {
            return Err("genesis_path must be set for MainNet".to_string());
        }
        Ok(())
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

    // ========================================================================
    // T205: Dynamic Discovery Configuration
    // ========================================================================
    /// Whether dynamic peer discovery is enabled (T205).
    ///
    /// When `true`, the node will exchange peer lists with connected peers
    /// and attempt to maintain a healthy peer set beyond static bootstrap peers.
    ///
    /// - DevNet: `false` (discovery disabled, uses static config only)
    /// - TestNet Alpha/Beta: `true` (enabled by default but not enforced)
    /// - MainNet: `true` (required; `validate_mainnet_invariants()` rejects `false`)
    pub discovery_enabled: bool,

    /// Interval in seconds between peer discovery exchanges (T205).
    ///
    /// Controls how often the node exchanges peer lists with connected peers
    /// and attempts new outbound connections to fill the peer set.
    ///
    /// Default: 30 seconds
    pub discovery_interval_secs: u64,

    /// Maximum number of known peers to track in the peer table (T205).
    ///
    /// Enforces a cap on memory usage from peer discovery. Excess peers
    /// are evicted based on age and liveness score.
    ///
    /// Default: 200
    pub max_known_peers: u32,

    /// Target number of outbound peer connections (T205).
    ///
    /// The discovery manager attempts to maintain at least this many
    /// outbound connections. When below target, it dials candidates from
    /// the peer table.
    ///
    /// - MainNet: 16 (default)
    /// - TestNet: 8 (default)
    pub target_outbound_peers: u32,

    // ========================================================================
    // T205: Liveness Configuration
    // ========================================================================
    /// Interval in seconds between liveness probes (T205).
    ///
    /// Controls how often the node sends Ping messages to connected peers
    /// to verify they are responsive.
    ///
    /// Default: 30 seconds
    pub liveness_probe_interval_secs: u64,

    /// Number of consecutive missed probes before marking peer unhealthy (T205).
    ///
    /// When a peer fails to respond to this many consecutive Pings,
    /// its liveness score is significantly decreased.
    ///
    /// Default: 3
    pub liveness_failure_threshold: u8,

    /// Minimum liveness score (0-100) before peer is disconnected (T205).
    ///
    /// Peers with scores below this threshold are evicted and marked
    /// as unhealthy for a cooling period.
    ///
    /// Default: 30
    pub liveness_min_score: u8,

    // ========================================================================
    // T206: Diversity Configuration (Anti-Eclipse)
    // ========================================================================
    /// Diversity enforcement mode for anti-eclipse constraints (T206).
    ///
    /// Controls how the P2P layer enforces IP-prefix diversity limits:
    /// - Off: No diversity checks (DevNet, TestNet Alpha default)
    /// - Warn: Log warnings but allow connections (TestNet Beta default)
    /// - Enforce: Reject connections that violate limits (MainNet required)
    ///
    /// MainNet profile requires `Enforce` mode.
    pub diversity_mode: crate::p2p_diversity::DiversityEnforcementMode,

    /// Maximum peers per IPv4 /24 prefix (T206).
    ///
    /// Limits the number of connections from the same /24 subnet.
    /// Helps prevent eclipse attacks from a single network range.
    ///
    /// Default: 2 (MainNet), 4 (TestNet Beta)
    pub max_peers_per_ipv4_prefix24: u16,

    /// Maximum peers per IPv4 /16 prefix (T206).
    ///
    /// Secondary cap limiting connections from the same /16 network.
    /// Provides broader protection against larger network allocations.
    ///
    /// Default: 8 (MainNet), 16 (TestNet Beta)
    pub max_peers_per_ipv4_prefix16: u16,

    /// Minimum number of distinct outbound diversity buckets (T206).
    ///
    /// Ensures outbound connections span multiple network ranges.
    /// Used for periodic health checks and dial blocking.
    ///
    /// Default: 4 (MainNet), 2 (TestNet Beta)
    pub min_outbound_diversity_buckets: u16,

    /// Maximum fraction of outbound peers in a single bucket (basis points) (T206).
    ///
    /// Prevents any single network range from dominating outbound connections.
    /// 2500 = 25%, 5000 = 50%, 10000 = 100%.
    ///
    /// Default: 2500 (25%, MainNet), 5000 (50%, TestNet Beta)
    pub max_single_bucket_fraction_bps: u16,
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
            // T205: Discovery defaults (disabled for DevNet/TestNet Alpha)
            discovery_enabled: false,
            discovery_interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 8, // TestNet default
            // T205: Liveness defaults
            liveness_probe_interval_secs: 30,
            liveness_failure_threshold: 3,
            liveness_min_score: 30,
            // T206: Diversity defaults (Off for DevNet/TestNet Alpha)
            diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Off,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500,
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
            // T205: Discovery enabled for TestNet Beta
            discovery_enabled: true,
            discovery_interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 8, // TestNet default
            // T205: Liveness defaults
            liveness_probe_interval_secs: 30,
            liveness_failure_threshold: 3,
            liveness_min_score: 30,
            // T206: Diversity in Warn mode with loose thresholds for TestNet Beta
            diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Warn,
            max_peers_per_ipv4_prefix24: 4,
            max_peers_per_ipv4_prefix16: 16,
            min_outbound_diversity_buckets: 2,
            max_single_bucket_fraction_bps: 5000, // 50%
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
            // T205: Discovery enabled and required for MainNet
            discovery_enabled: true,
            discovery_interval_secs: 30,
            max_known_peers: 200,
            target_outbound_peers: 16, // MainNet default
            // T205: Liveness defaults
            liveness_probe_interval_secs: 30,
            liveness_failure_threshold: 3,
            liveness_min_score: 30,
            // T206: Diversity in Enforce mode with strict thresholds for MainNet
            diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Enforce,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500, // 25%
        }
    }

    /// Check if the P2P overlay is enabled.
    pub fn is_p2p_enabled(&self) -> bool {
        self.enable_p2p
    }

    /// Check if dynamic peer discovery is enabled (T205).
    pub fn is_discovery_enabled(&self) -> bool {
        self.discovery_enabled
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

    // ========================================================================
    // T208: State Retention Configuration
    // ========================================================================
    /// State retention and pruning configuration (T208).
    ///
    /// Controls how the node manages historical state data to balance
    /// disk usage against history availability.
    ///
    /// - DevNet v0: `Disabled` (full history retained)
    /// - TestNet Alpha: `Disabled` (full history retained)
    /// - TestNet Beta: `Height` (retain_height=100_000, interval=1_000)
    /// - MainNet v0: `Height` (retain_height=500_000, interval=1_000)
    pub state_retention: StateRetentionConfig,

    // ========================================================================
    // T215: State Snapshot Configuration
    // ========================================================================
    /// State snapshot configuration (T215).
    ///
    /// Controls periodic snapshot creation for fast sync and recovery.
    ///
    /// - DevNet v0: `Disabled` (no periodic snapshots)
    /// - TestNet Alpha: `Disabled` (no periodic snapshots)
    /// - TestNet Beta: `Enabled` (interval=100_000, max_snapshots=3)
    /// - MainNet v0: `Enabled` (interval=50_000, max_snapshots=5)
    pub snapshot_config: SnapshotConfig,

    /// Fast-sync configuration (T215).
    ///
    /// Controls startup behavior when a local snapshot is available.
    ///
    /// - All environments: `Disabled` by default
    /// - Operators can enable with `--fast-sync-snapshot-dir=<path>`
    pub fast_sync_config: FastSyncConfig,

    // ========================================================================
    // T210: Signer Mode Configuration
    // ========================================================================
    /// Signer mode for validator key management (T210).
    ///
    /// Determines how the validator signing key is stored and accessed.
    ///
    /// - DevNet v0: `LoopbackTesting` (default for development)
    /// - TestNet Alpha/Beta: `EncryptedFsV1` (recommended)
    /// - MainNet v0: `EncryptedFsV1` or `HsmPkcs11` (**LoopbackTesting forbidden**)
    pub signer_mode: SignerMode,

    /// Path to the encrypted keystore directory (T210).
    ///
    /// Required when `signer_mode == SignerMode::EncryptedFsV1`.
    /// The keystore stores validator signing keys encrypted at rest.
    ///
    /// Example: `/data/qbind/keystore`
    pub signer_keystore_path: Option<PathBuf>,

    /// URL for the remote signer service (T210).
    ///
    /// Required when `signer_mode == SignerMode::RemoteSigner`.
    /// Supports `grpc://`, `http://`, or `unix://` schemes.
    ///
    /// Examples:
    /// - `grpc://localhost:50051`
    /// - `unix:///var/run/qbind-signer.sock`
    pub remote_signer_url: Option<String>,

    /// Path to the HSM/PKCS#11 configuration file (T210).
    ///
    /// Required when `signer_mode == SignerMode::HsmPkcs11`.
    /// Contains PKCS#11 library path, slot ID, and key label.
    ///
    /// Example: `/etc/qbind/hsm.toml`
    pub hsm_config_path: Option<PathBuf>,

    // ========================================================================
    // T214: Signer Failure Mode Configuration
    // ========================================================================
    /// Signer failure mode for HSM/remote signer errors (T214).
    ///
    /// Controls how the node reacts to signer/HSM failures during consensus operations.
    ///
    /// - DevNet v0: `ExitOnFailure` (default, can be overridden)
    /// - TestNet Alpha/Beta: `ExitOnFailure` (default, can be overridden to `LogAndContinue`)
    /// - MainNet v0: `ExitOnFailure` (**required**, cannot be changed)
    pub signer_failure_mode: SignerFailureMode,

    // ========================================================================
    // T218: Mempool DoS Configuration
    // ========================================================================
    /// Mempool DoS protection configuration (T218).
    ///
    /// Controls per-sender rate limits and batch size limits to prevent
    /// malicious senders from overwhelming the mempool.
    ///
    /// - DevNet v0: Very loose limits (debugging-friendly)
    /// - TestNet Alpha: Disabled / neutral (FIFO mode)
    /// - TestNet Beta: Moderate protection (testable limits)
    /// - MainNet v0: Tighter defaults (conservative; validated by invariants)
    pub mempool_dos: MempoolDosConfig,

    // ========================================================================
    // T219: Mempool Eviction Rate Limiting Configuration
    // ========================================================================
    /// Mempool eviction rate limiting configuration (T219).
    ///
    /// Controls the rate at which transactions can be evicted from the mempool
    /// to prevent excessive churn under adversarial conditions. Works alongside:
    /// - Fee-priority mempool (T169)
    /// - Per-sender quotas and batch caps (T218)
    ///
    /// - DevNet v0: Off (no rate limiting, debugging-friendly)
    /// - TestNet Alpha: Warn (observe limits but don't enforce)
    /// - TestNet Beta: Enforce (test enforcement behavior)
    /// - MainNet v0: Enforce (required; validated by invariants)
    pub mempool_eviction: MempoolEvictionConfig,

    // ========================================================================
    // T226: P2P Discovery and Liveness Configuration
    // ========================================================================
    /// P2P dynamic peer discovery configuration (T226).
    ///
    /// Controls how the node discovers and maintains connections to peers
    /// beyond static bootstrap peers.
    ///
    /// - DevNet v0: Fast intervals (10s) for testing
    /// - TestNet Alpha/Beta: Standard intervals (30s)
    /// - MainNet v0: **Required** (enabled must be true)
    pub p2p_discovery: P2pDiscoveryConfig,

    /// P2P peer liveness scoring configuration (T226).
    ///
    /// Controls periodic heartbeat probes and liveness scoring behavior.
    ///
    /// - DevNet v0: Fast heartbeats (10s interval, 5s timeout)
    /// - TestNet Alpha/Beta: Standard (15s interval, 10s timeout)
    /// - MainNet v0: Conservative (15s interval, 10s timeout, 3 max failures)
    pub p2p_liveness: P2pLivenessConfig,

    // ========================================================================
    // T231: P2P Anti-Eclipse Configuration
    // ========================================================================
    /// P2P anti-eclipse constraint configuration (T231).
    ///
    /// Controls additional diversity and outbound peer requirements for
    /// MainNet-grade protection against eclipse attacks.
    ///
    /// - DevNet v0: Loose limits (`enforce=false`)
    /// - TestNet Alpha/Beta: Moderate limits (`enforce=false`)
    /// - MainNet v0: Strict limits (`enforce=true`, required)
    pub p2p_anti_eclipse: Option<P2pAntiEclipseConfig>,

    // ========================================================================
    // T229: Slashing Configuration
    // ========================================================================
    /// Slashing penalty engine configuration (T229).
    ///
    /// Controls how the node processes slashing evidence and applies penalties.
    ///
    /// - DevNet v0: EnforceCritical (see actual penalties for testing)
    /// - TestNet Alpha/Beta: RecordOnly (evidence + metrics only)
    /// - MainNet v0: RecordOnly (governance can flip to EnforceCritical later)
    pub slashing: SlashingConfig,

    // ========================================================================
    // M2: Validator Stake Configuration
    // ========================================================================
    /// Validator stake configuration (M2).
    ///
    /// Controls minimum stake enforcement at validator registration and epoch transitions.
    ///
    /// - DevNet v0: 1 QBIND minimum (low barrier for testing)
    /// - TestNet Alpha/Beta: 10 QBIND minimum (moderate barrier)
    /// - MainNet v0: 100,000 QBIND minimum (economic security)
    pub validator_stake: ValidatorStakeConfig,

    // ========================================================================
    // T232: Genesis Source Configuration
    // ========================================================================
    /// Genesis source configuration (T232).
    ///
    /// Controls where the genesis configuration is loaded from.
    ///
    /// - DevNet v0: Embedded (uses built-in test genesis)
    /// - TestNet Alpha/Beta: Embedded (default) or External
    /// - MainNet v0: External (**required**, must specify genesis_path)
    pub genesis_source: GenesisSourceConfig,

    // ========================================================================
    // T233: Genesis Hash Commitment & Verification
    // ========================================================================
    /// Expected genesis hash for verification (T233).
    ///
    /// If set, the node computes the genesis hash from the loaded genesis file
    /// and compares it to this expected value. If they don't match, the node
    /// fails fast at startup.
    ///
    /// - DevNet v0: `None` (optional)
    /// - TestNet Alpha/Beta: `None` (optional, recommended)
    /// - MainNet v0: **Required** (`validate_mainnet_invariants()` rejects `None`)
    ///
    /// The hash is SHA3-256 over the exact bytes of the genesis JSON file.
    pub expected_genesis_hash: Option<GenesisHash>,
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
            // T208: State retention disabled for DevNet
            state_retention: StateRetentionConfig::disabled(),
            // T215: Snapshots disabled for DevNet
            snapshot_config: SnapshotConfig::disabled(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: Loopback signer for DevNet (testing only)
            signer_mode: SignerMode::LoopbackTesting,
            signer_keystore_path: None,
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: DevNet-style loose limits for backward compatibility
            mempool_dos: MempoolDosConfig::devnet_default(),
            // T219: DevNet-style loose limits for backward compatibility
            mempool_eviction: MempoolEvictionConfig::devnet_default(),
            // T226: DevNet discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::devnet_default(),
            p2p_liveness: P2pLivenessConfig::devnet_default(),
            // T231: DevNet anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
            // T229: DevNet slashing defaults (EnforceCritical mode)
            slashing: SlashingConfig::devnet_default(),
            // M2: DevNet validator stake defaults (low barrier)
            validator_stake: ValidatorStakeConfig::devnet_default(),
            // T232: DevNet genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::devnet_default(),
            // T233: No expected genesis hash for DevNet
            expected_genesis_hash: None,
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
            // T208: State retention disabled by default
            state_retention: StateRetentionConfig::disabled(),
            // T215: Snapshots disabled by default
            snapshot_config: SnapshotConfig::disabled(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: Loopback signer for testing (default)
            signer_mode: SignerMode::LoopbackTesting,
            signer_keystore_path: None,
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: DevNet-style loose limits for backward compatibility
            mempool_dos: MempoolDosConfig::devnet_default(),
            // T219: DevNet-style loose limits for backward compatibility
            mempool_eviction: MempoolEvictionConfig::devnet_default(),
            // T226: DevNet discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::devnet_default(),
            p2p_liveness: P2pLivenessConfig::devnet_default(),
            // T231: DevNet anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
            // T229: DevNet slashing defaults
            slashing: SlashingConfig::devnet_default(),
            // M2: DevNet validator stake defaults
            validator_stake: ValidatorStakeConfig::devnet_default(),
            // T232: DevNet genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::devnet_default(),
            // T233: No expected genesis hash by default
            expected_genesis_hash: None,
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
            // T208: State retention disabled by default
            state_retention: StateRetentionConfig::disabled(),
            // T215: Snapshots disabled by default
            snapshot_config: SnapshotConfig::disabled(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: Loopback signer for testing (default)
            signer_mode: SignerMode::LoopbackTesting,
            signer_keystore_path: None,
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: DevNet-style loose limits for backward compatibility
            mempool_dos: MempoolDosConfig::devnet_default(),
            // T219: DevNet-style loose limits for backward compatibility
            mempool_eviction: MempoolEvictionConfig::devnet_default(),
            // T226: DevNet discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::devnet_default(),
            p2p_liveness: P2pLivenessConfig::devnet_default(),
            // T231: DevNet anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
            // T229: DevNet slashing defaults
            slashing: SlashingConfig::devnet_default(),
            // M2: DevNet validator stake defaults
            validator_stake: ValidatorStakeConfig::devnet_default(),
            // T232: DevNet genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::devnet_default(),
            // T233: No expected genesis hash by default
            expected_genesis_hash: None,
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
    /// - State Retention: Disabled (T208)
    /// - Signer Mode: LoopbackTesting (T210)
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
            // T208: State retention disabled for DevNet
            state_retention: StateRetentionConfig::disabled(),
            // T215: Snapshots disabled for DevNet
            snapshot_config: SnapshotConfig::disabled(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: Loopback signer for DevNet (testing only)
            signer_mode: SignerMode::LoopbackTesting,
            signer_keystore_path: None,
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: DevNet-style loose limits
            mempool_dos: MempoolDosConfig::devnet_default(),
            // T219: DevNet-style loose limits (no rate limiting)
            mempool_eviction: MempoolEvictionConfig::devnet_default(),
            // T226: DevNet discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::devnet_default(),
            p2p_liveness: P2pLivenessConfig::devnet_default(),
            // T231: DevNet anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
            // T229: DevNet slashing defaults (EnforceCritical mode)
            slashing: SlashingConfig::devnet_default(),
            // M2: DevNet validator stake defaults (low barrier)
            validator_stake: ValidatorStakeConfig::devnet_default(),
            // T232: DevNet genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::devnet_default(),
            // T233: No expected genesis hash for DevNet
            expected_genesis_hash: None,
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
    /// - State Retention: Disabled (T208)
    /// - Signer Mode: EncryptedFsV1 (T210, recommended)
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
            // T208: State retention disabled for TestNet Alpha
            state_retention: StateRetentionConfig::disabled(),
            // T215: Snapshots disabled for TestNet Alpha
            snapshot_config: SnapshotConfig::disabled(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: EncryptedFsV1 recommended for TestNet (keystore path must be provided)
            signer_mode: SignerMode::EncryptedFsV1,
            signer_keystore_path: None, // Operator must provide
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: Disabled (neutral) for TestNet Alpha
            mempool_dos: MempoolDosConfig::disabled(),
            // T219: Warn mode for TestNet Alpha (observability)
            mempool_eviction: MempoolEvictionConfig::testnet_alpha_default(),
            // T226: TestNet Alpha discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::testnet_alpha_default(),
            p2p_liveness: P2pLivenessConfig::testnet_alpha_default(),
            // T231: TestNet Alpha anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::testnet_alpha_default()),
            // T229: TestNet Alpha slashing defaults (RecordOnly mode)
            slashing: SlashingConfig::testnet_alpha_default(),
            // M2: TestNet validator stake defaults (moderate barrier)
            validator_stake: ValidatorStakeConfig::testnet_default(),
            // T232: TestNet Alpha genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::testnet_default(),
            // T233: No expected genesis hash for TestNet (optional)
            expected_genesis_hash: None,
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
    /// - State Retention: **Height** (T208: retain_height=100_000, ~6 days at 5s blocks)
    /// - Signer Mode: **EncryptedFsV1** (T210, keystore path must be provided)
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
            // T208: State retention enabled for TestNet Beta (~6 days history)
            state_retention: StateRetentionConfig::testnet_beta_default(),
            // T215: Snapshots enabled for TestNet Beta (~6 days interval)
            snapshot_config: SnapshotConfig::testnet_beta_default(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: EncryptedFsV1 recommended for TestNet (keystore path must be provided)
            signer_mode: SignerMode::EncryptedFsV1,
            signer_keystore_path: None, // Operator must provide
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is the default
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: Moderate DoS limits for TestNet Beta
            mempool_dos: MempoolDosConfig::testnet_beta_default(),
            // T219: Enforce mode for TestNet Beta (test enforcement behavior)
            mempool_eviction: MempoolEvictionConfig::testnet_beta_default(),
            // T226: TestNet Beta discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::testnet_beta_default(),
            p2p_liveness: P2pLivenessConfig::testnet_beta_default(),
            // T231: TestNet Beta anti-eclipse defaults
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::testnet_beta_default()),
            // T229: TestNet Beta slashing defaults (RecordOnly mode)
            slashing: SlashingConfig::testnet_beta_default(),
            // M2: TestNet validator stake defaults (moderate barrier)
            validator_stake: ValidatorStakeConfig::testnet_default(),
            // T232: TestNet Beta genesis source defaults (embedded)
            genesis_source: GenesisSourceConfig::testnet_default(),
            // T233: No expected genesis hash for TestNet (optional)
            expected_genesis_hash: None,
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
    /// - State Retention: **Height** (T208: retain_height=500_000, ~30 days at 5s blocks)
    /// - Signer Mode: **EncryptedFsV1** (T210, LoopbackTesting forbidden)
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
            // T208: State retention enabled for MainNet (~30 days history)
            state_retention: StateRetentionConfig::mainnet_default(),
            // T215: Snapshots enabled for MainNet (~3.5 days interval)
            snapshot_config: SnapshotConfig::mainnet_default(),
            fast_sync_config: FastSyncConfig::disabled(),
            // T210: EncryptedFsV1 default for MainNet (LoopbackTesting forbidden by invariants)
            signer_mode: SignerMode::EncryptedFsV1,
            signer_keystore_path: None, // Operator must provide
            remote_signer_url: None,
            hsm_config_path: None,
            // T214: Exit on failure is required for MainNet
            signer_failure_mode: SignerFailureMode::ExitOnFailure,
            // T218: Conservative DoS limits for MainNet
            mempool_dos: MempoolDosConfig::mainnet_default(),
            // T219: Conservative eviction rate limits for MainNet (required)
            mempool_eviction: MempoolEvictionConfig::mainnet_default(),
            // T226: MainNet discovery and liveness defaults
            p2p_discovery: P2pDiscoveryConfig::mainnet_default(),
            p2p_liveness: P2pLivenessConfig::mainnet_default(),
            // T231: MainNet anti-eclipse defaults (enforce=true)
            p2p_anti_eclipse: Some(P2pAntiEclipseConfig::mainnet_default()),
            // T229: MainNet slashing defaults (RecordOnly mode, governance can flip)
            slashing: SlashingConfig::mainnet_default(),
            // M2: MainNet validator stake defaults (high barrier, fail-fast)
            validator_stake: ValidatorStakeConfig::mainnet_default(),
            // T232: MainNet genesis source (external file required)
            genesis_source: GenesisSourceConfig::mainnet_default(),
            // T233: Expected genesis hash required (must be set via --expect-genesis-hash)
            // This will fail validate_mainnet_invariants() until a hash is provided
            expected_genesis_hash: None,
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

    /// Set the state retention configuration (T208).
    ///
    /// # Arguments
    ///
    /// * `config` - The state retention configuration to use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, StateRetentionConfig, StateRetentionMode};
    ///
    /// // Custom state retention for testing
    /// let retention = StateRetentionConfig::height_based(50_000, 500);
    /// let config = NodeConfig::testnet_alpha_preset()
    ///     .with_state_retention(retention);
    ///
    /// assert_eq!(config.state_retention.mode, StateRetentionMode::Height);
    /// ```
    pub fn with_state_retention(mut self, config: StateRetentionConfig) -> Self {
        self.state_retention = config;
        self
    }

    // ========================================================================
    // T215: Snapshot Configuration Builder Methods
    // ========================================================================

    /// Set the snapshot configuration (T215).
    ///
    /// # Arguments
    ///
    /// * `config` - The snapshot configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, SnapshotConfig};
    /// use std::path::PathBuf;
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_snapshot_config(SnapshotConfig::enabled(
    ///         PathBuf::from("/data/qbind/snapshots"),
    ///         50_000,
    ///         5,
    ///     ));
    /// ```
    pub fn with_snapshot_config(mut self, config: SnapshotConfig) -> Self {
        self.snapshot_config = config;
        self
    }

    /// Set the snapshot directory (T215).
    ///
    /// Enables snapshots with the specified directory. Uses default interval
    /// and max_snapshots from the existing snapshot_config.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the snapshot directory
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::NodeConfig;
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_snapshot_dir("/data/qbind/snapshots");
    /// ```
    pub fn with_snapshot_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.snapshot_config.enabled = true;
        self.snapshot_config.snapshot_dir = Some(path.into());
        self
    }

    /// Set the fast-sync configuration (T215).
    ///
    /// # Arguments
    ///
    /// * `config` - The fast-sync configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, FastSyncConfig};
    /// use std::path::PathBuf;
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_fast_sync_config(FastSyncConfig::from_snapshot(
    ///         PathBuf::from("/data/qbind/snapshots/100000"),
    ///     ));
    /// ```
    pub fn with_fast_sync_config(mut self, config: FastSyncConfig) -> Self {
        self.fast_sync_config = config;
        self
    }

    /// Set the fast-sync snapshot directory (T215).
    ///
    /// Enables fast-sync restore from the specified snapshot directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the snapshot directory to restore from
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::NodeConfig;
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_fast_sync_snapshot_dir("/data/qbind/snapshots/100000");
    /// ```
    pub fn with_fast_sync_snapshot_dir<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.fast_sync_config.enabled = true;
        self.fast_sync_config.fast_sync_snapshot_dir = Some(path.into());
        self
    }

    // ========================================================================
    // T210: Signer Mode Builder Methods
    // ========================================================================

    /// Set the signer mode (T210).
    ///
    /// # Arguments
    ///
    /// * `mode` - The signer mode to use
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, SignerMode};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_signer_mode(SignerMode::HsmPkcs11)
    ///     .with_hsm_config_path("/etc/qbind/hsm.toml");
    /// ```
    pub fn with_signer_mode(mut self, mode: SignerMode) -> Self {
        self.signer_mode = mode;
        self
    }

    /// Set the signer keystore path (T210).
    ///
    /// Required when `signer_mode == SignerMode::EncryptedFsV1`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the encrypted keystore directory
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, SignerMode};
    ///
    /// let config = NodeConfig::testnet_alpha_preset()
    ///     .with_signer_keystore_path("/data/qbind/keystore");
    /// ```
    pub fn with_signer_keystore_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.signer_keystore_path = Some(path.into());
        self
    }

    /// Set the remote signer URL (T210).
    ///
    /// Required when `signer_mode == SignerMode::RemoteSigner`.
    ///
    /// # Arguments
    ///
    /// * `url` - URL for the remote signer service (grpc://, http://, or unix://)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, SignerMode};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_signer_mode(SignerMode::RemoteSigner)
    ///     .with_remote_signer_url("grpc://localhost:50051");
    /// ```
    pub fn with_remote_signer_url<S: Into<String>>(mut self, url: S) -> Self {
        self.remote_signer_url = Some(url.into());
        self
    }

    /// Set the HSM/PKCS#11 configuration path (T210).
    ///
    /// Required when `signer_mode == SignerMode::HsmPkcs11`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the HSM configuration file (TOML format)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, SignerMode};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_signer_mode(SignerMode::HsmPkcs11)
    ///     .with_hsm_config_path("/etc/qbind/hsm.toml");
    /// ```
    pub fn with_hsm_config_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.hsm_config_path = Some(path.into());
        self
    }

    /// Set the signer failure mode (T214).
    ///
    /// Controls how the node reacts to HSM/remote signer failures.
    ///
    /// # Arguments
    ///
    /// * `mode` - The failure mode to use (`ExitOnFailure` or `LogAndContinue`)
    ///
    /// # MainNet Requirement
    ///
    /// MainNet validators **must** use `ExitOnFailure`. This is enforced by
    /// `validate_mainnet_invariants()`. Using `LogAndContinue` on MainNet
    /// will cause config validation to fail.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, SignerFailureMode};
    ///
    /// // For chaos testing on testnet:
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_signer_failure_mode(SignerFailureMode::LogAndContinue);
    /// ```
    pub fn with_signer_failure_mode(mut self, mode: SignerFailureMode) -> Self {
        self.signer_failure_mode = mode;
        self
    }

    /// Set the mempool DoS protection configuration (T218).
    ///
    /// # Arguments
    ///
    /// * `config` - The mempool DoS configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, MempoolDosConfig};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_mempool_dos_config(MempoolDosConfig::mainnet_default());
    /// ```
    pub fn with_mempool_dos_config(mut self, config: MempoolDosConfig) -> Self {
        self.mempool_dos = config;
        self
    }

    /// Set the mempool eviction rate limiting configuration (T219).
    ///
    /// # Arguments
    ///
    /// * `config` - The mempool eviction rate limiting configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_node::node_config::{NodeConfig, MempoolEvictionConfig};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_mempool_eviction_config(MempoolEvictionConfig::mainnet_default());
    /// ```
    pub fn with_mempool_eviction_config(mut self, config: MempoolEvictionConfig) -> Self {
        self.mempool_eviction = config;
        self
    }

    // ========================================================================
    // T226: P2P Discovery and Liveness Builder Methods
    // ========================================================================

    /// Set the P2P discovery configuration (T226).
    ///
    /// # Arguments
    ///
    /// * `config` - The P2P discovery configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, P2pDiscoveryConfig};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_discovery_config(P2pDiscoveryConfig::mainnet_default());
    /// assert!(config.p2p_discovery.enabled);
    /// ```
    pub fn with_discovery_config(mut self, config: P2pDiscoveryConfig) -> Self {
        self.p2p_discovery = config;
        self
    }

    /// Set the P2P liveness configuration (T226).
    ///
    /// # Arguments
    ///
    /// * `config` - The P2P liveness configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, P2pLivenessConfig};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_liveness_config(P2pLivenessConfig::mainnet_default());
    /// assert_eq!(config.p2p_liveness.max_heartbeat_failures, 3);
    /// ```
    pub fn with_liveness_config(mut self, config: P2pLivenessConfig) -> Self {
        self.p2p_liveness = config;
        self
    }

    // ========================================================================
    // T231: P2P Anti-Eclipse Configuration Builder Methods
    // ========================================================================

    /// Set the P2P anti-eclipse configuration (T231).
    ///
    /// # Arguments
    ///
    /// * `cfg` - The P2P anti-eclipse configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, P2pAntiEclipseConfig};
    ///
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_p2p_anti_eclipse_config(P2pAntiEclipseConfig::mainnet_default());
    /// assert!(config.p2p_anti_eclipse.as_ref().unwrap().enforce);
    /// ```
    pub fn with_p2p_anti_eclipse_config(mut self, cfg: P2pAntiEclipseConfig) -> Self {
        self.p2p_anti_eclipse = Some(cfg);
        self
    }

    // ========================================================================
    // T229: Slashing Configuration Builder Methods
    // ========================================================================

    /// Set the slashing configuration (T229).
    ///
    /// # Arguments
    ///
    /// * `config` - The slashing configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, SlashingConfig, SlashingMode};
    ///
    /// let config = NodeConfig::testnet_beta_preset()
    ///     .with_slashing_config(SlashingConfig::devnet_default());
    /// assert_eq!(config.slashing.mode, SlashingMode::EnforceCritical);
    /// ```
    pub fn with_slashing_config(mut self, config: SlashingConfig) -> Self {
        self.slashing = config;
        self
    }

    /// Set the slashing mode (T229).
    ///
    /// # Arguments
    ///
    /// * `mode` - The slashing mode to use
    ///
    /// # Example
    ///
    /// ```rust
    /// use qbind_node::node_config::{NodeConfig, SlashingMode};
    ///
    /// let config = NodeConfig::devnet_v0_preset()
    ///     .with_slashing_mode(SlashingMode::RecordOnly);
    /// assert_eq!(config.slashing.mode, SlashingMode::RecordOnly);
    /// ```
    pub fn with_slashing_mode(mut self, mode: SlashingMode) -> Self {
        self.slashing.mode = mode;
        self
    }

    /// Set the genesis file path (T232).
    ///
    /// This configures the path to an external genesis file for MainNet.
    /// For MainNet, this is required - the node must use an externally
    /// provided genesis file rather than an embedded one.
    ///
    /// Note: This method also sets `use_external = true` to ensure the
    /// configuration is correctly set up for external genesis loading.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the genesis file
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_genesis_path("/etc/qbind/genesis.json");
    /// ```
    pub fn with_genesis_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.genesis_source.use_external = true;
        self.genesis_source.genesis_path = Some(path.into());
        self
    }

    /// Set the expected genesis hash for MainNet validation (T233).
    ///
    /// MainNet nodes MUST specify the expected genesis hash to prevent
    /// accidental startup with the wrong genesis file.
    ///
    /// # Arguments
    ///
    /// * `hash` - The expected genesis hash (32-byte array)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::mainnet_preset()
    ///     .with_expected_genesis_hash([0u8; 32]);
    /// ```
    pub fn with_expected_genesis_hash(mut self, hash: GenesisHash) -> Self {
        self.expected_genesis_hash = Some(hash);
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

        // T206: Diversity mode and caps
        let diversity_str = format!(
            "diversity={}(prefix24={},prefix16={},buckets>={})",
            self.network.diversity_mode,
            self.network.max_peers_per_ipv4_prefix24,
            self.network.max_peers_per_ipv4_prefix16,
            self.network.min_outbound_diversity_buckets
        );

        format!(
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={} profile={} network={} {} gas={} fee-priority={} fee_distribution={} mempool={} dag_availability={} dag_coupling={} stage_b={} {}",
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
            stage_b_str,
            diversity_str
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

        // 9. Discovery must be enabled (T205)
        if !self.network.discovery_enabled {
            return Err(MainnetConfigError::DiscoveryDisabled);
        }

        // 10. Target outbound peers must be at least 8 (T205)
        if self.network.target_outbound_peers < 8 {
            return Err(MainnetConfigError::InsufficientTargetOutboundPeers {
                minimum: 8,
                actual: self.network.target_outbound_peers,
            });
        }

        // 11. Diversity mode must be Enforce (T206)
        if self.network.diversity_mode != crate::p2p_diversity::DiversityEnforcementMode::Enforce {
            return Err(MainnetConfigError::DiversityNotEnforced {
                actual: self.network.diversity_mode,
            });
        }

        // 12. Diversity parameters must be sensible (T206)
        if self.network.max_peers_per_ipv4_prefix24 == 0
            || self.network.max_peers_per_ipv4_prefix16 == 0
            || self.network.min_outbound_diversity_buckets < 2
            || self.network.max_single_bucket_fraction_bps == 0
            || self.network.max_single_bucket_fraction_bps > 10000
        {
            return Err(MainnetConfigError::InvalidDiversityParameters);
        }

        // 13. Data directory must be set (no in-memory validators)
        if self.data_dir.is_none() {
            return Err(MainnetConfigError::MissingDataDir);
        }

        // 14. Fee distribution must be MainNet default (T193)
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

        // 15. Monetary mode must not be Off (T197)
        // MainNet must at least compute + expose decisions.
        if self.monetary_mode == MonetaryMode::Off {
            return Err(MainnetConfigError::MonetaryModeOff);
        }

        // 16. If monetary mode is Active, accounts and split must be valid (T197)
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

        // 17. State retention must be enabled for MainNet (T208)
        // MainNet validators should prune state to manage disk usage.
        if !self.state_retention.is_enabled() {
            return Err(MainnetConfigError::StateRetentionDisabled);
        }

        // 18. State retention must have a reasonable retain_height (T208)
        // For MainNet, we require at least some minimum history for reorg safety.
        if self.state_retention.mode == StateRetentionMode::Height {
            match self.state_retention.retain_height {
                None => {
                    return Err(MainnetConfigError::StateRetentionInvalid(
                        "retain_height must be set when mode is Height".to_string(),
                    ));
                }
                Some(h) if h < 10_000 => {
                    // Require at least ~14 hours of history at 5s blocks
                    return Err(MainnetConfigError::StateRetentionInvalid(format!(
                        "retain_height {} is too low for MainNet (minimum 10,000)",
                        h
                    )));
                }
                _ => {}
            }
        }

        // 19. Signer mode must not be LoopbackTesting (T210)
        // MainNet requires a production signer (EncryptedFsV1, RemoteSigner, or HsmPkcs11).
        // Loopback mode is only allowed for development/testing.
        if self.signer_mode == SignerMode::LoopbackTesting {
            return Err(MainnetConfigError::SignerModeLoopbackForbidden);
        }

        // 20. Signer mode requires appropriate configuration (T210)
        // Note: LoopbackTesting is already rejected above, so we only check production modes.
        match self.signer_mode {
            SignerMode::EncryptedFsV1 => {
                if self.signer_keystore_path.is_none() {
                    return Err(MainnetConfigError::SignerKeystorePathMissing);
                }
            }
            SignerMode::RemoteSigner => {
                if self.remote_signer_url.is_none() {
                    return Err(MainnetConfigError::RemoteSignerUrlMissing);
                }
            }
            SignerMode::HsmPkcs11 => {
                if self.hsm_config_path.is_none() {
                    return Err(MainnetConfigError::HsmConfigPathMissing);
                }
            }
            SignerMode::LoopbackTesting => {
                // Unreachable: already rejected above at line 2623
                unreachable!("LoopbackTesting should have been rejected above")
            }
        }

        // 21. Signer failure mode must be ExitOnFailure for MainNet (T214)
        // MainNet validators must fail-closed on signer errors.
        // LogAndContinue is only allowed for dev/test chaos testing.
        if self.signer_failure_mode != SignerFailureMode::ExitOnFailure {
            return Err(MainnetConfigError::SignerFailureModeInvalid {
                actual: self.signer_failure_mode,
            });
        }

        // 22. Snapshots must be enabled for MainNet (T215)
        // MainNet validators should create periodic snapshots for fast sync and recovery.
        // Note: Snapshot directory must be configured by operator via --snapshot-dir flag.
        if !self.snapshot_config.enabled {
            return Err(MainnetConfigError::SnapshotsDisabled);
        }

        // 23. Snapshot interval must be reasonable for MainNet (T215)
        // Too frequent snapshots waste disk space; too infrequent snapshots make recovery slow.
        // We require at least 10,000 block interval and at most 500,000 block interval.
        if self.snapshot_config.snapshot_interval_blocks < 10_000 {
            return Err(MainnetConfigError::SnapshotIntervalTooLow {
                minimum: 10_000,
                actual: self.snapshot_config.snapshot_interval_blocks,
            });
        }
        if self.snapshot_config.snapshot_interval_blocks > 500_000 {
            return Err(MainnetConfigError::SnapshotIntervalTooHigh {
                maximum: 500_000,
                actual: self.snapshot_config.snapshot_interval_blocks,
            });
        }

        // 24. Mempool DoS config must be valid for MainNet (T218)
        // MainNet requires reasonable DoS protection limits.
        if let Err(reason) = self.mempool_dos.validate_for_mainnet() {
            return Err(MainnetConfigError::MempoolDosMisconfigured { reason });
        }

        // 25. Mempool eviction rate limiting must be valid for MainNet (T219)
        // MainNet requires eviction rate limiting to be enforced.
        if let Err(reason) = self.mempool_eviction.validate_for_mainnet() {
            return Err(MainnetConfigError::MempoolEvictionMisconfigured { reason });
        }

        // 26. P2P discovery must be valid for MainNet (T226)
        // MainNet requires dynamic peer discovery to maintain a healthy peer set.
        if let Err(reason) = self.p2p_discovery.validate_for_mainnet() {
            return Err(MainnetConfigError::P2pDiscoveryMisconfigured { reason });
        }

        // 27. P2P liveness must be valid for MainNet (T226)
        // MainNet requires liveness probing to detect and evict unhealthy peers.
        if let Err(reason) = self.p2p_liveness.validate_for_mainnet() {
            return Err(MainnetConfigError::P2pLivenessMisconfigured { reason });
        }

        // 28. P2P anti-eclipse configuration must be valid for MainNet (T231)
        // MainNet requires anti-eclipse constraints to be enforced.
        match &self.p2p_anti_eclipse {
            None => {
                return Err(MainnetConfigError::P2pAntiEclipseMisconfigured {
                    reason: "p2p_anti_eclipse must be configured for MainNet".to_string(),
                });
            }
            Some(cfg) => {
                if let Err(reason) = cfg.validate_for_mainnet() {
                    return Err(MainnetConfigError::P2pAntiEclipseMisconfigured { reason });
                }
            }
        }

        // 29. Slashing configuration must be valid for MainNet (T229)
        // MainNet requires slashing to be at least in RecordOnly mode.
        // If penalties are enabled, parameters must be within T227 ranges.
        if let Err(reason) = self.slashing.validate_for_mainnet() {
            return Err(MainnetConfigError::SlashingMisconfigured { reason });
        }

        // 30. Validator stake configuration must be valid for MainNet (M2)
        // MainNet requires minimum stake enforcement with fail-fast on startup.
        if let Err(reason) = self.validator_stake.validate_for_mainnet() {
            return Err(MainnetConfigError::ValidatorStakeMisconfigured { reason });
        }

        // 31. Genesis source must be configured for MainNet (T232)
        // MainNet requires an external genesis file (no embedded genesis).
        if let Err(reason) = self.genesis_source.validate_for_mainnet() {
            return Err(MainnetConfigError::GenesisMisconfigured { reason });
        }

        // 32. Expected genesis hash must be configured for MainNet (T233)
        // MainNet validators MUST specify the expected genesis hash to prevent
        // accidental startup with the wrong genesis file.
        if self.expected_genesis_hash.is_none() {
            return Err(MainnetConfigError::ExpectedGenesisHashMissing);
        }

        // TODO(future): Add stricter rules for validators vs non-validators
        // when the code has a way to distinguish between them.
        // For now, all invariants are enforced unconditionally.

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

    /// Dynamic peer discovery is disabled (T205).
    ///
    /// MainNet validators must have dynamic discovery enabled to maintain
    /// a healthy peer set beyond static bootstrap peers.
    DiscoveryDisabled,

    /// Target outbound peers is below minimum (T205).
    ///
    /// MainNet validators must have at least 8 target outbound peers
    /// for network resilience and consensus liveness.
    InsufficientTargetOutboundPeers { minimum: u32, actual: u32 },

    /// Diversity mode is not Enforce (T206).
    ///
    /// MainNet validators must have diversity_mode=Enforce to prevent
    /// eclipse attacks from dominating peer connections.
    DiversityNotEnforced {
        actual: crate::p2p_diversity::DiversityEnforcementMode,
    },

    /// Diversity parameters are invalid (T206).
    ///
    /// MainNet requires sensible diversity parameters:
    /// - max_peers_per_ipv4_prefix24 > 0
    /// - max_peers_per_ipv4_prefix16 > 0
    /// - min_outbound_diversity_buckets >= 2
    /// - max_single_bucket_fraction_bps in (0, 10000]
    InvalidDiversityParameters,

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

    /// State retention is disabled for MainNet (T208).
    ///
    /// MainNet validators must enable state pruning to manage disk usage.
    /// Disabled state retention would lead to unbounded state growth.
    StateRetentionDisabled,

    /// State retention configuration is invalid for MainNet (T208).
    ///
    /// When state retention is enabled with Height mode, retain_height must
    /// be set and must be at least 10,000 blocks for reorg safety.
    StateRetentionInvalid(String),

    // ========================================================================
    // T210: Signer Mode Errors
    // ========================================================================
    /// Signer mode is LoopbackTesting on MainNet (T210).
    ///
    /// MainNet validators must use a production signer mode:
    /// - EncryptedFsV1: Encrypted filesystem keystore
    /// - RemoteSigner: External signer service
    /// - HsmPkcs11: Hardware Security Module
    ///
    /// LoopbackTesting is only allowed for development and testing.
    SignerModeLoopbackForbidden,

    /// Signer keystore path is missing when EncryptedFsV1 mode is selected (T210).
    ///
    /// When signer_mode is EncryptedFsV1, signer_keystore_path must be set
    /// to the path of the encrypted keystore directory.
    SignerKeystorePathMissing,

    /// Remote signer URL is missing when RemoteSigner mode is selected (T210).
    ///
    /// When signer_mode is RemoteSigner, remote_signer_url must be set
    /// to the URL of the remote signing service.
    RemoteSignerUrlMissing,

    /// Remote signer is unreachable at startup (T212).
    ///
    /// When signer_mode is RemoteSigner, the node performs a reachability
    /// check at startup. This error indicates the remote signer could not
    /// be reached after the configured number of attempts.
    RemoteSignerUnreachable,

    /// HSM configuration path is missing when HsmPkcs11 mode is selected (T210).
    ///
    /// When signer_mode is HsmPkcs11, hsm_config_path must be set
    /// to the path of the HSM configuration file.
    HsmConfigPathMissing,

    // ========================================================================
    // T214: Signer Failure Mode Errors
    // ========================================================================
    /// Signer failure mode is not ExitOnFailure on MainNet (T214).
    ///
    /// MainNet validators must use signer_failure_mode = ExitOnFailure to ensure
    /// fail-closed behavior. LogAndContinue is only allowed for dev/test chaos testing.
    SignerFailureModeInvalid { actual: SignerFailureMode },

    // ========================================================================
    // T215: Snapshot Configuration Errors
    // ========================================================================
    /// Snapshots are disabled for MainNet (T215).
    ///
    /// MainNet validators must enable periodic snapshots for fast sync and recovery.
    /// Enable snapshots with `--enable-snapshots=true`.
    SnapshotsDisabled,

    /// Snapshot interval is too low for MainNet (T215).
    ///
    /// MainNet requires at least 10,000 block interval between snapshots
    /// to avoid excessive disk usage.
    SnapshotIntervalTooLow { minimum: u64, actual: u64 },

    /// Snapshot interval is too high for MainNet (T215).
    ///
    /// MainNet requires at most 500,000 block interval between snapshots
    /// to ensure timely recovery capability.
    SnapshotIntervalTooHigh { maximum: u64, actual: u64 },

    // ========================================================================
    // T218: Mempool DoS Configuration Errors
    // ========================================================================
    /// Mempool DoS configuration is invalid for MainNet (T218).
    ///
    /// MainNet requires valid DoS protection limits:
    /// - All limits must be > 0
    /// - max_pending_per_sender must be reasonable (< 100,000)
    MempoolDosMisconfigured { reason: String },

    // ========================================================================
    // T219: Mempool Eviction Rate Limiting Errors
    // ========================================================================
    /// Mempool eviction rate limiting configuration is invalid for MainNet (T219).
    ///
    /// MainNet requires eviction rate limiting to be enforced:
    /// - mode must be Enforce
    /// - max_evictions_per_interval must be > 0
    /// - interval_secs must be >= 1
    /// - max_evictions_per_interval must be reasonable (< 1,000,000)
    MempoolEvictionMisconfigured { reason: String },

    // ========================================================================
    // T226: P2P Discovery and Liveness Errors
    // ========================================================================
    /// P2P discovery configuration is invalid for MainNet (T226).
    ///
    /// MainNet requires dynamic peer discovery:
    /// - enabled must be true
    /// - outbound_target must be >= 4
    /// - max_known_peers must be >= outbound_target
    P2pDiscoveryMisconfigured { reason: String },

    /// P2P liveness configuration is invalid for MainNet (T226).
    ///
    /// MainNet requires peer liveness probing:
    /// - heartbeat_interval_secs must be > 0
    /// - max_heartbeat_failures must be > 0
    P2pLivenessMisconfigured { reason: String },

    // ========================================================================
    // T231: P2P Anti-Eclipse Configuration Errors
    // ========================================================================
    /// P2P anti-eclipse configuration is invalid for MainNet (T231).
    ///
    /// MainNet requires anti-eclipse constraints:
    /// - p2p_anti_eclipse must be set
    /// - enforce must be true
    /// - max_peers_per_ipv4_prefix must be > 0
    /// - min_outbound_peers must be >= 4
    /// - min_asn_diversity must be >= 2
    P2pAntiEclipseMisconfigured { reason: String },

    // ========================================================================
    // T229: Slashing Configuration Errors
    // ========================================================================
    /// Slashing configuration is invalid for MainNet (T229).
    ///
    /// MainNet requires slashing to be at least in RecordOnly mode:
    /// - mode must not be Off
    /// - If enforcing, slash percentages must be in T227 ranges
    /// - If enforcing, jail epochs must be reasonable
    SlashingMisconfigured { reason: String },

    // ========================================================================
    // M2: Validator Stake Configuration Errors
    // ========================================================================
    /// Validator stake configuration is invalid for MainNet (M2).
    ///
    /// MainNet requires minimum stake enforcement:
    /// - min_validator_stake must be at least MIN_VALIDATOR_STAKE_MAINNET
    /// - fail_fast_on_startup must be true
    ValidatorStakeMisconfigured { reason: String },

    // ========================================================================
    // T232: Genesis Configuration Errors
    // ========================================================================
    /// Genesis source configuration is invalid for MainNet (T232).
    ///
    /// MainNet requires an external genesis file:
    /// - use_external must be true
    /// - genesis_path must be set
    GenesisMisconfigured { reason: String },

    // ========================================================================
    // T233: Genesis Hash Commitment Errors
    // ========================================================================
    /// Expected genesis hash not configured for MainNet (T233).
    ///
    /// MainNet validators MUST specify the expected genesis hash via
    /// `--expect-genesis-hash` to prevent accidental startup with the
    /// wrong genesis file.
    ExpectedGenesisHashMissing,

    // ========================================================================
    // M0: Validator Suite Invariant Errors
    // ========================================================================
    /// Validator uses an unsupported signature suite (M0).
    ///
    /// MainNet and TestNet require all validators to use ML-DSA-44 (suite_id 100).
    /// This prevents the slashing verification bypass where non-ML-DSA-44
    /// validators would skip cryptographic verification.
    ///
    /// See: SLASHING_INVARIANTS_AUDIT.md, Invariant 2 caveat.
    UnsupportedSignatureSuite {
        /// The validator ID using the unsupported suite.
        validator_id: u32,
        /// The unsupported suite ID.
        suite_id: u8,
    },
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
            MainnetConfigError::DiscoveryDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: dynamic peer discovery must be enabled (--discovery-enabled=true)"
                )
            }
            MainnetConfigError::InsufficientTargetOutboundPeers { minimum, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: target_outbound_peers must be at least {} but is {} (--target-outbound-peers={})",
                    minimum, actual, minimum
                )
            }
            MainnetConfigError::DiversityNotEnforced { actual } => {
                write!(
                    f,
                    "MainNet invariant violated: diversity_mode must be Enforce but is {} (--p2p-diversity-mode=enforce)",
                    actual
                )
            }
            MainnetConfigError::InvalidDiversityParameters => {
                write!(
                    f,
                    "MainNet invariant violated: diversity parameters must be sensible (non-zero caps, min_buckets>=2, fraction_bps in (0,10000])"
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
            MainnetConfigError::StateRetentionDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: state retention must be enabled (--state-retention-mode=height)"
                )
            }
            MainnetConfigError::StateRetentionInvalid(msg) => {
                write!(
                    f,
                    "MainNet invariant violated: state retention configuration invalid: {}",
                    msg
                )
            }
            // T210: Signer mode errors
            MainnetConfigError::SignerModeLoopbackForbidden => {
                write!(
                    f,
                    "MainNet invariant violated: signer mode 'loopback-testing' is forbidden on MainNet. \
                     Use 'encrypted-fs', 'remote-signer', or 'hsm-pkcs11' (--signer-mode=encrypted-fs)"
                )
            }
            MainnetConfigError::SignerKeystorePathMissing => {
                write!(
                    f,
                    "MainNet invariant violated: signer_keystore_path must be set when signer_mode is 'encrypted-fs' \
                     (--signer-keystore-path=/path/to/keystore)"
                )
            }
            MainnetConfigError::RemoteSignerUrlMissing => {
                write!(
                    f,
                    "MainNet invariant violated: remote_signer_url must be set when signer_mode is 'remote-signer' \
                     (--remote-signer-url=kemtls://localhost:9443)"
                )
            }
            MainnetConfigError::RemoteSignerUnreachable => {
                write!(
                    f,
                    "MainNet invariant violated: remote signer is unreachable at startup. \
                     Verify the remote signer is running and accessible at the configured URL."
                )
            }
            MainnetConfigError::HsmConfigPathMissing => {
                write!(
                    f,
                    "MainNet invariant violated: hsm_config_path must be set when signer_mode is 'hsm-pkcs11' \
                     (--hsm-config-path=/etc/qbind/hsm.toml)"
                )
            }
            // T214: Signer failure mode errors
            MainnetConfigError::SignerFailureModeInvalid { actual } => {
                write!(
                    f,
                    "MainNet invariant violated: signer_failure_mode must be 'exit-on-failure' but is '{}'. \
                     LogAndContinue is only allowed for dev/test chaos testing. \
                     (--signer-failure-mode=exit-on-failure)",
                    actual
                )
            }
            // T215: Snapshot configuration errors
            MainnetConfigError::SnapshotsDisabled => {
                write!(
                    f,
                    "MainNet invariant violated: snapshots must be enabled for fast sync and recovery \
                     (--enable-snapshots=true --snapshot-dir=/path/to/snapshots)"
                )
            }
            MainnetConfigError::SnapshotIntervalTooLow { minimum, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: snapshot_interval_blocks must be at least {} but is {} \
                     (--snapshot-interval={})",
                    minimum, actual, minimum
                )
            }
            MainnetConfigError::SnapshotIntervalTooHigh { maximum, actual } => {
                write!(
                    f,
                    "MainNet invariant violated: snapshot_interval_blocks must be at most {} but is {} \
                     (--snapshot-interval={})",
                    maximum, actual, maximum
                )
            }
            // T218: Mempool DoS configuration errors
            MainnetConfigError::MempoolDosMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: mempool DoS configuration is invalid: {}",
                    reason
                )
            }
            // T219: Mempool eviction rate limiting errors
            MainnetConfigError::MempoolEvictionMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: mempool eviction rate limiting configuration is invalid: {}",
                    reason
                )
            }
            // T226: P2P discovery and liveness errors
            MainnetConfigError::P2pDiscoveryMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: P2P discovery configuration is invalid: {}",
                    reason
                )
            }
            MainnetConfigError::P2pLivenessMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: P2P liveness configuration is invalid: {}",
                    reason
                )
            }
            // T231: P2P anti-eclipse configuration errors
            MainnetConfigError::P2pAntiEclipseMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: P2P anti-eclipse configuration is invalid: {}",
                    reason
                )
            }
            // T229: Slashing configuration errors
            MainnetConfigError::SlashingMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: slashing configuration is invalid: {}",
                    reason
                )
            }
            // T232: Genesis configuration errors
            MainnetConfigError::GenesisMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: genesis configuration is invalid: {} (--genesis-path=<path>)",
                    reason
                )
            }
            // T233: Expected genesis hash missing
            MainnetConfigError::ExpectedGenesisHashMissing => {
                write!(
                    f,
                    "MainNet invariant violated: expected genesis hash must be configured (--expect-genesis-hash=0x...)"
                )
            }
            // M2: Validator stake configuration errors
            MainnetConfigError::ValidatorStakeMisconfigured { reason } => {
                write!(
                    f,
                    "MainNet invariant violated: validator stake configuration is invalid: {}",
                    reason
                )
            }
            // M0: Unsupported signature suite
            MainnetConfigError::UnsupportedSignatureSuite { validator_id, suite_id } => {
                write!(
                    f,
                    "MainNet/TestNet invariant violated: validator {} uses unsupported signature suite {} \
                     (only ML-DSA-44 suite_id=100 is allowed); see SLASHING_INVARIANTS_AUDIT.md",
                    validator_id, suite_id
                )
            }
        }
    }
}

impl std::error::Error for MainnetConfigError {}

// ============================================================================
// M0: Validator Suite Validation
// ============================================================================

/// ML-DSA-44 suite ID constant (M0).
///
/// This is the only allowed signature suite for validators on MainNet and TestNet.
/// Using any other suite would bypass slashing cryptographic verification.
///
/// Value: 100 (derived from qbind_crypto::SUITE_PQ_RESERVED_1)
///
/// Note: This constant is derived at compile-time from the crypto crate to ensure
/// it stays synchronized with the canonical suite ID definition.
pub const ML_DSA_44_SUITE_ID: u8 = {
    let id = qbind_crypto::SUITE_PQ_RESERVED_1.as_u16();
    // Compile-time assertion that the value fits in u8
    assert!(id <= 255, "ML-DSA-44 suite ID must fit in u8");
    id as u8
};

/// Information about a validator for suite validation (M0).
///
/// This struct provides the minimal information needed to validate
/// that a validator uses an allowed signature suite.
#[derive(Debug, Clone)]
pub struct ValidatorSuiteInfo {
    /// The validator's ID.
    pub validator_id: u32,
    /// The validator's signature suite ID.
    pub suite_id: u8,
}

/// Validate that all validators use ML-DSA-44 signature suite (M0).
///
/// This function checks that every validator in the provided list uses
/// the ML-DSA-44 signature suite (suite_id = 100). This is required for
/// MainNet and TestNet to ensure slashing cryptographic verification
/// cannot be bypassed.
///
/// # Arguments
///
/// * `validators` - List of validators with their suite IDs
///
/// # Returns
///
/// `Ok(())` if all validators use ML-DSA-44, or `Err(MainnetConfigError)` with
/// the first validator found using an unsupported suite.
///
/// # Background
///
/// The slashing verification code in `qbind-consensus/src/slashing/mod.rs`
/// skips cryptographic verification for non-ML-DSA-44 validators (lines 551-556
/// and 637-642). This is intentional for backward compatibility with test suites,
/// but creates a security bypass if non-ML-DSA-44 validators exist in production.
///
/// See: SLASHING_INVARIANTS_AUDIT.md, Invariant 2 caveat.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::{validate_validators_use_ml_dsa_44, ValidatorSuiteInfo, ML_DSA_44_SUITE_ID};
///
/// // Valid: all validators use ML-DSA-44
/// let validators = vec![
///     ValidatorSuiteInfo { validator_id: 1, suite_id: ML_DSA_44_SUITE_ID },
///     ValidatorSuiteInfo { validator_id: 2, suite_id: ML_DSA_44_SUITE_ID },
/// ];
/// assert!(validate_validators_use_ml_dsa_44(&validators).is_ok());
///
/// // Invalid: validator 3 uses suite_id 1
/// let bad_validators = vec![
///     ValidatorSuiteInfo { validator_id: 1, suite_id: ML_DSA_44_SUITE_ID },
///     ValidatorSuiteInfo { validator_id: 3, suite_id: 1 },
/// ];
/// assert!(validate_validators_use_ml_dsa_44(&bad_validators).is_err());
/// ```
pub fn validate_validators_use_ml_dsa_44(
    validators: &[ValidatorSuiteInfo],
) -> Result<(), MainnetConfigError> {
    for validator in validators {
        if validator.suite_id != ML_DSA_44_SUITE_ID {
            return Err(MainnetConfigError::UnsupportedSignatureSuite {
                validator_id: validator.validator_id,
                suite_id: validator.suite_id,
            });
        }
    }
    Ok(())
}

// ============================================================================
// M0: TestNet Invariants Validation
// ============================================================================

/// Error indicating a TestNet configuration invariant violation (M0).
///
/// These errors are returned by `validate_testnet_invariants()` when the
/// configuration or validator set violates TestNet requirements.
///
/// TestNet nodes SHOULD refuse to start if any of these invariants are violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestnetConfigError {
    /// The network environment is not TestNet.
    WrongEnvironment {
        expected: NetworkEnvironment,
        actual: NetworkEnvironment,
    },

    /// Validator uses an unsupported signature suite (M0).
    ///
    /// TestNet requires all validators to use ML-DSA-44 (suite_id 100).
    /// This prevents the slashing verification bypass.
    UnsupportedSignatureSuite {
        /// The validator ID using the unsupported suite.
        validator_id: u32,
        /// The unsupported suite ID.
        suite_id: u8,
    },
}

impl std::fmt::Display for TestnetConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestnetConfigError::WrongEnvironment { expected, actual } => {
                write!(
                    f,
                    "TestNet invariant violated: environment must be {} but is {}",
                    expected, actual
                )
            }
            TestnetConfigError::UnsupportedSignatureSuite { validator_id, suite_id } => {
                write!(
                    f,
                    "TestNet invariant violated: validator {} uses unsupported signature suite {} \
                     (only ML-DSA-44 suite_id=100 is allowed); see SLASHING_INVARIANTS_AUDIT.md",
                    validator_id, suite_id
                )
            }
        }
    }
}

impl std::error::Error for TestnetConfigError {}

/// Validate TestNet invariants for a validator set (M0).
///
/// This function validates that a validator set satisfies TestNet requirements:
/// 1. All validators must use ML-DSA-44 signature suite (suite_id = 100)
///
/// # Arguments
///
/// * `environment` - The network environment (must be Testnet)
/// * `validators` - List of validators with their suite IDs
///
/// # Returns
///
/// `Ok(())` if all invariants are satisfied, or `Err(TestnetConfigError)` describing
/// the first violation found.
///
/// # Background
///
/// This validation closes the suite-bypass caveat documented in
/// SLASHING_INVARIANTS_AUDIT.md (Invariant 2). Without this check, validators
/// using non-ML-DSA-44 suites would bypass slashing cryptographic verification.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::{validate_testnet_invariants, ValidatorSuiteInfo, ML_DSA_44_SUITE_ID};
/// use qbind_types::NetworkEnvironment;
///
/// // Valid TestNet configuration
/// let validators = vec![
///     ValidatorSuiteInfo { validator_id: 1, suite_id: ML_DSA_44_SUITE_ID },
///     ValidatorSuiteInfo { validator_id: 2, suite_id: ML_DSA_44_SUITE_ID },
/// ];
/// assert!(validate_testnet_invariants(NetworkEnvironment::Testnet, &validators).is_ok());
///
/// // Invalid: wrong environment
/// assert!(validate_testnet_invariants(NetworkEnvironment::Devnet, &validators).is_err());
///
/// // Invalid: non-ML-DSA-44 validator
/// let bad_validators = vec![
///     ValidatorSuiteInfo { validator_id: 1, suite_id: 1 }, // Not ML-DSA-44
/// ];
/// assert!(validate_testnet_invariants(NetworkEnvironment::Testnet, &bad_validators).is_err());
/// ```
pub fn validate_testnet_invariants(
    environment: NetworkEnvironment,
    validators: &[ValidatorSuiteInfo],
) -> Result<(), TestnetConfigError> {
    // 1. Environment must be TestNet
    if environment != NetworkEnvironment::Testnet {
        return Err(TestnetConfigError::WrongEnvironment {
            expected: NetworkEnvironment::Testnet,
            actual: environment,
        });
    }

    // 2. All validators must use ML-DSA-44 (M0)
    for validator in validators {
        if validator.suite_id != ML_DSA_44_SUITE_ID {
            return Err(TestnetConfigError::UnsupportedSignatureSuite {
                validator_id: validator.validator_id,
                suite_id: validator.suite_id,
            });
        }
    }

    Ok(())
}

/// Validate MainNet invariants for a validator set (M0 extension).
///
/// This function validates that a validator set satisfies the additional
/// MainNet validator suite requirement:
/// - All validators must use ML-DSA-44 signature suite (suite_id = 100)
///
/// This is called after `NodeConfig::validate_mainnet_invariants()` when
/// the validator set is available.
///
/// # Arguments
///
/// * `validators` - List of validators with their suite IDs
///
/// # Returns
///
/// `Ok(())` if all validators use ML-DSA-44, or `Err(MainnetConfigError)` with
/// the first validator found using an unsupported suite.
///
/// # Example
///
/// ```rust
/// use qbind_node::node_config::{validate_mainnet_validator_suites, ValidatorSuiteInfo, ML_DSA_44_SUITE_ID};
///
/// // Valid: all validators use ML-DSA-44
/// let validators = vec![
///     ValidatorSuiteInfo { validator_id: 1, suite_id: ML_DSA_44_SUITE_ID },
///     ValidatorSuiteInfo { validator_id: 2, suite_id: ML_DSA_44_SUITE_ID },
/// ];
/// assert!(validate_mainnet_validator_suites(&validators).is_ok());
/// ```
pub fn validate_mainnet_validator_suites(
    validators: &[ValidatorSuiteInfo],
) -> Result<(), MainnetConfigError> {
    validate_validators_use_ml_dsa_44(validators)
}

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
            .with_signer_keystore_path("/tmp/test/keystore.json")
            .with_genesis_path("/tmp/test/genesis.json")
            .with_expected_genesis_hash([0u8; 32])
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
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_signer_keystore_path("/tmp/test/keystore.json")
            .with_genesis_path("/tmp/test/genesis.json")
            .with_expected_genesis_hash([0u8; 32]);

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
            .with_signer_keystore_path("/tmp/test/keystore.json")
            .with_genesis_path("/tmp/test/genesis.json")
            .with_expected_genesis_hash([0u8; 32])
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
            _ => panic!("Expected MonetaryAccountsInvalid error, got: {:?}", result),
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
            _ => panic!("Expected MonetaryAccountsInvalid error, got: {:?}", result),
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
            .with_signer_keystore_path("/tmp/test/keystore.json")
            .with_genesis_path("/tmp/test/genesis.json")
            .with_expected_genesis_hash([0u8; 32])
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
        let valid_accounts = MonetaryAccounts::new([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        assert!(valid_accounts.is_valid_for_mainnet());

        // Zero address should fail
        let accounts_with_zero = MonetaryAccounts::new([0u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        assert!(!accounts_with_zero.is_valid_for_mainnet());

        // Duplicates should fail
        let accounts_with_dup = MonetaryAccounts::new([1u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]);
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

    // ========================================================================
    // T206: Diversity Mode Tests
    // ========================================================================

    #[test]
    fn test_diversity_mode_devnet_default() {
        let config = NetworkTransportConfig::default();
        assert_eq!(
            config.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Off,
            "DevNet default should have diversity_mode = Off"
        );
    }

    #[test]
    fn test_diversity_mode_testnet_beta() {
        let config = NetworkTransportConfig::testnet_beta();
        assert_eq!(
            config.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Warn,
            "TestNet Beta should have diversity_mode = Warn"
        );
        assert_eq!(config.max_peers_per_ipv4_prefix24, 4);
        assert_eq!(config.max_peers_per_ipv4_prefix16, 16);
        assert_eq!(config.min_outbound_diversity_buckets, 2);
        assert_eq!(config.max_single_bucket_fraction_bps, 5000);
    }

    #[test]
    fn test_diversity_mode_mainnet() {
        let config = NetworkTransportConfig::mainnet();
        assert_eq!(
            config.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Enforce,
            "MainNet should have diversity_mode = Enforce"
        );
        assert_eq!(config.max_peers_per_ipv4_prefix24, 2);
        assert_eq!(config.max_peers_per_ipv4_prefix16, 8);
        assert_eq!(config.min_outbound_diversity_buckets, 4);
        assert_eq!(config.max_single_bucket_fraction_bps, 2500);
    }

    #[test]
    fn test_mainnet_preset_has_diversity_enforce() {
        let config = NodeConfig::mainnet_preset();
        assert_eq!(
            config.network.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Enforce,
            "MainNet preset should have diversity_mode = Enforce"
        );
    }

    #[test]
    fn test_mainnet_validation_rejects_diversity_not_enforce() {
        // Create a MainNet config but with diversity mode set to Off
        let mut config = NodeConfig::mainnet_preset().with_data_dir("/tmp/test");
        config.network.diversity_mode = crate::p2p_diversity::DiversityEnforcementMode::Off;

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when diversity_mode != Enforce"
        );
        match result {
            Err(MainnetConfigError::DiversityNotEnforced { actual }) => {
                assert_eq!(actual, crate::p2p_diversity::DiversityEnforcementMode::Off);
            }
            _ => panic!("Expected DiversityNotEnforced error, got: {:?}", result),
        }
    }

    #[test]
    fn test_mainnet_validation_rejects_diversity_warn() {
        // Create a MainNet config but with diversity mode set to Warn
        let mut config = NodeConfig::mainnet_preset().with_data_dir("/tmp/test");
        config.network.diversity_mode = crate::p2p_diversity::DiversityEnforcementMode::Warn;

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail when diversity_mode = Warn"
        );
        match result {
            Err(MainnetConfigError::DiversityNotEnforced { actual }) => {
                assert_eq!(actual, crate::p2p_diversity::DiversityEnforcementMode::Warn);
            }
            _ => panic!("Expected DiversityNotEnforced error, got: {:?}", result),
        }
    }

    #[test]
    fn test_mainnet_validation_accepts_diversity_enforce() {
        let config = NodeConfig::mainnet_preset()
            .with_data_dir("/tmp/test")
            .with_signer_keystore_path("/tmp/test/keystore.json")
            .with_genesis_path("/tmp/test/genesis.json")
            .with_expected_genesis_hash([0u8; 32]);

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_ok(),
            "MainNet validation should pass when diversity_mode = Enforce: {:?}",
            result
        );
    }

    #[test]
    fn test_mainnet_validation_rejects_invalid_diversity_params() {
        // Create a MainNet config but with invalid diversity parameters
        let mut config = NodeConfig::mainnet_preset().with_data_dir("/tmp/test");
        config.network.max_peers_per_ipv4_prefix24 = 0; // Invalid

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail with invalid diversity parameters"
        );
        match result {
            Err(MainnetConfigError::InvalidDiversityParameters) => (),
            _ => panic!(
                "Expected InvalidDiversityParameters error, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_mainnet_validation_rejects_invalid_min_buckets() {
        let mut config = NodeConfig::mainnet_preset().with_data_dir("/tmp/test");
        config.network.min_outbound_diversity_buckets = 1; // Invalid, must be >= 2

        let result = config.validate_mainnet_invariants();
        assert!(
            result.is_err(),
            "MainNet validation should fail with min_outbound_diversity_buckets < 2"
        );
        match result {
            Err(MainnetConfigError::InvalidDiversityParameters) => (),
            _ => panic!(
                "Expected InvalidDiversityParameters error, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_diversity_error_display() {
        let error = MainnetConfigError::DiversityNotEnforced {
            actual: crate::p2p_diversity::DiversityEnforcementMode::Off,
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("diversity_mode"));
        assert!(error_str.contains("Enforce"));
        assert!(error_str.contains("off"));
        assert!(error_str.contains("--p2p-diversity-mode=enforce"));
    }

    #[test]
    fn test_diversity_in_startup_info() {
        let config = NodeConfig::mainnet_preset();
        let info = config.startup_info_string(Some("V1"));
        assert!(
            info.contains("diversity=enforce"),
            "Startup info should show diversity=enforce for MainNet: {}",
            info
        );

        let config_off = NodeConfig::devnet_v0_preset();
        let info_off = config_off.startup_info_string(Some("V1"));
        assert!(
            info_off.contains("diversity=off"),
            "Startup info should show diversity=off for DevNet: {}",
            info_off
        );
    }

    #[test]
    fn test_devnet_allows_diversity_off() {
        let config = NodeConfig::devnet_v0_preset();
        assert_eq!(
            config.network.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Off,
            "DevNet should allow diversity_mode = Off"
        );
        // Note: DevNet doesn't have MainNet invariants so no validation to check
    }

    #[test]
    fn test_testnet_alpha_allows_diversity_off() {
        let config = NodeConfig::testnet_alpha_preset();
        assert_eq!(
            config.network.diversity_mode,
            crate::p2p_diversity::DiversityEnforcementMode::Off,
            "TestNet Alpha should allow diversity_mode = Off"
        );
    }

    // ========================================================================
    // T226: P2P Discovery and Liveness Config Tests
    // ========================================================================

    #[test]
    fn test_p2p_discovery_config_devnet_default() {
        let config = P2pDiscoveryConfig::devnet_default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 10);
        assert_eq!(config.max_known_peers, 200);
        assert_eq!(config.outbound_target, 4);
    }

    #[test]
    fn test_p2p_discovery_config_testnet_alpha_default() {
        let config = P2pDiscoveryConfig::testnet_alpha_default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.max_known_peers, 200);
        assert_eq!(config.outbound_target, 8);
    }

    #[test]
    fn test_p2p_discovery_config_testnet_beta_default() {
        let config = P2pDiscoveryConfig::testnet_beta_default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.max_known_peers, 200);
        assert_eq!(config.outbound_target, 8);
    }

    #[test]
    fn test_p2p_discovery_config_mainnet_default() {
        let config = P2pDiscoveryConfig::mainnet_default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.max_known_peers, 300);
        assert_eq!(config.outbound_target, 8);
    }

    #[test]
    fn test_p2p_discovery_config_disabled() {
        let config = P2pDiscoveryConfig::disabled();
        assert!(!config.enabled);
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_p2p_discovery_config_validate_mainnet_success() {
        let config = P2pDiscoveryConfig::mainnet_default();
        assert!(config.validate_for_mainnet().is_ok());
    }

    #[test]
    fn test_p2p_discovery_config_validate_mainnet_disabled() {
        let config = P2pDiscoveryConfig::disabled();
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("discovery must be enabled"));
    }

    #[test]
    fn test_p2p_discovery_config_validate_mainnet_low_outbound() {
        let config = P2pDiscoveryConfig {
            enabled: true,
            interval_secs: 30,
            max_known_peers: 200,
            outbound_target: 2, // Below minimum of 4
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outbound_target must be >= 4"));
    }

    #[test]
    fn test_p2p_discovery_config_validate_mainnet_max_known_too_low() {
        let config = P2pDiscoveryConfig {
            enabled: true,
            interval_secs: 30,
            max_known_peers: 5, // Less than outbound_target
            outbound_target: 8,
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_known_peers"));
    }

    #[test]
    fn test_p2p_liveness_config_devnet_default() {
        let config = P2pLivenessConfig::devnet_default();
        assert_eq!(config.heartbeat_interval_secs, 10);
        assert_eq!(config.heartbeat_timeout_secs, 5);
        assert_eq!(config.max_heartbeat_failures, 5);
    }

    #[test]
    fn test_p2p_liveness_config_testnet_alpha_default() {
        let config = P2pLivenessConfig::testnet_alpha_default();
        assert_eq!(config.heartbeat_interval_secs, 15);
        assert_eq!(config.heartbeat_timeout_secs, 10);
        assert_eq!(config.max_heartbeat_failures, 4);
    }

    #[test]
    fn test_p2p_liveness_config_testnet_beta_default() {
        let config = P2pLivenessConfig::testnet_beta_default();
        assert_eq!(config.heartbeat_interval_secs, 15);
        assert_eq!(config.heartbeat_timeout_secs, 10);
        assert_eq!(config.max_heartbeat_failures, 4);
    }

    #[test]
    fn test_p2p_liveness_config_mainnet_default() {
        let config = P2pLivenessConfig::mainnet_default();
        assert_eq!(config.heartbeat_interval_secs, 15);
        assert_eq!(config.heartbeat_timeout_secs, 10);
        assert_eq!(config.max_heartbeat_failures, 3);
    }

    #[test]
    fn test_p2p_liveness_config_disabled() {
        let config = P2pLivenessConfig::disabled();
        assert_eq!(config.heartbeat_interval_secs, 3600);
        assert_eq!(config.heartbeat_timeout_secs, 1800);
        assert_eq!(config.max_heartbeat_failures, 100);
    }

    #[test]
    fn test_p2p_liveness_config_validate_mainnet_success() {
        let config = P2pLivenessConfig::mainnet_default();
        assert!(config.validate_for_mainnet().is_ok());
    }

    #[test]
    fn test_p2p_liveness_config_validate_mainnet_zero_interval() {
        let config = P2pLivenessConfig {
            heartbeat_interval_secs: 0,
            heartbeat_timeout_secs: 5,
            max_heartbeat_failures: 3,
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("heartbeat_interval_secs must be > 0"));
    }

    #[test]
    fn test_p2p_liveness_config_validate_mainnet_zero_failures() {
        let config = P2pLivenessConfig {
            heartbeat_interval_secs: 15,
            heartbeat_timeout_secs: 10,
            max_heartbeat_failures: 0,
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("max_heartbeat_failures must be > 0"));
    }

    #[test]
    fn test_node_config_preset_discovery_liveness() {
        // DevNet preset
        let devnet = NodeConfig::devnet_v0_preset();
        assert!(devnet.p2p_discovery.enabled);
        assert_eq!(devnet.p2p_discovery.interval_secs, 10);
        assert_eq!(devnet.p2p_liveness.heartbeat_interval_secs, 10);
        assert_eq!(devnet.p2p_liveness.max_heartbeat_failures, 5);

        // TestNet Alpha preset
        let alpha = NodeConfig::testnet_alpha_preset();
        assert!(alpha.p2p_discovery.enabled);
        assert_eq!(alpha.p2p_discovery.interval_secs, 30);
        assert_eq!(alpha.p2p_liveness.heartbeat_interval_secs, 15);
        assert_eq!(alpha.p2p_liveness.max_heartbeat_failures, 4);

        // TestNet Beta preset
        let beta = NodeConfig::testnet_beta_preset();
        assert!(beta.p2p_discovery.enabled);
        assert_eq!(beta.p2p_discovery.interval_secs, 30);
        assert_eq!(beta.p2p_liveness.heartbeat_interval_secs, 15);
        assert_eq!(beta.p2p_liveness.max_heartbeat_failures, 4);

        // MainNet preset
        let mainnet = NodeConfig::mainnet_preset();
        assert!(mainnet.p2p_discovery.enabled);
        assert_eq!(mainnet.p2p_discovery.interval_secs, 30);
        assert_eq!(mainnet.p2p_discovery.max_known_peers, 300);
        assert_eq!(mainnet.p2p_liveness.heartbeat_interval_secs, 15);
        assert_eq!(mainnet.p2p_liveness.max_heartbeat_failures, 3);
    }

    #[test]
    fn test_node_config_with_discovery_config() {
        let custom_discovery = P2pDiscoveryConfig {
            enabled: true,
            interval_secs: 60,
            max_known_peers: 500,
            outbound_target: 16,
        };
        let config = NodeConfig::mainnet_preset().with_discovery_config(custom_discovery.clone());
        assert_eq!(config.p2p_discovery.interval_secs, 60);
        assert_eq!(config.p2p_discovery.max_known_peers, 500);
        assert_eq!(config.p2p_discovery.outbound_target, 16);
    }

    #[test]
    fn test_node_config_with_liveness_config() {
        let custom_liveness = P2pLivenessConfig {
            heartbeat_interval_secs: 30,
            heartbeat_timeout_secs: 20,
            max_heartbeat_failures: 5,
        };
        let config = NodeConfig::mainnet_preset().with_liveness_config(custom_liveness.clone());
        assert_eq!(config.p2p_liveness.heartbeat_interval_secs, 30);
        assert_eq!(config.p2p_liveness.heartbeat_timeout_secs, 20);
        assert_eq!(config.p2p_liveness.max_heartbeat_failures, 5);
    }

    #[test]
    fn test_mainnet_validation_discovery_disabled() {
        let mut config = NodeConfig::mainnet_preset()
            .with_data_dir("/data/qbind")
            .with_signer_keystore_path("/data/keystore")
            .with_snapshot_dir("/data/snapshots");
        config.p2p_discovery = P2pDiscoveryConfig::disabled();

        let result = config.validate_mainnet_invariants();
        assert!(result.is_err());
        match result.unwrap_err() {
            MainnetConfigError::P2pDiscoveryMisconfigured { reason } => {
                assert!(reason.contains("discovery must be enabled"));
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_mainnet_validation_liveness_invalid() {
        let mut config = NodeConfig::mainnet_preset()
            .with_data_dir("/data/qbind")
            .with_signer_keystore_path("/data/keystore")
            .with_snapshot_dir("/data/snapshots");
        config.p2p_liveness = P2pLivenessConfig {
            heartbeat_interval_secs: 0,
            heartbeat_timeout_secs: 5,
            max_heartbeat_failures: 3,
        };

        let result = config.validate_mainnet_invariants();
        assert!(result.is_err());
        match result.unwrap_err() {
            MainnetConfigError::P2pLivenessMisconfigured { reason } => {
                assert!(reason.contains("heartbeat_interval_secs must be > 0"));
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_mainnet_config_error_display_discovery() {
        let error = MainnetConfigError::P2pDiscoveryMisconfigured {
            reason: "discovery must be enabled for MainNet".to_string(),
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("P2P discovery configuration is invalid"));
        assert!(error_str.contains("discovery must be enabled"));
    }

    #[test]
    fn test_mainnet_config_error_display_liveness() {
        let error = MainnetConfigError::P2pLivenessMisconfigured {
            reason: "heartbeat_interval_secs must be > 0".to_string(),
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("P2P liveness configuration is invalid"));
        assert!(error_str.contains("heartbeat_interval_secs"));
    }

    // ========================================================================
    // T231: P2P Anti-Eclipse Config Tests
    // ========================================================================

    #[test]
    fn test_p2p_anti_eclipse_config_devnet_default() {
        let config = P2pAntiEclipseConfig::devnet_default();
        assert_eq!(config.max_peers_per_ipv4_prefix, 64);
        assert_eq!(config.min_outbound_peers, 4);
        assert_eq!(config.min_asn_diversity, 1);
        assert!(!config.enforce);
    }

    #[test]
    fn test_p2p_anti_eclipse_config_testnet_alpha_default() {
        let config = P2pAntiEclipseConfig::testnet_alpha_default();
        assert_eq!(config.max_peers_per_ipv4_prefix, 16);
        assert_eq!(config.min_outbound_peers, 6);
        assert_eq!(config.min_asn_diversity, 2);
        assert!(!config.enforce);
    }

    #[test]
    fn test_p2p_anti_eclipse_config_testnet_beta_default() {
        let config = P2pAntiEclipseConfig::testnet_beta_default();
        assert_eq!(config.max_peers_per_ipv4_prefix, 16);
        assert_eq!(config.min_outbound_peers, 6);
        assert_eq!(config.min_asn_diversity, 2);
        assert!(!config.enforce);
    }

    #[test]
    fn test_p2p_anti_eclipse_config_mainnet_default() {
        let config = P2pAntiEclipseConfig::mainnet_default();
        assert_eq!(config.max_peers_per_ipv4_prefix, 8);
        assert_eq!(config.min_outbound_peers, 8);
        assert_eq!(config.min_asn_diversity, 2);
        assert!(config.enforce);
    }

    #[test]
    fn test_p2p_anti_eclipse_config_disabled() {
        let config = P2pAntiEclipseConfig::disabled();
        assert_eq!(config.max_peers_per_ipv4_prefix, 128);
        assert_eq!(config.min_outbound_peers, 1);
        assert_eq!(config.min_asn_diversity, 1);
        assert!(!config.enforce);
    }

    #[test]
    fn test_p2p_anti_eclipse_config_validate_mainnet_success() {
        let config = P2pAntiEclipseConfig::mainnet_default();
        assert!(config.validate_for_mainnet().is_ok());
    }

    #[test]
    fn test_p2p_anti_eclipse_config_validate_mainnet_enforce_false() {
        let config = P2pAntiEclipseConfig {
            enforce: false,
            ..P2pAntiEclipseConfig::mainnet_default()
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("enforce must be true"));
    }

    #[test]
    fn test_p2p_anti_eclipse_config_validate_mainnet_zero_prefix() {
        let config = P2pAntiEclipseConfig {
            max_peers_per_ipv4_prefix: 0,
            ..P2pAntiEclipseConfig::mainnet_default()
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("max_peers_per_ipv4_prefix must be > 0"));
    }

    #[test]
    fn test_p2p_anti_eclipse_config_validate_mainnet_low_outbound() {
        let config = P2pAntiEclipseConfig {
            min_outbound_peers: 2, // Below minimum of 4
            ..P2pAntiEclipseConfig::mainnet_default()
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("min_outbound_peers must be >= 4"));
    }

    #[test]
    fn test_p2p_anti_eclipse_config_validate_mainnet_low_asn_diversity() {
        let config = P2pAntiEclipseConfig {
            min_asn_diversity: 1, // Below minimum of 2
            ..P2pAntiEclipseConfig::mainnet_default()
        };
        let result = config.validate_for_mainnet();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("min_asn_diversity must be >= 2"));
    }

    #[test]
    fn test_node_config_preset_anti_eclipse() {
        // DevNet preset
        let devnet = NodeConfig::devnet_v0_preset();
        let devnet_eclipse = devnet.p2p_anti_eclipse.as_ref().unwrap();
        assert_eq!(devnet_eclipse.max_peers_per_ipv4_prefix, 64);
        assert!(!devnet_eclipse.enforce);

        // TestNet Alpha preset
        let alpha = NodeConfig::testnet_alpha_preset();
        let alpha_eclipse = alpha.p2p_anti_eclipse.as_ref().unwrap();
        assert_eq!(alpha_eclipse.max_peers_per_ipv4_prefix, 16);
        assert!(!alpha_eclipse.enforce);

        // TestNet Beta preset
        let beta = NodeConfig::testnet_beta_preset();
        let beta_eclipse = beta.p2p_anti_eclipse.as_ref().unwrap();
        assert_eq!(beta_eclipse.max_peers_per_ipv4_prefix, 16);
        assert!(!beta_eclipse.enforce);

        // MainNet preset
        let mainnet = NodeConfig::mainnet_preset();
        let mainnet_eclipse = mainnet.p2p_anti_eclipse.as_ref().unwrap();
        assert_eq!(mainnet_eclipse.max_peers_per_ipv4_prefix, 8);
        assert!(mainnet_eclipse.enforce);
    }

    #[test]
    fn test_node_config_with_p2p_anti_eclipse_config() {
        let custom_eclipse = P2pAntiEclipseConfig {
            max_peers_per_ipv4_prefix: 4,
            min_outbound_peers: 10,
            min_asn_diversity: 3,
            enforce: true,
        };
        let config =
            NodeConfig::mainnet_preset().with_p2p_anti_eclipse_config(custom_eclipse.clone());
        let stored = config.p2p_anti_eclipse.as_ref().unwrap();
        assert_eq!(stored.max_peers_per_ipv4_prefix, 4);
        assert_eq!(stored.min_outbound_peers, 10);
        assert_eq!(stored.min_asn_diversity, 3);
        assert!(stored.enforce);
    }

    #[test]
    fn test_mainnet_validation_requires_anti_eclipse_config() {
        let mut config = NodeConfig::mainnet_preset()
            .with_data_dir("/data/qbind".to_string())
            .with_signer_keystore_path("/keystore".to_string());
        config.p2p_anti_eclipse = None;

        let result = config.validate_mainnet_invariants();
        assert!(result.is_err());
        match result.unwrap_err() {
            MainnetConfigError::P2pAntiEclipseMisconfigured { reason } => {
                assert!(reason.contains("p2p_anti_eclipse must be configured"));
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_mainnet_validation_anti_eclipse_enforce_required() {
        let mut config = NodeConfig::mainnet_preset()
            .with_data_dir("/data/qbind".to_string())
            .with_signer_keystore_path("/keystore".to_string());
        config.p2p_anti_eclipse = Some(P2pAntiEclipseConfig {
            enforce: false,
            ..P2pAntiEclipseConfig::mainnet_default()
        });

        let result = config.validate_mainnet_invariants();
        assert!(result.is_err());
        match result.unwrap_err() {
            MainnetConfigError::P2pAntiEclipseMisconfigured { reason } => {
                assert!(reason.contains("enforce must be true"));
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_mainnet_config_error_display_anti_eclipse() {
        let error = MainnetConfigError::P2pAntiEclipseMisconfigured {
            reason: "enforce must be true for MainNet".to_string(),
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("P2P anti-eclipse configuration is invalid"));
        assert!(error_str.contains("enforce must be true"));
    }

    // ========================================================================
    // M0: Validator Suite Validation Tests
    // ========================================================================

    #[test]
    fn test_ml_dsa_44_suite_id_constant() {
        // Verify the constant matches the expected value from qbind-crypto
        assert_eq!(ML_DSA_44_SUITE_ID, 100);
    }

    #[test]
    fn test_validate_validators_use_ml_dsa_44_accepts_valid() {
        // All validators use ML-DSA-44 - should pass
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 3,
                suite_id: ML_DSA_44_SUITE_ID,
            },
        ];
        let result = validate_validators_use_ml_dsa_44(&validators);
        assert!(
            result.is_ok(),
            "Should accept validators using ML-DSA-44"
        );
    }

    #[test]
    fn test_validate_validators_use_ml_dsa_44_rejects_non_ml_dsa() {
        // Validator 2 uses suite_id 1 (not ML-DSA-44) - should fail
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: 1, // Non-ML-DSA-44 suite
            },
            ValidatorSuiteInfo {
                validator_id: 3,
                suite_id: ML_DSA_44_SUITE_ID,
            },
        ];
        let result = validate_validators_use_ml_dsa_44(&validators);
        assert!(result.is_err(), "Should reject non-ML-DSA-44 validators");

        match result.unwrap_err() {
            MainnetConfigError::UnsupportedSignatureSuite {
                validator_id,
                suite_id,
            } => {
                assert_eq!(validator_id, 2, "Should identify validator 2");
                assert_eq!(suite_id, 1, "Should identify suite_id 1");
            }
            e => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_validate_validators_use_ml_dsa_44_empty_set() {
        // Empty validator set - should pass (vacuously true)
        let validators: Vec<ValidatorSuiteInfo> = vec![];
        let result = validate_validators_use_ml_dsa_44(&validators);
        assert!(result.is_ok(), "Should accept empty validator set");
    }

    #[test]
    fn test_validate_testnet_invariants_accepts_valid() {
        // Valid TestNet configuration with ML-DSA-44 validators
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: ML_DSA_44_SUITE_ID,
            },
        ];
        let result = validate_testnet_invariants(NetworkEnvironment::Testnet, &validators);
        assert!(
            result.is_ok(),
            "TestNet should accept ML-DSA-44 validators"
        );
    }

    #[test]
    fn test_validate_testnet_invariants_rejects_wrong_environment() {
        let validators = vec![ValidatorSuiteInfo {
            validator_id: 1,
            suite_id: ML_DSA_44_SUITE_ID,
        }];

        // DevNet environment should be rejected
        let result = validate_testnet_invariants(NetworkEnvironment::Devnet, &validators);
        assert!(result.is_err(), "Should reject DevNet environment");
        match result.unwrap_err() {
            TestnetConfigError::WrongEnvironment { expected, actual } => {
                assert_eq!(expected, NetworkEnvironment::Testnet);
                assert_eq!(actual, NetworkEnvironment::Devnet);
            }
            e => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_validate_testnet_invariants_rejects_non_ml_dsa() {
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: 0, // Toy suite (SUITE_TOY_SHA3)
            },
        ];
        let result = validate_testnet_invariants(NetworkEnvironment::Testnet, &validators);
        assert!(
            result.is_err(),
            "TestNet should reject non-ML-DSA-44 validators"
        );
        match result.unwrap_err() {
            TestnetConfigError::UnsupportedSignatureSuite {
                validator_id,
                suite_id,
            } => {
                assert_eq!(validator_id, 2);
                assert_eq!(suite_id, 0);
            }
            e => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_validate_mainnet_validator_suites_accepts_valid() {
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: ML_DSA_44_SUITE_ID,
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: ML_DSA_44_SUITE_ID,
            },
        ];
        let result = validate_mainnet_validator_suites(&validators);
        assert!(
            result.is_ok(),
            "MainNet should accept ML-DSA-44 validators"
        );
    }

    #[test]
    fn test_validate_mainnet_validator_suites_rejects_non_ml_dsa() {
        let validators = vec![ValidatorSuiteInfo {
            validator_id: 42,
            suite_id: 3, // Some other suite
        }];
        let result = validate_mainnet_validator_suites(&validators);
        assert!(
            result.is_err(),
            "MainNet should reject non-ML-DSA-44 validators"
        );
        match result.unwrap_err() {
            MainnetConfigError::UnsupportedSignatureSuite {
                validator_id,
                suite_id,
            } => {
                assert_eq!(validator_id, 42);
                assert_eq!(suite_id, 3);
            }
            e => panic!("Unexpected error type: {:?}", e),
        }
    }

    #[test]
    fn test_devnet_allows_non_ml_dsa_validators() {
        // DevNet does NOT have suite validation - this is intentional to allow
        // legacy test suites. The validate_testnet_invariants function will
        // fail for DevNet environment (wrong environment), but there's no
        // DevNet-specific validation that checks suite IDs.
        //
        // This test documents the expected behavior: DevNet allows any suite_id.
        let validators = vec![
            ValidatorSuiteInfo {
                validator_id: 1,
                suite_id: 1, // Non-ML-DSA-44 - allowed on DevNet
            },
            ValidatorSuiteInfo {
                validator_id: 2,
                suite_id: 0, // Toy suite - allowed on DevNet
            },
        ];

        // DevNet has no suite validation, so validators can use any suite.
        // The validate_validators_use_ml_dsa_44 function would fail, but
        // it's not called for DevNet deployments.
        //
        // This is the expected behavior for backward compatibility with test suites.
        let _ = validators; // DevNet does not validate suite IDs
    }

    #[test]
    fn test_mainnet_config_error_display_unsupported_suite() {
        let error = MainnetConfigError::UnsupportedSignatureSuite {
            validator_id: 42,
            suite_id: 1,
        };
        let error_str = format!("{}", error);
        assert!(error_str.contains("validator 42"));
        assert!(error_str.contains("unsupported signature suite 1"));
        assert!(error_str.contains("ML-DSA-44"));
        assert!(error_str.contains("SLASHING_INVARIANTS_AUDIT.md"));
    }

    #[test]
    fn test_testnet_config_error_display() {
        // Test wrong environment error
        let env_error = TestnetConfigError::WrongEnvironment {
            expected: NetworkEnvironment::Testnet,
            actual: NetworkEnvironment::Devnet,
        };
        let env_error_str = format!("{}", env_error);
        assert!(env_error_str.contains("TestNet invariant violated"));
        assert!(env_error_str.contains("TestNet"));
        assert!(env_error_str.contains("DevNet"));

        // Test unsupported suite error
        let suite_error = TestnetConfigError::UnsupportedSignatureSuite {
            validator_id: 5,
            suite_id: 2,
        };
        let suite_error_str = format!("{}", suite_error);
        assert!(suite_error_str.contains("validator 5"));
        assert!(suite_error_str.contains("unsupported signature suite 2"));
        assert!(suite_error_str.contains("ML-DSA-44"));
    }

    // ========================================================================
    // M2: ValidatorStakeConfig Tests
    // ========================================================================

    #[test]
    fn test_validator_stake_config_devnet_default() {
        let config = ValidatorStakeConfig::devnet_default();
        assert_eq!(config.min_validator_stake, MIN_VALIDATOR_STAKE_DEVNET);
        assert_eq!(config.min_validator_stake, 1_000_000); // 1 QBIND
        assert!(!config.fail_fast_on_startup);
    }

    #[test]
    fn test_validator_stake_config_testnet_default() {
        let config = ValidatorStakeConfig::testnet_default();
        assert_eq!(config.min_validator_stake, MIN_VALIDATOR_STAKE_TESTNET);
        assert_eq!(config.min_validator_stake, 10_000_000); // 10 QBIND
        assert!(!config.fail_fast_on_startup);
    }

    #[test]
    fn test_validator_stake_config_mainnet_default() {
        let config = ValidatorStakeConfig::mainnet_default();
        assert_eq!(config.min_validator_stake, MIN_VALIDATOR_STAKE_MAINNET);
        assert_eq!(config.min_validator_stake, 100_000_000_000); // 100,000 QBIND
        assert!(config.fail_fast_on_startup);
    }

    #[test]
    fn test_validator_stake_config_is_stake_sufficient() {
        let config = ValidatorStakeConfig::devnet_default();

        // Below threshold
        assert!(!config.is_stake_sufficient(999_999));

        // At threshold
        assert!(config.is_stake_sufficient(1_000_000));

        // Above threshold
        assert!(config.is_stake_sufficient(1_000_001));
        assert!(config.is_stake_sufficient(u64::MAX));
    }

    #[test]
    fn test_validator_stake_config_validate_for_mainnet() {
        // Valid MainNet config
        let valid = ValidatorStakeConfig::mainnet_default();
        assert!(valid.validate_for_mainnet().is_ok());

        // Invalid: stake too low
        let low_stake = ValidatorStakeConfig {
            min_validator_stake: MIN_VALIDATOR_STAKE_MAINNET - 1,
            fail_fast_on_startup: true,
        };
        let err = low_stake.validate_for_mainnet();
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("min_validator_stake"));

        // Invalid: fail_fast disabled
        let no_fail_fast = ValidatorStakeConfig {
            min_validator_stake: MIN_VALIDATOR_STAKE_MAINNET,
            fail_fast_on_startup: false,
        };
        let err = no_fail_fast.validate_for_mainnet();
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("fail_fast_on_startup"));
    }

    #[test]
    fn test_devnet_preset_validator_stake() {
        let config = NodeConfig::devnet_v0_preset();
        assert_eq!(
            config.validator_stake.min_validator_stake,
            MIN_VALIDATOR_STAKE_DEVNET
        );
        assert!(!config.validator_stake.fail_fast_on_startup);
    }

    #[test]
    fn test_testnet_alpha_preset_validator_stake() {
        let config = NodeConfig::testnet_alpha_preset();
        assert_eq!(
            config.validator_stake.min_validator_stake,
            MIN_VALIDATOR_STAKE_TESTNET
        );
        assert!(!config.validator_stake.fail_fast_on_startup);
    }

    #[test]
    fn test_testnet_beta_preset_validator_stake() {
        let config = NodeConfig::testnet_beta_preset();
        assert_eq!(
            config.validator_stake.min_validator_stake,
            MIN_VALIDATOR_STAKE_TESTNET
        );
        assert!(!config.validator_stake.fail_fast_on_startup);
    }

    #[test]
    fn test_mainnet_preset_validator_stake() {
        let config = NodeConfig::mainnet_preset();
        assert_eq!(
            config.validator_stake.min_validator_stake,
            MIN_VALIDATOR_STAKE_MAINNET
        );
        assert!(config.validator_stake.fail_fast_on_startup);
    }
}