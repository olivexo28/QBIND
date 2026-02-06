//! T175: CLI argument parsing for qbind-node binary.
//!
//! This module provides the command-line interface for running a QBIND node.
//! It supports configuration of:
//! - Network environment (DevNet/TestNet/MainNet)
//! - Execution profile (nonce-only/vm-v0)
//! - Network mode (local-mesh/p2p)
//! - P2P settings (listen address, advertised address, static peers)
//!
//! # Usage
//!
//! ```bash
//! # DevNet with default settings
//! qbind-node --env devnet
//!
//! # TestNet Alpha with P2P enabled
//! qbind-node \
//!   --env testnet \
//!   --execution-profile vm-v0 \
//!   --network-mode p2p \
//!   --enable-p2p \
//!   --p2p-listen-addr 0.0.0.0:19000 \
//!   --p2p-peer 127.0.0.1:19001 \
//!   --p2p-peer 127.0.0.1:19002 \
//!   --validator-id 0
//! ```
//!
//! # DevNet v0 Freeze
//!
//! DevNet defaults remain `LocalMesh` + `enable_p2p = false` to preserve
//! the DevNet v0 freeze. P2P mode is opt-in for TestNet Alpha experimentation.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use crate::node_config::{
    parse_config_profile, parse_dag_coupling_mode, parse_environment, parse_execution_profile,
    parse_mempool_mode, parse_network_mode, parse_signer_mode, parse_state_retention_mode,
    DagCouplingMode, MempoolMode, NetworkMode, NetworkTransportConfig, NodeConfig,
    ParseEnvironmentError, SignerFailureMode, SignerMode, StateRetentionConfig,
};
use crate::p2p_diversity::parse_diversity_mode;
use qbind_ledger::{parse_monetary_mode, FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};

// ============================================================================
// CLI Arguments
// ============================================================================

/// QBIND Node - Post-Quantum Blockchain Node
///
/// A validator or full node for the QBIND blockchain network.
/// Supports DevNet, TestNet, and MainNet environments with optional
/// P2P networking for multi-process deployments.
#[derive(Parser, Debug, Clone)]
#[command(name = "qbind-node")]
#[command(version = "0.1.0")]
#[command(about = "QBIND blockchain node with PQC consensus", long_about = None)]
pub struct CliArgs {
    // ========================================================================
    // T180/T185: Configuration Profile (takes precedence over individual settings)
    // ========================================================================
    /// Configuration profile: devnet-v0, testnet-alpha, testnet-beta, or mainnet.
    ///
    /// When specified, provides a canonical configuration preset.
    /// Individual settings below can still override specific values.
    ///
    /// - devnet-v0: Frozen DevNet (NonceOnly, FIFO, LocalMesh)
    /// - testnet-alpha: TestNet Alpha (VmV0, gas off, FIFO, LocalMesh)
    /// - testnet-beta: TestNet Beta (VmV0, gas on, DAG, P2P)
    /// - mainnet: MainNet v0 (VmV0, gas required, DAG required, P2P required)
    ///
    /// If not specified, falls back to building config from individual flags.
    ///
    /// NOTE: MainNet profile enforces strict invariants. See validate_mainnet_invariants().
    #[arg(long = "profile", short = 'P')]
    pub profile: Option<String>,

    // ========================================================================
    // Environment & Execution
    // ========================================================================
    /// Network environment: devnet, testnet, or mainnet.
    ///
    /// Determines the chain ID and domain scope for signing operations.
    /// Default: devnet
    #[arg(long = "env", short = 'e', default_value = "devnet")]
    pub environment: String,

    /// Execution profile: nonce-only or vm-v0.
    ///
    /// - nonce-only: DevNet default, nonce-based execution
    /// - vm-v0: TestNet Alpha, VM with account balances
    /// Default: nonce-only
    #[arg(long = "execution-profile", default_value = "nonce-only")]
    pub execution_profile: String,

    // ========================================================================
    // T180: Gas & Fee Priority
    // ========================================================================
    /// Enable gas enforcement.
    ///
    /// When true, transactions are validated and executed with gas metering.
    /// Default: false (DevNet/Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-gas")]
    pub enable_gas: Option<bool>,

    /// Enable fee-priority mempool ordering.
    ///
    /// When true, transactions are ordered by max_fee_per_gas and effective_fee.
    /// Requires gas enforcement to be meaningful.
    /// Default: false (DevNet/Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-fee-priority")]
    pub enable_fee_priority: Option<bool>,

    // ========================================================================
    // T180: Mempool Mode
    // ========================================================================
    /// Mempool mode: fifo or dag.
    ///
    /// - fifo: Traditional FIFO queue (DevNet/Alpha default)
    /// - dag: DAG-based mempool with batches (TestNet Beta default)
    #[arg(long = "mempool-mode")]
    pub mempool_mode: Option<String>,

    /// Enable DAG availability certificates.
    ///
    /// Only meaningful when mempool-mode is 'dag'.
    /// Default: false (Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-dag-availability")]
    pub enable_dag_availability: Option<bool>,

    // ========================================================================
    // T186: Stage B Parallel Execution
    // ========================================================================
    /// Enable Stage B parallel execution.
    ///
    /// When enabled, uses conflict-graph-based parallel execution for VM v0.
    /// Produces identical results as sequential execution but with improved throughput.
    ///
    /// Default: false (DevNet/Alpha/Beta default). MainNet preset enables this.
    #[arg(long = "enable-stage-b")]
    pub enable_stage_b: Option<bool>,

    // ========================================================================
    // T189: DAG Coupling Mode
    // ========================================================================
    /// DAG–consensus coupling mode: off, warn, or enforce.
    ///
    /// Controls how the consensus layer interacts with DAG availability certificates:
    /// - off: No coupling; consensus ignores DAG certificates (DevNet/TestNet default)
    /// - warn: Log warnings for uncertified batches but don't reject (testing)
    /// - enforce: Reject proposals with uncertified batches (MainNet required)
    ///
    /// MainNet profile requires `enforce` mode.
    #[arg(long = "dag-coupling-mode")]
    pub dag_coupling_mode: Option<String>,

    // ========================================================================
    // T197: Monetary Mode
    // ========================================================================
    /// Monetary engine mode: off, shadow, or active.
    ///
    /// Controls the monetary engine's behavior:
    /// - off: No decisions, no metrics, no issuance (DevNet default)
    /// - shadow: Decisions + metrics only, no state changes (TestNet default)
    /// - active: Decisions + metrics + minting + seigniorage split
    ///
    /// MainNet profile requires at least `shadow` mode (cannot be `off`).
    #[arg(long = "monetary-mode")]
    pub monetary_mode: Option<String>,

    // ========================================================================
    // Network Mode & P2P
    // ========================================================================
    /// Network mode: local-mesh or p2p.
    ///
    /// - local-mesh: Existing local/loopback networking (default)
    /// - p2p: P2P transport via TcpKemTlsP2pService
    /// Default: local-mesh
    #[arg(long = "network-mode", default_value = "local-mesh")]
    pub network_mode: String,

    /// Enable P2P networking.
    ///
    /// When true and network-mode is p2p, starts the P2P transport service.
    /// Default: false (DevNet freeze preserved)
    #[arg(long = "enable-p2p", default_value = "false")]
    pub enable_p2p: bool,

    /// P2P listen address (host:port).
    ///
    /// The address to bind the P2P listener to.
    /// Default: 127.0.0.1:0 (OS-assigned port)
    #[arg(long = "p2p-listen-addr", default_value = "127.0.0.1:0")]
    pub p2p_listen_addr: String,

    /// P2P advertised address (host:port).
    ///
    /// The address to advertise to peers. If not specified, uses listen_addr.
    /// Useful when behind NAT or load balancers.
    #[arg(long = "p2p-advertised-addr")]
    pub p2p_advertised_addr: Option<String>,

    /// Static peer addresses (host:port).
    ///
    /// Peers to connect to at startup. Can be specified multiple times.
    /// Example: --p2p-peer 192.168.1.10:19000 --p2p-peer 192.168.1.11:19000
    #[arg(long = "p2p-peer", action = clap::ArgAction::Append)]
    pub p2p_peers: Vec<String>,

    // ========================================================================
    // Node Identity & Storage
    // ========================================================================
    /// Validator ID (0-based index).
    ///
    /// The validator's index in the validator set.
    #[arg(long = "validator-id", short = 'v')]
    pub validator_id: Option<u64>,

    /// Data directory for persistent state.
    ///
    /// When specified, enables persistent storage (e.g., RocksDB for VM v0).
    /// When not specified, uses in-memory state only.
    #[arg(long = "data-dir", short = 'd')]
    pub data_dir: Option<PathBuf>,

    // ========================================================================
    // P2P Tuning
    // ========================================================================
    /// Maximum outbound P2P connections.
    ///
    /// Default: 16
    #[arg(long = "p2p-max-outbound", default_value = "16")]
    pub p2p_max_outbound: usize,

    /// Maximum inbound P2P connections.
    ///
    /// Default: 64
    #[arg(long = "p2p-max-inbound", default_value = "64")]
    pub p2p_max_inbound: usize,

    /// P2P gossip fanout.
    ///
    /// Number of peers to forward gossip messages to.
    /// Default: 6
    #[arg(long = "p2p-gossip-fanout", default_value = "6")]
    pub p2p_gossip_fanout: usize,

    // ========================================================================
    // T206: P2P Diversity Mode (Anti-Eclipse)
    // ========================================================================
    /// P2P diversity enforcement mode: off, warn, or enforce (T206).
    ///
    /// Controls anti-eclipse IP-prefix diversity constraints:
    /// - off: No diversity checks (DevNet, TestNet Alpha default)
    /// - warn: Log warnings but allow connections (TestNet Beta default)
    /// - enforce: Reject connections that violate limits (MainNet required)
    ///
    /// MainNet profile requires `enforce` mode.
    #[arg(long = "p2p-diversity-mode")]
    pub p2p_diversity_mode: Option<String>,

    // ========================================================================
    // T208: State Retention Configuration
    // ========================================================================
    /// State retention mode: disabled or height (T208).
    ///
    /// Controls how the node manages historical state data:
    /// - disabled: Retain all historical state (DevNet, TestNet Alpha default)
    /// - height: Prune state below `current_height - retain_height` (TestNet Beta, MainNet default)
    ///
    /// MainNet profile requires `height` mode for disk space management.
    #[arg(long = "state-retention-mode")]
    pub state_retention_mode: Option<String>,

    /// Number of blocks of history to retain when state-retention-mode is 'height' (T208).
    ///
    /// State data below `current_height - retain_height` may be pruned.
    ///
    /// Recommended values:
    /// - TestNet Beta: 100_000 (~6 days at 5s blocks)
    /// - MainNet: 500_000 (~30 days at 5s blocks)
    #[arg(long = "state-retain-height")]
    pub state_retain_height: Option<u64>,

    /// Interval (in committed blocks) between state pruning runs (T208).
    ///
    /// Pruning is triggered every N blocks to amortize the cost.
    ///
    /// Default: 1_000 blocks (~83 minutes at 5s blocks)
    #[arg(long = "state-prune-interval")]
    pub state_prune_interval: Option<u64>,

    // ========================================================================
    // T210: Signer Mode Configuration
    // ========================================================================
    /// Signer mode for validator key management (T210).
    ///
    /// Controls how the validator signing key is stored and accessed:
    /// - loopback-testing: In-memory keys for testing (DevNet only, forbidden on MainNet)
    /// - encrypted-fs: Encrypted filesystem keystore (recommended for TestNet/MainNet)
    /// - remote-signer: External signer service via gRPC/Unix socket
    /// - hsm-pkcs11: Hardware Security Module via PKCS#11 interface
    ///
    /// MainNet profile forbids 'loopback-testing' mode.
    #[arg(long = "signer-mode")]
    pub signer_mode: Option<String>,

    /// Path to the encrypted keystore directory (T210).
    ///
    /// Required when signer-mode is 'encrypted-fs'.
    /// The keystore stores validator signing keys encrypted at rest.
    ///
    /// Example: /data/qbind/keystore
    #[arg(long = "signer-keystore-path")]
    pub signer_keystore_path: Option<PathBuf>,

    /// URL for the remote signer service (T210).
    ///
    /// Required when signer-mode is 'remote-signer'.
    /// Supports grpc://, http://, or unix:// schemes.
    ///
    /// Examples:
    /// - grpc://localhost:50051
    /// - unix:///var/run/qbind-signer.sock
    #[arg(long = "remote-signer-url")]
    pub remote_signer_url: Option<String>,

    /// Path to the HSM/PKCS#11 configuration file (T210).
    ///
    /// Required when signer-mode is 'hsm-pkcs11'.
    /// Contains PKCS#11 library path, slot ID, and key label.
    ///
    /// Example: /etc/qbind/hsm.toml
    #[arg(long = "hsm-config-path")]
    pub hsm_config_path: Option<PathBuf>,
}

// ============================================================================
// CLI Error Types
// ============================================================================

/// Errors that can occur during CLI argument parsing and validation.
#[derive(Debug, Clone)]
pub enum CliError {
    /// Invalid environment string.
    InvalidEnvironment(ParseEnvironmentError),
    /// Invalid socket address.
    InvalidAddress {
        field: String,
        value: String,
        reason: String,
    },
    /// Configuration validation error.
    ConfigValidation(String),
    /// Invalid profile string (T180, T185).
    InvalidProfile(String),
    /// MainNet configuration invariant violation (T185).
    MainnetConfigInvalid(String),
    /// Invalid DAG coupling mode string (T189).
    InvalidDagCouplingMode(String),
    /// Invalid monetary mode string (T197).
    InvalidMonetaryMode(String),
    /// Invalid diversity mode string (T206).
    InvalidDiversityMode(String),
    /// Invalid state retention mode string (T208).
    InvalidStateRetentionMode(String),
    /// Invalid signer mode string (T210).
    InvalidSignerMode(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::InvalidEnvironment(e) => write!(f, "invalid environment: {}", e),
            CliError::InvalidAddress {
                field,
                value,
                reason,
            } => {
                write!(f, "invalid {} '{}': {}", field, value, reason)
            }
            CliError::ConfigValidation(msg) => write!(f, "config validation error: {}", msg),
            CliError::InvalidProfile(s) => {
                write!(
                    f,
                    "invalid profile '{}': expected 'devnet-v0', 'testnet-alpha', 'testnet-beta', or 'mainnet'",
                    s
                )
            }
            CliError::MainnetConfigInvalid(msg) => {
                write!(f, "MainNet configuration invalid: {}", msg)
            }
            CliError::InvalidDagCouplingMode(s) => {
                write!(
                    f,
                    "invalid dag-coupling-mode '{}': expected 'off', 'warn', or 'enforce'",
                    s
                )
            }
            CliError::InvalidMonetaryMode(s) => {
                write!(
                    f,
                    "invalid monetary-mode '{}': expected 'off', 'shadow', or 'active'",
                    s
                )
            }
            CliError::InvalidDiversityMode(s) => {
                write!(
                    f,
                    "invalid p2p-diversity-mode '{}': expected 'off', 'warn', or 'enforce'",
                    s
                )
            }
            CliError::InvalidStateRetentionMode(s) => {
                write!(
                    f,
                    "invalid state-retention-mode '{}': expected 'disabled' or 'height'",
                    s
                )
            }
            CliError::InvalidSignerMode(s) => {
                write!(
                    f,
                    "invalid signer-mode '{}': expected 'loopback-testing', 'encrypted-fs', 'remote-signer', or 'hsm-pkcs11'",
                    s
                )
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<ParseEnvironmentError> for CliError {
    fn from(e: ParseEnvironmentError) -> Self {
        CliError::InvalidEnvironment(e)
    }
}

// ============================================================================
// CLI Argument Processing
// ============================================================================

impl CliArgs {
    /// Parse CLI arguments from the command line.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parse a socket address from a string.
    pub fn parse_addr(s: &str, field: &str) -> Result<SocketAddr, CliError> {
        s.parse().map_err(|e| CliError::InvalidAddress {
            field: field.to_string(),
            value: s.to_string(),
            reason: format!("{}", e),
        })
    }

    /// Build a NodeConfig from CLI arguments.
    ///
    /// This method parses and validates all CLI arguments, building a complete
    /// NodeConfig suitable for node startup.
    ///
    /// # T180: Profile-Based Configuration
    ///
    /// If `--profile` is specified, the base configuration comes from the
    /// corresponding preset (devnet-v0, testnet-alpha, testnet-beta).
    /// Individual flags then override specific values.
    ///
    /// # Returns
    ///
    /// `Ok(NodeConfig)` if all arguments are valid.
    /// `Err(CliError)` if any argument is invalid.
    pub fn to_node_config(&self) -> Result<NodeConfig, CliError> {
        // T180: If a profile is specified, start from the preset
        let mut config = if let Some(ref profile_str) = self.profile {
            match parse_config_profile(profile_str) {
                Some(profile) => {
                    let preset = NodeConfig::from_profile(profile);
                    // Log that we're using a profile
                    eprintln!(
                        "[T180] Using configuration profile: {} (gas={}, fee-priority={}, mempool={}, network={})",
                        profile,
                        if preset.gas_enabled { "on" } else { "off" },
                        if preset.enable_fee_priority { "on" } else { "off" },
                        preset.mempool_mode,
                        preset.network_mode
                    );
                    preset
                }
                None => {
                    return Err(CliError::InvalidProfile(profile_str.clone()));
                }
            }
        } else {
            // No profile specified, build from individual flags (legacy behavior)
            // Parse environment
            let environment = parse_environment(&self.environment)?;

            // Parse execution profile
            let execution_profile = parse_execution_profile(&self.execution_profile);

            // Parse network mode
            let network_mode = parse_network_mode(&self.network_mode);

            // Parse P2P listen address
            let listen_addr = if self.enable_p2p && network_mode == NetworkMode::P2p {
                Some(self.p2p_listen_addr.clone())
            } else {
                None
            };

            // Parse P2P advertised address
            let advertised_addr = self.p2p_advertised_addr.clone();

            // Collect static peers
            let static_peers = self.p2p_peers.clone();

            // Build NetworkTransportConfig
            let network = NetworkTransportConfig {
                enable_p2p: self.enable_p2p,
                max_outbound: self.p2p_max_outbound,
                max_inbound: self.p2p_max_inbound,
                gossip_fanout: self.p2p_gossip_fanout,
                listen_addr,
                advertised_addr,
                static_peers,
                // T205: Discovery defaults (disabled for legacy path)
                discovery_enabled: false,
                discovery_interval_secs: 30,
                max_known_peers: 200,
                target_outbound_peers: 8,
                // T205: Liveness defaults
                liveness_probe_interval_secs: 30,
                liveness_failure_threshold: 3,
                liveness_min_score: 30,
                // T206: Diversity defaults (Off for legacy path)
                diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Off,
                max_peers_per_ipv4_prefix24: 2,
                max_peers_per_ipv4_prefix16: 8,
                min_outbound_diversity_buckets: 4,
                max_single_bucket_fraction_bps: 2500,
            };

            NodeConfig {
                environment,
                execution_profile,
                data_dir: self.data_dir.clone(),
                network,
                network_mode,
                gas_enabled: false,
                enable_fee_priority: false,
                mempool_mode: MempoolMode::Fifo,
                dag_availability_enabled: false,
                dag_coupling_mode: DagCouplingMode::Off,
                stage_b_enabled: false,
                fee_distribution_policy: FeeDistributionPolicy::burn_only(), // T193
                // T197: Default to Off for backward compatibility
                monetary_mode: MonetaryMode::Off,
                monetary_accounts: None,
                seigniorage_split: SeigniorageSplit::default(),
                // T208: State retention disabled by default for legacy path
                state_retention: StateRetentionConfig::disabled(),
                // T210: Loopback signer for legacy path (testing default)
                signer_mode: SignerMode::LoopbackTesting,
                signer_keystore_path: None,
                remote_signer_url: None,
                hsm_config_path: None,
                // T214: Exit on failure is the default
                signer_failure_mode: SignerFailureMode::ExitOnFailure,
            }
        };

        // Apply CLI overrides on top of the base config (profile or legacy)
        // Only override if the flag was explicitly provided
        if let Some(gas) = self.enable_gas {
            if self.profile.is_some() {
                eprintln!("[T180] CLI override: gas_enabled = {}", gas);
            }
            config.gas_enabled = gas;
        }

        if let Some(fee_priority) = self.enable_fee_priority {
            if self.profile.is_some() {
                eprintln!(
                    "[T180] CLI override: enable_fee_priority = {}",
                    fee_priority
                );
            }
            config.enable_fee_priority = fee_priority;
        }

        if let Some(ref mempool_mode_str) = self.mempool_mode {
            let mode = parse_mempool_mode(mempool_mode_str);
            if self.profile.is_some() {
                eprintln!("[T180] CLI override: mempool_mode = {}", mode);
            }
            config.mempool_mode = mode;
        }

        if let Some(dag_avail) = self.enable_dag_availability {
            if self.profile.is_some() {
                eprintln!(
                    "[T180] CLI override: dag_availability_enabled = {}",
                    dag_avail
                );
            }
            config.dag_availability_enabled = dag_avail;
        }

        // T189: Apply DAG coupling mode override
        if let Some(ref coupling_mode_str) = self.dag_coupling_mode {
            match parse_dag_coupling_mode(coupling_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T189] CLI override: dag_coupling_mode = {}", mode);
                    }
                    config.dag_coupling_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidDagCouplingMode(coupling_mode_str.clone()));
                }
            }
        }

        // T197: Apply monetary mode override
        if let Some(ref monetary_mode_str) = self.monetary_mode {
            match parse_monetary_mode(monetary_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T197] CLI override: monetary_mode = {}", mode);
                    }
                    config.monetary_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidMonetaryMode(monetary_mode_str.clone()));
                }
            }
        }

        // T186: Apply Stage B override
        if let Some(stage_b) = self.enable_stage_b {
            if self.profile.is_some() {
                eprintln!("[T186] CLI override: stage_b_enabled = {}", stage_b);
            }
            config.stage_b_enabled = stage_b;
        }

        // T206: Apply diversity mode override
        if let Some(ref diversity_mode_str) = self.p2p_diversity_mode {
            match parse_diversity_mode(diversity_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T206] CLI override: diversity_mode = {}", mode);
                    }
                    config.network.diversity_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidDiversityMode(diversity_mode_str.clone()));
                }
            }
        }

        // T208: Apply state retention mode override
        if let Some(ref retention_mode_str) = self.state_retention_mode {
            match parse_state_retention_mode(retention_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T208] CLI override: state_retention.mode = {}", mode);
                    }
                    config.state_retention.mode = mode;
                }
                None => {
                    return Err(CliError::InvalidStateRetentionMode(
                        retention_mode_str.clone(),
                    ));
                }
            }
        }

        // T208: Apply state retain height override
        if let Some(retain_height) = self.state_retain_height {
            if self.profile.is_some() {
                eprintln!(
                    "[T208] CLI override: state_retention.retain_height = {}",
                    retain_height
                );
            }
            config.state_retention.retain_height = Some(retain_height);
        }

        // T208: Apply state prune interval override
        if let Some(prune_interval) = self.state_prune_interval {
            if self.profile.is_some() {
                eprintln!(
                    "[T208] CLI override: state_retention.prune_interval_blocks = {}",
                    prune_interval
                );
            }
            config.state_retention.prune_interval_blocks = prune_interval;
        }

        // T210: Apply signer mode override
        if let Some(ref signer_mode_str) = self.signer_mode {
            match parse_signer_mode(signer_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T210] CLI override: signer_mode = {}", mode);
                    }
                    config.signer_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidSignerMode(signer_mode_str.clone()));
                }
            }
        }

        // T210: Apply signer keystore path override
        if let Some(ref path) = self.signer_keystore_path {
            if self.profile.is_some() {
                eprintln!(
                    "[T210] CLI override: signer_keystore_path = {}",
                    path.display()
                );
            }
            config.signer_keystore_path = Some(path.clone());
        }

        // T210: Apply remote signer URL override
        if let Some(ref url) = self.remote_signer_url {
            if self.profile.is_some() {
                eprintln!("[T210] CLI override: remote_signer_url = {}", url);
            }
            config.remote_signer_url = Some(url.clone());
        }

        // T210: Apply HSM config path override
        if let Some(ref path) = self.hsm_config_path {
            if self.profile.is_some() {
                eprintln!("[T210] CLI override: hsm_config_path = {}", path.display());
            }
            config.hsm_config_path = Some(path.clone());
        }

        // Apply data_dir if specified
        if let Some(ref data_dir) = self.data_dir {
            config.data_dir = Some(data_dir.clone());
        }

        // If not using a profile, network flags apply directly.
        // If using a profile, still allow network-level overrides.
        if self.profile.is_some() {
            // For profile mode, check if user explicitly overrode network settings.
            // Detection logic:
            // - If --network-mode is anything other than the default "local-mesh", user explicitly set it
            // - If --enable-p2p is true (non-default), user explicitly set it
            //
            // This allows: `--profile testnet-beta --network-mode local-mesh` to override
            // Beta's P2P default back to LocalMesh for CI testing.
            let cli_network_mode = parse_network_mode(&self.network_mode);
            let user_explicitly_set_network =
                cli_network_mode != NetworkMode::LocalMesh || self.enable_p2p;

            if user_explicitly_set_network {
                // User explicitly set network flags - override the profile's defaults
                config.network_mode = cli_network_mode;
                config.network.enable_p2p = self.enable_p2p;

                if self.enable_p2p && cli_network_mode == NetworkMode::P2p {
                    config.network.listen_addr = Some(self.p2p_listen_addr.clone());
                }
            }

            // Always allow P2P tuning overrides (these have no "detection" default issue)
            config.network.max_outbound = self.p2p_max_outbound;
            config.network.max_inbound = self.p2p_max_inbound;
            config.network.gossip_fanout = self.p2p_gossip_fanout;

            // Apply peer list if provided
            if !self.p2p_peers.is_empty() {
                config.network.static_peers = self.p2p_peers.clone();
            }

            if self.p2p_advertised_addr.is_some() {
                config.network.advertised_addr = self.p2p_advertised_addr.clone();
            }
        }

        // Validate P2P configuration
        config.validate_p2p_config();

        Ok(config)
    }

    /// Get the validator ID as a string for logging.
    pub fn validator_id_str(&self) -> String {
        self.validator_id
            .map(|id| format!("V{}", id))
            .unwrap_or_else(|| "none".to_string())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_types::NetworkEnvironment;

    #[test]
    fn test_cli_args_default_values() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert_eq!(args.environment, "devnet");
        assert_eq!(args.execution_profile, "nonce-only");
        assert_eq!(args.network_mode, "local-mesh");
        assert!(!args.enable_p2p);
        assert_eq!(args.p2p_listen_addr, "127.0.0.1:0");
        assert!(args.p2p_advertised_addr.is_none());
        assert!(args.p2p_peers.is_empty());
        assert!(args.validator_id.is_none());
        assert!(args.data_dir.is_none());
    }

    #[test]
    fn test_cli_args_testnet_p2p() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--execution-profile",
            "vm-v0",
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--p2p-listen-addr",
            "0.0.0.0:19000",
            "--p2p-advertised-addr",
            "203.0.113.10:19000",
            "--p2p-peer",
            "127.0.0.1:19001",
            "--p2p-peer",
            "127.0.0.1:19002",
            "--validator-id",
            "0",
        ])
        .unwrap();

        assert_eq!(args.environment, "testnet");
        assert_eq!(args.execution_profile, "vm-v0");
        assert_eq!(args.network_mode, "p2p");
        assert!(args.enable_p2p);
        assert_eq!(args.p2p_listen_addr, "0.0.0.0:19000");
        assert_eq!(
            args.p2p_advertised_addr,
            Some("203.0.113.10:19000".to_string())
        );
        assert_eq!(args.p2p_peers, vec!["127.0.0.1:19001", "127.0.0.1:19002"]);
        assert_eq!(args.validator_id, Some(0));
    }

    #[test]
    fn test_cli_args_to_node_config() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--p2p-listen-addr",
            "127.0.0.1:19000",
            "--p2p-peer",
            "127.0.0.1:19001",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.network_mode, NetworkMode::P2p);
        assert!(config.network.enable_p2p);
        assert_eq!(
            config.network.listen_addr,
            Some("127.0.0.1:19000".to_string())
        );
        assert_eq!(config.network.static_peers, vec!["127.0.0.1:19001"]);
    }

    #[test]
    fn test_cli_args_parse_addr_valid() {
        let addr = CliArgs::parse_addr("127.0.0.1:8080", "test").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_cli_args_parse_addr_invalid() {
        let result = CliArgs::parse_addr("invalid:addr:here", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_id_str() {
        let mut args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert_eq!(args.validator_id_str(), "none");

        args.validator_id = Some(5);
        assert_eq!(args.validator_id_str(), "V5");
    }

    // ========================================================================
    // T180: Profile Flag Tests
    // ========================================================================

    #[test]
    fn test_cli_profile_testnet_beta() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "testnet-beta"]).unwrap();

        assert_eq!(args.profile, Some("testnet-beta".to_string()));

        let config = args.to_node_config().unwrap();

        // Verify Beta defaults
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(config.gas_enabled, "Beta profile should enable gas");
        assert!(
            config.enable_fee_priority,
            "Beta profile should enable fee priority"
        );
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Dag,
            "Beta profile should use DAG mempool"
        );
        assert!(
            config.dag_availability_enabled,
            "Beta profile should enable DAG availability"
        );
        assert_eq!(
            config.network_mode,
            NetworkMode::P2p,
            "Beta profile should use P2P network mode"
        );
        assert!(config.network.enable_p2p, "Beta profile should enable P2P");
    }

    #[test]
    fn test_cli_profile_testnet_alpha() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "testnet-alpha"]).unwrap();

        let config = args.to_node_config().unwrap();

        // Verify Alpha defaults
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(
            !config.gas_enabled,
            "Alpha profile should have gas disabled"
        );
        assert!(
            !config.enable_fee_priority,
            "Alpha profile should have fee priority disabled"
        );
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Fifo,
            "Alpha profile should use FIFO mempool"
        );
        assert_eq!(
            config.network_mode,
            NetworkMode::LocalMesh,
            "Alpha profile should use LocalMesh"
        );
    }

    #[test]
    fn test_cli_profile_devnet_v0() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "devnet-v0"]).unwrap();

        let config = args.to_node_config().unwrap();

        // Verify DevNet defaults
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert!(!config.gas_enabled);
        assert!(!config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Fifo);
        assert_eq!(config.network_mode, NetworkMode::LocalMesh);
    }

    #[test]
    fn test_cli_profile_with_override() {
        // Start with Beta profile but override gas to false
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--profile",
            "testnet-beta",
            "--enable-gas",
            "false",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        // Gas should be overridden to false
        assert!(!config.gas_enabled, "CLI override should disable gas");
        // But other Beta defaults should remain
        assert!(config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Dag);
    }

    #[test]
    fn test_cli_profile_invalid() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "invalid-profile"]).unwrap();

        let result = args.to_node_config();
        assert!(result.is_err());
        match result {
            Err(CliError::InvalidProfile(s)) => {
                assert_eq!(s, "invalid-profile");
            }
            _ => panic!("Expected InvalidProfile error"),
        }
    }

    #[test]
    fn test_cli_profile_short_flag() {
        let args = CliArgs::try_parse_from(["qbind-node", "-P", "beta"]).unwrap();

        let config = args.to_node_config().unwrap();

        // "beta" should be parsed as testnet-beta
        assert!(config.gas_enabled);
        assert!(config.enable_fee_priority);
    }

    #[test]
    fn test_cli_default_values_include_t180_fields() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();

        // New T180 fields should have None as default (not specified)
        assert!(args.profile.is_none());
        assert!(args.enable_gas.is_none());
        assert!(args.enable_fee_priority.is_none());
        assert!(args.mempool_mode.is_none());
        assert!(args.enable_dag_availability.is_none());
    }

    #[test]
    fn test_cli_legacy_mode_without_profile() {
        // Without --profile, the legacy behavior should still work
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--execution-profile",
            "vm-v0",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        // Should have DevNet-like defaults (gas off, fee off, FIFO)
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(!config.gas_enabled);
        assert!(!config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Fifo);
    }

    // ========================================================================
    // T189: DAG Coupling Mode CLI Tests
    // ========================================================================

    #[test]
    fn test_cli_dag_coupling_mode_flag() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "enforce"]).unwrap();

        assert_eq!(args.dag_coupling_mode, Some("enforce".to_string()));
    }

    #[test]
    fn test_cli_dag_coupling_mode_off() {
        let args = CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "off"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Off);
    }

    #[test]
    fn test_cli_dag_coupling_mode_warn() {
        let args = CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "warn"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Warn);
    }

    #[test]
    fn test_cli_dag_coupling_mode_enforce() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "enforce"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Enforce);
    }

    #[test]
    fn test_cli_dag_coupling_mode_invalid() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "invalid"]).unwrap();

        let result = args.to_node_config();
        assert!(result.is_err());
        match result {
            Err(CliError::InvalidDagCouplingMode(s)) => {
                assert_eq!(s, "invalid");
            }
            _ => panic!("Expected InvalidDagCouplingMode error"),
        }
    }

    #[test]
    fn test_cli_dag_coupling_mode_case_insensitive() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "ENFORCE"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Enforce);
    }

    #[test]
    fn test_cli_dag_coupling_mode_with_profile() {
        // Profile mainnet sets Enforce by default
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "mainnet"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Enforce,
            "MainNet profile should default to Enforce"
        );
    }

    #[test]
    fn test_cli_dag_coupling_mode_override_profile() {
        // Start with testnet-beta profile (Off) and override to Warn
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--profile",
            "testnet-beta",
            "--dag-coupling-mode",
            "warn",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Warn,
            "CLI override should set dag_coupling_mode to Warn"
        );
    }

    #[test]
    fn test_cli_default_dag_coupling_mode_none() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert!(args.dag_coupling_mode.is_none());
    }
}