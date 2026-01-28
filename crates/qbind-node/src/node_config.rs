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

use qbind_types::{ChainId, NetworkEnvironment};
use std::path::PathBuf;

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

    /// Create a MainNet configuration.
    pub fn mainnet() -> Self {
        Self::new(NetworkEnvironment::Mainnet)
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
    /// qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only
    /// ```
    pub fn log_startup_info(&self, validator_id: Option<&str>) {
        let validator_str = validator_id.unwrap_or("none");
        let chain_id_hex = format!("0x{:016x}", self.chain_id().as_u64());

        println!(
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={} profile={}",
            validator_str,
            self.environment,
            chain_id_hex,
            self.scope(),
            self.execution_profile
        );
    }

    /// Format startup information as a string (for use in custom logging).
    ///
    /// # Arguments
    ///
    /// * `validator_id` - Optional validator identifier for logging
    ///
    /// # Returns
    ///
    /// A formatted string with environment information.
    pub fn startup_info_string(&self, validator_id: Option<&str>) -> String {
        let validator_str = validator_id.unwrap_or("none");
        let chain_id_hex = format!("0x{:016x}", self.chain_id().as_u64());

        format!(
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={} profile={}",
            validator_str,
            self.environment,
            chain_id_hex,
            self.scope(),
            self.execution_profile
        )
    }
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
}
