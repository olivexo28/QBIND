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
/// # Example
///
/// ```rust,ignore
/// use qbind_node::node_config::NodeConfig;
/// use qbind_types::NetworkEnvironment;
///
/// let config = NodeConfig::new(NetworkEnvironment::Testnet);
/// assert_eq!(config.environment, NetworkEnvironment::Testnet);
/// assert_eq!(config.chain_id().as_u64(), 0x51424E44_54535400);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    /// The network environment for this node.
    ///
    /// Determines the chain ID and domain scope used for all
    /// signing and verification operations.
    pub environment: NetworkEnvironment,
}

impl Default for NodeConfig {
    /// Default configuration uses DevNet environment.
    ///
    /// This ensures backward compatibility with existing code and scripts
    /// that don't explicitly specify an environment.
    fn default() -> Self {
        Self {
            environment: NetworkEnvironment::Devnet,
        }
    }
}

impl NodeConfig {
    /// Create a new node configuration with the specified environment.
    pub fn new(environment: NetworkEnvironment) -> Self {
        Self { environment }
    }

    /// Create a DevNet configuration.
    ///
    /// Convenience method for the most common test/dev case.
    pub fn devnet() -> Self {
        Self::new(NetworkEnvironment::Devnet)
    }

    /// Create a TestNet configuration.
    pub fn testnet() -> Self {
        Self::new(NetworkEnvironment::Testnet)
    }

    /// Create a MainNet configuration.
    pub fn mainnet() -> Self {
        Self::new(NetworkEnvironment::Mainnet)
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
    /// qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV
    /// ```
    pub fn log_startup_info(&self, validator_id: Option<&str>) {
        let validator_str = validator_id.unwrap_or("none");
        let chain_id_hex = format!("0x{:016x}", self.chain_id().as_u64());

        println!(
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={}",
            validator_str,
            self.environment,
            chain_id_hex,
            self.scope()
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
            "qbind-node[validator={}]: starting in environment={} chain_id={} scope={}",
            validator_str,
            self.environment,
            chain_id_hex,
            self.scope()
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
    }

    #[test]
    fn test_node_config_devnet() {
        let config = NodeConfig::devnet();
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert_eq!(config.chain_id(), QBIND_DEVNET_CHAIN_ID);
        assert_eq!(config.scope(), "DEV");
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::testnet();
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.chain_id(), QBIND_TESTNET_CHAIN_ID);
        assert_eq!(config.scope(), "TST");
    }

    #[test]
    fn test_node_config_mainnet() {
        let config = NodeConfig::mainnet();
        assert_eq!(config.environment, NetworkEnvironment::Mainnet);
        assert_eq!(config.chain_id(), QBIND_MAINNET_CHAIN_ID);
        assert_eq!(config.scope(), "MAIN");
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
}