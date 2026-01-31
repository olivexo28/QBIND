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
    parse_environment, parse_execution_profile, parse_network_mode, NetworkMode,
    NetworkTransportConfig, NodeConfig, ParseEnvironmentError,
};

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
    /// # Returns
    ///
    /// `Ok(NodeConfig)` if all arguments are valid.
    /// `Err(CliError)` if any argument is invalid.
    pub fn to_node_config(&self) -> Result<NodeConfig, CliError> {
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
        };

        // Build NodeConfig
        let mut config = NodeConfig {
            environment,
            execution_profile,
            data_dir: self.data_dir.clone(),
            network,
            network_mode,
        };

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
}
