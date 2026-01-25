//! Channel capacity configuration for the Canonot async runtime and network.
//!
//! This module provides `ChannelCapacityConfig`, a configuration struct that
//! centralizes all configurable channel capacities used by the async runtime,
//! network adapters, and peer manager.
//!
//! # Design (T90.2)
//!
//! This configuration layer enables tuning of mpsc channel capacities without
//! changing protocol semantics:
//!
//! - **ConsensusEvent channel**: Buffer for events sent to `AsyncNodeRunner`
//! - **Outbound command channel**: Buffer for outbound consensus messages
//! - **Async peer manager channels**: Per-peer inbound/outbound buffers
//!
//! # Environment Variable Overrides
//!
//! All capacity values can be overridden via environment variables:
//!
//! - `CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY`: ConsensusEvent channel capacity
//! - `CANO_OUTBOUND_COMMAND_CHANNEL_CAPACITY`: Outbound command channel capacity
//! - `CANO_ASYNC_PEER_INBOUND_CAPACITY`: AsyncPeerManager inbound channel capacity
//! - `CANO_ASYNC_PEER_OUTBOUND_CAPACITY`: AsyncPeerManager outbound channel capacity
//!
//! Environment variables are parsed on `ChannelCapacityConfig::from_env()`.
//! Invalid values trigger a warning and fall back to defaults.
//!
//! # Logging
//!
//! NOTE: This module uses `eprintln!` for debug output and warnings. In production,
//! this should be replaced with a proper logging framework (e.g., `tracing` or `log`)
//! to enable configurable log levels and structured logging.
//!
//! # Example
//!
//! ```ignore
//! use cano_node::channel_config::ChannelCapacityConfig;
//!
//! // Use defaults
//! let config = ChannelCapacityConfig::default();
//!
//! // Build with custom values
//! let config = ChannelCapacityConfig::default()
//!     .with_consensus_event_capacity(2048)
//!     .with_outbound_command_capacity(512);
//!
//! // Load from environment variables
//! let config = ChannelCapacityConfig::from_env();
//! ```

use std::env;

/// Configuration for async channel capacities in the Canonot node.
///
/// This struct centralizes all configurable channel capacities, providing:
/// - Default values matching current behavior (1024 for most channels)
/// - Builder methods for programmatic customization
/// - Environment variable parsing for operational tuning
///
/// # Default Values
///
/// | Field                        | Default | Description                            |
/// |------------------------------|---------|----------------------------------------|
/// | `consensus_event_capacity`   | 1024    | ConsensusEvent channel to AsyncRunner  |
/// | `outbound_command_capacity`  | 1024    | OutboundCommand channel for net sends  |
/// | `async_peer_inbound_capacity`| 1024    | AsyncPeerManager inbound events        |
/// | `async_peer_outbound_capacity`| 256    | AsyncPeerManager per-peer outbound     |
///
/// # Thread Safety
///
/// This struct is `Clone` and `Send + Sync`, so it can be shared across
/// tasks during node initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCapacityConfig {
    /// Capacity of the ConsensusEvent channel (AsyncNodeRunner).
    ///
    /// This channel buffers events from network workers to the consensus
    /// event loop. Higher values allow more buffering during traffic bursts.
    pub consensus_event_capacity: usize,

    /// Capacity of the outbound command channel (AsyncNetSender).
    ///
    /// This channel buffers outbound consensus messages (votes, proposals)
    /// waiting to be sent over the network.
    pub outbound_command_capacity: usize,

    /// Capacity of the AsyncPeerManager inbound event channel.
    ///
    /// This channel aggregates ConsensusNetworkEvents from all peer reader
    /// tasks. Used when the `async-peer-manager` feature is enabled.
    pub async_peer_inbound_capacity: usize,

    /// Capacity of AsyncPeerManager per-peer outbound channels.
    ///
    /// Each connected peer has a dedicated outbound channel. Lower values
    /// provide earlier backpressure per-peer; higher values allow more
    /// buffering per connection.
    pub async_peer_outbound_capacity: usize,
}

impl Default for ChannelCapacityConfig {
    fn default() -> Self {
        ChannelCapacityConfig {
            consensus_event_capacity: 1024,
            outbound_command_capacity: 1024,
            async_peer_inbound_capacity: 1024,
            async_peer_outbound_capacity: 256,
        }
    }
}

impl ChannelCapacityConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the ConsensusEvent channel capacity.
    pub fn with_consensus_event_capacity(mut self, capacity: usize) -> Self {
        self.consensus_event_capacity = capacity;
        self
    }

    /// Set the outbound command channel capacity.
    pub fn with_outbound_command_capacity(mut self, capacity: usize) -> Self {
        self.outbound_command_capacity = capacity;
        self
    }

    /// Set the AsyncPeerManager inbound channel capacity.
    pub fn with_async_peer_inbound_capacity(mut self, capacity: usize) -> Self {
        self.async_peer_inbound_capacity = capacity;
        self
    }

    /// Set the AsyncPeerManager per-peer outbound channel capacity.
    pub fn with_async_peer_outbound_capacity(mut self, capacity: usize) -> Self {
        self.async_peer_outbound_capacity = capacity;
        self
    }

    /// Load configuration from environment variables.
    ///
    /// Reads the following environment variables:
    /// - `CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY`
    /// - `CANO_OUTBOUND_COMMAND_CHANNEL_CAPACITY`
    /// - `CANO_ASYNC_PEER_INBOUND_CAPACITY`
    /// - `CANO_ASYNC_PEER_OUTBOUND_CAPACITY`
    ///
    /// Invalid values (non-numeric or < 1) trigger a warning via `eprintln!`
    /// and fall back to defaults.
    ///
    /// # Example
    ///
    /// ```bash
    /// # Set environment variable before running tests or applications
    /// CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY=2048 cargo test -p cano-node
    /// ```
    pub fn from_env() -> Self {
        let mut config = Self::default();
        let mut overrides = Vec::new();

        if let Some(val) = parse_env_capacity("CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY") {
            config.consensus_event_capacity = val;
            overrides.push(format!("event={}", val));
        }

        if let Some(val) = parse_env_capacity("CANO_OUTBOUND_COMMAND_CHANNEL_CAPACITY") {
            config.outbound_command_capacity = val;
            overrides.push(format!("outbound={}", val));
        }

        if let Some(val) = parse_env_capacity("CANO_ASYNC_PEER_INBOUND_CAPACITY") {
            config.async_peer_inbound_capacity = val;
            overrides.push(format!("async_peer_in={}", val));
        }

        if let Some(val) = parse_env_capacity("CANO_ASYNC_PEER_OUTBOUND_CAPACITY") {
            config.async_peer_outbound_capacity = val;
            overrides.push(format!("async_peer_out={}", val));
        }

        config
    }

    /// Log the effective channel capacities.
    ///
    /// Outputs a structured log line summarizing the configured values.
    /// Call this during node startup to record the effective configuration.
    ///
    /// # Arguments
    ///
    /// * `used_env` - Whether environment variables were used to override defaults.
    pub fn log_effective_capacities(&self, used_env: bool) {
        let source = if used_env {
            "env overrides"
        } else {
            "defaults"
        };
        eprintln!(
            "[ChannelCapacityConfig] channel capacities: event={} outbound={} async_peer_in={} async_peer_out={} ({})",
            self.consensus_event_capacity,
            self.outbound_command_capacity,
            self.async_peer_inbound_capacity,
            self.async_peer_outbound_capacity,
            source
        );
    }

    /// Check if any environment variables were set (for logging purposes).
    pub fn has_env_overrides() -> bool {
        env::var("CANO_CONSENSUS_EVENT_CHANNEL_CAPACITY").is_ok()
            || env::var("CANO_OUTBOUND_COMMAND_CHANNEL_CAPACITY").is_ok()
            || env::var("CANO_ASYNC_PEER_INBOUND_CAPACITY").is_ok()
            || env::var("CANO_ASYNC_PEER_OUTBOUND_CAPACITY").is_ok()
    }
}

/// Parse a capacity value from an environment variable.
///
/// Returns `Some(value)` if the variable is set and contains a valid usize >= 1.
/// Returns `None` if the variable is unset.
/// Logs a warning and returns `None` if the value is invalid.
fn parse_env_capacity(var_name: &str) -> Option<usize> {
    match env::var(var_name) {
        Ok(val) => match val.parse::<usize>() {
            Ok(n) if n >= 1 => Some(n),
            Ok(n) => {
                eprintln!(
                    "[ChannelCapacityConfig] WARNING: {} value {} is invalid (must be >= 1), using default",
                    var_name, n
                );
                None
            }
            Err(e) => {
                eprintln!(
                    "[ChannelCapacityConfig] WARNING: {} value '{}' is not a valid number ({}), using default",
                    var_name, val, e
                );
                None
            }
        },
        Err(_) => None,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = ChannelCapacityConfig::default();
        assert_eq!(config.consensus_event_capacity, 1024);
        assert_eq!(config.outbound_command_capacity, 1024);
        assert_eq!(config.async_peer_inbound_capacity, 1024);
        assert_eq!(config.async_peer_outbound_capacity, 256);
    }

    #[test]
    fn builder_methods_work() {
        let config = ChannelCapacityConfig::new()
            .with_consensus_event_capacity(2048)
            .with_outbound_command_capacity(512)
            .with_async_peer_inbound_capacity(4096)
            .with_async_peer_outbound_capacity(128);

        assert_eq!(config.consensus_event_capacity, 2048);
        assert_eq!(config.outbound_command_capacity, 512);
        assert_eq!(config.async_peer_inbound_capacity, 4096);
        assert_eq!(config.async_peer_outbound_capacity, 128);
    }

    #[test]
    fn config_is_clone_and_eq() {
        let config1 = ChannelCapacityConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1, config2);
    }

    #[test]
    fn config_debug_impl() {
        let config = ChannelCapacityConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ChannelCapacityConfig"));
        assert!(debug_str.contains("1024"));
    }

    // Note: Environment variable tests would need to be run in isolation
    // to avoid interference. These are better as integration tests.
}
