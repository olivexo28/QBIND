//! T206: P2P Anti-Eclipse Diversity Constraints
//!
//! This module provides IP-prefix-based anti-eclipse constraints for QBIND's P2P layer.
//! It classifies peer IP addresses into diversity buckets and enforces limits on the
//! number of peers from the same network prefix.
//!
//! # Overview
//!
//! Anti-eclipse protection prevents attackers from monopolizing a node's peer connections.
//! By limiting the number of connections from the same IP prefix, we ensure that an
//! attacker would need control over many distinct network ranges to eclipse a node.
//!
//! # Bucket Classification
//!
//! - **IPv4 /24**: Primary bucket (same /24 subnet)
//! - **IPv4 /16**: Secondary cap (same /16 network)
//! - **IPv6 /48**: For IPv6 addresses (site-local equivalent)
//!
//! # Diversity Enforcement Modes
//!
//! - **Off**: No diversity checks (DevNet, TestNet Alpha)
//! - **Warn**: Log warnings but allow connections (TestNet Beta)
//! - **Enforce**: Reject connections that violate diversity limits (MainNet)
//!
//! # Integration
//!
//! The `DiversityState` integrates with the P2P connection manager to:
//! - Check proposed connections against diversity limits
//! - Track active peers per bucket
//! - Emit metrics for monitoring

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// T206: DiversityEnforcementMode
// ============================================================================

/// Diversity enforcement mode for P2P anti-eclipse constraints (T206).
///
/// Controls how the P2P layer enforces IP-prefix diversity limits.
///
/// # Phased Rollout
///
/// - **DevNet**: `Off` (no diversity checks)
/// - **TestNet Alpha**: `Off` (no diversity checks)
/// - **TestNet Beta**: `Warn` (log warnings but allow connections)
/// - **MainNet v0**: `Enforce` (reject connections that violate limits)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DiversityEnforcementMode {
    /// Off: No diversity checks.
    ///
    /// Used in: DevNet, TestNet Alpha.
    /// All connections are accepted regardless of IP prefix distribution.
    #[default]
    Off,

    /// Warn: Log warnings but allow connections.
    ///
    /// Used in: TestNet Beta.
    /// Connections that violate diversity limits are allowed but logged.
    /// Metrics are emitted for monitoring.
    Warn,

    /// Enforce: Reject connections that violate diversity limits.
    ///
    /// Used in: MainNet v0.
    /// Connections that would exceed per-prefix limits are rejected.
    /// New outbound dials to dominant buckets are blocked.
    Enforce,
}

impl std::fmt::Display for DiversityEnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiversityEnforcementMode::Off => write!(f, "off"),
            DiversityEnforcementMode::Warn => write!(f, "warn"),
            DiversityEnforcementMode::Enforce => write!(f, "enforce"),
        }
    }
}

/// Parse a diversity enforcement mode from a string (T206).
///
/// Valid values: "off" | "warn" | "enforce" (case-insensitive)
///
/// # Returns
///
/// `Some(DiversityEnforcementMode)` if valid, `None` for unrecognized values.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_node::p2p_diversity::parse_diversity_mode;
///
/// assert_eq!(parse_diversity_mode("off"), Some(DiversityEnforcementMode::Off));
/// assert_eq!(parse_diversity_mode("warn"), Some(DiversityEnforcementMode::Warn));
/// assert_eq!(parse_diversity_mode("enforce"), Some(DiversityEnforcementMode::Enforce));
/// assert_eq!(parse_diversity_mode("invalid"), None);
/// ```
pub fn parse_diversity_mode(s: &str) -> Option<DiversityEnforcementMode> {
    match s.to_lowercase().as_str() {
        "off" => Some(DiversityEnforcementMode::Off),
        "warn" => Some(DiversityEnforcementMode::Warn),
        "enforce" => Some(DiversityEnforcementMode::Enforce),
        _ => None,
    }
}

/// Valid diversity enforcement mode values for CLI help text.
pub const VALID_DIVERSITY_MODES: &[&str] = &["off", "warn", "enforce"];

// ============================================================================
// T206: PeerBucketId - Diversity bucket classification
// ============================================================================

/// Identifier for a peer's diversity bucket (T206).
///
/// Used to group peers by IP prefix for diversity enforcement.
/// Peers in the same bucket are considered "close" in network topology.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PeerBucketId {
    /// IPv4 /24 prefix bucket (e.g., 192.168.1.x).
    ///
    /// Primary diversity bucket for IPv4 addresses.
    /// Represents a typical ISP allocation or small network.
    Ipv4Prefix24 {
        /// The /24 prefix bytes (first 3 octets).
        prefix: [u8; 3],
    },

    /// IPv4 /16 prefix bucket (e.g., 192.168.x.x).
    ///
    /// Secondary cap for IPv4 addresses.
    /// Represents a larger network allocation.
    Ipv4Prefix16 {
        /// The /16 prefix bytes (first 2 octets).
        prefix: [u8; 2],
    },

    /// IPv6 /48 prefix bucket.
    ///
    /// Site-local equivalent for IPv6 addresses.
    /// Represents a typical site allocation.
    Ipv6Prefix48 {
        /// The /48 prefix bytes (first 6 bytes).
        prefix: [u8; 6],
    },

    /// Unknown or unsupported address type.
    Unknown,
}

impl std::fmt::Display for PeerBucketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerBucketId::Ipv4Prefix24 { prefix } => {
                write!(f, "ipv4/{}.{}.{}.0/24", prefix[0], prefix[1], prefix[2])
            }
            PeerBucketId::Ipv4Prefix16 { prefix } => {
                write!(f, "ipv4/{}.{}.0.0/16", prefix[0], prefix[1])
            }
            PeerBucketId::Ipv6Prefix48 { prefix } => {
                write!(
                    f,
                    "ipv6/{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                    prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5]
                )
            }
            PeerBucketId::Unknown => write!(f, "unknown"),
        }
    }
}

// ============================================================================
// T206: DiversityClassifier - IP address classification
// ============================================================================

/// Classifier for mapping IP addresses to diversity buckets (T206).
///
/// This struct provides the `classify()` method to determine which
/// diversity bucket an IP address belongs to.
///
/// # Classification Rules
///
/// - IPv4 addresses → `Ipv4Prefix24` (using first 3 octets)
/// - IPv6 addresses → `Ipv6Prefix48` (using first 6 bytes)
/// - Loopback/unspecified → `Unknown`
///
/// # Example
///
/// ```rust,ignore
/// use std::net::IpAddr;
/// use qbind_node::p2p_diversity::{DiversityClassifier, PeerBucketId};
///
/// let ip: IpAddr = "192.168.1.100".parse().unwrap();
/// let bucket = DiversityClassifier::classify(&ip);
/// assert!(matches!(bucket, PeerBucketId::Ipv4Prefix24 { .. }));
/// ```
pub struct DiversityClassifier;

impl DiversityClassifier {
    /// Classify an IP address into a diversity bucket.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to classify
    ///
    /// # Returns
    ///
    /// The `PeerBucketId` representing the diversity bucket for this address.
    pub fn classify(ip: &IpAddr) -> PeerBucketId {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();

                // Skip loopback and unspecified addresses
                if ipv4.is_loopback() || ipv4.is_unspecified() {
                    return PeerBucketId::Unknown;
                }

                PeerBucketId::Ipv4Prefix24 {
                    prefix: [octets[0], octets[1], octets[2]],
                }
            }
            IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();

                // Skip loopback and unspecified addresses
                if ipv6.is_loopback() || ipv6.is_unspecified() {
                    return PeerBucketId::Unknown;
                }

                PeerBucketId::Ipv6Prefix48 {
                    prefix: [
                        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                    ],
                }
            }
        }
    }

    /// Get the /16 prefix bucket for an IPv4 address.
    ///
    /// Used for secondary diversity caps.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to classify
    ///
    /// # Returns
    ///
    /// `Some(PeerBucketId::Ipv4Prefix16)` for IPv4 addresses, `None` for IPv6.
    pub fn classify_ipv4_prefix16(ip: &IpAddr) -> Option<PeerBucketId> {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() || ipv4.is_unspecified() {
                    return None;
                }
                let octets = ipv4.octets();
                Some(PeerBucketId::Ipv4Prefix16 {
                    prefix: [octets[0], octets[1]],
                })
            }
            IpAddr::V6(_) => None,
        }
    }
}

// ============================================================================
// T206: DiversityCheckResult - Connection check outcome
// ============================================================================

/// Result of a diversity check for a new connection (T206).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiversityCheckResult {
    /// Connection is allowed.
    Allowed,

    /// Connection violates /24 prefix limit.
    RejectedPrefix24 {
        /// The /24 bucket that is at capacity.
        bucket: PeerBucketId,
        /// Current count of peers in this bucket.
        current_count: u16,
        /// Maximum allowed peers in this bucket.
        max_allowed: u16,
    },

    /// Connection violates /16 prefix limit.
    RejectedPrefix16 {
        /// The /16 bucket that is at capacity.
        bucket: PeerBucketId,
        /// Current count of peers in this bucket.
        current_count: u16,
        /// Maximum allowed peers in this bucket.
        max_allowed: u16,
    },

    /// Connection violates max single bucket fraction limit.
    RejectedMaxFraction {
        /// The bucket that has too high a fraction of connections.
        bucket: PeerBucketId,
        /// Current fraction in basis points.
        current_fraction_bps: u16,
        /// Maximum allowed fraction in basis points.
        max_fraction_bps: u16,
    },
}

impl DiversityCheckResult {
    /// Returns true if the connection is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, DiversityCheckResult::Allowed)
    }

    /// Returns the rejection reason as a string for metrics.
    pub fn rejection_reason(&self) -> Option<&'static str> {
        match self {
            DiversityCheckResult::Allowed => None,
            DiversityCheckResult::RejectedPrefix24 { .. } => Some("prefix24"),
            DiversityCheckResult::RejectedPrefix16 { .. } => Some("prefix16"),
            DiversityCheckResult::RejectedMaxFraction { .. } => Some("max_fraction"),
        }
    }
}

// ============================================================================
// T206: DiversityState - Active peer diversity tracking
// ============================================================================

/// Configuration for diversity enforcement (T206).
#[derive(Clone, Debug)]
pub struct DiversityConfig {
    /// Enforcement mode.
    pub mode: DiversityEnforcementMode,
    /// Maximum peers per IPv4 /24 prefix.
    pub max_peers_per_ipv4_prefix24: u16,
    /// Maximum peers per IPv4 /16 prefix.
    pub max_peers_per_ipv4_prefix16: u16,
    /// Minimum number of distinct outbound buckets.
    pub min_outbound_diversity_buckets: u16,
    /// Maximum fraction of outbound peers in a single bucket (basis points).
    pub max_single_bucket_fraction_bps: u16,
}

impl Default for DiversityConfig {
    fn default() -> Self {
        Self {
            mode: DiversityEnforcementMode::Off,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500, // 25%
        }
    }
}

impl DiversityConfig {
    /// Create a configuration for DevNet (no enforcement).
    pub fn devnet() -> Self {
        Self {
            mode: DiversityEnforcementMode::Off,
            ..Self::default()
        }
    }

    /// Create a configuration for TestNet Beta (warn mode with loose thresholds).
    pub fn testnet_beta() -> Self {
        Self {
            mode: DiversityEnforcementMode::Warn,
            max_peers_per_ipv4_prefix24: 4,
            max_peers_per_ipv4_prefix16: 16,
            min_outbound_diversity_buckets: 2,
            max_single_bucket_fraction_bps: 5000, // 50%
        }
    }

    /// Create a configuration for MainNet (strict enforcement).
    pub fn mainnet() -> Self {
        Self {
            mode: DiversityEnforcementMode::Enforce,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 8,
            min_outbound_diversity_buckets: 4,
            max_single_bucket_fraction_bps: 2500, // 25%
        }
    }
}

/// State for tracking peer diversity (T206).
///
/// Maintains counts of peers per diversity bucket for both inbound and
/// outbound connections. Used to enforce anti-eclipse constraints.
#[derive(Debug, Default)]
pub struct DiversityState {
    /// Peer counts per /24 bucket (combined inbound + outbound).
    prefix24_counts: HashMap<PeerBucketId, u16>,
    /// Peer counts per /16 bucket (combined inbound + outbound).
    prefix16_counts: HashMap<PeerBucketId, u16>,
    /// Outbound peer counts per /24 bucket.
    outbound_prefix24_counts: HashMap<PeerBucketId, u16>,
    /// Total outbound peer count.
    total_outbound: u16,
    /// Total inbound peer count.
    total_inbound: u16,
}

impl DiversityState {
    /// Create a new empty diversity state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a new connection would violate diversity limits.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address of the prospective peer
    /// * `is_outbound` - Whether this is an outbound connection
    /// * `config` - The diversity configuration
    ///
    /// # Returns
    ///
    /// `DiversityCheckResult` indicating whether the connection is allowed.
    pub fn check_connection(
        &self,
        ip: &IpAddr,
        is_outbound: bool,
        config: &DiversityConfig,
    ) -> DiversityCheckResult {
        // No checks in Off mode
        if config.mode == DiversityEnforcementMode::Off {
            return DiversityCheckResult::Allowed;
        }

        let bucket24 = DiversityClassifier::classify(ip);

        // Check /24 limit
        let current_24 = self.prefix24_counts.get(&bucket24).copied().unwrap_or(0);
        if current_24 >= config.max_peers_per_ipv4_prefix24 {
            return DiversityCheckResult::RejectedPrefix24 {
                bucket: bucket24,
                current_count: current_24,
                max_allowed: config.max_peers_per_ipv4_prefix24,
            };
        }

        // Check /16 limit for IPv4
        if let Some(bucket16) = DiversityClassifier::classify_ipv4_prefix16(ip) {
            let current_16 = self.prefix16_counts.get(&bucket16).copied().unwrap_or(0);
            if current_16 >= config.max_peers_per_ipv4_prefix16 {
                return DiversityCheckResult::RejectedPrefix16 {
                    bucket: bucket16,
                    current_count: current_16,
                    max_allowed: config.max_peers_per_ipv4_prefix16,
                };
            }
        }

        // Check max fraction for outbound connections
        if is_outbound && self.total_outbound > 0 {
            let outbound_in_bucket = self
                .outbound_prefix24_counts
                .get(&bucket24)
                .copied()
                .unwrap_or(0);
            // Calculate what the fraction would be after adding this peer
            let new_total = self.total_outbound + 1;
            let new_count = outbound_in_bucket + 1;
            let fraction_bps = (new_count as u32 * 10000 / new_total as u32) as u16;

            if fraction_bps > config.max_single_bucket_fraction_bps {
                return DiversityCheckResult::RejectedMaxFraction {
                    bucket: bucket24,
                    current_fraction_bps: fraction_bps,
                    max_fraction_bps: config.max_single_bucket_fraction_bps,
                };
            }
        }

        DiversityCheckResult::Allowed
    }

    /// Record a new peer connection.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address of the connected peer
    /// * `is_outbound` - Whether this is an outbound connection
    pub fn add_peer(&mut self, ip: &IpAddr, is_outbound: bool) {
        let bucket24 = DiversityClassifier::classify(ip);

        // Skip unknown buckets
        if matches!(bucket24, PeerBucketId::Unknown) {
            return;
        }

        // Update /24 count
        *self.prefix24_counts.entry(bucket24.clone()).or_insert(0) += 1;

        // Update /16 count for IPv4
        if let Some(bucket16) = DiversityClassifier::classify_ipv4_prefix16(ip) {
            *self.prefix16_counts.entry(bucket16).or_insert(0) += 1;
        }

        // Update totals
        if is_outbound {
            *self.outbound_prefix24_counts.entry(bucket24).or_insert(0) += 1;
            self.total_outbound += 1;
        } else {
            self.total_inbound += 1;
        }
    }

    /// Record a peer disconnection.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address of the disconnected peer
    /// * `is_outbound` - Whether this was an outbound connection
    pub fn remove_peer(&mut self, ip: &IpAddr, is_outbound: bool) {
        let bucket24 = DiversityClassifier::classify(ip);

        // Skip unknown buckets
        if matches!(bucket24, PeerBucketId::Unknown) {
            return;
        }

        // Update /24 count
        if let Some(count) = self.prefix24_counts.get_mut(&bucket24) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.prefix24_counts.remove(&bucket24);
            }
        }

        // Update /16 count for IPv4
        if let Some(bucket16) = DiversityClassifier::classify_ipv4_prefix16(ip) {
            if let Some(count) = self.prefix16_counts.get_mut(&bucket16) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.prefix16_counts.remove(&bucket16);
                }
            }
        }

        // Update totals
        if is_outbound {
            if let Some(count) = self.outbound_prefix24_counts.get_mut(&bucket24) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.outbound_prefix24_counts.remove(&bucket24);
                }
            }
            self.total_outbound = self.total_outbound.saturating_sub(1);
        } else {
            self.total_inbound = self.total_inbound.saturating_sub(1);
        }
    }

    /// Get the number of distinct outbound buckets.
    pub fn distinct_outbound_buckets(&self) -> usize {
        self.outbound_prefix24_counts.len()
    }

    /// Get the maximum bucket fraction of outbound peers (in basis points).
    ///
    /// Returns 0 if there are no outbound peers.
    pub fn max_outbound_bucket_fraction_bps(&self) -> u16 {
        if self.total_outbound == 0 {
            return 0;
        }

        let max_count = self
            .outbound_prefix24_counts
            .values()
            .max()
            .copied()
            .unwrap_or(0);
        (max_count as u32 * 10000 / self.total_outbound as u32) as u16
    }

    /// Check if the current state violates diversity requirements.
    ///
    /// # Arguments
    ///
    /// * `config` - The diversity configuration
    ///
    /// # Returns
    ///
    /// `true` if diversity requirements are violated.
    pub fn is_diversity_violated(&self, config: &DiversityConfig) -> bool {
        // Check minimum distinct buckets
        if self.distinct_outbound_buckets() < config.min_outbound_diversity_buckets as usize {
            return true;
        }

        // Check max bucket fraction
        if self.max_outbound_bucket_fraction_bps() > config.max_single_bucket_fraction_bps {
            return true;
        }

        false
    }

    /// Get the total number of outbound peers.
    pub fn total_outbound(&self) -> u16 {
        self.total_outbound
    }

    /// Get the total number of inbound peers.
    pub fn total_inbound(&self) -> u16 {
        self.total_inbound
    }
}

// ============================================================================
// T206: Diversity Metrics
// ============================================================================

/// Metrics for diversity enforcement (T206).
#[derive(Debug, Default)]
pub struct DiversityMetrics {
    /// Current diversity mode (0=Off, 1=Warn, 2=Enforce).
    diversity_mode: AtomicU64,
    /// Current number of distinct outbound buckets.
    distinct_outbound_buckets: AtomicU64,
    /// Current max bucket fraction of outbound peers (basis points).
    max_bucket_fraction_bps: AtomicU64,
    /// Total peers rejected due to /24 prefix limit.
    rejected_prefix24_total: AtomicU64,
    /// Total peers rejected due to /16 prefix limit.
    rejected_prefix16_total: AtomicU64,
    /// Total peers rejected due to max fraction limit.
    rejected_max_fraction_total: AtomicU64,
    /// Total diversity violations in warn mode.
    violation_warn_total: AtomicU64,
    /// Total diversity violations in enforce mode.
    violation_enforce_total: AtomicU64,
}

impl DiversityMetrics {
    /// Create new diversity metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current diversity mode.
    pub fn set_diversity_mode(&self, mode: DiversityEnforcementMode) {
        let value = match mode {
            DiversityEnforcementMode::Off => 0,
            DiversityEnforcementMode::Warn => 1,
            DiversityEnforcementMode::Enforce => 2,
        };
        self.diversity_mode.store(value, Ordering::Relaxed);
    }

    /// Get the current diversity mode value.
    pub fn diversity_mode(&self) -> u64 {
        self.diversity_mode.load(Ordering::Relaxed)
    }

    /// Set the current number of distinct outbound buckets.
    pub fn set_distinct_outbound_buckets(&self, count: u64) {
        self.distinct_outbound_buckets
            .store(count, Ordering::Relaxed);
    }

    /// Get the current number of distinct outbound buckets.
    pub fn distinct_outbound_buckets(&self) -> u64 {
        self.distinct_outbound_buckets.load(Ordering::Relaxed)
    }

    /// Set the current max bucket fraction.
    pub fn set_max_bucket_fraction_bps(&self, bps: u64) {
        self.max_bucket_fraction_bps.store(bps, Ordering::Relaxed);
    }

    /// Get the current max bucket fraction.
    pub fn max_bucket_fraction_bps(&self) -> u64 {
        self.max_bucket_fraction_bps.load(Ordering::Relaxed)
    }

    /// Record a peer rejection.
    pub fn record_rejection(&self, reason: &str) {
        match reason {
            "prefix24" => {
                self.rejected_prefix24_total.fetch_add(1, Ordering::Relaxed);
            }
            "prefix16" => {
                self.rejected_prefix16_total.fetch_add(1, Ordering::Relaxed);
            }
            "max_fraction" => {
                self.rejected_max_fraction_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Get total rejections for a reason.
    pub fn rejected_total(&self, reason: &str) -> u64 {
        match reason {
            "prefix24" => self.rejected_prefix24_total.load(Ordering::Relaxed),
            "prefix16" => self.rejected_prefix16_total.load(Ordering::Relaxed),
            "max_fraction" => self.rejected_max_fraction_total.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Record a diversity violation.
    pub fn record_violation(&self, mode: DiversityEnforcementMode) {
        match mode {
            DiversityEnforcementMode::Warn => {
                self.violation_warn_total.fetch_add(1, Ordering::Relaxed);
            }
            DiversityEnforcementMode::Enforce => {
                self.violation_enforce_total.fetch_add(1, Ordering::Relaxed);
            }
            DiversityEnforcementMode::Off => {}
        }
    }

    /// Get total violations for a mode.
    pub fn violation_total(&self, mode: &str) -> u64 {
        match mode {
            "warn" => self.violation_warn_total.load(Ordering::Relaxed),
            "enforce" => self.violation_enforce_total.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Format metrics as Prometheus-compatible output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();

        output.push_str("# P2P diversity metrics (T206)\n");
        output.push_str(&format!(
            "qbind_p2p_diversity_mode {}\n",
            self.diversity_mode()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_distinct_buckets {}\n",
            self.distinct_outbound_buckets()
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_max_bucket_fraction_bps {}\n",
            self.max_bucket_fraction_bps()
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"prefix24\"}} {}\n",
            self.rejected_total("prefix24")
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"prefix16\"}} {}\n",
            self.rejected_total("prefix16")
        ));
        output.push_str(&format!(
            "qbind_p2p_peer_rejected_diversity_total{{reason=\"max_fraction\"}} {}\n",
            self.rejected_total("max_fraction")
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_violation_total{{mode=\"warn\"}} {}\n",
            self.violation_total("warn")
        ));
        output.push_str(&format!(
            "qbind_p2p_diversity_violation_total{{mode=\"enforce\"}} {}\n",
            self.violation_total("enforce")
        ));

        output
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_diversity_mode_default() {
        let mode = DiversityEnforcementMode::default();
        assert_eq!(mode, DiversityEnforcementMode::Off);
    }

    #[test]
    fn test_diversity_mode_display() {
        assert_eq!(format!("{}", DiversityEnforcementMode::Off), "off");
        assert_eq!(format!("{}", DiversityEnforcementMode::Warn), "warn");
        assert_eq!(format!("{}", DiversityEnforcementMode::Enforce), "enforce");
    }

    #[test]
    fn test_parse_diversity_mode_valid() {
        assert_eq!(
            parse_diversity_mode("off"),
            Some(DiversityEnforcementMode::Off)
        );
        assert_eq!(
            parse_diversity_mode("OFF"),
            Some(DiversityEnforcementMode::Off)
        );
        assert_eq!(
            parse_diversity_mode("warn"),
            Some(DiversityEnforcementMode::Warn)
        );
        assert_eq!(
            parse_diversity_mode("WARN"),
            Some(DiversityEnforcementMode::Warn)
        );
        assert_eq!(
            parse_diversity_mode("enforce"),
            Some(DiversityEnforcementMode::Enforce)
        );
        assert_eq!(
            parse_diversity_mode("ENFORCE"),
            Some(DiversityEnforcementMode::Enforce)
        );
    }

    #[test]
    fn test_parse_diversity_mode_invalid() {
        assert_eq!(parse_diversity_mode("invalid"), None);
        assert_eq!(parse_diversity_mode(""), None);
        assert_eq!(parse_diversity_mode("on"), None);
    }

    #[test]
    fn test_classify_ipv4() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let bucket = DiversityClassifier::classify(&ip);

        match bucket {
            PeerBucketId::Ipv4Prefix24 { prefix } => {
                assert_eq!(prefix, [192, 168, 1]);
            }
            _ => panic!("Expected Ipv4Prefix24"),
        }
    }

    #[test]
    fn test_classify_ipv4_same_prefix() {
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

        let bucket1 = DiversityClassifier::classify(&ip1);
        let bucket2 = DiversityClassifier::classify(&ip2);

        assert_eq!(bucket1, bucket2);
    }

    #[test]
    fn test_classify_ipv4_different_prefix() {
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100));

        let bucket1 = DiversityClassifier::classify(&ip1);
        let bucket2 = DiversityClassifier::classify(&ip2);

        assert_ne!(bucket1, bucket2);
    }

    #[test]
    fn test_classify_ipv4_prefix16() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let bucket = DiversityClassifier::classify_ipv4_prefix16(&ip);

        match bucket {
            Some(PeerBucketId::Ipv4Prefix16 { prefix }) => {
                assert_eq!(prefix, [192, 168]);
            }
            _ => panic!("Expected Ipv4Prefix16"),
        }
    }

    #[test]
    fn test_classify_ipv6() {
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1));
        let bucket = DiversityClassifier::classify(&ip);

        match bucket {
            PeerBucketId::Ipv6Prefix48 { prefix } => {
                assert_eq!(prefix, [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3]);
            }
            _ => panic!("Expected Ipv6Prefix48"),
        }
    }

    #[test]
    fn test_classify_loopback() {
        let ipv4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(DiversityClassifier::classify(&ipv4), PeerBucketId::Unknown);

        let ipv6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(DiversityClassifier::classify(&ipv6), PeerBucketId::Unknown);
    }

    #[test]
    fn test_diversity_state_add_remove() {
        let mut state = DiversityState::new();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        state.add_peer(&ip, true);
        assert_eq!(state.total_outbound(), 1);
        assert_eq!(state.distinct_outbound_buckets(), 1);

        state.add_peer(&ip, false);
        assert_eq!(state.total_inbound(), 1);

        state.remove_peer(&ip, true);
        assert_eq!(state.total_outbound(), 0);
        assert_eq!(state.distinct_outbound_buckets(), 0);
    }

    #[test]
    fn test_diversity_check_off_mode() {
        let state = DiversityState::new();
        let config = DiversityConfig {
            mode: DiversityEnforcementMode::Off,
            max_peers_per_ipv4_prefix24: 1,
            ..DiversityConfig::default()
        };

        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let result = state.check_connection(&ip, true, &config);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_diversity_check_prefix24_limit() {
        let mut state = DiversityState::new();
        let config = DiversityConfig {
            mode: DiversityEnforcementMode::Enforce,
            max_peers_per_ipv4_prefix24: 2,
            max_peers_per_ipv4_prefix16: 100,
            min_outbound_diversity_buckets: 2,
            max_single_bucket_fraction_bps: 10000, // 100% - disable fraction check for this test
        };

        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
        let ip3: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102));

        // First two should be allowed
        assert!(state.check_connection(&ip1, true, &config).is_allowed());
        state.add_peer(&ip1, true);

        assert!(state.check_connection(&ip2, true, &config).is_allowed());
        state.add_peer(&ip2, true);

        // Third should be rejected
        let result = state.check_connection(&ip3, true, &config);
        assert!(!result.is_allowed());
        assert_eq!(result.rejection_reason(), Some("prefix24"));
    }

    #[test]
    fn test_diversity_check_prefix16_limit() {
        let mut state = DiversityState::new();
        let config = DiversityConfig {
            mode: DiversityEnforcementMode::Enforce,
            max_peers_per_ipv4_prefix24: 10,
            max_peers_per_ipv4_prefix16: 2,
            min_outbound_diversity_buckets: 2,
            max_single_bucket_fraction_bps: 10000, // 100% - disable fraction check for this test
        };

        // Add peers from different /24s but same /16
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100));
        let ip3: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 3, 100));

        state.add_peer(&ip1, true);
        state.add_peer(&ip2, true);

        // Third should be rejected due to /16 limit
        let result = state.check_connection(&ip3, true, &config);
        assert!(!result.is_allowed());
        assert_eq!(result.rejection_reason(), Some("prefix16"));
    }

    #[test]
    fn test_diversity_max_bucket_fraction() {
        let mut state = DiversityState::new();
        let config = DiversityConfig {
            mode: DiversityEnforcementMode::Enforce,
            max_peers_per_ipv4_prefix24: 100,
            max_peers_per_ipv4_prefix16: 100,
            max_single_bucket_fraction_bps: 3000, // 30%
            ..DiversityConfig::default()
        };

        // Add 3 peers from different /24s
        state.add_peer(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
        state.add_peer(&IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), true);
        state.add_peer(&IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1)), true);

        // Try to add another from the first /24 - this would make 2/4 = 50%
        let ip_same: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
        let result = state.check_connection(&ip_same, true, &config);
        assert!(!result.is_allowed());
        assert_eq!(result.rejection_reason(), Some("max_fraction"));
    }

    #[test]
    fn test_diversity_metrics() {
        let metrics = DiversityMetrics::new();

        metrics.set_diversity_mode(DiversityEnforcementMode::Enforce);
        assert_eq!(metrics.diversity_mode(), 2);

        metrics.set_distinct_outbound_buckets(5);
        assert_eq!(metrics.distinct_outbound_buckets(), 5);

        metrics.record_rejection("prefix24");
        assert_eq!(metrics.rejected_total("prefix24"), 1);

        metrics.record_violation(DiversityEnforcementMode::Warn);
        assert_eq!(metrics.violation_total("warn"), 1);
    }

    #[test]
    fn test_peer_bucket_id_display() {
        let ipv4_24 = PeerBucketId::Ipv4Prefix24 {
            prefix: [192, 168, 1],
        };
        assert_eq!(format!("{}", ipv4_24), "ipv4/192.168.1.0/24");

        let ipv4_16 = PeerBucketId::Ipv4Prefix16 { prefix: [192, 168] };
        assert_eq!(format!("{}", ipv4_16), "ipv4/192.168.0.0/16");

        let ipv6_48 = PeerBucketId::Ipv6Prefix48 {
            prefix: [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3],
        };
        assert_eq!(format!("{}", ipv6_48), "ipv6/2001:0db8:85a3::/48");

        assert_eq!(format!("{}", PeerBucketId::Unknown), "unknown");
    }

    #[test]
    fn test_diversity_config_presets() {
        let devnet = DiversityConfig::devnet();
        assert_eq!(devnet.mode, DiversityEnforcementMode::Off);

        let beta = DiversityConfig::testnet_beta();
        assert_eq!(beta.mode, DiversityEnforcementMode::Warn);
        assert_eq!(beta.max_peers_per_ipv4_prefix24, 4);

        let mainnet = DiversityConfig::mainnet();
        assert_eq!(mainnet.mode, DiversityEnforcementMode::Enforce);
        assert_eq!(mainnet.max_peers_per_ipv4_prefix24, 2);
    }
}
