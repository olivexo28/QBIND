//! T231: P2P Anti-Eclipse Enforcement Tests
//!
//! This module tests the runtime enforcement of P2P anti-eclipse constraints:
//!
//! - `PeerDiversityState` integration with `P2pAntiEclipseConfig`
//! - IP prefix limit enforcement
//! - ASN diversity tracking
//! - Minimum outbound peer requirements
//! - Metrics for enforcement actions
//!
//! # Run tests
//!
//! ```bash
//! cargo test -p qbind-node --test t231_p2p_anti_eclipse_tests
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use qbind_node::node_config::P2pAntiEclipseConfig;
use qbind_node::p2p_diversity::{
    AntiEclipseCheckResult, AntiEclipseMetrics, DiversityClassifier, PeerBucketId,
    PeerDiversityState,
};

// ============================================================================
// Part 1: PeerDiversityState Integration with P2pAntiEclipseConfig
// ============================================================================

#[test]
fn test_peer_diversity_state_from_devnet_config() {
    let config = P2pAntiEclipseConfig::devnet_default();
    let state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    assert!(!state.is_enforcing());
    assert_eq!(state.max_peers_per_ipv4_prefix(), 64);
    assert_eq!(state.min_outbound_peers(), 4);
    assert_eq!(state.min_asn_diversity(), 1);
}

#[test]
fn test_peer_diversity_state_from_mainnet_config() {
    let config = P2pAntiEclipseConfig::mainnet_default();
    let state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    assert!(state.is_enforcing());
    assert_eq!(state.max_peers_per_ipv4_prefix(), 8);
    assert_eq!(state.min_outbound_peers(), 8);
    assert_eq!(state.min_asn_diversity(), 2);
}

#[test]
fn test_peer_diversity_state_from_testnet_alpha_config() {
    let config = P2pAntiEclipseConfig::testnet_alpha_default();
    let state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    assert!(!state.is_enforcing());
    assert_eq!(state.max_peers_per_ipv4_prefix(), 16);
    assert_eq!(state.min_outbound_peers(), 6);
    assert_eq!(state.min_asn_diversity(), 2);
}

// ============================================================================
// Part 2: IP Prefix Limit Enforcement
// ============================================================================

#[test]
fn test_mainnet_prefix_limit_enforcement() {
    let config = P2pAntiEclipseConfig::mainnet_default();
    let mut state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    // MainNet allows max 8 peers from the same /24 prefix
    let base_ip = [10, 0, 1];
    for i in 0..8 {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], i + 1));
        let result = state.check_connection(&ip, true);
        assert!(result.is_allowed(), "Peer {} should be allowed", i + 1);
        state.on_peer_connected(&ip, true);
    }

    // 9th peer from same /24 should be rejected
    let ip9: IpAddr = IpAddr::V4(Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], 9));
    let result = state.check_connection(&ip9, true);
    assert!(!result.is_allowed());
    assert_eq!(result.rejection_reason(), Some("anti_eclipse_prefix"));

    if let AntiEclipseCheckResult::RejectedPrefixLimit {
        current_count,
        max_allowed,
        ..
    } = result
    {
        assert_eq!(current_count, 8);
        assert_eq!(max_allowed, 8);
    } else {
        panic!("Expected RejectedPrefixLimit");
    }
}

#[test]
fn test_devnet_permissive_prefix_limit() {
    let config = P2pAntiEclipseConfig::devnet_default();
    let mut state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    // DevNet allows 64 peers from the same /24 prefix
    // Since we only need 64 peers and valid last octets are 1-254,
    // we use (i + 1) as the last octet to get unique IPs 1-64
    let base_ip = [192, 168, 1];
    for i in 0..64u8 {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], i + 1));
        let result = state.check_connection(&ip, true);
        assert!(
            result.is_allowed(),
            "Peer {} should be allowed in DevNet",
            i + 1
        );
        state.on_peer_connected(&ip, true);
    }

    // 65th should be rejected
    let ip65: IpAddr = IpAddr::V4(Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], 200));
    let result = state.check_connection(&ip65, true);
    assert!(!result.is_allowed());
}

#[test]
fn test_prefix_limit_across_multiple_prefixes() {
    let config = P2pAntiEclipseConfig::mainnet_default();
    let mut state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    // Fill up one prefix
    for i in 0..8 {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, i + 1));
        state.on_peer_connected(&ip, true);
    }

    // Different /24 prefix should still be allowed
    let different_prefix: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let result = state.check_connection(&different_prefix, true);
    assert!(
        result.is_allowed(),
        "Different /24 prefix should still be allowed"
    );

    // Same /16 but different /24 is OK
    let same_16: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1));
    let result = state.check_connection(&same_16, true);
    assert!(result.is_allowed());
}

// ============================================================================
// Part 3: ASN Diversity Tracking
// ============================================================================

#[test]
fn test_asn_diversity_tracking() {
    let config = P2pAntiEclipseConfig::mainnet_default();
    let mut state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    // Initially no ASN diversity
    assert_eq!(state.distinct_asn_count(), 0);
    assert!(!state.is_min_asn_diversity_met());

    // Add peer from first /16 (ASN proxy)
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 1);
    assert!(!state.is_min_asn_diversity_met()); // Need 2 for MainNet

    // Add peer from same /16 - should not increase ASN count
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), true);
    assert_eq!(state.distinct_asn_count(), 1);

    // Add peer from different /16
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 2);
    assert!(state.is_min_asn_diversity_met()); // Now meets MainNet requirement

    // Add more diversity
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 3);
}

#[test]
fn test_asn_diversity_decreases_on_disconnect() {
    let mut state = PeerDiversityState::new(64, 4, 2, true);

    // Add peers from 3 different /16 prefixes
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 3);

    // Disconnect the 192.168.x.x peer
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 2);

    // Add another peer from 192.168.x.x and then two from same /16
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), true);
    assert_eq!(state.distinct_asn_count(), 3); // Still 3, same /16

    // Disconnect one 192.168 peer - should still have ASN since another exists
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);
    assert_eq!(state.distinct_asn_count(), 3);

    // Disconnect the other - now 192.168 /16 is gone
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), true);
    assert_eq!(state.distinct_asn_count(), 2);
}

// ============================================================================
// Part 4: Minimum Outbound Peer Requirements
// ============================================================================

#[test]
fn test_min_outbound_peers_check() {
    let config = P2pAntiEclipseConfig::mainnet_default();
    let mut state = PeerDiversityState::new(
        config.max_peers_per_ipv4_prefix,
        config.min_outbound_peers,
        config.min_asn_diversity,
        config.enforce,
    );

    // Initially not met (need 8 for MainNet)
    assert!(!state.is_min_outbound_met());
    assert_eq!(state.outbound_peers(), 0);

    // Add 7 outbound peers
    for i in 0..7 {
        state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, i, 1, 1)), true);
    }
    assert_eq!(state.outbound_peers(), 7);
    assert!(!state.is_min_outbound_met()); // Need 8

    // Add 8th outbound peer
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 7, 1, 1)), true);
    assert_eq!(state.outbound_peers(), 8);
    assert!(state.is_min_outbound_met());

    // Adding inbound peers doesn't affect outbound count
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1)), false);
    assert_eq!(state.outbound_peers(), 8);
    assert!(state.is_min_outbound_met());
}

#[test]
fn test_outbound_count_decreases_on_disconnect() {
    let mut state = PeerDiversityState::new(64, 4, 2, true);

    // Add outbound peers
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), true);
    assert_eq!(state.outbound_peers(), 2);

    // Disconnect one outbound
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    assert_eq!(state.outbound_peers(), 1);

    // Disconnect an inbound shouldn't affect outbound count
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), false);
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), false);
    assert_eq!(state.outbound_peers(), 1);
}

// ============================================================================
// Part 5: Metrics Integration
// ============================================================================

#[test]
fn test_anti_eclipse_metrics_track_state() {
    let metrics = AntiEclipseMetrics::new();
    let mut state = PeerDiversityState::new(8, 8, 2, true);

    // Connect some peers
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), true);
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true);

    // Update metrics from state
    metrics.set_outbound_peers(state.outbound_peers() as u64);
    metrics.set_distinct_asn(state.distinct_asn_count() as u64);

    assert_eq!(metrics.outbound_peers(), 3);
    assert_eq!(metrics.distinct_asn(), 3);
}

#[test]
fn test_anti_eclipse_metrics_record_rejections() {
    let metrics = AntiEclipseMetrics::new();

    // Simulate rejections
    for _ in 0..5 {
        metrics.inc_rejected_prefix_limit();
    }
    assert_eq!(metrics.rejected_prefix_limit_total(), 5);

    metrics.inc_min_outbound_violation();
    metrics.inc_min_outbound_violation();
    assert_eq!(metrics.min_outbound_violation_total(), 2);

    metrics.inc_min_asn_violation();
    assert_eq!(metrics.min_asn_violation_total(), 1);
}

#[test]
fn test_anti_eclipse_metrics_prometheus_format() {
    let metrics = AntiEclipseMetrics::new();

    // Set up config
    metrics.set_config(8, 8, 2, true);

    // Set some values
    metrics.set_outbound_peers(10);
    metrics.set_distinct_asn(4);
    metrics.inc_rejected_prefix_limit();

    let output = metrics.format_metrics();

    // Verify Prometheus format
    assert!(output.contains("# T231: P2P anti-eclipse metrics"));
    assert!(output.contains("qbind_p2p_anti_eclipse_outbound_peers 10"));
    assert!(output.contains("qbind_p2p_anti_eclipse_distinct_asn 4"));
    assert!(output.contains("qbind_p2p_anti_eclipse_rejected_prefix_limit_total 1"));
    assert!(output.contains("qbind_p2p_anti_eclipse_config_max_peers_per_prefix 8"));
    assert!(output.contains("qbind_p2p_anti_eclipse_config_min_outbound 8"));
    assert!(output.contains("qbind_p2p_anti_eclipse_config_min_asn 2"));
    assert!(output.contains("qbind_p2p_anti_eclipse_config_enforce 1"));
}

// ============================================================================
// Part 6: Edge Cases
// ============================================================================

#[test]
fn test_ipv6_peer_handling() {
    let mut state = PeerDiversityState::new(8, 4, 2, true);

    // IPv6 peers should be handled (classified as IPv6 prefix)
    let ipv6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 1));
    let result = state.check_connection(&ipv6, true);
    assert!(result.is_allowed());

    state.on_peer_connected(&ipv6, true);
    assert_eq!(state.outbound_peers(), 1);
    // ASN count doesn't increase for IPv6 (only tracks /16 for IPv4)
    assert_eq!(state.distinct_asn_count(), 0);
}

#[test]
fn test_loopback_address_ignored() {
    let mut state = PeerDiversityState::new(8, 4, 2, true);

    let loopback: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    state.on_peer_connected(&loopback, true);

    // Loopback should be ignored
    assert_eq!(state.outbound_peers(), 0);
    assert_eq!(state.distinct_asn_count(), 0);
    assert_eq!(state.total_peers(), 0);
}

#[test]
fn test_disabled_state_accepts_all() {
    let state = PeerDiversityState::disabled();

    // Should accept any connection
    for i in 0..255 {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, i));
        let result = state.check_connection(&ip, true);
        assert!(result.is_allowed());
    }
}

#[test]
fn test_bucket_id_classification() {
    // Verify bucket classification works correctly
    let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

    let bucket1 = DiversityClassifier::classify(&ip1);
    let bucket2 = DiversityClassifier::classify(&ip2);

    // Same /24 prefix
    assert_eq!(bucket1, bucket2);

    // Different /24 prefix
    let ip3: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100));
    let bucket3 = DiversityClassifier::classify(&ip3);
    assert_ne!(bucket1, bucket3);
}

#[test]
fn test_multiple_connect_disconnect_cycles() {
    let mut state = PeerDiversityState::new(8, 4, 2, true);
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    // Connect and disconnect multiple times
    for _ in 0..5 {
        state.on_peer_connected(&ip, true);
        assert_eq!(state.outbound_peers(), 1);

        state.on_peer_disconnected(&ip, true);
        assert_eq!(state.outbound_peers(), 0);
    }

    // Final state should be clean
    assert_eq!(state.total_peers(), 0);
    assert_eq!(state.distinct_asn_count(), 0);
}

#[test]
fn test_peers_in_prefix_tracking() {
    let mut state = PeerDiversityState::new(64, 4, 2, true);

    let bucket = PeerBucketId::Ipv4Prefix24 { prefix: [10, 0, 1] };

    // Initially no peers in prefix
    assert_eq!(state.peers_in_prefix(&bucket), 0);

    // Add peers
    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    assert_eq!(state.peers_in_prefix(&bucket), 1);

    state.on_peer_connected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), true);
    assert_eq!(state.peers_in_prefix(&bucket), 2);

    // Remove one
    state.on_peer_disconnected(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), true);
    assert_eq!(state.peers_in_prefix(&bucket), 1);
}
