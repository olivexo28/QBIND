//! T172: P2P Transport v1 Smoke Tests
//!
//! This module contains smoke tests for the minimal P2P transport implementation.
//! These tests verify basic functionality without requiring a full network setup.

use qbind_crypto::{CryptoProvider, StaticCryptoProvider};
use qbind_net::connection::{ClientConnectionConfig, ServerConnectionConfig};
use qbind_net::handshake::{ClientHandshakeConfig, ServerHandshakeConfig};
use qbind_net::keys::KemPrivateKey;
use qbind_node::metrics::P2pMetrics;
use qbind_node::node_config::NetworkTransportConfig;
use qbind_node::p2p::{ControlMsg, NodeId, P2pMessage, P2pService};
use qbind_node::p2p_tcp::TcpKemTlsP2pService;
use std::sync::Arc;
use std::time::Duration;

/// Helper function to create a test crypto provider.
fn create_test_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(StaticCryptoProvider::new())
}

/// Helper function to create test connection configs.
fn create_test_connection_configs(
    crypto: Arc<dyn CryptoProvider>,
) -> (ServerConnectionConfig, ClientConnectionConfig) {
    let server_kem_sk = vec![0u8; 32];
    let server_kem_pk = vec![0u8; 32];

    let validator_id = [0u8; 32];

    let server_cfg = ServerConnectionConfig {
        handshake_config: ServerHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto: crypto.clone(),
            local_root_network_pk: vec![0u8; 32],
            local_delegation_cert: vec![],
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: validator_id,
        },
        server_random: [0u8; 32],
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: ClientHandshakeConfig {
            kem_suite_id: 1,
            aead_suite_id: 2,
            crypto,
            peer_root_network_pk: vec![0u8; 32],
            kem_metrics: None,
        },
        client_random: [0u8; 32],
        validator_id: [0u8; 32],
        peer_kem_pk: server_kem_pk,
    };

    (server_cfg, client_cfg)
}

/// Helper function to create a test network config.
fn create_test_config(port: u16) -> NetworkTransportConfig {
    NetworkTransportConfig {
        enable_p2p: true,
        max_outbound: 4,
        max_inbound: 8,
        gossip_fanout: 3,
        listen_addr: Some(format!("127.0.0.1:{}", port)),
        advertised_addr: Some(format!("127.0.0.1:{}", port)),
        static_peers: vec![],
        // T205: Discovery and liveness defaults for test
        discovery_enabled: false,
        discovery_interval_secs: 30,
        max_known_peers: 200,
        target_outbound_peers: 8,
        liveness_probe_interval_secs: 30,
        liveness_failure_threshold: 3,
        liveness_min_score: 30,
        // T206: Diversity defaults for test
        diversity_mode: qbind_node::p2p_diversity::DiversityEnforcementMode::Off,
        max_peers_per_ipv4_prefix24: 2,
        max_peers_per_ipv4_prefix16: 8,
        min_outbound_diversity_buckets: 4,
        max_single_bucket_fraction_bps: 2500,
    }
}

// ============================================================================
// Test 1: P2P Service Creation
// ============================================================================

#[tokio::test]
async fn test_p2p_service_creation() {
    let crypto = create_test_crypto();
    let config = create_test_config(0); // Let OS assign port
    let node_id = NodeId::zero();
    let (server_cfg, client_cfg) = create_test_connection_configs(crypto.clone());

    let result = TcpKemTlsP2pService::new(node_id, config, crypto, server_cfg, client_cfg);
    assert!(
        result.is_ok(),
        "Should successfully create P2P service: {:?}",
        result.err()
    );

    let service = result.unwrap();
    assert_eq!(service.local_node_id(), node_id);
    assert_eq!(service.connected_peers().len(), 0);
}

// ============================================================================
// Test 2: P2P Service Start and Shutdown
// ============================================================================

#[tokio::test]
async fn test_p2p_service_start_and_shutdown() {
    let crypto = create_test_crypto();
    let config = create_test_config(0);
    let node_id = NodeId::new([1u8; 32]);
    let (server_cfg, client_cfg) = create_test_connection_configs(crypto.clone());

    let mut service = TcpKemTlsP2pService::new(node_id, config, crypto, server_cfg, client_cfg)
        .expect("Failed to create service");

    // Start the service
    service.start().await.expect("Failed to start service");

    // Give it a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check that the service is running
    assert_eq!(service.local_node_id(), node_id);

    // Shutdown the service
    service.shutdown().await;

    // Give it a moment to shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ============================================================================
// Test 3: P2P Null Service
// ============================================================================

#[tokio::test]
async fn test_p2p_null_service() {
    let null_service = qbind_node::p2p::NullP2pService::new(NodeId::zero());
    let node_id = null_service.local_node_id();

    // Null service should have zero node ID
    assert_eq!(node_id, NodeId::zero());

    // Null service should have no connected peers
    assert_eq!(null_service.connected_peers().len(), 0);

    // Broadcast should not error (it's a no-op)
    let msg = P2pMessage::Control(ControlMsg::Heartbeat {
        view: 1,
        timestamp_ms: 1000,
    });
    null_service.broadcast(msg);

    // Send to specific peer should not error (it's a no-op)
    let msg = P2pMessage::Control(ControlMsg::Heartbeat {
        view: 1,
        timestamp_ms: 1000,
    });
    null_service.send_to(NodeId::zero(), msg);
}

// ============================================================================
// Test 4: NodeId Operations
// ============================================================================

#[test]
fn test_node_id_operations() {
    // Create from array
    let bytes = [42u8; 32];
    let node_id = NodeId::new(bytes);
    assert_eq!(node_id.as_bytes(), &bytes);

    // Create from slice
    let slice = &bytes[..];
    let node_id2 = NodeId::from_slice(slice);
    assert_eq!(node_id, node_id2);

    // Zero node ID
    let zero = NodeId::zero();
    assert_eq!(zero.as_bytes(), &[0u8; 32]);

    // Display format
    let display = format!("{}", node_id);
    assert!(display.starts_with("2a2a2a2a"));

    // Debug format
    let debug = format!("{:?}", node_id);
    assert!(debug.contains("NodeId"));
}

// ============================================================================
// Test 5: Control Message Serialization
// ============================================================================

#[test]
fn test_control_message_serialization() {
    let msg = ControlMsg::Heartbeat {
        view: 42,
        timestamp_ms: 1234567890,
    };

    // Serialize
    let serialized = bincode::serialize(&msg).expect("Failed to serialize");
    assert!(!serialized.is_empty());

    // Deserialize
    let deserialized: ControlMsg =
        bincode::deserialize(&serialized).expect("Failed to deserialize");

    match deserialized {
        ControlMsg::Heartbeat { view, timestamp_ms } => {
            assert_eq!(view, 42);
            assert_eq!(timestamp_ms, 1234567890);
        }
        _ => panic!("Expected Heartbeat variant"),
    }
}

// ============================================================================
// Test 6: P2pMessage Serialization
// ============================================================================

#[test]
fn test_p2p_message_serialization() {
    let control_msg = ControlMsg::Heartbeat {
        view: 100,
        timestamp_ms: 9876543210,
    };
    let p2p_msg = P2pMessage::Control(control_msg);

    // Serialize
    let serialized = bincode::serialize(&p2p_msg).expect("Failed to serialize P2pMessage");
    assert!(!serialized.is_empty());

    // Deserialize
    let deserialized: P2pMessage =
        bincode::deserialize(&serialized).expect("Failed to deserialize P2pMessage");

    match deserialized {
        P2pMessage::Control(ControlMsg::Heartbeat { view, timestamp_ms }) => {
            assert_eq!(view, 100);
            assert_eq!(timestamp_ms, 9876543210);
        }
        _ => panic!("Expected Control(Heartbeat) variant"),
    }
}

// ============================================================================
// Test 7: Network Transport Config
// ============================================================================

#[test]
fn test_network_transport_config() {
    // Default config
    let config = NetworkTransportConfig::default();
    assert!(!config.enable_p2p);
    assert_eq!(config.max_outbound, 16);
    assert_eq!(config.max_inbound, 64);
    assert_eq!(config.gossip_fanout, 6);
    assert!(config.listen_addr.is_none());
    assert!(config.advertised_addr.is_none());
    assert_eq!(config.static_peers.len(), 0);

    // Disabled config
    let disabled = NetworkTransportConfig::disabled();
    assert!(!disabled.enable_p2p);

    // Custom config
    let custom = NetworkTransportConfig {
        enable_p2p: true,
        max_outbound: 10,
        max_inbound: 20,
        gossip_fanout: 5,
        listen_addr: Some("0.0.0.0:9000".to_string()),
        advertised_addr: Some("1.2.3.4:9000".to_string()),
        static_peers: vec!["peer1:9000".to_string(), "peer2:9000".to_string()],
        // T205: Discovery and liveness defaults for test
        discovery_enabled: false,
        discovery_interval_secs: 30,
        max_known_peers: 200,
        target_outbound_peers: 8,
        liveness_probe_interval_secs: 30,
        liveness_failure_threshold: 3,
        liveness_min_score: 30,
        // T206: Diversity defaults for test
        diversity_mode: qbind_node::p2p_diversity::DiversityEnforcementMode::Off,
        max_peers_per_ipv4_prefix24: 2,
        max_peers_per_ipv4_prefix16: 8,
        min_outbound_diversity_buckets: 4,
        max_single_bucket_fraction_bps: 2500,
    };

    assert!(custom.enable_p2p);
    assert_eq!(custom.max_outbound, 10);
    assert_eq!(custom.static_peers.len(), 2);
}

// ============================================================================
// Test 8: P2P Metrics
// ============================================================================

#[test]
fn test_p2p_metrics() {
    let metrics = P2pMetrics::new();

    // Initial state
    assert_eq!(metrics.connections_current(), 0);
    assert_eq!(metrics.bytes_sent_total(), 0);
    assert_eq!(metrics.bytes_received_total(), 0);

    // Update connections
    metrics.set_connections_current(5);
    assert_eq!(metrics.connections_current(), 5);

    // Record bytes sent
    metrics.add_bytes_sent(1024);
    assert_eq!(metrics.bytes_sent_total(), 1024);
    metrics.add_bytes_sent(512);
    assert_eq!(metrics.bytes_sent_total(), 1536);

    // Record bytes received
    metrics.add_bytes_received(2048);
    assert_eq!(metrics.bytes_received_total(), 2048);

    // Record message sent
    metrics.inc_message_sent("consensus");
    assert_eq!(metrics.messages_sent_total("consensus"), 1);

    metrics.inc_message_sent("dag");
    assert_eq!(metrics.messages_sent_total("dag"), 1);

    metrics.inc_message_sent("control");
    assert_eq!(metrics.messages_sent_total("control"), 1);

    // Record message received
    metrics.inc_message_received("consensus");
    assert_eq!(metrics.messages_received_total("consensus"), 1);

    metrics.inc_message_received("dag");
    assert_eq!(metrics.messages_received_total("dag"), 1);

    metrics.inc_message_received("control");
    assert_eq!(metrics.messages_received_total("control"), 1);
}

// ============================================================================
// Test 9: Service Broadcast (No Panic)
// ============================================================================

#[tokio::test]
async fn test_service_broadcast_no_panic() {
    let crypto = create_test_crypto();
    let config = create_test_config(0);
    let node_id = NodeId::new([3u8; 32]);
    let (server_cfg, client_cfg) = create_test_connection_configs(crypto.clone());

    let mut service = TcpKemTlsP2pService::new(node_id, config, crypto, server_cfg, client_cfg)
        .expect("Failed to create service");

    service.start().await.expect("Failed to start service");

    // Broadcast to no peers should not panic
    let msg = P2pMessage::Control(ControlMsg::Heartbeat {
        view: 1,
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    });
    service.broadcast(msg);

    // Give broadcast time to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    service.shutdown().await;
}