//! T175 P2P Wiring Smoke Tests
//!
//! This module tests the P2P node wiring (T175):
//! - P2pNodeBuilder can create a P2P node context
//! - TcpKemTlsP2pService starts successfully
//! - Basic P2P node lifecycle (build + shutdown)
//!
//! These are single-process, in-memory tests. They do not test
//! multi-process communication - that is covered by the runbook.

use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
use qbind_node::node_config::{
    DagCouplingMode, ExecutionProfile, MempoolMode, NetworkMode, NetworkTransportConfig,
    NodeConfig, SignerMode, StateRetentionConfig,
};
use qbind_node::p2p_node_builder::{P2pNodeBuilder, P2pNodeError};
use qbind_types::NetworkEnvironment;

// ============================================================================
// Helper Functions
// ============================================================================

fn make_test_p2p_config() -> NodeConfig {
    NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
        data_dir: None,
        network: NetworkTransportConfig {
            enable_p2p: true,
            max_outbound: 4,
            max_inbound: 8,
            gossip_fanout: 3,
            listen_addr: Some("127.0.0.1:0".to_string()),
            advertised_addr: None,
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
        },
        network_mode: NetworkMode::P2p,
        gas_enabled: false,
        enable_fee_priority: false,
        mempool_mode: MempoolMode::Fifo,
        dag_availability_enabled: false,
        dag_coupling_mode: DagCouplingMode::Off,
        stage_b_enabled: false,
        fee_distribution_policy: FeeDistributionPolicy::burn_only(),
        // T197: Monetary mode defaults
        monetary_mode: MonetaryMode::Off,
        monetary_accounts: None,
        seigniorage_split: SeigniorageSplit::default(),
        // T208: State retention defaults
        state_retention: StateRetentionConfig::disabled(),
        // T210: Signer mode defaults
        signer_mode: SignerMode::LoopbackTesting,
        signer_keystore_path: None,
        remote_signer_url: None,
        hsm_config_path: None,
    }
}

fn make_test_local_mesh_config() -> NodeConfig {
    NodeConfig {
        environment: NetworkEnvironment::Testnet,
        execution_profile: ExecutionProfile::VmV0,
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
        // T197: Monetary mode defaults
        monetary_mode: MonetaryMode::Off,
        monetary_accounts: None,
        seigniorage_split: SeigniorageSplit::default(),
        // T208: State retention defaults
        state_retention: StateRetentionConfig::disabled(),
        // T210: Signer mode defaults
        signer_mode: SignerMode::LoopbackTesting,
        signer_keystore_path: None,
        remote_signer_url: None,
        hsm_config_path: None,
    }
}

// ============================================================================
// Part 1: P2pNodeBuilder Basic Tests
// ============================================================================

#[test]
fn test_p2p_node_builder_new() {
    let builder = P2pNodeBuilder::new();
    // Just verify it can be created
    drop(builder);
}

#[test]
fn test_p2p_node_builder_with_num_validators() {
    let builder = P2pNodeBuilder::new().with_num_validators(7);
    // Verify builder pattern works
    drop(builder);
}

// ============================================================================
// Part 2: P2P Node Lifecycle Tests
// ============================================================================

/// Test that P2pNodeBuilder can build a P2P node context.
#[tokio::test]
async fn test_p2p_node_builder_build_and_shutdown() {
    let config = make_test_p2p_config();
    let builder = P2pNodeBuilder::new().with_num_validators(4);

    // Build the P2P node
    let result = builder.build(&config, 0).await;
    assert!(
        result.is_ok(),
        "P2pNodeBuilder::build should succeed: {:?}",
        result.err()
    );

    let context = result.unwrap();

    // Verify basic context properties
    assert_eq!(context.validator_id.as_u64(), 0);

    // Shutdown the node
    let shutdown_result = P2pNodeBuilder::shutdown(context).await;
    assert!(
        shutdown_result.is_ok(),
        "P2pNodeBuilder::shutdown should succeed: {:?}",
        shutdown_result.err()
    );
}

/// Test that multiple validators can be built.
#[tokio::test]
async fn test_p2p_node_builder_multiple_validators() {
    let config = make_test_p2p_config();

    // Build validator 0
    let builder0 = P2pNodeBuilder::new().with_num_validators(4);
    let ctx0 = builder0.build(&config, 0).await.unwrap();

    // Build validator 1 (with different listen address)
    let mut config1 = make_test_p2p_config();
    config1.network.listen_addr = Some("127.0.0.1:0".to_string()); // OS-assigned port
    let builder1 = P2pNodeBuilder::new().with_num_validators(4);
    let ctx1 = builder1.build(&config1, 1).await.unwrap();

    // Verify different validator IDs
    assert_eq!(ctx0.validator_id.as_u64(), 0);
    assert_eq!(ctx1.validator_id.as_u64(), 1);

    // Shutdown both
    P2pNodeBuilder::shutdown(ctx0).await.unwrap();
    P2pNodeBuilder::shutdown(ctx1).await.unwrap();
}

// ============================================================================
// Part 3: Configuration Tests
// ============================================================================

#[test]
fn test_config_is_p2p_mode() {
    let p2p_config = make_test_p2p_config();
    assert!(p2p_config.is_p2p_mode());

    let local_mesh_config = make_test_local_mesh_config();
    assert!(!local_mesh_config.is_p2p_mode());
}

#[test]
fn test_config_validate_p2p_config() {
    let mut config = make_test_p2p_config();
    let enabled = config.validate_p2p_config();
    assert!(enabled, "P2P mode should be enabled");
}

#[test]
fn test_config_validate_local_mesh_config() {
    let mut config = make_test_local_mesh_config();
    let enabled = config.validate_p2p_config();
    assert!(!enabled, "LocalMesh mode should not enable P2P");
}

// ============================================================================
// Part 4: Error Handling Tests
// ============================================================================

#[test]
fn test_p2p_node_error_display() {
    let err = P2pNodeError::Config("test error".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("test error"));
}

// ============================================================================
// Part 5: P2P Consensus Network Tests
// ============================================================================

/// Test that the P2pConsensusNetwork is created correctly.
#[tokio::test]
async fn test_p2p_consensus_network_created() {
    let config = make_test_p2p_config();
    let builder = P2pNodeBuilder::new().with_num_validators(4);

    let context = builder.build(&config, 0).await.unwrap();

    // The consensus_network should be available
    let _local_node_id = context.consensus_network.local_node_id();
    // Just verify we can get the node ID without error

    P2pNodeBuilder::shutdown(context).await.unwrap();
}

// ============================================================================
// Part 6: Metrics Tests
// ============================================================================

/// Test that P2P metrics are created.
#[tokio::test]
async fn test_p2p_metrics_created() {
    let config = make_test_p2p_config();
    let builder = P2pNodeBuilder::new();

    let context = builder.build(&config, 0).await.unwrap();

    // Metrics should be available
    let _metrics = &context.metrics;

    P2pNodeBuilder::shutdown(context).await.unwrap();
}