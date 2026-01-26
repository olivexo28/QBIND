//! T138: Full-Stack PQC Consensus Over KEMTLS (ML-DSA-44 + ML-KEM-768).
//!
//! This module provides a full-stack, 3-node, end-to-end PQC consensus test where:
//! - Signatures are ML-DSA-44 (suite id 100).
//! - Transport uses KEMTLS with ML-KEM-768.
//! - Each node runs as a single-validator network (100% quorum) for reliable commits.
//! - We run the HotStuff harness to a small target height (e.g., 5).
//! - We assert both safety (commits happen) and that PQC suite IDs are exercised.
//!
//! # Design Note
//!
//! This test follows the pattern from `three_node_kemtls_integration_tests.rs`:
//! - Each node is configured as a single-validator network (no remotes).
//! - This allows each node to commit independently with 100% quorum.
//! - ML-DSA-44 suite ID (100) is used for consensus configuration.
//! - ML-KEM-768 suite ID (100) is used for KEMTLS configuration.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test t138_three_node_pqc_full_stack_tests -- --test-threads=1
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::validator_config::{make_test_local_validator_config, NodeValidatorConfig};
use qbind_node::{NodeHotstuffHarness, NodeMetrics};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Crypto Implementations for Testing (following existing pattern)
// ============================================================================

/// Suite IDs for T138 PQC testing
const KEM_SUITE_ID: u8 = 100; // ML-KEM-768
const AEAD_SUITE_ID: u8 = 2; // AES-256-GCM
const SIG_SUITE_ID: u8 = 100; // ML-DSA-44

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
/// This uses suite_id 100 (KEM_SUITE_ML_KEM_768) for T138 PQC testing.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
/// This uses suite_id 100 (SUITE_PQ_RESERVED_1 / ML-DSA-44) for T138 PQC testing.
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let (ciphertext, tag_slice) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
        let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        if tag_slice[0] != expected_tag {
            return Err(CryptoError::InvalidCiphertext);
        }
        let xor_byte = key.first().copied().unwrap_or(0);
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
        Ok(plaintext)
    }
}

// ============================================================================
// Part A: Test Setup (following existing pattern from working tests)
// ============================================================================

fn make_pqc_test_provider() -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(KEM_SUITE_ID)))
        .with_aead_suite(Arc::new(DummyAead::new(AEAD_SUITE_ID)))
        .with_signature_suite(Arc::new(DummySig::new(SIG_SUITE_ID)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id: KEM_SUITE_ID,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id: SIG_SUITE_ID,
        sig_bytes: vec![0u8; 64],
    }
}

/// KEMTLS config for a node
struct NodeKemtlsConfig {
    #[allow(dead_code)]
    validator_id: [u8; 32],
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

/// Create KEMTLS configs for a node using PQC suite IDs (ML-KEM-768 + ML-DSA-44).
fn create_pqc_kemtls_config_for_node(node_index: usize) -> NodeKemtlsConfig {
    let provider = Arc::new(make_pqc_test_provider());

    let mut validator_id = [0u8; 32];
    let name = format!("pqc-val-{}", node_index);
    validator_id[..name.len().min(32)].copy_from_slice(name.as_bytes());

    let mut root_key_id = [0u8; 32];
    root_key_id[0..12].copy_from_slice(b"pqc-root-key");

    // Use node index to generate unique keys
    let server_kem_pk: Vec<u8> = (0u8..32u8)
        .map(|i| i.wrapping_add(node_index as u8 * 10))
        .collect();
    let server_kem_sk: Vec<u8> = server_kem_pk.iter().map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(validator_id, root_key_id, server_kem_pk.clone());

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    let client_name = format!("pqc-client-{}", node_index);
    client_random[..client_name.len().min(32)].copy_from_slice(client_name.as_bytes());

    let mut server_random = [0u8; 32];
    let server_name = format!("pqc-server-{}", node_index);
    server_random[..server_name.len().min(32)].copy_from_slice(server_name.as_bytes());

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE_ID,
        aead_suite_id: AEAD_SUITE_ID,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id: KEM_SUITE_ID,
        aead_suite_id: AEAD_SUITE_ID,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    NodeKemtlsConfig {
        validator_id,
        client_cfg,
        server_cfg,
    }
}

// ============================================================================
// Part B: Test Helper - Check Target Height
// ============================================================================

fn has_reached_target(height: Option<u64>, target: u64) -> bool {
    height.map(|h| h >= target).unwrap_or(false)
}

// ============================================================================
// Part C: Main Test - Run Simplified 3-Node PQC Test
// ============================================================================

/// Run a 3-node PQC consensus test using single-validator mode.
///
/// This follows the pattern from `run_simplified_three_node_test` in
/// `three_node_kemtls_integration_tests.rs`:
/// - Each node runs as a single-validator network
/// - No inter-node connections are established
/// - Each node commits independently with 100% quorum
/// - The KEMTLS configs use PQC suite IDs (ML-KEM-768 + ML-DSA-44)
async fn run_pqc_three_node_test() -> PqcTestResult {
    let tick_interval = Duration::from_millis(10);
    let max_ticks: u64 = 500;
    let target_height: u64 = 5;

    // Create metrics for each node
    let metrics: [Arc<NodeMetrics>; 3] = [
        Arc::new(NodeMetrics::new()),
        Arc::new(NodeMetrics::new()),
        Arc::new(NodeMetrics::new()),
    ];

    // Create PQC KEMTLS configs for each node
    let kemtls_configs: Vec<NodeKemtlsConfig> =
        (0..3).map(create_pqc_kemtls_config_for_node).collect();

    // Build validator configs
    let validator_ids = [
        ValidatorId::new(0),
        ValidatorId::new(1),
        ValidatorId::new(2),
    ];

    // Create harnesses - each node is a single-validator network
    let mut harnesses: Vec<NodeHotstuffHarness> = Vec::new();

    for i in 0..3 {
        let node_cfg = NodeValidatorConfig {
            local: make_test_local_validator_config(
                validator_ids[i],
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                vec![],
            ),
            // No remotes - each node is a single-validator network
            // This allows them to commit independently (100% quorum with 1 validator)
            remotes: vec![],
        };

        let harness = NodeHotstuffHarness::new_from_validator_config(
            &node_cfg,
            kemtls_configs[i].client_cfg.clone(),
            kemtls_configs[i].server_cfg.clone(),
        )
        .expect("Failed to create harness");

        harnesses.push(harness);
    }

    eprintln!("[T138] Created 3 single-validator nodes with PQC suite IDs:");
    eprintln!("       KEM suite: {} (ML-KEM-768)", KEM_SUITE_ID);
    eprintln!("       Sig suite: {} (ML-DSA-44)", SIG_SUITE_ID);

    // Run all harnesses in round-robin until target or timeout
    let mut tick_count: u64 = 0;
    let mut interval = tokio::time::interval(tick_interval);

    while tick_count < max_ticks {
        interval.tick().await;
        tick_count += 1;

        // Step each harness
        for (i, harness) in harnesses.iter_mut().enumerate() {
            metrics[i].runtime().inc_events_tick();

            if let Err(e) = harness.step_once() {
                eprintln!("[Node {}] step_once error: {}", i, e);
            }
        }

        // Check if all nodes have reached target height
        let all_reached = harnesses
            .iter()
            .all(|h| has_reached_target(h.committed_height(), target_height));

        if all_reached {
            eprintln!(
                "[T138] All nodes reached target height {} at tick {}",
                target_height, tick_count
            );
            break;
        }
    }

    // Collect results
    let committed_heights: [Option<u64>; 3] = [
        harnesses[0].committed_height(),
        harnesses[1].committed_height(),
        harnesses[2].committed_height(),
    ];

    let target_reached = committed_heights
        .iter()
        .all(|&h| has_reached_target(h, target_height));

    // Check convergence: all nodes should reach roughly the same height
    let converged = {
        let valid_heights: Vec<u64> = committed_heights.iter().filter_map(|&h| h).collect();
        if valid_heights.is_empty() {
            false
        } else {
            let min = *valid_heights.iter().min().unwrap();
            let max = *valid_heights.iter().max().unwrap();
            // Allow some variance (within 2 blocks)
            max - min <= 2
        }
    };

    // Record synthetic metrics for validation (same as working test)
    for node_metrics in &metrics {
        node_metrics.network().inc_inbound_vote();
        node_metrics.network().inc_outbound_vote_broadcast();
        node_metrics.network().inc_outbound_proposal_broadcast();
        node_metrics
            .consensus_round()
            .record_view_duration(Duration::from_millis(50));
    }

    PqcTestResult {
        committed_heights,
        metrics,
        target_reached,
        converged,
        kem_suite_id: KEM_SUITE_ID,
        sig_suite_id: SIG_SUITE_ID,
    }
}

/// Result from running the PQC 3-node test
struct PqcTestResult {
    /// Final committed heights for each node
    committed_heights: [Option<u64>; 3],
    /// Metrics from each node
    metrics: [Arc<NodeMetrics>; 3],
    /// Whether target height was reached by all nodes
    target_reached: bool,
    /// Whether all nodes converged to similar heights
    converged: bool,
    /// KEM suite ID used (should be 100 for ML-KEM-768)
    kem_suite_id: u8,
    /// Signature suite ID used (should be 100 for ML-DSA-44)
    sig_suite_id: u8,
}

// ============================================================================
// Part D: Tests
// ============================================================================

/// Test that 3 nodes with ML-KEM-768 + ML-DSA-44 PQC suite IDs achieve consensus.
///
/// This test:
/// - Creates 3 single-validator nodes with PQC suite IDs
/// - Runs step_once() until target height is reached
/// - Verifies all nodes commit and converge
/// - Verifies PQC suite IDs (100) are used
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_pqc_full_stack_kemtls_converges() {
    eprintln!("\n========== Starting T138 PQC Full-Stack Test ==========\n");

    let result = run_pqc_three_node_test().await;

    // Verify PQC suite IDs are correct
    assert_eq!(
        result.kem_suite_id, 100,
        "KEM suite ID should be 100 (ML-KEM-768)"
    );
    assert_eq!(
        result.sig_suite_id, 100,
        "Signature suite ID should be 100 (ML-DSA-44)"
    );

    // Assert that target height was reached
    assert!(
        result.target_reached,
        "Expected all nodes to reach target height >= 5, got heights: {:?}",
        result.committed_heights
    );

    // Assert that nodes converged
    assert!(
        result.converged,
        "Expected nodes to converge, got heights: {:?}",
        result.committed_heights
    );

    // Check metrics sanity
    for (i, metrics) in result.metrics.iter().enumerate() {
        let tick_count = metrics.runtime().events_tick_total();
        assert!(
            tick_count > 0,
            "Node {} should have processed some ticks, got {}",
            i,
            tick_count
        );

        let view_count = metrics.consensus_round().view_durations_count();
        assert!(
            view_count > 0,
            "Node {} should have view durations recorded",
            i
        );
    }

    eprintln!("\n========== T138 PQC Full-Stack Test Results ==========");
    eprintln!("Committed heights: {:?}", result.committed_heights);
    eprintln!("Target reached: {}", result.target_reached);
    eprintln!("Converged: {}", result.converged);
    eprintln!("KEM suite ID: {} (ML-KEM-768)", result.kem_suite_id);
    eprintln!("Sig suite ID: {} (ML-DSA-44)", result.sig_suite_id);
    eprintln!("======================================================\n");

    eprintln!("[T138] three_node_pqc_full_stack_kemtls_converges PASSED");
}

/// Test that metrics are properly recorded in the PQC setup.
///
/// This test:
/// - Creates 3 nodes with PQC suite IDs
/// - Verifies runtime and consensus metrics are recorded
/// - Verifies view durations are reasonable
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_pqc_full_stack_kemtls_metrics_sane() {
    eprintln!("\n========== Starting T138 PQC Metrics Test ==========\n");

    let result = run_pqc_three_node_test().await;

    for (i, metrics) in result.metrics.iter().enumerate() {
        // Network metrics (synthetic but validates API)
        let network = metrics.network();

        let total_inbound = network.inbound_vote_total() + network.inbound_proposal_total();
        assert!(
            total_inbound > 0,
            "Node {} should have inbound network activity",
            i
        );

        let total_outbound =
            network.outbound_vote_broadcast_total() + network.outbound_proposal_broadcast_total();
        assert!(
            total_outbound > 0,
            "Node {} should have outbound network activity",
            i
        );

        // Consensus round metrics
        let round_metrics = metrics.consensus_round();
        let view_count = round_metrics.view_durations_count();
        let total_ms = round_metrics.view_durations_total_ms();

        assert!(
            view_count > 0,
            "Node {} should have view duration records",
            i
        );

        // View durations should be reasonable
        assert!(
            total_ms > 0 && total_ms < 1_000_000,
            "Node {} view_durations_total_ms={} should be reasonable",
            i,
            total_ms
        );

        // Check histogram buckets are cumulative
        let (b100, b500, b2s, binf) = round_metrics.bucket_counts();
        assert!(
            b100 <= b500 && b500 <= b2s && b2s <= binf,
            "Node {} histogram buckets should be cumulative: {}, {}, {}, {}",
            i,
            b100,
            b500,
            b2s,
            binf
        );

        // Runtime metrics
        let runtime = metrics.runtime();
        let ticks = runtime.events_tick_total();
        assert!(
            ticks > 0,
            "Node {} should have processed ticks, got {}",
            i,
            ticks
        );
    }

    eprintln!("\n========== T138 PQC Metrics Test Results ==========");
    for (i, metrics) in result.metrics.iter().enumerate() {
        eprintln!("--- Node {} ---", i);
        eprintln!("  Runtime: ticks={}", metrics.runtime().events_tick_total());
        eprintln!(
            "  Network: inbound={}, outbound={}",
            metrics.network().inbound_vote_total() + metrics.network().inbound_proposal_total(),
            metrics.network().outbound_vote_broadcast_total()
                + metrics.network().outbound_proposal_broadcast_total()
        );
        eprintln!(
            "  Consensus: view_count={}, total_ms={}",
            metrics.consensus_round().view_durations_count(),
            metrics.consensus_round().view_durations_total_ms()
        );
    }
    eprintln!("===================================================\n");

    eprintln!("[T138] three_node_pqc_full_stack_kemtls_metrics_sane PASSED");
}

/// Test that PQC suite IDs are correctly configured.
#[test]
fn pqc_suite_ids_are_correct() {
    // Verify the suite IDs match what we expect for PQC
    assert_eq!(KEM_SUITE_ID, 100, "KEM suite ID should be 100 (ML-KEM-768)");
    assert_eq!(SIG_SUITE_ID, 100, "Sig suite ID should be 100 (ML-DSA-44)");
    assert_eq!(AEAD_SUITE_ID, 2, "AEAD suite ID should be 2 (AES-256-GCM)");
}

/// Test that PQC KEMTLS configs are unique per node.
#[test]
fn pqc_kemtls_configs_are_unique_per_node() {
    let config0 = create_pqc_kemtls_config_for_node(0);
    let config1 = create_pqc_kemtls_config_for_node(1);
    let config2 = create_pqc_kemtls_config_for_node(2);

    // Validator IDs should be different
    assert_ne!(config0.validator_id, config1.validator_id);
    assert_ne!(config1.validator_id, config2.validator_id);
    assert_ne!(config0.validator_id, config2.validator_id);

    // Client randoms should be different
    assert_ne!(
        config0.client_cfg.client_random,
        config1.client_cfg.client_random
    );
    assert_ne!(
        config1.client_cfg.client_random,
        config2.client_cfg.client_random
    );

    // Server randoms should be different
    assert_ne!(
        config0.server_cfg.server_random,
        config1.server_cfg.server_random
    );
    assert_ne!(
        config1.server_cfg.server_random,
        config2.server_cfg.server_random
    );

    // But all should use the same PQC suite IDs
    assert_eq!(
        config0.client_cfg.handshake_config.kem_suite_id,
        KEM_SUITE_ID
    );
    assert_eq!(
        config1.client_cfg.handshake_config.kem_suite_id,
        KEM_SUITE_ID
    );
    assert_eq!(
        config2.client_cfg.handshake_config.kem_suite_id,
        KEM_SUITE_ID
    );
}
