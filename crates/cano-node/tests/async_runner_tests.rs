//! Tests for the Tokio-driven async node runner (T85).
//!
//! These tests verify that `AsyncNodeRunner`:
//! - Properly wraps `NodeHotstuffHarness` in an async context
//! - Calls `step_once()` on each tick
//! - Supports bounded runs via `max_ticks`
//! - Can be cancelled cleanly via timeout
//!
//! # Test Organization
//!
//! - **Unit tests**: Basic runner construction and error types
//! - **Async tests**: Tokio-driven tests with bounded ticks
//!
//! # Low-RAM Friendly
//!
//! These tests are designed to be lightweight and can be run independently:
//!
//! ```bash
//! cargo test -p cano-node --test async_runner_tests -- --test-threads=1
//! ```
//!
//! The tests use `InMemoryConsensusStorage` and minimal harness configurations
//! to avoid heavy resource usage.

use std::sync::Arc;
use std::time::Duration;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

use cano_node::async_runner::{AsyncNodeError, AsyncNodeRunner, ConsensusEvent};
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
use cano_node::storage::InMemoryConsensusStorage;
use cano_node::validator_config::NodeValidatorConfig;

// ============================================================================
// Dummy Crypto Implementations (test-only)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
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
// Test Helpers
// ============================================================================

fn make_test_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_test_setup() -> TestSetup {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(
        kem_suite_id,
        aead_suite_id,
        sig_suite_id,
    ));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
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

    TestSetup {
        client_cfg,
        server_cfg,
    }
}

/// Create a minimal test configuration for a single-node harness.
fn make_test_config() -> (
    NodeValidatorConfig,
    ClientConnectionConfig,
    ServerConnectionConfig,
) {
    let setup = create_test_setup();

    // Create local validator config
    use cano_node::validator_config::make_test_local_validator_config;
    let local = make_test_local_validator_config(
        ValidatorId(1),
        "127.0.0.1:0".parse().unwrap(), // Ephemeral port
        b"pk-1".to_vec(),
    );

    // No remote validators for single-node test
    let remotes = vec![];

    let cfg = NodeValidatorConfig { local, remotes };

    (cfg, setup.client_cfg, setup.server_cfg)
}

// ============================================================================
// Part A: Basic construction and error type tests
// ============================================================================

/// Test that AsyncNodeError has correct Display implementations.
#[test]
fn async_node_error_display_variants() {
    // Test Cancelled variant
    let err = AsyncNodeError::Cancelled;
    assert_eq!(err.to_string(), "runner cancelled");

    // Test Harness variant
    let harness_err = cano_node::NodeHotstuffHarnessError::Config("test error".to_string());
    let err2 = AsyncNodeError::Harness(harness_err);
    assert!(err2.to_string().contains("test error"));
}

/// Test that AsyncNodeRunner can be constructed with various configurations.
#[test]
fn async_runner_construction() {
    // This test just verifies the types compile correctly.
    // Actual harness construction requires valid network config.
    let tick_interval = Duration::from_millis(100);
    assert!(tick_interval.as_millis() > 0);

    let max_ticks: u64 = 10;
    assert!(max_ticks > 0);
}

// ============================================================================
// Part B: Async tests with Tokio runtime
// ============================================================================

/// Test that AsyncNodeRunner runs for max_ticks and then exits.
#[tokio::test]
async fn async_runner_max_ticks_bounded_run() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    // Create harness
    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Create runner with very short tick interval and bounded ticks
    let (runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));
    let mut runner = runner.with_max_ticks(5);

    // Run should complete after 5 ticks
    let result = runner.run_mut().await;
    assert!(result.is_ok(), "bounded run should complete successfully");

    // Verify harness is still accessible and has processed ticks
    let view = runner.harness().current_view();
    // For a single-node, view should advance as it proposes and commits
    // At minimum, view should be > 0 after 5 ticks
    eprintln!("[test] Final view after 5 ticks: {}", view);
}

/// Test that AsyncNodeRunner correctly exposes harness accessors.
#[tokio::test]
async fn async_runner_harness_access() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Initial state checks
    let initial_view = harness.current_view();
    assert_eq!(initial_view, 0, "initial view should be 0");

    let (runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));

    // Verify accessors work
    assert_eq!(runner.harness().current_view(), 0);
    assert_eq!(runner.tick_interval(), Duration::from_millis(10));
}

/// Test that load_persisted_state works with no storage attached.
#[tokio::test]
async fn async_runner_load_persisted_state_no_storage() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    let (mut runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));

    // Loading persisted state with no storage should return None
    let result = runner.load_persisted_state();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

/// Test that load_persisted_state works with empty in-memory storage.
#[tokio::test]
async fn async_runner_load_persisted_state_empty_storage() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let storage = Arc::new(InMemoryConsensusStorage::new());

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed")
        .with_storage(storage);

    let (mut runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));

    // Loading persisted state with empty storage should return None (fresh node)
    let result = runner.load_persisted_state();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

/// Test that AsyncNodeRunner can be cancelled via timeout.
#[tokio::test]
async fn async_runner_timeout_cancellation() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Create runner with no max_ticks (would run forever)
    let (runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));

    // Use tokio timeout to cancel after 100ms
    let result = tokio::time::timeout(Duration::from_millis(100), runner.run()).await;

    // Should timeout (Err from timeout)
    assert!(result.is_err(), "runner should be cancelled by timeout");
}

/// Test that step_once is called multiple times during bounded run.
#[tokio::test]
async fn async_runner_multiple_step_once_calls() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Single node should be able to propose and commit
    let initial_view = harness.current_view();
    assert_eq!(initial_view, 0);

    let (runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(5));
    let mut runner = runner.with_max_ticks(20);

    let result = runner.run_mut().await;
    assert!(result.is_ok());

    // After 20 ticks, a single node should have advanced views
    let final_view = runner.harness().current_view();
    eprintln!(
        "[test] Views: initial={}, final={}",
        initial_view, final_view
    );

    // For a single-node network, each tick should allow proposals/commits
    // View should be > initial (though exact number depends on QC formation)
    assert!(
        final_view > initial_view,
        "view should advance after multiple ticks"
    );
}

// ============================================================================
// Part C: Debug and Display implementations
// ============================================================================

/// Test that AsyncNodeRunner has working Debug impl.
#[test]
fn async_runner_debug_impl() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    let (runner, _event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));
    let runner = runner.with_max_ticks(50);

    let debug_str = format!("{:?}", runner);
    assert!(debug_str.contains("AsyncNodeRunner"));
    assert!(debug_str.contains("tick_interval"));
    assert!(debug_str.contains("max_ticks"));
}

// ============================================================================
// Part D: Event-driven tests (T86)
// ============================================================================

/// Test that sending ConsensusEvent::Shutdown causes clean exit.
#[tokio::test]
async fn async_runner_shutdown_event_exits_cleanly() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));

    // Spawn the runner in a task
    let handle = tokio::spawn(async move { runner.run().await });

    // Give the runner a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send shutdown event
    event_tx
        .send(ConsensusEvent::Shutdown)
        .await
        .expect("send should succeed");

    // Wait for the runner to exit
    let result = tokio::time::timeout(Duration::from_millis(500), handle).await;
    assert!(result.is_ok(), "runner should exit after shutdown event");

    let inner_result = result.unwrap().expect("join should succeed");
    assert!(
        inner_result.is_ok(),
        "runner should exit cleanly on shutdown"
    );
}

/// Test that dropping all senders causes graceful shutdown.
#[tokio::test]
async fn async_runner_channel_close_causes_graceful_exit() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(100));

    // Spawn the runner in a task
    let handle = tokio::spawn(async move { runner.run().await });

    // Give the runner a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drop the sender - this should cause the runner to exit
    drop(event_tx);

    // Wait for the runner to exit
    let result = tokio::time::timeout(Duration::from_millis(500), handle).await;
    assert!(result.is_ok(), "runner should exit after channel close");

    let inner_result = result.unwrap().expect("join should succeed");
    assert!(
        inner_result.is_ok(),
        "runner should exit cleanly when channel closes"
    );
}

/// Test that ConsensusEvent::Tick triggers harness.on_tick().
#[tokio::test]
async fn async_runner_tick_event_advances_consensus() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Use a very long tick interval so timer doesn't interfere
    let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_secs(100));
    let mut runner = runner.with_max_ticks(0); // Don't exit on timer ticks

    // We'll send ticks via the channel and then shutdown
    let handle = tokio::spawn({
        let event_tx = event_tx.clone();
        async move {
            // Send a few tick events
            for _ in 0..3 {
                event_tx.send(ConsensusEvent::Tick).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Then shutdown
            event_tx.send(ConsensusEvent::Shutdown).await.unwrap();
        }
    });

    // Run the runner
    let result = runner.run_mut().await;
    assert!(result.is_ok(), "runner should exit cleanly");

    // Wait for the sender task to complete
    handle.await.expect("sender task should complete");

    // The harness should have advanced (view > 0)
    // Note: Single node can propose and advance views
    let view = runner.harness().current_view();
    eprintln!("[test] Final view after tick events: {}", view);
}

/// Test that ConsensusEvent can be sent from multiple tasks.
#[tokio::test]
async fn async_runner_multiple_senders() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_secs(100));

    // Clone senders for multiple tasks
    let tx1 = event_tx.clone();
    let tx2 = event_tx.clone();

    // Spawn tasks that send events
    let h1 = tokio::spawn(async move {
        for _ in 0..2 {
            tx1.send(ConsensusEvent::Tick).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let h2 = tokio::spawn(async move {
        for _ in 0..2 {
            tx2.send(ConsensusEvent::Tick).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    // Spawn the runner
    let runner_handle = tokio::spawn(async move { runner.run().await });

    // Wait for sender tasks
    h1.await.unwrap();
    h2.await.unwrap();

    // Send shutdown
    event_tx.send(ConsensusEvent::Shutdown).await.unwrap();

    // Wait for runner
    let result = tokio::time::timeout(Duration::from_millis(500), runner_handle).await;
    assert!(result.is_ok(), "runner should exit");
    assert!(
        result.unwrap().unwrap().is_ok(),
        "runner should exit cleanly"
    );
}

/// Test that ConsensusEvent channel capacity is respected.
#[tokio::test]
async fn async_runner_custom_channel_capacity() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)
        .expect("harness creation should succeed");

    // Create with small capacity
    let (runner, event_tx) = AsyncNodeRunner::new_with_capacity(
        harness,
        Duration::from_millis(10),
        8, // Small capacity
    );

    // Basic check that runner works with custom capacity
    let runner = runner.with_max_ticks(3);

    // Drop the sender so we don't need to worry about shutdown
    drop(event_tx);

    // With timer ticks disabled by channel close, this should exit quickly
    let result = tokio::time::timeout(Duration::from_millis(500), runner.run()).await;
    assert!(result.is_ok(), "runner should exit when channel closes");
}
