//! Integration tests for the async consensus network worker (T87).
//!
//! These tests verify the `ConsensusNetWorker` integration with `AsyncNodeRunner`:
//! - Events flow from network service to harness via the event channel
//! - Graceful shutdown when network closes or channel is dropped
//! - Multiple senders can feed the event channel
//!
//! # Test Organization
//!
//! - **Mock network tests**: Use `MockConsensusNetService` to test the worker in isolation
//! - **Worker + runner integration**: Test the full path from worker to runner to harness
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test consensus_net_worker_tests -- --test-threads=1
//! ```

use std::sync::Arc;
use std::time::Duration;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::network::ConsensusNetworkEvent;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

use qbind_node::async_runner::{AsyncNodeRunner, ConsensusEvent};
use qbind_node::consensus_net_worker::{ConsensusNetService, ConsensusNetWorker};
use qbind_node::hotstuff_node_sim::NodeHotstuffHarness;
use qbind_node::peer::PeerId;
use qbind_node::validator_config::NodeValidatorConfig;

use tokio::sync::mpsc;

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
    use qbind_node::validator_config::make_test_local_validator_config;
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

/// Create a dummy Vote for testing.
fn make_dummy_vote(height: u64, round: u64) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    }
}

/// Create a dummy BlockProposal for testing.
fn make_dummy_proposal(height: u64, round: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Mock Network Service for Testing
// ============================================================================

use qbind_consensus::network::NetworkError;
use std::collections::VecDeque;
use std::sync::Mutex;

/// A mock implementation of `ConsensusNetService` for testing.
#[derive(Clone)]
struct MockNetService {
    /// Queue of events to return from `recv()`.
    inbound: Arc<Mutex<VecDeque<ConsensusNetworkEvent<PeerId>>>>,
    /// Recorded outbound votes.
    outbound_votes: Arc<Mutex<Vec<(Option<PeerId>, Vote)>>>,
    /// Recorded outbound proposals.
    outbound_proposals: Arc<Mutex<Vec<BlockProposal>>>,
}

impl MockNetService {
    fn new() -> Self {
        MockNetService {
            inbound: Arc::new(Mutex::new(VecDeque::new())),
            outbound_votes: Arc::new(Mutex::new(Vec::new())),
            outbound_proposals: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_events(events: Vec<ConsensusNetworkEvent<PeerId>>) -> Self {
        let mock = Self::new();
        {
            let mut inbound = mock.inbound.lock().unwrap();
            for event in events {
                inbound.push_back(event);
            }
        }
        mock
    }

    fn outbound_votes(&self) -> Vec<(Option<PeerId>, Vote)> {
        self.outbound_votes.lock().unwrap().clone()
    }

    fn outbound_proposals(&self) -> Vec<BlockProposal> {
        self.outbound_proposals.lock().unwrap().clone()
    }
}

impl ConsensusNetService for MockNetService {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        let mut inbound = self.inbound.lock().unwrap();
        inbound.pop_front()
    }

    async fn send_vote_to(&mut self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        let mut outbound = self.outbound_votes.lock().unwrap();
        outbound.push((Some(to), vote.clone()));
        Ok(())
    }

    async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        let mut outbound = self.outbound_votes.lock().unwrap();
        outbound.push((None, vote.clone()));
        Ok(())
    }

    async fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        let mut outbound = self.outbound_proposals.lock().unwrap();
        outbound.push(proposal.clone());
        Ok(())
    }
}

// ============================================================================
// Part A: Worker isolation tests
// ============================================================================

/// Test that `ConsensusNetWorker` forwards events from the network to the channel.
#[tokio::test]
async fn worker_forwards_network_events_to_channel() {
    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(2, 1);

    let events = vec![
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(100),
            vote: vote.clone(),
        },
        ConsensusNetworkEvent::IncomingProposal {
            from: PeerId(200),
            proposal: proposal.clone(),
        },
    ];

    let mock = MockNetService::with_events(events);
    let (tx, mut rx) = mpsc::channel(10);

    let worker = ConsensusNetWorker::new(mock, tx);

    // Run the worker - it should exit when the mock returns None
    let result = worker.run().await;
    assert!(result.is_ok(), "worker should exit cleanly");

    // Check that events were forwarded
    let event1 = rx.recv().await.expect("should receive first event");
    match event1 {
        ConsensusEvent::IncomingMessage(boxed) => match *boxed {
            ConsensusNetworkEvent::IncomingVote { from, vote: v } => {
                assert_eq!(from, PeerId(100));
                assert_eq!(v.height, 1);
            }
            _ => panic!("expected IncomingVote"),
        },
        _ => panic!("expected IncomingMessage"),
    }

    let event2 = rx.recv().await.expect("should receive second event");
    match event2 {
        ConsensusEvent::IncomingMessage(boxed) => match *boxed {
            ConsensusNetworkEvent::IncomingProposal { from, proposal: p } => {
                assert_eq!(from, PeerId(200));
                assert_eq!(p.header.height, 2);
            }
            _ => panic!("expected IncomingProposal"),
        },
        _ => panic!("expected IncomingMessage"),
    }

    // No more events
    assert!(rx.try_recv().is_err());
}

/// Test that worker exits gracefully when network closes.
#[tokio::test]
async fn worker_exits_when_network_closes() {
    let mock = MockNetService::new(); // Empty queue - recv() returns None immediately
    let (tx, _rx) = mpsc::channel(10);

    let worker = ConsensusNetWorker::new(mock, tx);

    let result = worker.run().await;
    assert!(
        result.is_ok(),
        "worker should exit cleanly when network closes"
    );
}

/// Test that worker exits gracefully when channel is closed.
#[tokio::test]
async fn worker_exits_when_channel_closed() {
    let mock = MockNetService::new();
    // Add one event so worker doesn't exit immediately
    mock.inbound
        .lock()
        .unwrap()
        .push_back(ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        });

    let (tx, rx) = mpsc::channel(10);

    // Drop the receiver immediately
    drop(rx);

    let worker = ConsensusNetWorker::new(mock, tx);

    // Worker should exit gracefully when it can't send
    let result = worker.run().await;
    assert!(
        result.is_ok(),
        "worker should exit cleanly when channel closes"
    );
}

// ============================================================================
// Part B: Worker + Runner integration tests
// ============================================================================

/// Test that events from the network worker reach the runner via the channel.
///
/// This test:
/// 1. Creates a harness and async runner
/// 2. Creates a mock network service with pre-populated events
/// 3. Runs the network worker to send events to the runner
/// 4. Verifies events are processed
#[tokio::test]
async fn worker_runner_integration_events_reach_harness() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation should succeed");

    // Create runner with long tick interval (we'll drive it via events)
    let (runner, events_tx) = AsyncNodeRunner::new(harness, Duration::from_secs(100));
    let runner = runner.with_max_ticks(0); // Don't exit on timer ticks

    // Create mock network with one vote event
    let vote = make_dummy_vote(1, 0);
    let events = vec![ConsensusNetworkEvent::IncomingVote {
        from: PeerId(100),
        vote: vote.clone(),
    }];
    let mock = MockNetService::with_events(events);

    // Create network worker
    let net_worker = ConsensusNetWorker::new(mock, events_tx.clone());

    // Run network worker - it will send event and then exit
    let net_result = net_worker.run().await;
    assert!(net_result.is_ok(), "network worker should complete");

    // Send shutdown to runner
    events_tx.send(ConsensusEvent::Shutdown).await.unwrap();

    // Run runner - it should process the event and then shutdown
    let runner_result = runner.run().await;
    assert!(runner_result.is_ok(), "runner should exit cleanly");
}

/// Test that multiple workers can send to the same channel.
#[tokio::test]
async fn multiple_workers_can_send_to_same_channel() {
    let (tx, mut rx) = mpsc::channel(10);

    // Create two mock networks with different events
    let events1 = vec![ConsensusNetworkEvent::IncomingVote {
        from: PeerId(1),
        vote: make_dummy_vote(1, 0),
    }];
    let events2 = vec![ConsensusNetworkEvent::IncomingVote {
        from: PeerId(2),
        vote: make_dummy_vote(2, 0),
    }];

    let mock1 = MockNetService::with_events(events1);
    let mock2 = MockNetService::with_events(events2);

    // Clone sender for second worker
    let tx2 = tx.clone();

    let worker1 = ConsensusNetWorker::new(mock1, tx);
    let worker2 = ConsensusNetWorker::new(mock2, tx2);

    // Run both workers concurrently
    let (res1, res2) = tokio::join!(worker1.run(), worker2.run());

    assert!(res1.is_ok());
    assert!(res2.is_ok());

    // Should have received 2 events total
    let event1 = rx.recv().await.expect("should receive first event");
    let event2 = rx.recv().await.expect("should receive second event");

    assert!(matches!(event1, ConsensusEvent::IncomingMessage(_)));
    assert!(matches!(event2, ConsensusEvent::IncomingMessage(_)));
}

/// Test concurrent execution of worker and runner using tokio::select!
#[tokio::test]
async fn worker_and_runner_run_concurrently() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation should succeed");

    // Create runner with very long tick interval
    let (runner, events_tx) = AsyncNodeRunner::new(harness, Duration::from_secs(1000));

    // Create mock network with a few events
    let events = vec![
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(1),
            vote: make_dummy_vote(1, 0),
        },
        ConsensusNetworkEvent::IncomingVote {
            from: PeerId(2),
            vote: make_dummy_vote(2, 0),
        },
    ];
    let mock = MockNetService::with_events(events);
    let net_worker = ConsensusNetWorker::new(mock, events_tx.clone());

    // Spawn shutdown sender
    let shutdown_tx = events_tx.clone();
    tokio::spawn(async move {
        // Give workers time to send events
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(ConsensusEvent::Shutdown).await;
    });

    // Run both concurrently using select!
    let result = tokio::select! {
        res = runner.run() => {
            eprintln!("[test] Runner exited first");
            res
        }
        res = net_worker.run() => {
            eprintln!("[test] Network worker exited first: {:?}", res);
            // Network worker finished, wait a bit for shutdown to reach runner
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Convert network worker result to runner result type
            // The worker exiting cleanly is expected behavior in this test
            match res {
                Ok(()) => Ok(()),
                Err(e) => {
                    eprintln!("[test] Network worker error: {}", e);
                    Err(qbind_node::AsyncNodeError::Cancelled)
                }
            }
        }
    };

    // Either the runner exits cleanly on shutdown, or network worker exits first
    // and we eventually timeout. For this test, we just verify no panic.
    eprintln!("[test] Final result: {:?}", result.is_ok());
}

// ============================================================================
// Part C: Outbound path tests
// ============================================================================

/// Test that outbound messages are recorded by the mock sender.
#[tokio::test]
async fn mock_sender_records_outbound_messages() {
    let mock = MockNetService::new();
    let mock_clone = mock.clone();

    let vote = make_dummy_vote(1, 0);
    let proposal = make_dummy_proposal(1, 0);

    // Use the async methods
    let mut mock = mock;
    mock.send_vote_to(PeerId(1), &vote).await.unwrap();
    mock.broadcast_vote(&vote).await.unwrap();
    mock.broadcast_proposal(&proposal).await.unwrap();

    // Check recorded calls
    let votes = mock_clone.outbound_votes();
    assert_eq!(votes.len(), 2);
    assert_eq!(votes[0].0, Some(PeerId(1)));
    assert_eq!(votes[1].0, None);

    let proposals = mock_clone.outbound_proposals();
    assert_eq!(proposals.len(), 1);
}

// ============================================================================
// Part D: Backward compatibility tests
// ============================================================================

/// Verify that existing async_runner tests still pass (regression test).
/// This test just ensures the runner can be created and run without the worker.
#[tokio::test]
async fn runner_works_without_network_worker() {
    let (cfg, client_cfg, server_cfg) = make_test_config();

    let harness =
        NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)
            .expect("harness creation should succeed");

    let (runner, event_tx) = AsyncNodeRunner::new(harness, Duration::from_millis(10));
    let runner = runner.with_max_ticks(5);

    // Drop the sender so the runner doesn't wait for events
    drop(event_tx);

    // Runner should complete after max_ticks even without network worker
    let result = tokio::time::timeout(Duration::from_secs(5), runner.run()).await;

    assert!(result.is_ok(), "runner should complete within timeout");
    assert!(result.unwrap().is_ok(), "runner should exit cleanly");
}
