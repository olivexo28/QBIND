//! T139: Real ML-KEM-768 + KEMTLS Two-Node Network Test.
//!
//! This test suite exercises real ML-KEM-768 KEMTLS handshakes between two nodes
//! over actual TCP connections. Unlike T138 (which uses dummy crypto), this test
//! uses the actual `MlKem768Backend` for key encapsulation.
//!
//! # What This Tests
//!
//! - Real ML-KEM-768 encapsulation and decapsulation
//! - KEMTLS handshake over TCP
//! - SecureChannel and SecureChannelAsync message roundtrip
//! - KemOpMetrics recording for real PQC operations
//!
//! # Design Notes
//!
//! - Uses real ML-KEM-768 (no dummy KEM)
//! - Uses real ChaCha20-Poly1305 for AEAD (T140 upgrade)
//! - Uses DummySig for signature verification (test-only)
//! - Two nodes: server (binds to 127.0.0.1:0) and client (connects to server)
//! - No HotStuff consensus - purely network-level test
//!
//! # T140 Update
//!
//! This test suite now uses real ChaCha20-Poly1305 AEAD instead of DummyAead,
//! providing production-grade authenticated encryption for the KEMTLS data path.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p cano-node --test t139_real_pqc_kemtls_two_node_tests -- --test-threads=1
//! ```

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_crypto::{
    ChaCha20Poly1305Backend, CryptoError, KemSuite, MlKem768Backend, SignatureSuite,
    StaticCryptoProvider, AEAD_SUITE_CHACHA20_POLY1305, KEM_SUITE_ML_KEM_768,
};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemOpMetrics, KemPrivateKey,
    ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::secure_channel::{SecureChannel, SecureChannelAsync};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Test Constants
// ============================================================================

/// KEM suite ID for ML-KEM-768.
const KEM_SUITE_ID: u8 = KEM_SUITE_ML_KEM_768; // 100

/// AEAD suite ID - using real ChaCha20-Poly1305 (T140 upgrade).
const AEAD_SUITE_ID: u8 = AEAD_SUITE_CHACHA20_POLY1305; // 101

/// Signature suite ID (using DummySig for test isolation).
const SIG_SUITE_ID: u8 = 3;

/// Number of messages to send in roundtrip tests.
const MESSAGE_COUNT: usize = 16;

/// Payload size for test messages (bytes).
const MESSAGE_SIZE: usize = 64;

// ============================================================================
// Dummy Crypto Implementations (Signature only - KEM and AEAD use real impls)
// ============================================================================

/// A DummySig that always verifies successfully (for testing only).
///
/// This allows us to focus on testing ML-KEM-768 + ChaCha20-Poly1305 without
/// needing full ML-DSA-44 integration for the delegation certificate.
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
        // Always succeed for testing
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a crypto provider with real ML-KEM-768 and real ChaCha20-Poly1305 AEAD.
///
/// # T140 Update
///
/// This now uses `ChaCha20Poly1305Backend` instead of `DummyAead` for production-grade
/// authenticated encryption in the KEMTLS data path.
fn make_mlkem768_provider() -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(MlKem768Backend::new()))
        .with_aead_suite(Arc::new(ChaCha20Poly1305Backend::new()))
        .with_signature_suite(Arc::new(DummySig::new(SIG_SUITE_ID)))
}

/// Create a synthetic NetworkDelegationCert for testing.
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
        sig_bytes: vec![0u8; 64], // Dummy signature (DummySig accepts anything)
    }
}

/// Configuration for a test node.
struct TestNodeConfig {
    /// Client config (for when this node acts as a client connecting to another server)
    #[allow(dead_code)]
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
    /// Server's validator ID (needed by clients connecting to this server)
    validator_id: [u8; 32],
    /// Server's KEM public key (needed by clients to encapsulate to)
    server_kem_pk: Vec<u8>,
}

/// Create ML-KEM-768 KEMTLS configurations for server node.
///
/// Returns configurations for both acting as server and client.
fn make_mlkem768_server_config(kem_metrics: Option<Arc<KemOpMetrics>>) -> TestNodeConfig {
    let provider = Arc::new(make_mlkem768_provider());

    // Generate real ML-KEM-768 keypair
    let (server_kem_pk, server_kem_sk) =
        MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen should succeed");

    // Verify key sizes
    assert_eq!(
        server_kem_pk.len(),
        1184,
        "ML-KEM-768 public key should be 1184 bytes"
    );
    assert_eq!(
        server_kem_sk.len(),
        2400,
        "ML-KEM-768 secret key should be 2400 bytes"
    );

    // Create validator identity
    let mut validator_id = [0u8; 32];
    validator_id[0..11].copy_from_slice(b"t139-server");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..13].copy_from_slice(b"t139-root-key");

    // Create delegation cert
    let cert = make_test_delegation_cert(validator_id, root_key_id, server_kem_pk.clone());

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Random values
    let mut client_random = [0u8; 32];
    client_random[0..12].copy_from_slice(b"server-c-rnd");

    let mut server_random = [0u8; 32];
    server_random[0..12].copy_from_slice(b"server-s-rnd");

    // Client handshake config (for when server acts as client)
    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE_ID,
        aead_suite_id: AEAD_SUITE_ID,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: kem_metrics.clone(),
    };

    // Server handshake config
    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id: KEM_SUITE_ID,
        aead_suite_id: AEAD_SUITE_ID,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk.clone(),
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    TestNodeConfig {
        client_cfg,
        server_cfg,
        validator_id,
        server_kem_pk,
    }
}

/// Create ML-KEM-768 KEMTLS client configuration.
///
/// The client needs:
/// - The server's KEM public key to encapsulate to
/// - The server's validator_id (must match the server's delegation cert)
fn make_mlkem768_client_config(
    server_kem_pk: Vec<u8>,
    server_validator_id: [u8; 32],
    kem_metrics: Option<Arc<KemOpMetrics>>,
) -> ClientConnectionConfig {
    let provider = Arc::new(make_mlkem768_provider());

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    client_random[0..12].copy_from_slice(b"client-c-rnd");

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE_ID,
        aead_suite_id: AEAD_SUITE_ID,
        crypto: provider,
        peer_root_network_pk: root_network_pk,
        kem_metrics,
    };

    ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        // Use the server's validator_id - must match the server's delegation cert
        validator_id: server_validator_id,
        peer_kem_pk: server_kem_pk,
    }
}

/// Generate a test message of specified size with deterministic content.
fn make_test_message(index: usize, size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i + index * 17) % 256) as u8).collect()
}

// ============================================================================
// Test 1: Two-Node ML-KEM-768 KEMTLS Roundtrip (Sync)
// ============================================================================

/// Test that two nodes can complete ML-KEM-768 KEMTLS handshake and exchange messages.
///
/// This test validates:
/// - Real ML-KEM-768 encapsulation/decapsulation
/// - SecureChannel handshake over TCP
/// - Bidirectional message exchange
#[test]
fn two_node_mlkem768_kemtls_roundtrip_sync_succeeds() {
    eprintln!("\n========== T139: two_node_mlkem768_kemtls_roundtrip_sync ==========\n");

    // Create server config with real ML-KEM-768
    let server_node = make_mlkem768_server_config(None);
    let server_cfg = server_node.server_cfg;

    // Extract server's info for client
    let server_kem_pk = server_node.server_kem_pk.clone();
    let server_validator_id = server_node.validator_id;
    eprintln!(
        "[T139] Server KEM public key size: {} bytes",
        server_kem_pk.len()
    );

    // Create client config (must use server's validator_id to match delegation cert)
    let client_cfg = make_mlkem768_client_config(server_kem_pk, server_validator_id, None);

    // Bind server to OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");
    let addr_str = addr.to_string();
    eprintln!("[T139] Server listening on {}", addr_str);

    // Spawn server thread
    let server_handle = thread::spawn(move || {
        // Accept connection
        let (stream, peer_addr) = listener.accept().expect("accept should succeed");
        eprintln!("[T139] Server accepted connection from {}", peer_addr);

        // Perform KEMTLS handshake with real ML-KEM-768
        let mut channel = SecureChannel::from_accepted(stream, server_cfg)
            .expect("server handshake should succeed");

        assert!(
            channel.is_established(),
            "server channel should be established"
        );
        eprintln!("[T139] Server KEMTLS handshake complete");

        // Receive messages from client
        for i in 0..MESSAGE_COUNT {
            let received = channel.recv_app().expect("server recv should succeed");
            let expected = make_test_message(i, MESSAGE_SIZE);
            assert_eq!(
                received, expected,
                "server should receive correct message {}",
                i
            );
        }
        eprintln!("[T139] Server received {} messages", MESSAGE_COUNT);

        // Send responses back to client
        for i in 0..MESSAGE_COUNT {
            let msg = make_test_message(i + 1000, MESSAGE_SIZE);
            channel.send_app(&msg).expect("server send should succeed");
        }
        eprintln!("[T139] Server sent {} messages", MESSAGE_COUNT);
    });

    // Client connects and performs handshake
    let mut client_channel =
        SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

    assert!(
        client_channel.is_established(),
        "client channel should be established"
    );
    eprintln!("[T139] Client KEMTLS handshake complete");

    // Send messages to server
    for i in 0..MESSAGE_COUNT {
        let msg = make_test_message(i, MESSAGE_SIZE);
        client_channel
            .send_app(&msg)
            .expect("client send should succeed");
    }
    eprintln!("[T139] Client sent {} messages", MESSAGE_COUNT);

    // Receive responses from server
    for i in 0..MESSAGE_COUNT {
        let received = client_channel
            .recv_app()
            .expect("client recv should succeed");
        let expected = make_test_message(i + 1000, MESSAGE_SIZE);
        assert_eq!(
            received, expected,
            "client should receive correct message {}",
            i
        );
    }
    eprintln!("[T139] Client received {} messages", MESSAGE_COUNT);

    // Wait for server to finish
    server_handle
        .join()
        .expect("server thread should not panic");

    eprintln!("[T139] two_node_mlkem768_kemtls_roundtrip_sync PASSED\n");
}

// ============================================================================
// Test 2: Two-Node ML-KEM-768 KEMTLS Roundtrip with SecureChannelAsync
// ============================================================================

/// Test that two nodes can use SecureChannelAsync for async message exchange.
///
/// This test validates:
/// - Real ML-KEM-768 KEMTLS handshake
/// - SecureChannelAsync send/recv
/// - Async message roundtrip
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_node_mlkem768_kemtls_roundtrip_async_succeeds() {
    eprintln!("\n========== T139: two_node_mlkem768_kemtls_roundtrip_async ==========\n");

    // Create server config with real ML-KEM-768
    let server_node = make_mlkem768_server_config(None);
    let server_cfg = server_node.server_cfg;

    // Extract server's info for client
    let server_kem_pk = server_node.server_kem_pk.clone();
    let server_validator_id = server_node.validator_id;

    // Create client config (must use server's validator_id to match delegation cert)
    let client_cfg = make_mlkem768_client_config(server_kem_pk, server_validator_id, None);

    // Bind server to OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");
    let addr_str = addr.to_string();
    eprintln!("[T139] Server listening on {}", addr_str);

    // Spawn server task
    let server_task = tokio::task::spawn_blocking(move || {
        // Accept connection
        let (stream, _peer_addr) = listener.accept().expect("accept should succeed");

        // Perform KEMTLS handshake
        let channel = SecureChannel::from_accepted(stream, server_cfg)
            .expect("server handshake should succeed");

        assert!(channel.is_established());
        channel
    });

    // Give server time to start accepting
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client connects in blocking task
    let client_task = tokio::task::spawn_blocking(move || {
        let channel =
            SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

        assert!(channel.is_established());
        channel
    });

    // Wait for both handshakes to complete
    let server_channel = server_task.await.expect("server task should complete");
    let client_channel = client_task.await.expect("client task should complete");

    eprintln!("[T139] Both KEMTLS handshakes complete");

    // Wrap in SecureChannelAsync
    let server_async = SecureChannelAsync::new(server_channel);
    let client_async = SecureChannelAsync::new(client_channel);

    // Give workers time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client sends messages
    for i in 0..MESSAGE_COUNT {
        let msg = make_test_message(i, MESSAGE_SIZE);
        client_async
            .send(&msg)
            .await
            .expect("client async send should succeed");
    }
    eprintln!("[T139] Client async sent {} messages", MESSAGE_COUNT);

    // Server receives messages
    for i in 0..MESSAGE_COUNT {
        let received = server_async
            .recv()
            .await
            .expect("server async recv should succeed");
        let expected = make_test_message(i, MESSAGE_SIZE);
        assert_eq!(
            received, expected,
            "server should receive correct async message {}",
            i
        );
    }
    eprintln!("[T139] Server async received {} messages", MESSAGE_COUNT);

    // Server sends responses
    for i in 0..MESSAGE_COUNT {
        let msg = make_test_message(i + 2000, MESSAGE_SIZE);
        server_async
            .send(&msg)
            .await
            .expect("server async send should succeed");
    }
    eprintln!("[T139] Server async sent {} responses", MESSAGE_COUNT);

    // Client receives responses
    for i in 0..MESSAGE_COUNT {
        let received = client_async
            .recv()
            .await
            .expect("client async recv should succeed");
        let expected = make_test_message(i + 2000, MESSAGE_SIZE);
        assert_eq!(
            received, expected,
            "client should receive correct async response {}",
            i
        );
    }
    eprintln!("[T139] Client async received {} responses", MESSAGE_COUNT);

    eprintln!("[T139] two_node_mlkem768_kemtls_roundtrip_async PASSED\n");
}

// ============================================================================
// Test 3: Two-Node ML-KEM-768 KEMTLS Records KEM Metrics
// ============================================================================

/// Test that KEM operations are recorded in metrics during handshake.
///
/// This test validates:
/// - KemOpMetrics.encaps_total >= 1
/// - KemOpMetrics.decaps_total >= 1
/// - Latency buckets are populated
#[test]
fn two_node_mlkem768_kemtls_records_kem_metrics() {
    eprintln!("\n========== T139: two_node_mlkem768_kemtls_records_kem_metrics ==========\n");

    // Create shared metrics instance
    let metrics = Arc::new(KemOpMetrics::new());

    // Create server config with metrics
    let server_node = make_mlkem768_server_config(Some(metrics.clone()));
    let server_cfg = server_node.server_cfg;

    // Extract server's info for client
    let server_kem_pk = server_node.server_kem_pk.clone();
    let server_validator_id = server_node.validator_id;

    // Create client config with same metrics (must use server's validator_id)
    let client_cfg =
        make_mlkem768_client_config(server_kem_pk, server_validator_id, Some(metrics.clone()));

    // Verify metrics are initially zero
    assert_eq!(metrics.encaps_total(), 0, "initial encaps should be 0");
    assert_eq!(metrics.decaps_total(), 0, "initial decaps should be 0");

    // Bind server
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");
    let addr_str = addr.to_string();
    eprintln!("[T139] Server listening on {}", addr_str);

    // Spawn server thread
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept should succeed");
        let mut channel = SecureChannel::from_accepted(stream, server_cfg)
            .expect("server handshake should succeed");

        // Exchange a few messages to verify channel works
        let received = channel.recv_app().expect("server recv should succeed");
        assert_eq!(&received[..], b"metrics test message");

        channel
            .send_app(b"metrics test response")
            .expect("server send should succeed");
    });

    // Client connects
    let mut client_channel =
        SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

    assert!(client_channel.is_established());

    // Exchange test messages
    client_channel
        .send_app(b"metrics test message")
        .expect("client send should succeed");
    let response = client_channel
        .recv_app()
        .expect("client recv should succeed");
    assert_eq!(&response[..], b"metrics test response");

    // Wait for server
    server_handle.join().expect("server should complete");

    // Verify metrics were recorded
    eprintln!("[T139] KEM Metrics after handshake:");
    eprintln!("{}", metrics.format_for_tests());

    assert!(
        metrics.encaps_total() >= 1,
        "encaps_total should be at least 1, got {}",
        metrics.encaps_total()
    );
    assert!(
        metrics.decaps_total() >= 1,
        "decaps_total should be at least 1, got {}",
        metrics.decaps_total()
    );

    // Verify latency buckets
    let (_encaps_0_1, _encaps_1, encaps_10, encaps_inf) = metrics.encaps_latency_buckets();
    let (_decaps_0_1, _decaps_1, decaps_10, decaps_inf) = metrics.decaps_latency_buckets();

    assert!(encaps_inf >= 1, "encaps_latency_inf should be at least 1");
    assert!(decaps_inf >= 1, "decaps_latency_inf should be at least 1");

    // ML-KEM-768 should typically complete in < 10ms
    assert!(
        encaps_10 >= 1,
        "encaps should complete in < 10ms (bucket count: {})",
        encaps_10
    );
    assert!(
        decaps_10 >= 1,
        "decaps should complete in < 10ms (bucket count: {})",
        decaps_10
    );

    eprintln!("[T139] two_node_mlkem768_kemtls_records_kem_metrics PASSED\n");
}

// ============================================================================
// Test 4: Verify ML-KEM-768 Suite ID is Used
// ============================================================================

/// Test that ML-KEM-768 suite ID (100) is correctly configured.
#[test]
fn mlkem768_suite_id_is_correct() {
    assert_eq!(KEM_SUITE_ID, 100, "ML-KEM-768 suite ID should be 100");

    let backend = MlKem768Backend::new();
    assert_eq!(
        backend.suite_id(),
        KEM_SUITE_ID,
        "MlKem768Backend suite_id() should return 100"
    );

    // Verify key sizes match spec
    assert_eq!(backend.public_key_len(), 1184);
    assert_eq!(backend.secret_key_len(), 2400);
    assert_eq!(backend.ciphertext_len(), 1088);
    assert_eq!(backend.shared_secret_len(), 32);
}

// ============================================================================
// Test 5: Multiple Sequential Handshakes with Metrics
// ============================================================================

/// Test that multiple handshakes correctly aggregate metrics.
#[test]
fn multiple_handshakes_aggregate_metrics() {
    eprintln!("\n========== T139: multiple_handshakes_aggregate_metrics ==========\n");

    let metrics = Arc::new(KemOpMetrics::new());
    const HANDSHAKE_COUNT: usize = 3;

    for i in 0..HANDSHAKE_COUNT {
        // Create fresh configs for each handshake
        let server_node = make_mlkem768_server_config(Some(metrics.clone()));
        let server_cfg = server_node.server_cfg;
        let server_kem_pk = server_node.server_kem_pk.clone();
        let server_validator_id = server_node.validator_id;
        let client_cfg =
            make_mlkem768_client_config(server_kem_pk, server_validator_id, Some(metrics.clone()));

        // Bind server
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
        let addr = listener.local_addr().expect("local_addr should succeed");
        let addr_str = addr.to_string();

        // Spawn server thread
        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept should succeed");
            let _channel = SecureChannel::from_accepted(stream, server_cfg)
                .expect("server handshake should succeed");
        });

        // Client connects
        let _client_channel =
            SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

        // Wait for server
        server_handle.join().expect("server should complete");

        eprintln!("[T139] Handshake {} complete", i + 1);
    }

    // Verify metrics aggregated correctly
    assert_eq!(
        metrics.encaps_total(),
        HANDSHAKE_COUNT as u64,
        "encaps_total should equal number of handshakes"
    );
    assert_eq!(
        metrics.decaps_total(),
        HANDSHAKE_COUNT as u64,
        "decaps_total should equal number of handshakes"
    );

    eprintln!("[T139] Final metrics after {} handshakes:", HANDSHAKE_COUNT);
    eprintln!("{}", metrics.format_for_tests());

    eprintln!("[T139] multiple_handshakes_aggregate_metrics PASSED\n");
}

// ============================================================================
// Test 6: Large Message Transfer
// ============================================================================

/// Test that large messages can be transferred over ML-KEM-768 KEMTLS channel.
#[test]
fn large_message_transfer_succeeds() {
    eprintln!("\n========== T139: large_message_transfer_succeeds ==========\n");

    let server_node = make_mlkem768_server_config(None);
    let server_cfg = server_node.server_cfg;
    let server_kem_pk = server_node.server_kem_pk.clone();
    let server_validator_id = server_node.validator_id;
    let client_cfg = make_mlkem768_client_config(server_kem_pk, server_validator_id, None);

    // Create a large test message (4KB)
    let large_message: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let large_message_clone = large_message.clone();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");
    let addr_str = addr.to_string();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept should succeed");
        let mut channel = SecureChannel::from_accepted(stream, server_cfg)
            .expect("server handshake should succeed");

        let received = channel.recv_app().expect("server recv should succeed");
        assert_eq!(
            received, large_message_clone,
            "server should receive correct large message"
        );
        eprintln!("[T139] Server received {} byte message", received.len());

        channel
            .send_app(&large_message_clone)
            .expect("server send should succeed");
    });

    let mut client_channel =
        SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

    client_channel
        .send_app(&large_message)
        .expect("client send should succeed");
    eprintln!("[T139] Client sent {} byte message", large_message.len());

    let response = client_channel
        .recv_app()
        .expect("client recv should succeed");
    assert_eq!(
        response, large_message,
        "client should receive correct large response"
    );
    eprintln!("[T139] Client received {} byte response", response.len());

    server_handle.join().expect("server should complete");

    eprintln!("[T139] large_message_transfer_succeeds PASSED\n");
}

// ============================================================================
// Test 7: Real AEAD Ciphertext Tampering Detection (T140)
// ============================================================================

/// Test that real ChaCha20-Poly1305 AEAD correctly detects tampering.
///
/// This test validates a critical security property: any modification to the
/// ciphertext (including the authentication tag) should cause decryption to fail.
///
/// # T140
///
/// This test was added as part of T140 to verify that real AEAD provides
/// proper authenticated encryption, unlike DummyAead which had weak tampering detection.
#[test]
fn real_aead_detects_ciphertext_tampering() {
    eprintln!("\n========== T140: real_aead_detects_ciphertext_tampering ==========\n");

    // This test works at the AEAD level, not the full network level,
    // to directly verify the ChaCha20-Poly1305 implementation.
    use cano_crypto::AeadSuite;

    let aead = ChaCha20Poly1305Backend::new();

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"CANO:T140";
    let plaintext = b"Real AEAD tampering detection test";

    // Seal the plaintext
    let ciphertext = aead
        .seal(&key, &nonce, aad, plaintext)
        .expect("seal should succeed");

    eprintln!(
        "[T140] Ciphertext length: {} bytes (plaintext: {} + tag: 16)",
        ciphertext.len(),
        plaintext.len()
    );

    // Verify normal decryption works
    let decrypted = aead
        .open(&key, &nonce, aad, &ciphertext)
        .expect("normal open should succeed");
    assert_eq!(&decrypted[..], plaintext);
    eprintln!("[T140] Normal decryption succeeded");

    // Test 1: Tamper with first byte of ciphertext
    {
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xff;
        let result = aead.open(&key, &nonce, aad, &tampered);
        assert!(
            result.is_err(),
            "Tampered ciphertext (first byte) should fail"
        );
        eprintln!("[T140] Tampered first byte correctly rejected");
    }

    // Test 2: Tamper with last byte (in tag)
    {
        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let result = aead.open(&key, &nonce, aad, &tampered);
        assert!(result.is_err(), "Tampered tag should fail");
        eprintln!("[T140] Tampered tag correctly rejected");
    }

    // Test 3: Tamper with middle byte
    {
        let mut tampered = ciphertext.clone();
        tampered[ciphertext.len() / 2] ^= 0xaa;
        let result = aead.open(&key, &nonce, aad, &tampered);
        assert!(result.is_err(), "Tampered middle byte should fail");
        eprintln!("[T140] Tampered middle byte correctly rejected");
    }

    // Test 4: Wrong AAD
    {
        let wrong_aad = b"CANO:WRONG";
        let result = aead.open(&key, &nonce, wrong_aad, &ciphertext);
        assert!(result.is_err(), "Wrong AAD should fail");
        eprintln!("[T140] Wrong AAD correctly rejected");
    }

    // Test 5: Truncated ciphertext
    {
        let truncated = &ciphertext[..ciphertext.len() - 1];
        let result = aead.open(&key, &nonce, aad, truncated);
        assert!(result.is_err(), "Truncated ciphertext should fail");
        eprintln!("[T140] Truncated ciphertext correctly rejected");
    }

    eprintln!("[T140] real_aead_detects_ciphertext_tampering PASSED\n");
}

// ============================================================================
// Test 8: Combined ML-KEM-768 + Real AEAD End-to-End (T140)
// ============================================================================

/// Test that verifies the complete real PQC crypto stack works end-to-end.
///
/// This test exercises:
/// - Real ML-KEM-768 key encapsulation
/// - Real ChaCha20-Poly1305 authenticated encryption
/// - Both combined in a full KEMTLS handshake over TCP
///
/// # T140
///
/// This test confirms that the T140 AEAD upgrade integrates correctly with
/// the existing ML-KEM-768 KEMTLS infrastructure.
#[test]
fn mlkem768_chacha20poly1305_full_stack_test() {
    eprintln!("\n========== T140: mlkem768_chacha20poly1305_full_stack_test ==========\n");

    // Create shared metrics to verify both KEM and AEAD operations
    let metrics = Arc::new(KemOpMetrics::new());

    // Create server config
    let server_node = make_mlkem768_server_config(Some(metrics.clone()));
    let server_cfg = server_node.server_cfg;
    let server_kem_pk = server_node.server_kem_pk.clone();
    let server_validator_id = server_node.validator_id;

    // Verify key sizes (ML-KEM-768 + ChaCha20-Poly1305)
    assert_eq!(server_kem_pk.len(), 1184, "ML-KEM-768 public key size");
    eprintln!("[T140] Using ML-KEM-768 (pk: 1184 bytes) + ChaCha20-Poly1305 (key: 32, tag: 16)");

    // Create client config
    let client_cfg =
        make_mlkem768_client_config(server_kem_pk, server_validator_id, Some(metrics.clone()));

    // Bind server
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");
    let addr_str = addr.to_string();
    eprintln!("[T140] Server listening on {}", addr_str);

    // Test messages of various sizes
    let test_messages: Vec<Vec<u8>> = vec![
        b"Short message".to_vec(),
        (0..256).map(|i| (i % 256) as u8).collect(), // 256 bytes
        (0..1024).map(|i| (i % 256) as u8).collect(), // 1KB
        (0..4096).map(|i| (i % 256) as u8).collect(), // 4KB
    ];

    let test_messages_clone = test_messages.clone();

    // Spawn server thread
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept should succeed");
        let mut channel = SecureChannel::from_accepted(stream, server_cfg)
            .expect("server handshake should succeed");

        // Receive and verify each message
        for (i, expected) in test_messages_clone.iter().enumerate() {
            let received = channel
                .recv_app()
                .expect(&format!("server recv {} should succeed", i));
            assert_eq!(
                &received, expected,
                "server should receive correct message {}",
                i
            );
        }
        eprintln!(
            "[T140] Server received all {} test messages",
            test_messages_clone.len()
        );

        // Send response
        channel
            .send_app(b"T140: All messages received correctly!")
            .expect("server send response should succeed");
    });

    // Client connects
    let mut client_channel =
        SecureChannel::connect(&addr_str, client_cfg).expect("client connect should succeed");

    assert!(
        client_channel.is_established(),
        "client channel should be established"
    );
    eprintln!("[T140] Client KEMTLS handshake complete with real crypto");

    // Send test messages
    for (i, msg) in test_messages.iter().enumerate() {
        client_channel
            .send_app(msg)
            .expect(&format!("client send {} should succeed", i));
        eprintln!("[T140] Client sent message {} ({} bytes)", i, msg.len());
    }

    // Receive server response
    let response = client_channel
        .recv_app()
        .expect("client recv response should succeed");
    assert_eq!(&response[..], b"T140: All messages received correctly!");
    eprintln!("[T140] Client received server confirmation");

    // Wait for server
    server_handle.join().expect("server should complete");

    // Verify KEM metrics
    eprintln!("\n[T140] KEM Metrics:");
    eprintln!("{}", metrics.format_for_tests());

    assert!(
        metrics.encaps_total() >= 1,
        "encaps_total should be at least 1, got {}",
        metrics.encaps_total()
    );
    assert!(
        metrics.decaps_total() >= 1,
        "decaps_total should be at least 1, got {}",
        metrics.decaps_total()
    );

    eprintln!("[T140] mlkem768_chacha20poly1305_full_stack_test PASSED\n");
}
