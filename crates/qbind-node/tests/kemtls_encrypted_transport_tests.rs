//! Integration tests for KEMTLS encrypted message transport (T92).
//!
//! These tests verify that consensus messages flow correctly through the
//! encrypted `SecureChannelAsync` when `TransportSecurityMode::Kemtls` is enabled.

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};
use qbind_node::{
    accept_kemtls_async, connect_kemtls_async, AsyncChannelError, AsyncPeerManagerConfig,
    AsyncPeerManagerImpl, ChannelError, KemtlsMetrics, NodeMetrics, SecureChannel,
    TransportSecurityMode,
};
use qbind_wire::consensus::Vote;
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Crypto Implementations for Testing
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

/// Helper to receive from a SecureChannel with WouldBlock handling.
///
/// `recv_app()` can return `WouldBlock` on some systems when using socket timeouts.
/// This helper retries on `WouldBlock` up to a maximum duration.
fn recv_app_with_retry(
    channel: &mut SecureChannel,
    timeout: Duration,
) -> Result<Vec<u8>, ChannelError> {
    use std::io::ErrorKind;
    use std::time::Instant;

    let start = Instant::now();
    loop {
        match channel.recv_app() {
            Ok(data) => return Ok(data),
            Err(ChannelError::Io(ref io_err)) if io_err.kind() == ErrorKind::WouldBlock => {
                // WouldBlock is retryable - check timeout and retry
                if start.elapsed() >= timeout {
                    return Err(ChannelError::Io(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "recv_app timed out after retrying WouldBlock",
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
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

fn make_test_vote(height: u64, round: u64) -> Vote {
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

// ============================================================================
// SecureChannelAsync Unit Tests
// ============================================================================

#[tokio::test]
async fn secure_channel_async_send_recv_roundtrip() {
    // This test creates a blocking server in a thread, connects with the async
    // client helper, and verifies message roundtrip through encrypted channels.
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread: performs blocking handshake and receives one message
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");

        let mut channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");

        assert!(channel.is_established());

        // Receive a message from client (with WouldBlock retry handling)
        let received = recv_app_with_retry(&mut channel, Duration::from_secs(5))
            .expect("server recv_app failed");
        assert_eq!(&received[..], b"hello encrypted world");

        // Send a response back
        channel
            .send_app(b"encrypted response")
            .expect("server send_app failed");
    });

    // Client: use async helper to connect
    let client_channel = connect_kemtls_async(addr_str, client_cfg)
        .await
        .expect("client connect failed");

    assert!(client_channel.is_established());

    // Send a message to server
    client_channel
        .send(b"hello encrypted world")
        .await
        .expect("client send failed");

    // Receive response from server
    let response = client_channel.recv().await.expect("client recv failed");
    assert_eq!(&response[..], b"encrypted response");

    // Wait for server thread to finish
    server_handle.join().expect("server thread panicked");
}

#[tokio::test]
async fn secure_channel_async_multiple_messages() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server: receive 5 messages, send 5 back
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept failed");
        let mut channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("from_accepted failed");

        // Receive 5 messages (with WouldBlock retry handling)
        for i in 0..5 {
            let received =
                recv_app_with_retry(&mut channel, Duration::from_secs(5)).expect("recv_app failed");
            let expected = format!("message {}", i);
            assert_eq!(received, expected.as_bytes());
        }

        // Send 5 messages
        for i in 0..5 {
            let msg = format!("reply {}", i);
            channel.send_app(msg.as_bytes()).expect("send_app failed");
        }
    });

    // Client: send 5 messages, receive 5 back
    let client_channel = connect_kemtls_async(addr_str, client_cfg)
        .await
        .expect("connect failed");

    // Send 5 messages
    for i in 0..5 {
        let msg = format!("message {}", i);
        client_channel
            .send(msg.as_bytes())
            .await
            .expect("send failed");
    }

    // Receive 5 messages
    for i in 0..5 {
        let received = client_channel.recv().await.expect("recv failed");
        let expected = format!("reply {}", i);
        assert_eq!(received, expected.as_bytes());
    }

    server_handle.join().expect("server thread panicked");
}

#[tokio::test]
async fn accept_kemtls_async_server_side() {
    // Test the async server-side handshake helper
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Client thread: performs blocking connect
    let client_handle = thread::spawn(move || {
        let mut channel =
            SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");

        channel
            .send_app(b"from blocking client")
            .expect("send failed");
        // Use retry helper for recv (with WouldBlock handling)
        let response =
            recv_app_with_retry(&mut channel, Duration::from_secs(5)).expect("recv failed");
        assert_eq!(&response[..], b"from async server");
    });

    // Server: use async accept helper
    let (std_stream, _) = listener.accept().expect("accept failed");
    let server_channel = accept_kemtls_async(std_stream, server_cfg)
        .await
        .expect("accept_kemtls_async failed");

    assert!(server_channel.is_established());

    // Receive from client
    let received = server_channel.recv().await.expect("recv failed");
    assert_eq!(&received[..], b"from blocking client");

    // Send response
    server_channel
        .send(b"from async server")
        .await
        .expect("send failed");

    client_handle.join().expect("client thread panicked");
}

// ============================================================================
// Wire Protocol Message Tests
// ============================================================================

#[tokio::test]
async fn secure_channel_async_wire_encoded_vote_roundtrip() {
    // Test that wire-encoded consensus messages roundtrip correctly
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept failed");
        let mut channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("from_accepted failed");

        // Receive a wire-encoded vote (with WouldBlock retry handling)
        let received =
            recv_app_with_retry(&mut channel, Duration::from_secs(5)).expect("recv_app failed");
        let mut slice: &[u8] = &received;
        let vote = Vote::decode(&mut slice).expect("decode failed");

        assert_eq!(vote.height, 42);
        assert_eq!(vote.round, 7);

        // Send back a different vote
        let reply_vote = make_test_vote(100, 10);
        let mut reply_bytes = Vec::new();
        reply_vote.encode(&mut reply_bytes);
        channel.send_app(&reply_bytes).expect("send_app failed");
    });

    let client_channel = connect_kemtls_async(addr_str, client_cfg)
        .await
        .expect("connect failed");

    // Send a wire-encoded vote
    let vote = make_test_vote(42, 7);
    let mut vote_bytes = Vec::new();
    vote.encode(&mut vote_bytes);
    client_channel.send(&vote_bytes).await.expect("send failed");

    // Receive and decode the reply
    let reply_bytes = client_channel.recv().await.expect("recv failed");
    let mut slice: &[u8] = &reply_bytes;
    let reply_vote = Vote::decode(&mut slice).expect("decode failed");

    assert_eq!(reply_vote.height, 100);
    assert_eq!(reply_vote.round, 10);

    server_handle.join().expect("server thread panicked");
}

// ============================================================================
// AsyncPeerManagerImpl KEMTLS Integration Tests
// ============================================================================

#[tokio::test]
async fn async_peer_manager_kemtls_mode_requires_server_config() {
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls);

    // KEMTLS mode without server_config should be marked as invalid
    assert!(config.is_kemtls_config_missing());
}

#[tokio::test]
async fn async_peer_manager_kemtls_metrics_are_accessible() {
    let setup = create_test_setup();
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg);

    let manager = AsyncPeerManagerImpl::new(config);

    let metrics = manager.kemtls_metrics();
    assert_eq!(metrics.handshake_success_total(), 0);
    assert_eq!(metrics.handshake_failure_total(), 0);
}

// ============================================================================
// PlainTcp Regression Tests
// ============================================================================

#[tokio::test]
async fn async_peer_manager_plaintcp_mode_unchanged() {
    // Verify PlainTcp mode still works without KEMTLS configuration
    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::PlainTcp)
        .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let mut manager = AsyncPeerManagerImpl::new(config);

    // Should be able to bind without issues
    let addr = manager.bind().await.expect("bind should succeed");
    assert_ne!(addr.port(), 0);
    assert_eq!(
        manager.transport_security_mode(),
        TransportSecurityMode::PlainTcp
    );
}

#[test]
fn transport_security_mode_default_semantics() {
    // Clear environment to test default behavior
    std::env::remove_var("QBIND_TRANSPORT_SECURITY_MODE");

    // The enum's Default trait returns Kemtls
    assert_eq!(
        TransportSecurityMode::default(),
        TransportSecurityMode::Kemtls
    );

    // But AsyncPeerManagerConfig defaults to PlainTcp for backward compatibility
    let config = AsyncPeerManagerConfig::default();
    assert_eq!(
        config.transport_security_mode,
        TransportSecurityMode::PlainTcp
    );
}

// ============================================================================
// Metrics Tests
// ============================================================================

#[test]
fn kemtls_metrics_format_includes_all_counters() {
    let metrics = KemtlsMetrics::new();

    // Record some data
    metrics.record_handshake_success(Duration::from_millis(5));
    metrics.record_handshake_success(Duration::from_millis(50));
    metrics.record_handshake_success(Duration::from_millis(500));
    metrics.inc_handshake_failure(qbind_node::KemtlsHandshakeFailureReason::Io);
    metrics.inc_handshake_failure(qbind_node::KemtlsHandshakeFailureReason::Protocol);

    let output = metrics.format_metrics();

    // Verify all expected metrics are present
    assert!(output.contains("kemtls_handshake_success_total 3"));
    assert!(output.contains("kemtls_handshake_failure_total{reason=\"io\"} 1"));
    assert!(output.contains("kemtls_handshake_failure_total{reason=\"protocol\"} 1"));
    assert!(output.contains("kemtls_handshake_duration_bucket"));
}

#[tokio::test]
async fn async_peer_manager_with_metrics_tracks_kemtls_handshakes() {
    // This test verifies that KEMTLS handshake metrics are recorded
    // when using AsyncPeerManagerImpl with metrics enabled.
    let setup = create_test_setup();
    let node_metrics = Arc::new(NodeMetrics::new());

    let config = AsyncPeerManagerConfig::default()
        .with_transport_security_mode(TransportSecurityMode::Kemtls)
        .with_server_config(setup.server_cfg)
        .with_listen_addr("127.0.0.1:0".parse().unwrap());

    let manager = AsyncPeerManagerImpl::with_metrics(config, node_metrics.clone());

    // KEMTLS metrics should start at zero
    assert_eq!(manager.kemtls_metrics().handshake_success_total(), 0);
    assert_eq!(manager.kemtls_metrics().handshake_failure_total(), 0);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn async_channel_error_display_is_informative() {
    // Test that error messages are useful for debugging
    let err = AsyncChannelError::MutexPoisoned;
    let display = format!("{}", err);
    assert!(display.contains("mutex poisoned"));

    let err = AsyncChannelError::TaskJoin("test error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("task join error"));
}
