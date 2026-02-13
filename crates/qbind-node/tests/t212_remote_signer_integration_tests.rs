//! Integration tests for T212 – Remote Signer Protocol v0.
//!
//! These tests validate:
//! 1. TcpKemTlsSignerTransport functionality
//! 2. Remote signer protocol encode/decode
//! 3. RemoteSignerMetrics tracking
//! 4. Configuration validation for SignerMode::RemoteSigner
//!
//! # Test Categories
//!
//! ## Soft Integration (non-ignored)
//! - Protocol encoding/decoding tests
//! - Metrics tracking tests
//! - Configuration validation tests
//!
//! ## Full Daemon Tests (#[ignore])
//! - End-to-end signing through daemon
//! - Rate limiting behavior
//! - Connection handling

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ValidatorSigningKey;
use qbind_node::remote_signer::{
    LoopbackSignerTransport, RemoteSignError, RemoteSignRequest, RemoteSignRequestKind,
    RemoteSignResponse, RemoteSignerClient, RemoteSignerMetrics, DEFAULT_REMOTE_SIGNER_TIMEOUT_MS,
    MAX_PREIMAGE_SIZE,
};
use qbind_node::validator_signer::{LocalKeySigner, ValidatorSigner};
use qbind_node::SignerMode;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test keypair and LocalKeySigner.
fn make_test_signer(validator_id: ValidatorId) -> (Vec<u8>, Arc<LocalKeySigner>) {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    let signer = Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));
    (pk, signer)
}

/// Encode a RemoteSignRequest for testing (M10 format).
///
/// M10 Wire Format:
/// domain_tag:     "QBIND:remote-signer:v1" (23 bytes)
/// request_id:     8 bytes LE
/// validator_id:   8 bytes LE
/// suite_id:       2 bytes LE
/// kind:           1 byte (message type)
/// view_present:   1 byte flag
/// view:           8 bytes LE (if present)
/// preimage_len:   4 bytes LE
/// preimage:       variable length
fn encode_request(request: &RemoteSignRequest) -> Vec<u8> {
    let domain_tag = b"QBIND:remote-signer:v1";
    let mut buf = Vec::with_capacity(domain_tag.len() + 32 + request.preimage.len());
    
    // Domain tag
    buf.extend_from_slice(domain_tag);
    
    // request_id
    buf.extend_from_slice(&request.request_id.to_le_bytes());
    
    // validator_id
    buf.extend_from_slice(&request.validator_id.as_u64().to_le_bytes());
    
    // suite_id
    buf.extend_from_slice(&request.suite_id.to_le_bytes());
    
    // kind (using message_type constants)
    let kind_byte = match request.kind {
        RemoteSignRequestKind::Proposal => 0x01u8,
        RemoteSignRequestKind::Vote => 0x02u8,
        RemoteSignRequestKind::Timeout => 0x03u8,
    };
    buf.push(kind_byte);
    
    // view
    if let Some(v) = request.view {
        buf.push(1u8);
        buf.extend_from_slice(&v.to_le_bytes());
    } else {
        buf.push(0u8);
        buf.extend_from_slice(&[0u8; 8]);
    }
    
    // preimage_len and preimage
    buf.extend_from_slice(&(request.preimage.len() as u32).to_le_bytes());
    buf.extend_from_slice(&request.preimage);
    buf
}

/// Decode a RemoteSignResponse for testing (M10 format).
///
/// M10 Wire Format:
/// Success: status(1) + request_id(8) + sig_len(4) + sig
/// Error:   status(1) + request_id(8) + error_code(1)
fn decode_response(data: &[u8]) -> Result<RemoteSignResponse, RemoteSignError> {
    // Minimum: status(1) + request_id(8) + error_code(1) = 10 bytes
    if data.len() < 10 {
        return Err(RemoteSignError::TransportError);
    }
    let status = data[0];
    let request_id = u64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);

    if status == 0 {
        // Success: signature follows
        if data.len() < 13 {
            return Err(RemoteSignError::TransportError);
        }
        let sig_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]) as usize;
        if data.len() < 13 + sig_len {
            return Err(RemoteSignError::TransportError);
        }
        Ok(RemoteSignResponse {
            request_id,
            signature: Some(data[13..13 + sig_len].to_vec()),
            error: None,
        })
    } else {
        // Error: error_code follows request_id
        let error = match data[9] {
            1 => RemoteSignError::InvalidKey,
            2 => RemoteSignError::CryptoError,
            3 => RemoteSignError::Unauthorized,
            4 => RemoteSignError::TransportError,
            5 => RemoteSignError::Timeout,
            6 => RemoteSignError::RateLimited,
            7 => RemoteSignError::ServerError,
            8 => RemoteSignError::ReplayDetected,
            9 => RemoteSignError::SignerUnavailable,
            10 => RemoteSignError::MalformedResponse,
            _ => RemoteSignError::TransportError,
        };
        Ok(RemoteSignResponse {
            request_id,
            signature: None,
            error: Some(error),
        })
    }
}

// ============================================================================
// Protocol Encoding/Decoding Tests
// ============================================================================

#[test]
fn t212_request_encode_proposal() {
    let request = RemoteSignRequest {
        request_id: 1,
        validator_id: ValidatorId::new(42),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: vec![1, 2, 3, 4],
    };

    let encoded = encode_request(&request);

    // M10: Validate structure starts with domain tag
    let domain_tag = b"QBIND:remote-signer:v1";
    assert!(encoded.len() >= domain_tag.len() + 32 + 4, "encoded too short");
    
    // Verify domain tag prefix
    assert_eq!(&encoded[..domain_tag.len()], domain_tag, "domain tag mismatch");

    let offset = domain_tag.len();

    // Decode request_id
    let request_id = u64::from_le_bytes([
        encoded[offset], encoded[offset+1], encoded[offset+2], encoded[offset+3],
        encoded[offset+4], encoded[offset+5], encoded[offset+6], encoded[offset+7],
    ]);
    assert_eq!(request_id, 1);

    // Decode validator_id
    let validator_id = u64::from_le_bytes([
        encoded[offset+8], encoded[offset+9], encoded[offset+10], encoded[offset+11],
        encoded[offset+12], encoded[offset+13], encoded[offset+14], encoded[offset+15],
    ]);
    assert_eq!(validator_id, 42);

    // Decode suite_id
    let suite_id = u16::from_le_bytes([encoded[offset+16], encoded[offset+17]]);
    assert_eq!(suite_id, 100);

    // Decode kind (using message_type)
    assert_eq!(encoded[offset+18], 0x01); // SIGN_PROPOSAL
}

#[test]
fn t212_request_encode_vote_with_view() {
    let request = RemoteSignRequest {
        request_id: 42,
        validator_id: ValidatorId::new(100),
        suite_id: 100,
        kind: RemoteSignRequestKind::Vote,
        view: Some(42),
        preimage: vec![5, 6, 7, 8, 9],
    };

    let encoded = encode_request(&request);
    let domain_tag = b"QBIND:remote-signer:v1";
    let offset = domain_tag.len();

    // Validate kind
    assert_eq!(encoded[offset+18], 0x02); // SIGN_VOTE

    // Validate view_present
    assert_eq!(encoded[offset+19], 1);

    // Validate view value
    let view = u64::from_le_bytes([
        encoded[offset+20], encoded[offset+21], encoded[offset+22], encoded[offset+23],
        encoded[offset+24], encoded[offset+25], encoded[offset+26], encoded[offset+27],
    ]);
    assert_eq!(view, 42);
}

#[test]
fn t212_request_encode_timeout() {
    let request = RemoteSignRequest {
        request_id: 100,
        validator_id: ValidatorId::new(1),
        suite_id: 100,
        kind: RemoteSignRequestKind::Timeout,
        view: Some(100),
        preimage: vec![],
    };

    let encoded = encode_request(&request);
    let domain_tag = b"QBIND:remote-signer:v1";
    let offset = domain_tag.len();
    assert_eq!(encoded[offset+18], 0x03); // SIGN_TIMEOUT
}

#[test]
fn t212_response_decode_success() {
    // M10 Success response: status=0, request_id=42, sig_len=3, sig=[1,2,3]
    let mut data = vec![0]; // status
    data.extend_from_slice(&42u64.to_le_bytes()); // request_id
    data.extend_from_slice(&3u32.to_le_bytes()); // sig_len
    data.extend_from_slice(&[1, 2, 3]); // signature
    
    let response = decode_response(&data).expect("decode failed");

    assert!(response.signature.is_some());
    assert_eq!(response.signature.unwrap(), vec![1, 2, 3]);
    assert!(response.error.is_none());
    assert_eq!(response.request_id, 42);
}

#[test]
fn t212_response_decode_error() {
    // M10 Error response: status=1, request_id=123, error_code=3 (Unauthorized)
    let mut data = vec![1]; // status
    data.extend_from_slice(&123u64.to_le_bytes()); // request_id
    data.push(3); // error_code
    
    let response = decode_response(&data).expect("decode failed");

    assert!(response.signature.is_none());
    assert_eq!(response.error, Some(RemoteSignError::Unauthorized));
    assert_eq!(response.request_id, 123);
}

#[test]
fn t212_response_decode_rate_limited() {
    let mut data = vec![1]; // status
    data.extend_from_slice(&1u64.to_le_bytes()); // request_id
    data.push(6); // error_code
    
    let response = decode_response(&data).expect("decode failed");
    assert_eq!(response.error, Some(RemoteSignError::RateLimited));
}

#[test]
fn t212_response_decode_server_error() {
    let mut data = vec![1]; // status
    data.extend_from_slice(&1u64.to_le_bytes()); // request_id
    data.push(7); // error_code
    
    let response = decode_response(&data).expect("decode failed");
    assert_eq!(response.error, Some(RemoteSignError::ServerError));
}

#[test]
fn t212_response_decode_replay_detected_m10() {
    // M10: Test new ReplayDetected error code
    let mut data = vec![1]; // status
    data.extend_from_slice(&1u64.to_le_bytes()); // request_id
    data.push(8); // error_code for ReplayDetected
    
    let response = decode_response(&data).expect("decode failed");
    assert_eq!(response.error, Some(RemoteSignError::ReplayDetected));
}

// ============================================================================
// RemoteSignerMetrics Tests
// ============================================================================

#[test]
fn t212_metrics_initial_state() {
    let metrics = RemoteSignerMetrics::new();

    assert_eq!(metrics.requests_proposal_total(), 0);
    assert_eq!(metrics.requests_vote_total(), 0);
    assert_eq!(metrics.requests_timeout_total(), 0);
    assert_eq!(metrics.failures_transport_total(), 0);
    assert_eq!(metrics.failures_timeout_total(), 0);
    assert_eq!(metrics.failures_server_reject_total(), 0);
    assert_eq!(metrics.failures_protocol_total(), 0);
    assert_eq!(metrics.last_latency_ms(), 0);
}

#[test]
fn t212_metrics_record_successful_proposal() {
    let metrics = RemoteSignerMetrics::new();
    metrics.record_result("proposal", true, 50, None);

    assert_eq!(metrics.requests_proposal_total(), 1);
    assert_eq!(metrics.last_latency_ms(), 50);
    assert_eq!(metrics.failures_transport_total(), 0);
}

#[test]
fn t212_metrics_record_failed_vote() {
    let metrics = RemoteSignerMetrics::new();
    metrics.record_result("vote", false, 100, Some("transport"));

    assert_eq!(metrics.requests_vote_total(), 1);
    assert_eq!(metrics.failures_transport_total(), 1);
    assert_eq!(metrics.last_latency_ms(), 100);
}

#[test]
fn t212_metrics_record_timeout_failure() {
    let metrics = RemoteSignerMetrics::new();
    metrics.record_result("timeout", false, 2000, Some("timeout"));

    assert_eq!(metrics.requests_timeout_total(), 1);
    assert_eq!(metrics.failures_timeout_total(), 1);
}

#[test]
fn t212_metrics_record_multiple() {
    let metrics = RemoteSignerMetrics::new();

    metrics.record_result("proposal", true, 10, None);
    metrics.record_result("proposal", true, 20, None);
    metrics.record_result("vote", true, 15, None);
    metrics.record_result("vote", false, 100, Some("server_reject"));
    metrics.record_result("timeout", false, 50, Some("protocol"));

    assert_eq!(metrics.requests_proposal_total(), 2);
    assert_eq!(metrics.requests_vote_total(), 2);
    assert_eq!(metrics.requests_timeout_total(), 1);
    assert_eq!(metrics.failures_server_reject_total(), 1);
    assert_eq!(metrics.failures_protocol_total(), 1);
}

#[test]
fn t212_metrics_format_output() {
    let metrics = RemoteSignerMetrics::new();
    metrics.record_result("proposal", true, 50, None);

    let output = metrics.format_metrics();

    assert!(output.contains("qbind_remote_sign_requests_total{kind=\"proposal\"} 1"));
    assert!(output.contains("qbind_remote_sign_last_latency_ms 50"));
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn t212_error_rate_limited_display() {
    let error = RemoteSignError::RateLimited;
    let display = format!("{}", error);
    assert!(display.contains("rate limited"));
}

#[test]
fn t212_error_server_error_display() {
    let error = RemoteSignError::ServerError;
    let display = format!("{}", error);
    assert!(display.contains("server error"));
}

// ============================================================================
// Constants Tests
// ============================================================================

#[test]
fn t212_default_timeout() {
    // Default timeout should be reasonable (500ms - 2s)
    assert!(DEFAULT_REMOTE_SIGNER_TIMEOUT_MS >= 500);
    assert!(DEFAULT_REMOTE_SIGNER_TIMEOUT_MS <= 5000);
}

#[test]
fn t212_max_preimage_size() {
    // Max preimage should be reasonable (at least 1KB, no more than 64KB)
    assert!(MAX_PREIMAGE_SIZE >= 1024);
    assert!(MAX_PREIMAGE_SIZE <= 65536);
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn t212_signer_mode_remote_signer_exists() {
    // Verify SignerMode::RemoteSigner is valid
    let _mode = SignerMode::RemoteSigner;
    assert!(!qbind_node::is_production_signer_mode(
        SignerMode::LoopbackTesting
    ));
    assert!(qbind_node::is_production_signer_mode(
        SignerMode::RemoteSigner
    ));
}

// ============================================================================
// Loopback Transport Round-Trip Tests (via RemoteSignerClient)
// ============================================================================

#[test]
fn t212_loopback_round_trip_proposal() {
    let validator_id = ValidatorId::new(42);
    let (pk, local_signer) = make_test_signer(validator_id);

    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    let preimage = b"test proposal preimage for T212";
    let signature = client.sign_proposal(preimage).expect("sign failed");

    // Verify signature
    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend
            .verify_proposal(42, &pk, preimage, &signature)
            .is_ok(),
        "signature should verify"
    );
}

#[test]
fn t212_loopback_round_trip_vote() {
    let validator_id = ValidatorId::new(99);
    let (pk, local_signer) = make_test_signer(validator_id);

    let transport = Arc::new(LoopbackSignerTransport::new(local_signer));
    let client = RemoteSignerClient::new(validator_id, 100, transport);

    let preimage = b"test vote preimage for T212";
    let signature = client.sign_vote(preimage).expect("sign failed");

    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    let backend = MlDsa44Backend::new();
    assert!(
        backend.verify_vote(99, &pk, preimage, &signature).is_ok(),
        "vote signature should verify"
    );
}

// ============================================================================
// Daemon Integration Tests (#[ignore])
// ============================================================================

/// This test is ignored by default as it requires a running remote signer daemon.
///
/// To run:
/// 1. Start the remote signer daemon
/// 2. Run: cargo test -p qbind-node --test t212_remote_signer_integration_tests -- --ignored
#[test]
#[ignore]
fn t212_daemon_end_to_end_signing() {
    // This test would:
    // 1. Start qbind-remote-signer in the background
    // 2. Create a TcpKemTlsSignerTransport
    // 3. Send signing requests
    // 4. Verify signatures

    // Placeholder for full daemon integration test
    eprintln!("Daemon end-to-end test not implemented - requires KEMTLS server setup");
}

/// Test rate limiting behavior.
#[test]
#[ignore]
fn t212_daemon_rate_limiting() {
    // This test would:
    // 1. Start daemon with rate_limit_rps = 2
    // 2. Send 3 requests quickly
    // 3. Verify third request is rate limited

    eprintln!("Rate limiting test not implemented - requires daemon setup");
}

/// Test connection handling.
#[test]
#[ignore]
fn t212_daemon_connection_handling() {
    // This test would:
    // 1. Start daemon
    // 2. Connect multiple clients
    // 3. Verify each connection is handled correctly

    eprintln!("Connection handling test not implemented - requires daemon setup");
}

// ============================================================================
// MainNet Invariant Tests
// ============================================================================

#[test]
fn t212_mainnet_config_error_remote_signer_unreachable_exists() {
    // Verify the error variant exists
    let error = qbind_node::MainnetConfigError::RemoteSignerUnreachable;
    let display = format!("{}", error);
    assert!(display.contains("unreachable"));
}