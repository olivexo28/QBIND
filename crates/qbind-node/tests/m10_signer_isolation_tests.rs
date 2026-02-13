//! M10 Signer Isolation Tests
//!
//! Tests for production-grade key isolation for validator signing (M10).
//!
//! # Test Categories
//!
//! 1. **Domain separation**: Remote signer protocol uses "QBIND:remote-signer:v1" tag
//! 2. **Replay protection**: Monotonic request_id prevents replay attacks
//! 3. **Fail-closed behavior**: Signer unavailable -> node refuses to sign
//! 4. **Protocol framing**: Request/response encoding matches M10 spec

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::ValidatorSigningKey;
use qbind_node::remote_signer::{
    LoopbackSignerTransport, RemoteSignError, RemoteSignRequest, RemoteSignRequestKind,
    RemoteSignerClient, RemoteSignerTransport, REMOTE_SIGNER_DOMAIN_TAG,
};
use qbind_node::validator_signer::{LocalKeySigner, ValidatorSigner};
use std::sync::Arc;

// ============================================================================
// Test Helpers
// ============================================================================

fn make_test_signer(validator_id: u64) -> Arc<LocalKeySigner> {
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let signing_key = Arc::new(ValidatorSigningKey::new(sk));
    Arc::new(LocalKeySigner::new(ValidatorId::new(validator_id), 100, signing_key))
}

// ============================================================================
// Domain Separation Tests (M10)
// ============================================================================

#[test]
fn m10_domain_tag_constant_correct() {
    assert_eq!(REMOTE_SIGNER_DOMAIN_TAG, "QBIND:remote-signer:v1");
    assert_eq!(REMOTE_SIGNER_DOMAIN_TAG.len(), 23);
}

#[test]
fn m10_message_type_constants() {
    use qbind_node::remote_signer::message_type;
    
    assert_eq!(message_type::SIGN_PROPOSAL, 0x01);
    assert_eq!(message_type::SIGN_VOTE, 0x02);
    assert_eq!(message_type::SIGN_TIMEOUT, 0x03);
    assert_eq!(message_type::PING, 0x10);
}

#[test]
fn m10_request_kind_message_type_conversion() {
    assert_eq!(RemoteSignRequestKind::Proposal.message_type(), 0x01);
    assert_eq!(RemoteSignRequestKind::Vote.message_type(), 0x02);
    assert_eq!(RemoteSignRequestKind::Timeout.message_type(), 0x03);
    
    // Round-trip
    assert_eq!(RemoteSignRequestKind::from_message_type(0x01), Some(RemoteSignRequestKind::Proposal));
    assert_eq!(RemoteSignRequestKind::from_message_type(0x02), Some(RemoteSignRequestKind::Vote));
    assert_eq!(RemoteSignRequestKind::from_message_type(0x03), Some(RemoteSignRequestKind::Timeout));
    assert_eq!(RemoteSignRequestKind::from_message_type(0xFF), None);
}

// ============================================================================
// Replay Protection Tests (M10)
// ============================================================================

#[test]
fn m10_replay_protection_rejects_duplicate_request_id() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    
    let preimage = b"test preimage data";
    
    // First request with request_id = 1 should succeed
    let req1 = RemoteSignRequest {
        request_id: 1,
        validator_id: ValidatorId::new(42),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: preimage.to_vec(),
    };
    let resp1 = transport.send_sign_request(req1).expect("request 1 failed");
    assert!(resp1.signature.is_some(), "request 1 should succeed");
    assert_eq!(resp1.request_id, 1);
    
    // Second request with same request_id = 1 should be rejected
    let req2 = RemoteSignRequest {
        request_id: 1, // Replay!
        validator_id: ValidatorId::new(42),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: preimage.to_vec(),
    };
    let resp2 = transport.send_sign_request(req2).expect("request 2 should return error response");
    assert!(resp2.signature.is_none(), "replay should be rejected");
    assert_eq!(resp2.error, Some(RemoteSignError::ReplayDetected));
}

#[test]
fn m10_replay_protection_allows_incrementing_request_id() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    
    let preimage = b"test preimage data";
    
    // Sequential requests with incrementing request_id should all succeed
    for i in 1..=5 {
        let req = RemoteSignRequest {
            request_id: i,
            validator_id: ValidatorId::new(42),
            suite_id: 100,
            kind: RemoteSignRequestKind::Proposal,
            view: None,
            preimage: preimage.to_vec(),
        };
        let resp = transport.send_sign_request(req).expect(&format!("request {} failed", i));
        assert!(resp.signature.is_some(), "request {} should succeed", i);
        assert_eq!(resp.request_id, i);
    }
}

#[test]
fn m10_replay_protection_rejects_lower_request_id() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    
    let preimage = b"test preimage data";
    
    // First request with request_id = 100
    let req1 = RemoteSignRequest {
        request_id: 100,
        validator_id: ValidatorId::new(42),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: preimage.to_vec(),
    };
    let resp1 = transport.send_sign_request(req1).expect("request 1 failed");
    assert!(resp1.signature.is_some());
    
    // Second request with lower request_id = 50 should be rejected
    let req2 = RemoteSignRequest {
        request_id: 50, // Lower than 100!
        validator_id: ValidatorId::new(42),
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: preimage.to_vec(),
    };
    let resp2 = transport.send_sign_request(req2).expect("request 2 should return error response");
    assert!(resp2.signature.is_none(), "lower request_id should be rejected");
    assert_eq!(resp2.error, Some(RemoteSignError::ReplayDetected));
}

// ============================================================================
// Fail-Closed Behavior Tests (M10)
// ============================================================================

#[test]
fn m10_unauthorized_validator_id_rejected() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    
    // Request with wrong validator_id
    let req = RemoteSignRequest {
        request_id: 1,
        validator_id: ValidatorId::new(999), // Wrong validator!
        suite_id: 100,
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: b"test".to_vec(),
    };
    let resp = transport.send_sign_request(req).expect("should return error response");
    assert!(resp.signature.is_none());
    assert_eq!(resp.error, Some(RemoteSignError::Unauthorized));
}

#[test]
fn m10_unauthorized_suite_id_rejected() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    
    // Request with wrong suite_id
    let req = RemoteSignRequest {
        request_id: 1,
        validator_id: ValidatorId::new(42),
        suite_id: 999, // Wrong suite!
        kind: RemoteSignRequestKind::Proposal,
        view: None,
        preimage: b"test".to_vec(),
    };
    let resp = transport.send_sign_request(req).expect("should return error response");
    assert!(resp.signature.is_none());
    assert_eq!(resp.error, Some(RemoteSignError::Unauthorized));
}

// ============================================================================
// RemoteSignerClient Monotonic Request ID Tests (M10)
// ============================================================================

#[test]
fn m10_client_generates_monotonic_request_ids() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    let client = RemoteSignerClient::new(ValidatorId::new(42), 100, transport);
    
    // Sign multiple proposals - internal request_id should increment
    // and loopback transport should accept all of them
    for _ in 0..5 {
        let preimage = b"test proposal preimage";
        let result = client.sign_proposal(preimage);
        assert!(result.is_ok(), "signing should succeed: {:?}", result);
    }
}

// ============================================================================
// Error Variant Tests (M10)
// ============================================================================

#[test]
fn m10_error_display_strings() {
    assert_eq!(format!("{}", RemoteSignError::ReplayDetected), "replay detected: request_id not monotonic");
    assert_eq!(format!("{}", RemoteSignError::SignerUnavailable), "signer unavailable (fail-closed)");
    assert_eq!(format!("{}", RemoteSignError::MalformedResponse), "malformed response from signer");
}

// ============================================================================
// Protocol Round-Trip Tests (M10)
// ============================================================================

#[test]
fn m10_loopback_round_trip_proposal() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    let client = RemoteSignerClient::new(ValidatorId::new(42), 100, transport);
    
    let preimage = b"test proposal signing preimage with domain tag";
    let signature = client.sign_proposal(preimage).expect("signing failed");
    
    // Signature should be non-empty (ML-DSA-44 produces 2420 byte sigs)
    assert!(!signature.is_empty());
    assert!(signature.len() > 2000, "ML-DSA-44 signatures should be ~2420 bytes");
}

#[test]
fn m10_loopback_round_trip_vote() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    let client = RemoteSignerClient::new(ValidatorId::new(42), 100, transport);
    
    let preimage = b"test vote signing preimage";
    let signature = client.sign_vote(preimage).expect("signing failed");
    
    assert!(!signature.is_empty());
}

#[test]
fn m10_loopback_round_trip_timeout() {
    let signer = make_test_signer(42);
    let transport = Arc::new(LoopbackSignerTransport::new(signer.clone()));
    let client = RemoteSignerClient::new(ValidatorId::new(42), 100, transport);
    
    // sign_timeout computes its own preimage
    let signature = client.sign_timeout(100, None).expect("signing failed");
    
    assert!(!signature.is_empty());
}
