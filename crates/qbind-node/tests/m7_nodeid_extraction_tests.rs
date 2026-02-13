//! M7: NodeId extraction from KEMTLS certificate tests.
//!
//! These tests verify that:
//! 1. NodeId derivation is deterministic for the same cert/pubkey bytes
//! 2. Different certs/pubkeys produce different NodeIds
//! 3. NodeId no longer defaults to zero for outbound connections
//! 4. The derivation uses the correct domain separation tag

use qbind_hash::{
    derive_node_id_from_cert, derive_node_id_from_pubkey, INBOUND_SESSION_DOMAIN_TAG,
    NODEID_DOMAIN_TAG,
};
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// NodeId Derivation Tests
// ============================================================================

/// Test 1: NodeId derivation from public key is deterministic
#[test]
fn test_nodeid_derivation_from_pubkey_is_deterministic() {
    let pubkey = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    
    let node_id_1 = derive_node_id_from_pubkey(&pubkey);
    let node_id_2 = derive_node_id_from_pubkey(&pubkey);
    
    assert_eq!(node_id_1, node_id_2, "Same pubkey should produce same NodeId");
}

/// Test 2: Different public keys produce different NodeIds
#[test]
fn test_different_pubkeys_produce_different_nodeids() {
    let pubkey_a = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let pubkey_b = vec![0x01, 0x02, 0x03, 0x04, 0x06]; // One byte different
    
    let node_id_a = derive_node_id_from_pubkey(&pubkey_a);
    let node_id_b = derive_node_id_from_pubkey(&pubkey_b);
    
    assert_ne!(node_id_a, node_id_b, "Different pubkeys should produce different NodeIds");
}

/// Test 3: NodeId derivation from certificate is deterministic
#[test]
fn test_nodeid_derivation_from_cert_is_deterministic() {
    let cert = create_test_cert(1);
    
    let node_id_1 = derive_node_id_from_cert(&cert);
    let node_id_2 = derive_node_id_from_cert(&cert);
    
    assert_eq!(node_id_1, node_id_2, "Same cert should produce same NodeId");
}

/// Test 4: Different certs produce different NodeIds
#[test]
fn test_different_certs_produce_different_nodeids() {
    let cert_a = create_test_cert(1);
    let cert_b = create_test_cert(2);
    
    let node_id_a = derive_node_id_from_cert(&cert_a);
    let node_id_b = derive_node_id_from_cert(&cert_b);
    
    assert_ne!(node_id_a, node_id_b, "Different certs should produce different NodeIds");
}

/// Test 5: NodeId is not all zeros for valid inputs
#[test]
fn test_nodeid_is_not_zero_for_valid_input() {
    let pubkey = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let node_id = derive_node_id_from_pubkey(&pubkey);
    
    let zero = [0u8; 32];
    assert_ne!(node_id, zero, "NodeId should not be zero for valid input");
}

/// Test 6: Domain tag is correct
#[test]
fn test_nodeid_domain_tag() {
    assert_eq!(NODEID_DOMAIN_TAG, "QBIND:nodeid:v1");
}

/// Test 6b: Inbound session domain tag is correct
#[test]
fn test_inbound_session_domain_tag() {
    assert_eq!(INBOUND_SESSION_DOMAIN_TAG, "QBIND:inbound:session:v1");
}

/// Test 7: Certs with only signature difference produce different NodeIds
/// (signatures are included in the canonical bytes)
#[test]
fn test_signature_affects_nodeid() {
    let mut cert_a = create_test_cert(1);
    let mut cert_b = create_test_cert(1);
    
    // Same cert but different signatures
    cert_a.sig_bytes = vec![0xAA; 64];
    cert_b.sig_bytes = vec![0xBB; 64];
    
    let node_id_a = derive_node_id_from_cert(&cert_a);
    let node_id_b = derive_node_id_from_cert(&cert_b);
    
    assert_ne!(node_id_a, node_id_b, "Different signatures should produce different NodeIds");
}

/// Test 8: Cert with different leaf_kem_pk produces different NodeId
#[test]
fn test_different_leaf_kem_pk_produces_different_nodeid() {
    let mut cert_a = create_test_cert(1);
    let mut cert_b = create_test_cert(1);
    
    cert_a.leaf_kem_pk = vec![0x01; 32];
    cert_b.leaf_kem_pk = vec![0x02; 32];
    
    let node_id_a = derive_node_id_from_cert(&cert_a);
    let node_id_b = derive_node_id_from_cert(&cert_b);
    
    assert_ne!(node_id_a, node_id_b, "Different leaf_kem_pk should produce different NodeIds");
}

/// Test 9: Empty public key still produces valid (non-zero) NodeId
/// (domain tag ensures non-zero output)
#[test]
fn test_empty_pubkey_produces_nonzero_nodeid() {
    let empty_pubkey: Vec<u8> = vec![];
    let node_id = derive_node_id_from_pubkey(&empty_pubkey);
    
    let zero = [0u8; 32];
    assert_ne!(node_id, zero, "Even empty pubkey should produce non-zero NodeId due to domain tag");
}

/// Test 10: Large public key works correctly
#[test]
fn test_large_pubkey_works() {
    // ML-KEM-768 public keys are 1184 bytes
    let large_pubkey: Vec<u8> = (0..1184).map(|i| (i % 256) as u8).collect();
    let node_id = derive_node_id_from_pubkey(&large_pubkey);
    
    let zero = [0u8; 32];
    assert_ne!(node_id, zero, "Large pubkey should produce valid NodeId");
    
    // Verify determinism with large key
    let node_id_2 = derive_node_id_from_pubkey(&large_pubkey);
    assert_eq!(node_id, node_id_2, "Large pubkey derivation should be deterministic");
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test NetworkDelegationCert with a given seed for variance
fn create_test_cert(seed: u8) -> NetworkDelegationCert {
    let mut validator_id = [0u8; 32];
    validator_id[0] = seed;
    
    let mut root_key_id = [0u8; 32];
    root_key_id[0] = seed;
    root_key_id[1] = 0x01;
    
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id: 1, // ML-KEM-768
        leaf_kem_pk: vec![seed; 32],
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: vec![],
        sig_suite_id: 100, // ML-DSA-44
        sig_bytes: vec![seed; 64],
    }
}

// ============================================================================
// Regression Tests
// ============================================================================

/// Test 11: Regression - NodeId should NOT be the zero constant anymore
/// This test verifies the M7 requirement that NodeId is no longer set to zero
#[test]
fn test_regression_nodeid_not_zero() {
    // Any valid public key should produce non-zero NodeId
    let pubkey_scenarios = vec![
        vec![0u8; 32],           // All zeros pubkey
        vec![1u8; 32],           // All ones pubkey  
        vec![0xFF; 32],          // All 0xFF pubkey
        (0..32).collect(),       // Sequential bytes
    ];
    
    let zero = [0u8; 32];
    
    for (i, pubkey) in pubkey_scenarios.iter().enumerate() {
        let node_id = derive_node_id_from_pubkey(pubkey);
        assert_ne!(
            node_id, zero,
            "Scenario {}: NodeId should not be zero for any valid pubkey", i
        );
    }
}

/// Test 12: Cross-check - pubkey derivation and cert derivation should differ
/// even when using the same underlying key bytes
#[test]
fn test_pubkey_and_cert_derivation_differ() {
    let key_bytes = vec![0x42; 32];
    
    // Derive from just the public key
    let node_id_from_pubkey = derive_node_id_from_pubkey(&key_bytes);
    
    // Derive from a cert containing the same public key
    let mut cert = create_test_cert(0x42);
    cert.leaf_kem_pk = key_bytes;
    let node_id_from_cert = derive_node_id_from_cert(&cert);
    
    // They should be different because the cert includes more data
    assert_ne!(
        node_id_from_pubkey, node_id_from_cert,
        "NodeId from pubkey alone should differ from NodeId from cert"
    );
}

// ============================================================================
// Integration-Style Tests
// ============================================================================

/// Test 13: Verify that the derivation is stable across restarts
/// (simulated by calling the function multiple times in sequence)
#[test]
fn test_nodeid_stable_across_calls() {
    let cert = create_test_cert(99);
    
    // Simulate "restart" by creating fresh calls
    let node_ids: Vec<_> = (0..10)
        .map(|_| derive_node_id_from_cert(&cert))
        .collect();
    
    // All should be identical
    for (i, node_id) in node_ids.iter().enumerate() {
        assert_eq!(
            *node_id, node_ids[0],
            "NodeId at iteration {} should match first derivation", i
        );
    }
}
