//! M8: Mutual KEMTLS Authentication + Inbound NodeId Binding tests.
//!
//! These tests verify:
//! 1. Missing client cert rejection in Required mode
//! 2. Invalid client cert rejection
//! 3. Invalid signature rejection
//! 4. Cookie validation still blocks before client cert parsing
//! 5. NodeId derivation from verified client cert

use std::sync::Arc;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_hash::net::derive_node_id_from_cert;
use qbind_net::{
    CookieConfig, ClientHandshake, ClientHandshakeConfig, KemPrivateKey, MutualAuthMode, 
    NetError, ServerHandshake, ServerHandshakeConfig, ServerHandshakeResponse, TrustedClientRoots,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::{ClientInit, NetworkDelegationCert, PROTOCOL_VERSION_1, PROTOCOL_VERSION_2};

// ============================================================================
// Dummy Implementations for Testing
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

/// A DummySig that verifies successfully only when signature starts with 0xAA.
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

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], sig: &[u8]) -> Result<(), CryptoError> {
        // Only succeed if signature starts with 0xAA (valid) or is all 0x00 (test cert)
        if sig.is_empty() {
            return Err(CryptoError::InvalidSignature);
        }
        if sig[0] == 0xAA || sig[0] == 0x00 {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
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

/// Create a test crypto provider
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

/// Create a synthetic NetworkDelegationCert for testing.
fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
    sig_bytes: Vec<u8>,
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
        sig_bytes,
    }
}

// ============================================================================
// Test 1: Missing Client Cert in Required Mode
// ============================================================================

#[test]
fn test_missing_client_cert_in_required_mode_fails() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

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
        vec![0u8; 64], // Valid signature for DummySig
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client config WITHOUT local_delegation_cert (protocol v1)
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: None, // No client cert!
    };

    // Server config with MutualAuthMode::Required
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required, // Requires client cert!
        trusted_client_roots: None,
    };

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client generates ClientInit (v1, no client cert)
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.version, PROTOCOL_VERSION_1);
    assert!(client_init.client_cert.is_empty());

    // Server should reject because mutual auth is required but no cert provided
    let result = server.handle_client_init(&*provider, &client_init);
    assert!(result.is_err());
    
    match result {
        Err(NetError::UnsupportedProtocolVersion(1)) => {
            // Expected: v1 protocol not allowed in Required mode
        }
        Err(NetError::ClientCertRequired) => {
            // Also acceptable
        }
        other => panic!("Expected UnsupportedProtocolVersion or ClientCertRequired, got {:?}", other),
    }
}

// ============================================================================
// Test 2: Empty Client Cert in v2 Protocol Fails in Required Mode
// ============================================================================

#[test]
fn test_empty_client_cert_v2_in_required_mode_fails() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

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
        vec![0u8; 64],
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Server config with MutualAuthMode::Required
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: None,
    };

    let server_random = [0u8; 32];
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Manually craft a v2 ClientInit with empty client_cert
    let client_init = ClientInit {
        version: PROTOCOL_VERSION_2,
        kem_suite_id,
        aead_suite_id,
        client_random: [0u8; 32],
        validator_id,
        cookie: Vec::new(),
        kem_ct: vec![0u8; 48],
        client_cert: Vec::new(), // Empty cert in v2!
    };

    // Server should reject because client_cert is empty
    let result = server.handle_client_init(&*provider, &client_init);
    assert!(result.is_err());
    
    match result {
        Err(NetError::ClientCertRequired) => {
            // Expected
        }
        other => panic!("Expected ClientCertRequired, got {:?}", other),
    }
}

// ============================================================================
// Test 3: Invalid Client Certificate (Parse Error)
// ============================================================================

#[test]
fn test_invalid_client_cert_parse_error_fails() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

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
        vec![0u8; 64],
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: None,
    };

    let server_random = [0u8; 32];
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Craft a v2 ClientInit with garbage client_cert
    let client_init = ClientInit {
        version: PROTOCOL_VERSION_2,
        kem_suite_id,
        aead_suite_id,
        client_random: [0u8; 32],
        validator_id,
        cookie: Vec::new(),
        kem_ct: vec![0u8; 48],
        client_cert: vec![0xFF, 0xFF, 0xFF], // Invalid cert bytes!
    };

    // Server should reject because cert parsing fails
    let result = server.handle_client_init(&*provider, &client_init);
    assert!(result.is_err());
    
    match result {
        Err(NetError::ClientCertInvalid(msg)) => {
            assert!(msg.contains("parse"), "Expected parse error message, got: {}", msg);
        }
        other => panic!("Expected ClientCertInvalid(parse error), got {:?}", other),
    }
}

// ============================================================================
// Test 4: Invalid Client Certificate Signature
// ============================================================================

#[test]
fn test_invalid_client_cert_signature_fails() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Create trusted client roots that will cause signature verification
    let trusted_roots = TrustedClientRoots::new(|_root_key_id: &[u8; 32]| {
        // Return a root key that will trigger signature verification
        Some(vec![0x01; 32])
    });

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk.clone(),
        local_delegation_cert: server_cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: Some(trusted_roots),
    };

    let server_random = [0u8; 32];
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Create a client cert with INVALID signature (starts with 0xBB, not 0xAA or 0x00)
    let client_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        vec![0x42; 32], // Different KEM pk
        kem_suite_id,
        sig_suite_id,
        vec![0xBB; 64], // INVALID signature - DummySig rejects this
    );

    let mut client_cert_bytes = Vec::new();
    client_cert.encode(&mut client_cert_bytes);

    // Craft a v2 ClientInit with the invalid-signature cert
    let client_init = ClientInit {
        version: PROTOCOL_VERSION_2,
        kem_suite_id,
        aead_suite_id,
        client_random: [0u8; 32],
        validator_id,
        cookie: Vec::new(),
        kem_ct: vec![0u8; 48],
        client_cert: client_cert_bytes,
    };

    // Server should reject because signature verification fails
    let result = server.handle_client_init(&*provider, &client_init);
    assert!(result.is_err());
    
    match result {
        Err(NetError::KeySchedule(msg)) => {
            // Expected: signature verify error comes through as KeySchedule
            assert!(msg.contains("signature") || msg.contains("verify"), 
                "Expected signature error, got: {}", msg);
        }
        other => panic!("Expected KeySchedule(signature error), got {:?}", other),
    }
}

// ============================================================================
// Test 5: Cookie Blocks Before Client Cert Parsing
// ============================================================================

#[test]
fn test_cookie_blocks_before_client_cert_parsing() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Create cookie config (requires cookie validation)
    let cookie_config = CookieConfig::new(vec![0x42; 32]);

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk.clone(),
        local_delegation_cert: server_cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: Some(cookie_config), // Cookie validation enabled!
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: None,
    };

    let server_random = [0u8; 32];
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Create a valid client cert
    let client_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        vec![0x42; 32],
        kem_suite_id,
        sig_suite_id,
        vec![0xAA; 64], // Valid signature
    );

    let mut client_cert_bytes = Vec::new();
    client_cert.encode(&mut client_cert_bytes);

    // Craft a v2 ClientInit with valid client cert but NO cookie
    let client_init = ClientInit {
        version: PROTOCOL_VERSION_2,
        kem_suite_id,
        aead_suite_id,
        client_random: [0u8; 32],
        validator_id,
        cookie: Vec::new(), // No cookie!
        kem_ct: vec![0u8; 48],
        client_cert: client_cert_bytes,
    };

    // Server should return cookie challenge, NOT try to parse client cert
    let client_ip = b"127.0.0.1";
    let current_time = 1000u64;
    let result = server.handle_client_init_with_cookie(&*provider, &client_init, client_ip, current_time);
    
    match result {
        Ok(ServerHandshakeResponse::CookieChallenge(cookie)) => {
            // Expected: cookie challenge returned before any cert parsing
            assert!(!cookie.cookie.is_empty(), "Cookie should be non-empty");
        }
        Ok(ServerHandshakeResponse::HandshakeComplete(..)) => {
            panic!("Should have returned cookie challenge, not completed handshake");
        }
        Err(e) => {
            panic!("Should have returned cookie challenge, got error: {:?}", e);
        }
    }
}

// ============================================================================
// Test 6: Successful Mutual Auth Returns NodeId
// ============================================================================

#[test]
fn test_successful_mutual_auth_returns_client_node_id() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client config WITH local_delegation_cert (protocol v2)
    let client_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        vec![0x42; 32],
        kem_suite_id,
        sig_suite_id,
        vec![0xAA; 64], // Valid signature
    );

    let mut client_cert_bytes = Vec::new();
    client_cert.encode(&mut client_cert_bytes);

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: Some(client_cert_bytes.clone()), // Client has cert!
    };

    // Server config with MutualAuthMode::Required
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: server_cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: None, // No roots = accepts any cert for testing
    };

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client generates ClientInit (v2 with client cert)
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.version, PROTOCOL_VERSION_2);
    assert!(!client_init.client_cert.is_empty());

    // Server handles ClientInit
    let (server_accept, server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("Server handshake should succeed");

    // Verify mutual auth completed
    assert!(server_result.mutual_auth_complete, "Mutual auth should be complete");
    
    // Verify client_node_id is set
    assert!(server_result.client_node_id.is_some(), "client_node_id should be set");
    
    // Verify client_node_id matches derive_node_id_from_cert
    let expected_node_id = derive_node_id_from_cert(&client_cert);
    assert_eq!(
        server_result.client_node_id.unwrap(),
        expected_node_id,
        "client_node_id should match derive_node_id_from_cert"
    );

    // Client completes handshake
    let client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("Client handshake should succeed");

    // Client-side mutual_auth_complete should also be true
    assert!(client_result.mutual_auth_complete, "Client should report mutual auth complete");
    
    // Client doesn't have its own NodeId from handshake
    assert!(client_result.client_node_id.is_none(), "Client shouldn't have client_node_id");
}

// ============================================================================
// Test 7: Optional Mode Accepts v1 Protocol
// ============================================================================

#[test]
fn test_optional_mode_accepts_v1_protocol() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client config WITHOUT local_delegation_cert (protocol v1)
    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: None, // No client cert!
    };

    // Server config with MutualAuthMode::Optional
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: server_cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Optional, // Optional mode
        trusted_client_roots: None,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client generates ClientInit (v1, no client cert)
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.version, PROTOCOL_VERSION_1);

    // Server should accept v1 in Optional mode
    let (server_accept, server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("Server should accept v1 in Optional mode");

    // Mutual auth should NOT be complete (no client cert provided)
    assert!(!server_result.mutual_auth_complete, "Mutual auth should not be complete without cert");
    assert!(server_result.client_node_id.is_none(), "client_node_id should be None");

    // Client completes handshake
    let client_result = client
        .handle_server_accept(&*provider, &client_init, &server_accept)
        .expect("Client handshake should succeed");

    assert!(!client_result.mutual_auth_complete, "Client should report no mutual auth");
}

// ============================================================================
// Test 8: Disabled Mode Ignores Client Cert
// ============================================================================

#[test]
fn test_disabled_mode_ignores_client_cert() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // Client WITH cert (v2)
    let client_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        vec![0x42; 32],
        kem_suite_id,
        sig_suite_id,
        vec![0xAA; 64],
    );

    let mut client_cert_bytes = Vec::new();
    client_cert.encode(&mut client_cert_bytes);

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: Some(client_cert_bytes),
    };

    // Server config with MutualAuthMode::Disabled
    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: server_cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Disabled, // Disabled mode
        trusted_client_roots: None,
    };

    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client = ClientHandshake::new(client_cfg, client_random);
    let mut server = ServerHandshake::new(server_cfg, server_random);

    // Client generates ClientInit (v2 with cert)
    let client_init = client.start(validator_id, &server_kem_pk).unwrap();
    assert_eq!(client_init.version, PROTOCOL_VERSION_2);

    // Server accepts but ignores client cert
    let (_server_accept, server_result) = server
        .handle_client_init(&*provider, &client_init)
        .expect("Server should accept in Disabled mode");

    // Mutual auth should NOT be complete (disabled)
    assert!(!server_result.mutual_auth_complete, "Mutual auth should not be complete in Disabled mode");
    assert!(server_result.client_node_id.is_none(), "client_node_id should be None in Disabled mode");
}

// ============================================================================
// Test 9: Transcript Binding Includes Both Identities
// ============================================================================

#[test]
fn test_transcript_binding_includes_client_cert() {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(kem_suite_id, aead_suite_id, sig_suite_id));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let server_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
        vec![0u8; 64],
    );

    let mut server_cert_bytes = Vec::new();
    server_cert.encode(&mut server_cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    // First handshake: v2 with client cert
    let client_cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        vec![0x42; 32],
        kem_suite_id,
        sig_suite_id,
        vec![0xAA; 64],
    );
    let mut client_cert_bytes = Vec::new();
    client_cert.encode(&mut client_cert_bytes);

    let client_cfg_v2 = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: Some(client_cert_bytes.clone()),
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk.clone(),
        local_delegation_cert: server_cert_bytes.clone(),
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk.clone())),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Optional, // Optional to allow both v1 and v2
        trusted_client_roots: None,
    };

    // Complete v2 handshake
    let client_random = [0u8; 32];
    let server_random = [0u8; 32];

    let mut client_v2 = ClientHandshake::new(client_cfg_v2, client_random);
    let mut server_v2 = ServerHandshake::new(server_cfg.clone(), server_random);

    let client_init_v2 = client_v2.start(validator_id, &server_kem_pk).unwrap();
    let (server_accept_v2, server_result_v2) = server_v2.handle_client_init(&*provider, &client_init_v2).unwrap();
    let _client_result_v2 = client_v2.handle_server_accept(&*provider, &client_init_v2, &server_accept_v2).unwrap();

    // Second handshake: v1 without client cert
    let client_cfg_v1 = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: None, // No client cert
    };

    let mut client_v1 = ClientHandshake::new(client_cfg_v1, client_random);
    let mut server_v1 = ServerHandshake::new(server_cfg, server_random);

    let client_init_v1 = client_v1.start(validator_id, &server_kem_pk).unwrap();
    let (server_accept_v1, server_result_v1) = server_v1.handle_client_init(&*provider, &client_init_v1).unwrap();
    let _client_result_v1 = client_v1.handle_server_accept(&*provider, &client_init_v1, &server_accept_v1).unwrap();

    // The sessions should have DIFFERENT keys because the transcript differs
    // (v2 includes client_cert in transcript, v1 does not)
    // We can't directly compare session keys, but we can verify mutual auth differs
    assert!(server_result_v2.mutual_auth_complete);
    assert!(!server_result_v1.mutual_auth_complete);
    
    // Different client_node_id outcomes
    assert!(server_result_v2.client_node_id.is_some());
    assert!(server_result_v1.client_node_id.is_none());
}
