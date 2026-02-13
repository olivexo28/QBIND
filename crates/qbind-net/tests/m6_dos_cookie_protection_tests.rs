//! M6 DoS Cookie Protection Tests for KEMTLS Handshake.
//!
//! These tests verify that the server enforces cookie-based DoS protection:
//! - No-cookie init → cookie challenge returned
//! - Invalid cookie → cookie challenge returned  
//! - Valid cookie → handshake succeeds
//! - Expired cookie → rejected
//! - Random cookie bytes never trigger decapsulation

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientHandshake, ClientHandshakeConfig, CookieConfig, KemPrivateKey,
    MutualAuthMode, ServerHandshake, ServerHandshakeConfig, ServerHandshakeResponse, COOKIE_SIZE,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// ============================================================================

/// A DummyKem with decapsulation counter for verifying DoS protection.
struct CountingDummyKem {
    suite_id: u8,
    decaps_count: Arc<AtomicU64>,
}

impl CountingDummyKem {
    fn new(suite_id: u8, decaps_count: Arc<AtomicU64>) -> Self {
        CountingDummyKem { suite_id, decaps_count }
    }
}

impl KemSuite for CountingDummyKem {
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
        // Increment counter when decapsulation is called
        self.decaps_count.fetch_add(1, Ordering::SeqCst);

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

/// Standard DummyKem without counter (for client side).
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

// ============================================================================
// Test Setup Helpers
// ============================================================================

struct TestContext {
    client_cfg: ClientHandshakeConfig,
    server_cfg: ServerHandshakeConfig,
    validator_id: [u8; 32],
    server_kem_pk: Vec<u8>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    client_ip: Vec<u8>,
    time_secs: u64,
    decaps_count: Arc<AtomicU64>,
}

fn create_test_context_with_cookie_config(cookie_config: Option<CookieConfig>) -> TestContext {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let decaps_count = Arc::new(AtomicU64::new(0));

    // Client provider (standard KEM)
    let client_provider = Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
            .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
            .with_signature_suite(Arc::new(DummySig::new(sig_suite_id))),
    );

    // Server provider (counting KEM)
    let server_provider = Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(CountingDummyKem::new(kem_suite_id, decaps_count.clone())))
            .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
            .with_signature_suite(Arc::new(DummySig::new(sig_suite_id))),
    );

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

    let client_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: client_provider,
        peer_root_network_pk: root_network_pk.clone(),
        kem_metrics: None,
        local_delegation_cert: None, // M8: No client cert for backward compat tests
    };

    let server_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: server_provider,
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
        kem_metrics: None,
        cookie_config,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
        trusted_client_roots: None,
    };

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let client_ip = vec![127, 0, 0, 1];
    let time_secs = 1000u64;

    TestContext {
        client_cfg,
        server_cfg,
        validator_id,
        server_kem_pk,
        client_random,
        server_random,
        client_ip,
        time_secs,
        decaps_count,
    }
}

fn create_test_context_with_cookie() -> TestContext {
    let cookie_secret = vec![0x42u8; 32];
    let cookie_config = CookieConfig::new(cookie_secret);
    create_test_context_with_cookie_config(Some(cookie_config))
}

// ============================================================================
// M6 Tests
// ============================================================================

/// Test: No-cookie init → cookie challenge returned
#[test]
fn m6_no_cookie_init_returns_cookie_challenge() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg, ctx.client_random);
    let crypto = ctx.server_cfg.crypto.clone();
    let mut server = ServerHandshake::new(ctx.server_cfg, ctx.server_random);

    // Client generates ClientInit (with empty cookie by default)
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Verify client_init has no cookie
    assert!(client_init.cookie.is_empty(), "ClientInit should have no cookie initially");

    // Server handles ClientInit with cookie enforcement
    let response = server
        .handle_client_init_with_cookie(
            crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("handle_client_init_with_cookie should succeed");

    // Should return cookie challenge, not handshake complete
    match response {
        ServerHandshakeResponse::CookieChallenge(server_cookie) => {
            assert_eq!(server_cookie.cookie.len(), COOKIE_SIZE);
            assert_eq!(server_cookie.client_random, client_init.client_random);
            assert_eq!(server_cookie.kem_suite_id, client_init.kem_suite_id);
            assert_eq!(server_cookie.aead_suite_id, client_init.aead_suite_id);
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Expected CookieChallenge, got HandshakeComplete");
        }
    }

    // Verify NO decapsulation occurred
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur without valid cookie"
    );
}

/// Test: Invalid cookie → cookie challenge returned
#[test]
fn m6_invalid_cookie_returns_cookie_challenge() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg, ctx.client_random);
    let crypto = ctx.server_cfg.crypto.clone();
    let mut server = ServerHandshake::new(ctx.server_cfg, ctx.server_random);

    // Client generates ClientInit
    let mut client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Set an invalid cookie (wrong bytes)
    client_init.cookie = vec![0xAB; COOKIE_SIZE];

    // Server handles ClientInit with cookie enforcement
    let response = server
        .handle_client_init_with_cookie(
            crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("handle_client_init_with_cookie should succeed");

    // Should return cookie challenge
    match response {
        ServerHandshakeResponse::CookieChallenge(server_cookie) => {
            assert_eq!(server_cookie.cookie.len(), COOKIE_SIZE);
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Expected CookieChallenge for invalid cookie");
        }
    }

    // Verify NO decapsulation occurred
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur with invalid cookie"
    );
}

/// Test: Valid cookie → handshake succeeds
#[test]
fn m6_valid_cookie_handshake_succeeds() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Step 1: Client generates ClientInit (no cookie)
    let client_init_no_cookie = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Step 2: Server returns cookie challenge
    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_no_cookie,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("first handle should succeed");

    let server_cookie = match response {
        ServerHandshakeResponse::CookieChallenge(sc) => sc,
        _ => panic!("Expected cookie challenge"),
    };

    // Verify no decaps yet
    assert_eq!(ctx.decaps_count.load(Ordering::SeqCst), 0);

    // Step 3: Client retries with valid cookie
    let mut client_init_with_cookie = client_init_no_cookie.clone();
    client_init_with_cookie.cookie = server_cookie.cookie;

    // Step 4: Server completes handshake
    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_with_cookie,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("second handle should succeed");

    match response {
        ServerHandshakeResponse::HandshakeComplete(server_accept, _result) => {
            assert_eq!(server_accept.client_random, client_init_with_cookie.client_random);
            assert_eq!(server_accept.kem_suite_id, client_init_with_cookie.kem_suite_id);
        }
        ServerHandshakeResponse::CookieChallenge(_) => {
            panic!("Expected HandshakeComplete with valid cookie");
        }
    }

    // Verify decapsulation occurred exactly once
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        1,
        "Decapsulation should occur exactly once with valid cookie"
    );
}

/// Test: Expired cookie → rejected
#[test]
fn m6_expired_cookie_rejected() {
    let cookie_secret = vec![0x42u8; 32];
    let cookie_config = CookieConfig::with_params(cookie_secret, 30, 1); // 30s buckets, 1 skew
    let ctx = create_test_context_with_cookie_config(Some(cookie_config.clone()));

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Step 1: Get cookie at time 1000
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    let gen_time = 1000u64;
    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            gen_time,
        )
        .expect("first handle should succeed");

    let server_cookie = match response {
        ServerHandshakeResponse::CookieChallenge(sc) => sc,
        _ => panic!("Expected cookie challenge"),
    };

    // Step 2: Try to use cookie at time 1100 (100s later = 3+ buckets, expired)
    let mut client_init_with_cookie = client_init.clone();
    client_init_with_cookie.cookie = server_cookie.cookie;

    let verify_time = 1100u64; // 100 seconds later

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_with_cookie,
            &ctx.client_ip,
            verify_time,
        )
        .expect("handle should succeed");

    // Should return cookie challenge (expired cookie = invalid)
    match response {
        ServerHandshakeResponse::CookieChallenge(_) => {
            // Expected - expired cookie treated as invalid
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Expected CookieChallenge for expired cookie");
        }
    }

    // Verify NO decapsulation occurred
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur with expired cookie"
    );
}

/// Test: Random cookie bytes never trigger decapsulation
#[test]
fn m6_random_cookies_never_trigger_decapsulation() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Generate ClientInit
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Try multiple random cookies
    for i in 0..100 {
        let mut client_init_random = client_init.clone();
        // Generate pseudo-random cookie bytes
        client_init_random.cookie = (0..COOKIE_SIZE).map(|j| ((i + j) * 17 % 256) as u8).collect();

        let response = server
            .handle_client_init_with_cookie(
                ctx.server_cfg.crypto.as_ref(),
                &client_init_random,
                &ctx.client_ip,
                ctx.time_secs,
            )
            .expect("handle should succeed");

        // Should always return cookie challenge
        match response {
            ServerHandshakeResponse::CookieChallenge(_) => {
                // Expected
            }
            ServerHandshakeResponse::HandshakeComplete(_, _) => {
                panic!("Random cookie #{} should not trigger handshake complete", i);
            }
        }
    }

    // Verify NO decapsulation occurred across all attempts
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur with any random cookie"
    );
}

/// Test: Cookie bound to client IP
#[test]
fn m6_cookie_bound_to_client_ip() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Get cookie for client IP 127.0.0.1
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    let client_ip_a = vec![127, 0, 0, 1];
    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init,
            &client_ip_a,
            ctx.time_secs,
        )
        .expect("handle should succeed");

    let server_cookie = match response {
        ServerHandshakeResponse::CookieChallenge(sc) => sc,
        _ => panic!("Expected cookie challenge"),
    };

    // Try to use cookie from different IP
    let mut client_init_with_cookie = client_init.clone();
    client_init_with_cookie.cookie = server_cookie.cookie;

    let client_ip_b = vec![192, 168, 1, 1]; // Different IP

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_with_cookie,
            &client_ip_b,
            ctx.time_secs,
        )
        .expect("handle should succeed");

    // Should reject - cookie bound to different IP
    match response {
        ServerHandshakeResponse::CookieChallenge(_) => {
            // Expected
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Cookie from different IP should not be accepted");
        }
    }

    // Verify NO decapsulation
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur with IP-mismatched cookie"
    );
}

/// Test: Cookie bound to client_random
#[test]
fn m6_cookie_bound_to_client_random() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Get cookie
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("handle should succeed");

    let server_cookie = match response {
        ServerHandshakeResponse::CookieChallenge(sc) => sc,
        _ => panic!("Expected cookie challenge"),
    };

    // Try to use cookie with different client_random
    let mut client_init_modified = client_init.clone();
    client_init_modified.cookie = server_cookie.cookie;
    client_init_modified.client_random = [0xFF; 32]; // Different random

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_modified,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("handle should succeed");

    // Should reject - cookie bound to different client_random
    match response {
        ServerHandshakeResponse::CookieChallenge(_) => {
            // Expected
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Cookie with modified client_random should not be accepted");
        }
    }

    // Verify NO decapsulation
    assert_eq!(ctx.decaps_count.load(Ordering::SeqCst), 0);
}

/// Test: Backward compatibility - no cookie config means no enforcement
#[test]
fn m6_backward_compatibility_no_cookie_config() {
    let ctx = create_test_context_with_cookie_config(None); // No cookie enforcement

    let mut client = ClientHandshake::new(ctx.client_cfg, ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Client generates ClientInit (no cookie)
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Old method should still work without cookie
    let (server_accept, _result) = server
        .handle_client_init(ctx.server_cfg.crypto.as_ref(), &client_init)
        .expect("handle_client_init should succeed without cookie config");

    assert_eq!(server_accept.client_random, client_init.client_random);

    // Decapsulation should have occurred
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        1,
        "Decapsulation should occur when cookie config is None"
    );
}

/// Test: Cookie too large is rejected
#[test]
fn m6_oversized_cookie_rejected() {
    let ctx = create_test_context_with_cookie();

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Generate ClientInit
    let mut client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    // Set oversized cookie (larger than MAX_COOKIE_SIZE)
    client_init.cookie = vec![0xAB; 100]; // MAX_COOKIE_SIZE is 64

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            ctx.time_secs,
        )
        .expect("handle should succeed");

    // Should return cookie challenge (oversized = treated as invalid)
    match response {
        ServerHandshakeResponse::CookieChallenge(_) => {
            // Expected
        }
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            panic!("Oversized cookie should be rejected");
        }
    }

    // Verify NO decapsulation
    assert_eq!(
        ctx.decaps_count.load(Ordering::SeqCst),
        0,
        "No decapsulation should occur with oversized cookie"
    );
}

/// Test: Clock skew tolerance works within window
#[test]
fn m6_clock_skew_tolerance() {
    let cookie_secret = vec![0x42u8; 32];
    let cookie_config = CookieConfig::with_params(cookie_secret, 30, 1); // 30s buckets, 1 skew
    let ctx = create_test_context_with_cookie_config(Some(cookie_config));

    let mut client = ClientHandshake::new(ctx.client_cfg.clone(), ctx.client_random);
    let mut server = ServerHandshake::new(ctx.server_cfg.clone(), ctx.server_random);

    // Get cookie at time 1000 (bucket 33)
    let client_init = client
        .start(ctx.validator_id, &ctx.server_kem_pk)
        .expect("client start should succeed");

    let gen_time = 1000u64;
    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init,
            &ctx.client_ip,
            gen_time,
        )
        .expect("handle should succeed");

    let server_cookie = match response {
        ServerHandshakeResponse::CookieChallenge(sc) => sc,
        _ => panic!("Expected cookie challenge"),
    };

    // Use cookie at time 1020 (bucket 34 = one bucket later, within skew)
    let mut client_init_with_cookie = client_init.clone();
    client_init_with_cookie.cookie = server_cookie.cookie;

    let verify_time = 1020u64;

    let response = server
        .handle_client_init_with_cookie(
            ctx.server_cfg.crypto.as_ref(),
            &client_init_with_cookie,
            &ctx.client_ip,
            verify_time,
        )
        .expect("handle should succeed");

    // Should complete handshake within clock skew window
    match response {
        ServerHandshakeResponse::HandshakeComplete(_, _) => {
            // Expected
        }
        ServerHandshakeResponse::CookieChallenge(_) => {
            panic!("Cookie within clock skew window should be accepted");
        }
    }

    // Verify decapsulation occurred
    assert_eq!(ctx.decaps_count.load(Ordering::SeqCst), 1);
}