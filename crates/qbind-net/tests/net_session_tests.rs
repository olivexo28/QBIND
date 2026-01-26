use qbind_crypto::{AeadSuite, CryptoError, StaticCryptoProvider};
use qbind_net::{AeadSession, SessionKeys};
use std::sync::Arc;

// Helper to derive a pair of session keys with the same inputs.
// Since SessionKeys is consumed by AeadSession::new, we need to derive fresh keys
// for each session.
fn derive_test_keys(
    shared_secret: &[u8],
    transcript_hash: &[u8],
    kem_suite_id: u8,
    aead_suite_id: u8,
    key_len: usize,
) -> SessionKeys {
    SessionKeys::derive(
        shared_secret,
        transcript_hash,
        kem_suite_id,
        aead_suite_id,
        key_len,
    )
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
        1
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
        // Simple XOR with first byte of key, then append tag
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        // Tag is just XOR of all ciphertext bytes
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

fn make_test_provider(aead_suite_id: u8) -> StaticCryptoProvider {
    StaticCryptoProvider::new().with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
}

#[test]
fn session_keys_derive_is_deterministic() {
    let shared_secret = b"test_shared_secret";
    let transcript_hash = b"test_transcript_hash";
    let kem_suite_id = 0x01;
    let aead_suite_id = 0x02;
    let key_len = 16;

    let keys1 = SessionKeys::derive(
        shared_secret,
        transcript_hash,
        kem_suite_id,
        aead_suite_id,
        key_len,
    );

    let keys2 = SessionKeys::derive(
        shared_secret,
        transcript_hash,
        kem_suite_id,
        aead_suite_id,
        key_len,
    );

    // Should be deterministic - session_id is public and comparable
    assert_eq!(keys1.session_id, keys2.session_id);
    // Key comparison via as_bytes() for testing purposes only.
    // Note: AeadKeyMaterial intentionally doesn't implement PartialEq to avoid timing attacks.
    assert_eq!(keys1.k_c2s.as_bytes(), keys2.k_c2s.as_bytes());
    assert_eq!(keys1.k_s2c.as_bytes(), keys2.k_s2c.as_bytes());
    assert_eq!(keys1.key_len, keys2.key_len);
    assert_eq!(keys1.key_len, key_len);
}

#[test]
fn session_keys_derive_different_for_different_inputs() {
    let shared_secret1 = b"test_shared_secret_1";
    let shared_secret2 = b"test_shared_secret_2";
    let transcript_hash = b"test_transcript_hash";
    let kem_suite_id = 0x01;
    let aead_suite_id = 0x02;
    let key_len = 16;

    let keys1 = SessionKeys::derive(
        shared_secret1,
        transcript_hash,
        kem_suite_id,
        aead_suite_id,
        key_len,
    );

    let keys2 = SessionKeys::derive(
        shared_secret2,
        transcript_hash,
        kem_suite_id,
        aead_suite_id,
        key_len,
    );

    // Should be different for different inputs
    assert_ne!(keys1.session_id, keys2.session_id);
    // Key comparison via as_bytes() for testing purposes only.
    assert_ne!(keys1.k_c2s.as_bytes(), keys2.k_c2s.as_bytes());
    assert_ne!(keys1.k_s2c.as_bytes(), keys2.k_s2c.as_bytes());
}

#[test]
fn aead_session_roundtrip_c2s() {
    let aead_suite_id = 0xAA;
    let provider = make_test_provider(aead_suite_id);

    // Note: SessionKeys is consumed by AeadSession::new (T141 design),
    // so we derive separate keys for client and server with identical inputs.
    let client_keys = derive_test_keys(
        b"shared_secret",
        b"transcript",
        0x01,
        aead_suite_id,
        1, // key_len must be 1 for DummyAead
    );
    let server_keys = derive_test_keys(b"shared_secret", b"transcript", 0x01, aead_suite_id, 1);

    // Client creates session
    let mut client_session = AeadSession::new(&provider, aead_suite_id, client_keys)
        .expect("client session creation should succeed");

    // Server creates session with same keys (derived identically)
    let mut server_session = AeadSession::new(&provider, aead_suite_id, server_keys)
        .expect("server session creation should succeed");

    // Test c2s direction
    let plaintext = b"Hello from client to server!";
    let aad = b"associated data";

    let ciphertext = client_session
        .c2s
        .seal(aad, plaintext)
        .expect("seal should succeed");

    let decrypted = server_session
        .c2s
        .open(aad, &ciphertext)
        .expect("open should succeed");

    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn aead_session_roundtrip_s2c() {
    let aead_suite_id = 0xBB;
    let provider = make_test_provider(aead_suite_id);

    let client_keys = derive_test_keys(
        b"shared_secret",
        b"transcript",
        0x01,
        aead_suite_id,
        1, // key_len must be 1 for DummyAead
    );
    let server_keys = derive_test_keys(b"shared_secret", b"transcript", 0x01, aead_suite_id, 1);

    // Client creates session
    let mut client_session = AeadSession::new(&provider, aead_suite_id, client_keys)
        .expect("client session creation should succeed");

    // Server creates session with same keys (derived identically)
    let mut server_session = AeadSession::new(&provider, aead_suite_id, server_keys)
        .expect("server session creation should succeed");

    // Test s2c direction
    let plaintext = b"Hello from server to client!";
    let aad = b"associated data";

    let ciphertext = server_session
        .s2c
        .seal(aad, plaintext)
        .expect("seal should succeed");

    let decrypted = client_session
        .s2c
        .open(aad, &ciphertext)
        .expect("open should succeed");

    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn aead_session_counters_advance_independently() {
    let aead_suite_id = 0xCC;
    let provider = make_test_provider(aead_suite_id);

    let keys = derive_test_keys(b"shared_secret", b"transcript", 0x01, aead_suite_id, 1);

    let mut session =
        AeadSession::new(&provider, aead_suite_id, keys).expect("session creation should succeed");

    // Seal multiple messages in c2s direction
    for _ in 0..5 {
        session.c2s.seal(b"aad", b"plaintext").expect("seal c2s");
    }

    // Seal multiple messages in s2c direction (independent counter)
    for _ in 0..3 {
        session.s2c.seal(b"aad", b"plaintext").expect("seal s2c");
    }

    // Should not panic and counters should be independent
    // c2s counter should be at 5, s2c counter should be at 3
    // We can verify this by sealing more messages
    session
        .c2s
        .seal(b"aad", b"more plaintext")
        .expect("seal c2s again");
    session
        .s2c
        .seal(b"aad", b"more plaintext")
        .expect("seal s2c again");
}

#[test]
fn unsupported_suite_returns_error() {
    let provider = make_test_provider(0xAA);

    let keys = derive_test_keys(
        b"shared_secret",
        b"transcript",
        0x01,
        0xBB, // Different suite ID
        1,
    );

    // Try to create session with non-existent suite
    let result = AeadSession::new(&provider, 0xBB, keys);
    assert!(result.is_err());
}
