//! T141: AEAD Key Hygiene Tests
//!
//! This module tests the zeroization behavior of key wrapper types introduced
//! in T141 to harden the PQC transport against key/secret leakage.
//!
//! # Test Categories
//!
//! 1. **Key Wrapper Tests**: Verify that `AeadKeyMaterial` and `SharedSecret`
//!    correctly zeroize their contents when `zeroize()` is called.
//!
//! 2. **Structural Drop Tests**: Verify that key material is held in the
//!    expected structs and that dropping those structs triggers zeroization.
//!
//! # Limitations
//!
//! We cannot reliably read freed memory in Rust to verify zeroization after
//! drop. Instead, we:
//! - Test explicit `zeroize()` calls and verify contents are zeroed
//! - Rely on the `ZeroizeOnDrop` derive macro for drop-based zeroization
//! - Document these limitations in the audit doc

use qbind_net::{AeadKeyMaterial, KemPrivateKey, SessionKeys, SharedSecret};
use zeroize::Zeroize;

// ============================================================================
// Part 1: AeadKeyMaterial Tests
// ============================================================================

#[test]
fn aead_key_material_explicit_zeroize() {
    // Create key with non-zero bytes
    let non_zero_key = vec![0xAB; 32];
    let mut key = AeadKeyMaterial::from_vec(non_zero_key);

    // Verify key is non-zero before zeroize
    assert!(
        key.as_bytes().iter().any(|&b| b != 0),
        "key should be non-zero initially"
    );

    // Explicitly zeroize
    key.zeroize();

    // Verify all bytes are now zero
    assert!(
        key.as_bytes().iter().all(|&b| b == 0),
        "all key bytes should be zero after zeroize()"
    );
}

#[test]
fn aead_key_material_from_slice() {
    let source = [0x42u8; 16];
    let key = AeadKeyMaterial::from_slice(&source);

    // Verify the key contains the expected bytes
    assert_eq!(key.as_bytes(), &source);
    assert_eq!(key.len(), 16);
    assert!(!key.is_empty());
}

#[test]
fn aead_key_material_from_vec() {
    let source = vec![0x37u8; 24];
    let expected = source.clone();
    let key = AeadKeyMaterial::from_vec(source);

    // Verify the key contains the expected bytes
    assert_eq!(key.as_bytes(), expected.as_slice());
    assert_eq!(key.len(), 24);
}

#[test]
fn aead_key_material_debug_does_not_leak() {
    let key = AeadKeyMaterial::from_vec(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let debug_str = format!("{:?}", key);

    // Verify the debug output does not contain actual key bytes in hex format
    // We check for specific hex patterns that would indicate key material leakage
    assert!(!debug_str.contains("0xDE") && !debug_str.contains("0xde"));
    assert!(!debug_str.contains("0xAD") && !debug_str.contains("0xad"));
    assert!(!debug_str.contains("0xBE") && !debug_str.contains("0xbe"));
    assert!(!debug_str.contains("0xEF") && !debug_str.contains("0xef"));
    // Also check for array-style hex output [222, 173, 190, 239]
    assert!(!debug_str.contains("222"));
    assert!(!debug_str.contains("173"));
    assert!(!debug_str.contains("190"));
    assert!(!debug_str.contains("239"));

    // Verify it contains the redacted marker
    assert!(debug_str.contains("redacted"));
}

// ============================================================================
// Part 2: SharedSecret Tests
// ============================================================================

#[test]
fn shared_secret_explicit_zeroize() {
    // Create secret with non-zero bytes
    let non_zero_secret = vec![0xCD; 32];
    let mut secret = SharedSecret::new(non_zero_secret);

    // Verify secret is non-zero before zeroize
    assert!(
        secret.as_bytes().iter().any(|&b| b != 0),
        "secret should be non-zero initially"
    );

    // Explicitly zeroize
    secret.zeroize();

    // Verify all bytes are now zero
    assert!(
        secret.as_bytes().iter().all(|&b| b == 0),
        "all secret bytes should be zero after zeroize()"
    );
}

#[test]
fn shared_secret_takes_ownership() {
    let source = vec![0x99u8; 32];
    let expected = source.clone();
    let secret = SharedSecret::new(source);
    // source is moved, cannot be used

    // Verify the secret contains the expected bytes
    assert_eq!(secret.as_bytes(), expected.as_slice());
    assert_eq!(secret.len(), 32);
    assert!(!secret.is_empty());
}

#[test]
fn shared_secret_debug_does_not_leak() {
    let secret = SharedSecret::new(vec![0xCA, 0xFE, 0xBA, 0xBE]);
    let debug_str = format!("{:?}", secret);

    // Verify the debug output does not contain actual secret bytes
    assert!(!debug_str.contains("ca") && !debug_str.contains("CA"));
    assert!(!debug_str.contains("fe") && !debug_str.contains("FE"));
    assert!(!debug_str.contains("ba") && !debug_str.contains("BA"));
    assert!(!debug_str.contains("be") && !debug_str.contains("BE"));

    // Verify it contains the redacted marker
    assert!(debug_str.contains("redacted"));
}

// ============================================================================
// Part 3: KemPrivateKey Tests (T142)
// ============================================================================

#[test]
fn kem_private_key_explicit_zeroize() {
    // Create key with non-zero bytes
    let non_zero_key = vec![0xDE; 2400]; // ML-KEM-768 secret key size
    let mut key = KemPrivateKey::new(non_zero_key);

    // Verify key is non-zero before zeroize
    assert!(
        key.as_bytes().iter().any(|&b| b != 0),
        "key should be non-zero initially"
    );

    // Explicitly zeroize
    key.zeroize();

    // Verify all bytes are now zero
    assert!(
        key.as_bytes().iter().all(|&b| b == 0),
        "all key bytes should be zero after zeroize()"
    );
}

#[test]
fn kem_private_key_takes_ownership() {
    let source = vec![0x99u8; 2400];
    let expected = source.clone();
    let key = KemPrivateKey::new(source);
    // source is moved, cannot be used

    // Verify the key contains the expected bytes
    assert_eq!(key.as_bytes(), expected.as_slice());
    assert_eq!(key.len(), 2400);
    assert!(!key.is_empty());
}

#[test]
fn kem_private_key_debug_does_not_leak() {
    let key = KemPrivateKey::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let debug_str = format!("{:?}", key);

    // Verify the debug output does not contain actual key bytes in hex format
    assert!(!debug_str.contains("0xDE") && !debug_str.contains("0xde"));
    assert!(!debug_str.contains("0xAD") && !debug_str.contains("0xad"));
    assert!(!debug_str.contains("0xBE") && !debug_str.contains("0xbe"));
    assert!(!debug_str.contains("0xEF") && !debug_str.contains("0xef"));
    // Also check for array-style decimal output [222, 173, 190, 239]
    assert!(!debug_str.contains("222"));
    assert!(!debug_str.contains("173"));
    assert!(!debug_str.contains("190"));
    assert!(!debug_str.contains("239"));

    // Verify it contains the redacted marker
    assert!(debug_str.contains("redacted"));
}

#[test]
fn kem_private_key_is_not_clone() {
    // This test is a compile-time test - KemPrivateKey should not implement Clone.
    // The test simply documents this property. If Clone were implemented,
    // this comment would be wrong and should be updated.
    //
    // Compile-time test: The following would fail to compile if uncommented
    // because KemPrivateKey does not implement Clone:
    //
    // let key = KemPrivateKey::new(vec![0u8; 32]);
    // let _cloned = key.clone();  // Would fail: Clone not implemented
}

#[test]
fn kem_private_key_zeroize_is_idempotent() {
    let mut key = KemPrivateKey::new(vec![0xFF; 2400]);

    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));

    // Second zeroize should be safe and maintain zero state
    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn empty_kem_private_key_zeroize_is_safe() {
    let mut key = KemPrivateKey::new(vec![]);
    assert!(key.is_empty());

    // Should not panic
    key.zeroize();
    assert!(key.is_empty());
}

// ============================================================================
// Part 4: SessionKeys Tests
// ============================================================================

#[test]
fn session_keys_derive_produces_non_zero_keys() {
    let keys = SessionKeys::derive(
        b"test_shared_secret_32_bytes_long",
        b"test_transcript_hash",
        0x01,
        0x02,
        32,
    );

    // Verify keys are non-zero (would be astronomically unlikely for proper HKDF output)
    assert!(
        keys.k_c2s.as_bytes().iter().any(|&b| b != 0),
        "k_c2s should be non-zero"
    );
    assert!(
        keys.k_s2c.as_bytes().iter().any(|&b| b != 0),
        "k_s2c should be non-zero"
    );
}

#[test]
fn session_keys_debug_does_not_leak() {
    let keys = SessionKeys::derive(
        b"sensitive_shared_secret_here",
        b"transcript_hash",
        0x01,
        0x02,
        32,
    );

    let debug_str = format!("{:?}", keys);

    // Verify the debug output does not expose key material
    // The debug should show "<redacted>" for sensitive fields
    assert!(
        debug_str.contains("redacted"),
        "debug should show redacted for keys"
    );

    // Verify it shows the session_id (which is public)
    assert!(
        debug_str.contains("session_id"),
        "debug should show session_id field"
    );
}

#[test]
fn session_keys_different_inputs_produce_different_keys() {
    let keys1 = SessionKeys::derive(b"secret_1", b"transcript", 0x01, 0x02, 32);
    let keys2 = SessionKeys::derive(b"secret_2", b"transcript", 0x01, 0x02, 32);

    // Different secrets should produce different keys
    assert_ne!(keys1.k_c2s.as_bytes(), keys2.k_c2s.as_bytes());
    assert_ne!(keys1.k_s2c.as_bytes(), keys2.k_s2c.as_bytes());
    assert_ne!(keys1.session_id, keys2.session_id);
}

// ============================================================================
// Part 5: Structural Tests (verifying key placement)
// ============================================================================

/// This test verifies that SessionKeys holds AeadKeyMaterial instances,
/// not raw Vec<u8>. This is a compile-time guarantee via the type system,
/// but we test it here for documentation purposes.
#[test]
fn session_keys_contains_aead_key_material() {
    let keys = SessionKeys::derive(b"secret", b"transcript", 0x01, 0x02, 32);

    // These calls verify the types at compile time
    let _c2s_bytes: &[u8] = keys.k_c2s.as_bytes();
    let _s2c_bytes: &[u8] = keys.k_s2c.as_bytes();

    // Verify key lengths
    assert_eq!(keys.k_c2s.len(), 32);
    assert_eq!(keys.k_s2c.len(), 32);
    assert_eq!(keys.key_len, 32);
}

/// Test that deriving keys with variable key lengths works correctly.
/// This is important for test suites that use smaller key sizes.
#[test]
fn session_keys_supports_variable_key_lengths() {
    for key_len in [1, 8, 16, 24, 32] {
        let keys = SessionKeys::derive(b"secret", b"transcript", 0x01, 0x02, key_len);

        assert_eq!(keys.k_c2s.len(), key_len);
        assert_eq!(keys.k_s2c.len(), key_len);
        assert_eq!(keys.key_len, key_len);
    }
}

// ============================================================================
// Part 6: Zeroization Verification Tests
// ============================================================================

/// Test that verifies zeroize() can be called multiple times safely.
#[test]
fn zeroize_is_idempotent() {
    let mut key = AeadKeyMaterial::from_vec(vec![0xFF; 32]);

    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));

    // Second zeroize should be safe and maintain zero state
    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));

    // Third time for good measure
    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));
}

/// Test that verifies empty keys are handled correctly.
#[test]
fn empty_key_zeroize_is_safe() {
    let mut key = AeadKeyMaterial::from_vec(vec![]);
    assert!(key.is_empty());

    // Should not panic
    key.zeroize();
    assert!(key.is_empty());
}

/// Test that verifies empty secrets are handled correctly.
#[test]
fn empty_secret_zeroize_is_safe() {
    let mut secret = SharedSecret::new(vec![]);
    assert!(secret.is_empty());

    // Should not panic
    secret.zeroize();
    assert!(secret.is_empty());
}

// ============================================================================
// Part 7: Documentation Tests
// ============================================================================

/// This test documents the expected behavior of ZeroizeOnDrop.
///
/// We cannot directly test that memory is zeroed after drop because:
/// 1. Reading freed memory is undefined behavior in Rust
/// 2. The compiler may optimize away reads after drop
/// 3. The allocator may reuse or overwrite the memory
///
/// Instead, we rely on:
/// 1. The `zeroize` crate's well-tested implementation
/// 2. The `ZeroizeOnDrop` derive macro
/// 3. Manual code review (see T141_PQC_AEAD_KEY_HYGIENE_AUDIT.md)
#[test]
fn zeroize_on_drop_documentation() {
    // Create a key and drop it
    let key = AeadKeyMaterial::from_vec(vec![0xAA; 32]);
    drop(key);
    // After this point, the memory should be zeroed by ZeroizeOnDrop,
    // but we cannot verify this programmatically.

    // Create a secret and drop it
    let secret = SharedSecret::new(vec![0xBB; 32]);
    drop(secret);
    // Same limitation applies.

    // This test passes by not panicking.
    // The actual zeroization is verified by the zeroize crate's test suite.
}
