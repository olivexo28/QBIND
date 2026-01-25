//! T142: Node Key Hygiene Tests
//!
//! This module tests the zeroization behavior of validator signing key wrapper
//! types introduced in T142 to harden node keys against leakage.
//!
//! # Test Categories
//!
//! 1. **ValidatorSigningKey Tests**: Verify that `ValidatorSigningKey` correctly
//!    zeroizes its contents when `zeroize()` is called or when dropped.
//!
//! 2. **Signing Tests**: Verify that signing works through the wrapper type.
//!
//! 3. **Debug Redaction Tests**: Verify that debug output does not leak key bytes.
//!
//! # Limitations
//!
//! We cannot reliably read freed memory in Rust to verify zeroization after
//! drop. Instead, we:
//! - Test explicit `zeroize()` calls and verify contents are zeroed
//! - Rely on the `ZeroizeOnDrop` derive macro for drop-based zeroization
//! - Document these limitations in the audit doc

use cano_crypto::{
    ConsensusSigVerifier, MlDsa44Backend, ValidatorSigningKey, ML_DSA_44_SECRET_KEY_SIZE,
    ML_DSA_44_SIGNATURE_SIZE,
};
use zeroize::Zeroize;

// ============================================================================
// Part 1: ValidatorSigningKey Zeroization Tests
// ============================================================================

#[test]
fn validator_signing_key_explicit_zeroize() {
    // Create key with non-zero bytes
    let non_zero_key = vec![0xAB; ML_DSA_44_SECRET_KEY_SIZE];
    let mut key = ValidatorSigningKey::new(non_zero_key);

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
fn validator_signing_key_takes_ownership() {
    let source = vec![0x99u8; ML_DSA_44_SECRET_KEY_SIZE];
    let expected = source.clone();
    let key = ValidatorSigningKey::new(source);
    // source is moved, cannot be used

    // Verify the key contains the expected bytes
    assert_eq!(key.as_bytes(), expected.as_slice());
    assert_eq!(key.len(), ML_DSA_44_SECRET_KEY_SIZE);
    assert!(!key.is_empty());
}

#[test]
fn validator_signing_key_zeroize_is_idempotent() {
    let mut key = ValidatorSigningKey::new(vec![0xFF; ML_DSA_44_SECRET_KEY_SIZE]);

    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));

    // Second zeroize should be safe and maintain zero state
    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));

    // Third time for good measure
    key.zeroize();
    assert!(key.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn empty_validator_signing_key_zeroize_is_safe() {
    let mut key = ValidatorSigningKey::new(vec![]);
    assert!(key.is_empty());

    // Should not panic
    key.zeroize();
    assert!(key.is_empty());
}

// ============================================================================
// Part 2: Debug Redaction Tests
// ============================================================================

#[test]
fn validator_signing_key_debug_does_not_leak() {
    let key = ValidatorSigningKey::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
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
fn validator_signing_key_debug_shows_length() {
    let key = ValidatorSigningKey::new(vec![0u8; ML_DSA_44_SECRET_KEY_SIZE]);
    let debug_str = format!("{:?}", key);

    // The debug output should include the key length
    assert!(
        debug_str.contains(&format!("{}", ML_DSA_44_SECRET_KEY_SIZE)),
        "debug should show key length for diagnostic purposes"
    );
}

// ============================================================================
// Part 3: Signing Integration Tests
// ============================================================================

#[test]
fn validator_signing_key_sign_method_works() {
    // Generate a real keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keypair generation should succeed");

    // Wrap the secret key
    let signing_key = ValidatorSigningKey::new(sk);
    assert_eq!(signing_key.len(), ML_DSA_44_SECRET_KEY_SIZE);

    // Sign a message using the wrapper
    let message = b"test vote message for consensus";
    let signature = signing_key.sign(message).expect("signing should succeed");

    assert_eq!(signature.len(), ML_DSA_44_SIGNATURE_SIZE);

    // Verify the signature
    let backend = MlDsa44Backend::new();
    let result = backend.verify_vote(1, &pk, message, &signature);
    assert!(result.is_ok(), "signature should verify successfully");
}

#[test]
fn validator_signing_key_as_bytes_works_with_raw_sign() {
    // Generate a real keypair
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keypair generation should succeed");

    // Wrap the secret key
    let signing_key = ValidatorSigningKey::new(sk);

    // Sign using as_bytes() directly with MlDsa44Backend::sign
    let message = b"test proposal message";
    let signature =
        MlDsa44Backend::sign(signing_key.as_bytes(), message).expect("signing should succeed");

    // Verify the signature
    let backend = MlDsa44Backend::new();
    let result = backend.verify_proposal(1, &pk, message, &signature);
    assert!(result.is_ok(), "signature should verify successfully");
}

#[test]
fn validator_signing_key_different_messages_different_signatures() {
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keypair generation should succeed");

    let signing_key = ValidatorSigningKey::new(sk);

    let msg1 = b"message one";
    let msg2 = b"message two";

    let sig1 = signing_key.sign(msg1).expect("signing should succeed");
    let sig2 = signing_key.sign(msg2).expect("signing should succeed");

    // Different messages should produce different signatures
    assert_ne!(sig1, sig2);
}

// ============================================================================
// Part 4: Clone Prevention (Compile-Time) Test
// ============================================================================

/// This test documents that ValidatorSigningKey does not implement Clone.
///
/// This is a compile-time property enforced by not deriving Clone.
/// If Clone were accidentally added, this comment would need updating.
///
/// Uncomment the following to verify compilation fails:
/// ```compile_fail
/// use cano_crypto::ValidatorSigningKey;
/// let key = ValidatorSigningKey::new(vec![0u8; 32]);
/// let _cloned = key.clone();
/// ```
#[test]
fn validator_signing_key_is_not_clone_documentation() {
    // This test passes - it documents the security property.
    // ValidatorSigningKey does not implement Clone, preventing accidental
    // key duplication that could lead to multiple copies in memory.
}

// ============================================================================
// Part 5: Drop Behavior Documentation Test
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
/// 3. Manual code review (see T142_NODE_KEY_HYGIENE_AUDIT.md)
#[test]
fn zeroize_on_drop_documentation() {
    // Generate a real key
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keypair generation should succeed");

    // Create a signing key and drop it
    let key = ValidatorSigningKey::new(sk);
    drop(key);
    // After this point, the memory should be zeroed by ZeroizeOnDrop,
    // but we cannot verify this programmatically.

    // This test passes by not panicking.
    // The actual zeroization is verified by the zeroize crate's test suite.
}
