//! Tests for ML-KEM-768 Key Encapsulation Mechanism backend.
//!
//! These tests verify the ML-KEM-768 post-quantum KEM backend:
//! - Keypair generation produces correct sizes
//! - Encapsulation/decapsulation roundtrip yields identical shared secrets
//! - Encapsulation is randomized (different ciphertexts for same pk)
//! - Corrupted ciphertext handling (implicit rejection)
//! - Backend integrates with KemSuite trait

use qbind_crypto::kem::KemSuite;
use qbind_crypto::ml_kem768::{
    MlKem768Backend, KEM_SUITE_ML_KEM_768, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_SECRET_KEY_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
};
use qbind_crypto::CryptoError;

// ============================================================================
// Key and ciphertext size tests
// ============================================================================

/// Test that ML-KEM-768 key and ciphertext sizes match FIPS 203 spec.
#[test]
fn ml_kem_768_sizes_match_spec() {
    // Per FIPS 203 ML-KEM-768:
    // - Public key (encapsulation key): 1,184 bytes
    // - Secret key (decapsulation key): 2,400 bytes
    // - Ciphertext: 1,088 bytes
    // - Shared secret: 32 bytes
    assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
    assert_eq!(ML_KEM_768_SECRET_KEY_SIZE, 2400);
    assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, 1088);
    assert_eq!(ML_KEM_768_SHARED_SECRET_SIZE, 32);
}

/// Test that generated keypairs have correct sizes.
#[test]
fn keygen_produces_correct_sizes() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    assert_eq!(
        pk.len(),
        ML_KEM_768_PUBLIC_KEY_SIZE,
        "public key size mismatch"
    );
    assert_eq!(
        sk.len(),
        ML_KEM_768_SECRET_KEY_SIZE,
        "secret key size mismatch"
    );
}

/// Test that ciphertexts have correct size.
#[test]
fn ciphertext_has_correct_size() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();
    let (ct, _) = backend.encaps(&pk).expect("encapsulation should succeed");
    assert_eq!(
        ct.len(),
        ML_KEM_768_CIPHERTEXT_SIZE,
        "ciphertext size mismatch"
    );
}

/// Test that shared secrets have correct size.
#[test]
fn shared_secret_has_correct_size() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();
    let (_, ss) = backend.encaps(&pk).expect("encapsulation should succeed");
    assert_eq!(
        ss.len(),
        ML_KEM_768_SHARED_SECRET_SIZE,
        "shared secret size mismatch"
    );
}

// ============================================================================
// Encapsulation and decapsulation roundtrip tests
// ============================================================================

/// Test basic encaps/decaps roundtrip.
#[test]
fn encaps_decaps_roundtrip() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let (ct, ss_encaps) = backend.encaps(&pk).expect("encapsulation should succeed");
    let ss_decaps = backend
        .decaps(&sk, &ct)
        .expect("decapsulation should succeed");

    assert_eq!(ss_encaps, ss_decaps, "shared secrets must match");
}

/// Test multiple independent encaps/decaps operations.
#[test]
fn multiple_operations_independent() {
    let (pk1, sk1) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let (pk2, sk2) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    // Encapsulate to each public key
    let (ct1, ss1_encaps) = backend.encaps(&pk1).expect("encapsulation should succeed");
    let (ct2, ss2_encaps) = backend.encaps(&pk2).expect("encapsulation should succeed");

    // Decapsulate with corresponding secret keys
    let ss1_decaps = backend
        .decaps(&sk1, &ct1)
        .expect("decapsulation should succeed");
    let ss2_decaps = backend
        .decaps(&sk2, &ct2)
        .expect("decapsulation should succeed");

    // Verify roundtrips
    assert_eq!(ss1_encaps, ss1_decaps);
    assert_eq!(ss2_encaps, ss2_decaps);

    // Shared secrets should differ (different encapsulations)
    assert_ne!(ss1_encaps, ss2_encaps);
}

/// Test that many roundtrips all succeed.
#[test]
fn many_roundtrips() {
    let backend = MlKem768Backend::new();

    for _ in 0..10 {
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
        let (ct, ss_encaps) = backend.encaps(&pk).expect("encapsulation should succeed");
        let ss_decaps = backend
            .decaps(&sk, &ct)
            .expect("decapsulation should succeed");
        assert_eq!(ss_encaps, ss_decaps);
    }
}

// ============================================================================
// Randomization tests
// ============================================================================

/// Test that encapsulation is randomized (different ciphertexts for same pk).
#[test]
fn encapsulation_is_randomized() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let (ct1, ss1) = backend
        .encaps(&pk)
        .expect("first encapsulation should succeed");
    let (ct2, ss2) = backend
        .encaps(&pk)
        .expect("second encapsulation should succeed");

    // Ciphertexts must differ (randomized)
    assert_ne!(ct1, ct2, "ciphertexts should differ for randomized KEM");

    // Shared secrets should also differ
    assert_ne!(
        ss1, ss2,
        "shared secrets should differ for different encapsulations"
    );

    // But both should decapsulate correctly
    let ss1_decaps = backend
        .decaps(&sk, &ct1)
        .expect("decapsulation should succeed");
    let ss2_decaps = backend
        .decaps(&sk, &ct2)
        .expect("decapsulation should succeed");

    assert_eq!(ss1, ss1_decaps);
    assert_eq!(ss2, ss2_decaps);
}

// ============================================================================
// Implicit rejection tests (corrupted ciphertext)
// ============================================================================

/// Test that decapsulation with corrupted ciphertext yields different secret.
/// This tests the implicit rejection property of ML-KEM.
#[test]
fn decaps_corrupted_ciphertext_yields_different_secret() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let (mut ct, ss_original) = backend.encaps(&pk).expect("encapsulation should succeed");

    // Corrupt the ciphertext (flip first byte)
    ct[0] ^= 0xff;

    // Decapsulation should still succeed (implicit rejection)
    // but produce a different shared secret
    let ss_corrupted = backend
        .decaps(&sk, &ct)
        .expect("decapsulation should not fail");

    assert_ne!(
        ss_original, ss_corrupted,
        "corrupted ciphertext should yield different shared secret"
    );
}

/// Test that corrupting different bytes yields different secrets.
#[test]
fn decaps_various_corruptions_yield_different_secrets() {
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let (ct, ss_original) = backend.encaps(&pk).expect("encapsulation should succeed");

    // Try corrupting at different positions
    for pos in [0, ct.len() / 4, ct.len() / 2, ct.len() - 1] {
        let mut corrupted_ct = ct.clone();
        corrupted_ct[pos] ^= 0xff;

        let ss_corrupted = backend
            .decaps(&sk, &corrupted_ct)
            .expect("decapsulation should succeed with implicit rejection");

        assert_ne!(
            ss_original, ss_corrupted,
            "corruption at position {} should yield different shared secret",
            pos
        );
    }
}

// ============================================================================
// Wrong key tests
// ============================================================================

/// Test that decapsulation with wrong secret key yields different secret.
#[test]
fn decaps_wrong_key_yields_different_secret() {
    let (pk, _sk1) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let (_, sk2) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let (ct, ss_encaps) = backend.encaps(&pk).expect("encapsulation should succeed");

    // Decapsulate with wrong key - should succeed but yield different secret
    let ss_wrong = backend
        .decaps(&sk2, &ct)
        .expect("decapsulation should succeed");

    assert_ne!(
        ss_encaps, ss_wrong,
        "wrong key should yield different shared secret"
    );
}

// ============================================================================
// Malformed input tests
// ============================================================================

/// Test that malformed (short) public key is rejected.
#[test]
fn encaps_rejects_short_public_key() {
    let backend = MlKem768Backend::new();
    let short_pk = vec![0u8; 100];

    let result = backend.encaps(&short_pk);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "short public key should be rejected"
    );
}

/// Test that malformed (long) public key is rejected.
#[test]
fn encaps_rejects_long_public_key() {
    let backend = MlKem768Backend::new();
    let long_pk = vec![0u8; ML_KEM_768_PUBLIC_KEY_SIZE + 100];

    let result = backend.encaps(&long_pk);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "long public key should be rejected"
    );
}

/// Test that empty public key is rejected.
#[test]
fn encaps_rejects_empty_public_key() {
    let backend = MlKem768Backend::new();
    let empty_pk = vec![];

    let result = backend.encaps(&empty_pk);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "empty public key should be rejected"
    );
}

/// Test that malformed (short) secret key is rejected.
#[test]
fn decaps_rejects_short_secret_key() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();
    let (ct, _) = backend.encaps(&pk).expect("encapsulation should succeed");

    let short_sk = vec![0u8; 100];

    let result = backend.decaps(&short_sk, &ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "short secret key should be rejected"
    );
}

/// Test that malformed (long) secret key is rejected.
#[test]
fn decaps_rejects_long_secret_key() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();
    let (ct, _) = backend.encaps(&pk).expect("encapsulation should succeed");

    let long_sk = vec![0u8; ML_KEM_768_SECRET_KEY_SIZE + 100];

    let result = backend.decaps(&long_sk, &ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "long secret key should be rejected"
    );
}

/// Test that empty secret key is rejected.
#[test]
fn decaps_rejects_empty_secret_key() {
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();
    let (ct, _) = backend.encaps(&pk).expect("encapsulation should succeed");

    let empty_sk = vec![];

    let result = backend.decaps(&empty_sk, &ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "empty secret key should be rejected"
    );
}

/// Test that malformed (short) ciphertext is rejected.
#[test]
fn decaps_rejects_short_ciphertext() {
    let (_, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let short_ct = vec![0u8; 100];

    let result = backend.decaps(&sk, &short_ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertext)),
        "short ciphertext should be rejected"
    );
}

/// Test that malformed (long) ciphertext is rejected.
#[test]
fn decaps_rejects_long_ciphertext() {
    let (_, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let long_ct = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE + 100];

    let result = backend.decaps(&sk, &long_ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertext)),
        "long ciphertext should be rejected"
    );
}

/// Test that empty ciphertext is rejected.
#[test]
fn decaps_rejects_empty_ciphertext() {
    let (_, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = MlKem768Backend::new();

    let empty_ct = vec![];

    let result = backend.decaps(&sk, &empty_ct);
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertext)),
        "empty ciphertext should be rejected"
    );
}

// ============================================================================
// KemSuite trait tests
// ============================================================================

/// Test KemSuite trait implementation.
#[test]
fn kem_suite_trait_implementation() {
    let backend = MlKem768Backend::new();

    assert_eq!(backend.suite_id(), KEM_SUITE_ML_KEM_768);
    assert_eq!(backend.public_key_len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    assert_eq!(backend.secret_key_len(), ML_KEM_768_SECRET_KEY_SIZE);
    assert_eq!(backend.ciphertext_len(), ML_KEM_768_CIPHERTEXT_SIZE);
    assert_eq!(backend.shared_secret_len(), ML_KEM_768_SHARED_SECRET_SIZE);
}

/// Test that suite_id is 100.
#[test]
fn suite_id_is_100() {
    assert_eq!(KEM_SUITE_ML_KEM_768, 100);
}

// ============================================================================
// Backend properties tests
// ============================================================================

/// Test that backend is thread-safe (Send + Sync).
#[test]
fn backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MlKem768Backend>();
}

/// Test that backend can be used from multiple threads.
#[test]
fn backend_multithreaded() {
    use std::sync::Arc;
    use std::thread;

    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let backend = Arc::new(MlKem768Backend::new());
    let pk = Arc::new(pk);
    let sk = Arc::new(sk);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let backend = backend.clone();
            let pk = pk.clone();
            let sk = sk.clone();
            thread::spawn(move || {
                for _ in 0..10 {
                    let (ct, ss_encaps) = backend.encaps(&pk).expect("encaps should succeed");
                    let ss_decaps = backend.decaps(&sk, &ct).expect("decaps should succeed");
                    assert_eq!(ss_encaps, ss_decaps);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}

/// Test Debug implementation.
#[test]
fn backend_debug() {
    let backend = MlKem768Backend::new();
    let debug_str = format!("{:?}", backend);
    assert!(debug_str.contains("MlKem768Backend"));
}

/// Test Clone implementation.
#[test]
#[allow(clippy::clone_on_copy)]
fn backend_clone() {
    let backend1 = MlKem768Backend::new();
    let backend2 = backend1.clone();

    // Both should work identically
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let (ct, ss1) = backend1.encaps(&pk).expect("encaps should succeed");
    let ss2 = backend2.decaps(&sk, &ct).expect("decaps should succeed");
    assert_eq!(ss1, ss2);
}

/// Test Default implementation.
#[test]
fn backend_default() {
    let backend: MlKem768Backend = Default::default();
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let (ct, ss1) = backend.encaps(&pk).expect("encaps should succeed");
    let ss2 = backend.decaps(&sk, &ct).expect("decaps should succeed");
    assert_eq!(ss1, ss2);
}

/// Test Copy implementation.
#[test]
fn backend_copy() {
    let backend1 = MlKem768Backend::new();
    let backend2: MlKem768Backend = backend1; // Copy

    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");
    let (ct, ss1) = backend1.encaps(&pk).expect("encaps should succeed");
    let ss2 = backend2.decaps(&sk, &ct).expect("decaps should succeed");
    assert_eq!(ss1, ss2);
}
