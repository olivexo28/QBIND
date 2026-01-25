//! Integration tests for T134: ML-KEM-768 multi-suite KEM behavior.
//!
//! These tests verify that:
//! - ML-KEM-768 backend can be registered with `StaticCryptoProvider`
//! - ML-KEM-768 and toy KEM suites are independent
//! - Suite selection by ID works correctly
//! - Cross-suite operations fail cleanly without panics

use std::sync::Arc;

use cano_crypto::{
    CryptoError, CryptoProvider, KemSuite, MlKem768Backend, StaticCryptoProvider,
    KEM_SUITE_ML_KEM_768, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_SECRET_KEY_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
};

// ============================================================================
// Test-only toy KEM implementation (for cross-suite testing)
// ============================================================================

/// A test-only "toy" KEM that produces deterministic shared secrets.
///
/// - encaps(pk) → (ct = pk || padding, ss = SHA3(pk))
/// - decaps(sk, ct) → ss derived from ct prefix
///
/// **NOT FOR PRODUCTION** - this is only for testing.
struct ToyKem {
    suite_id: u8,
}

impl ToyKem {
    fn new(suite_id: u8) -> Self {
        ToyKem { suite_id }
    }
}

impl KemSuite for ToyKem {
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
        32
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if pk.len() != self.public_key_len() {
            return Err(CryptoError::InvalidKey);
        }

        // Deterministic ciphertext and shared secret for testing
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"toy-kem-padding-");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        // Shared secret is just XOR of pk bytes with padding
        let mut ss = vec![0u8; self.shared_secret_len()];
        for (i, &b) in pk.iter().enumerate() {
            ss[i % self.shared_secret_len()] ^= b;
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ct.len() != self.ciphertext_len() {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Extract pk from ciphertext and derive same shared secret
        let pk = &ct[..self.public_key_len()];
        let mut ss = vec![0u8; self.shared_secret_len()];
        for (i, &b) in pk.iter().enumerate() {
            ss[i % self.shared_secret_len()] ^= b;
        }

        Ok(ss)
    }
}

// ============================================================================
// Suite ID constants
// ============================================================================

/// Toy KEM suite ID for testing
const TOY_KEM_SUITE_ID: u8 = 1;

// ============================================================================
// Provider registration tests
// ============================================================================

/// Test that ML-KEM-768 backend can be registered in StaticCryptoProvider.
#[test]
fn ml_kem_768_provider_registration() {
    let provider = StaticCryptoProvider::new().with_kem_suite(Arc::new(MlKem768Backend::new()));

    // Should be able to retrieve the suite
    let kem = provider.kem_suite(KEM_SUITE_ML_KEM_768);
    assert!(kem.is_some(), "ML-KEM-768 should be registered");

    let kem = kem.unwrap();
    assert_eq!(kem.suite_id(), KEM_SUITE_ML_KEM_768);
    assert_eq!(kem.public_key_len(), ML_KEM_768_PUBLIC_KEY_SIZE);
}

/// Test that both toy and ML-KEM-768 backends can coexist.
#[test]
fn toy_and_ml_kem_768_coexist() {
    let provider = StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(ToyKem::new(TOY_KEM_SUITE_ID)))
        .with_kem_suite(Arc::new(MlKem768Backend::new()));

    // Both should be retrievable
    assert!(provider.kem_suite(TOY_KEM_SUITE_ID).is_some());
    assert!(provider.kem_suite(KEM_SUITE_ML_KEM_768).is_some());

    // Unknown suite should not be found
    assert!(provider.kem_suite(255).is_none());
}

// ============================================================================
// Suite selection by ID tests
// ============================================================================

/// Test select by suite ID → perform KEM roundtrip for ML-KEM-768.
#[test]
fn select_by_suite_id_ml_kem_768_roundtrip() {
    let provider = StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(ToyKem::new(TOY_KEM_SUITE_ID)))
        .with_kem_suite(Arc::new(MlKem768Backend::new()));

    // Generate ML-KEM-768 keypair
    let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");

    // Look up ML-KEM-768 by suite ID
    let kem = provider
        .kem_suite(KEM_SUITE_ML_KEM_768)
        .expect("ML-KEM-768 should be registered");

    // Perform encapsulation
    let (ct, ss_encaps) = kem.encaps(&pk).expect("encapsulation should succeed");

    // Perform decapsulation
    let ss_decaps = kem.decaps(&sk, &ct).expect("decapsulation should succeed");

    // Shared secrets must match
    assert_eq!(ss_encaps, ss_decaps, "shared secrets must match");
}

/// Test select by suite ID → perform KEM roundtrip for toy KEM.
#[test]
fn select_by_suite_id_toy_kem_roundtrip() {
    let provider = StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(ToyKem::new(TOY_KEM_SUITE_ID)))
        .with_kem_suite(Arc::new(MlKem768Backend::new()));

    // Generate toy keypair
    let pk = vec![42u8; 32];
    let sk = vec![42u8; 32];

    // Look up toy KEM by suite ID
    let kem = provider
        .kem_suite(TOY_KEM_SUITE_ID)
        .expect("Toy KEM should be registered");

    // Perform encapsulation
    let (ct, ss_encaps) = kem.encaps(&pk).expect("encapsulation should succeed");

    // Perform decapsulation
    let ss_decaps = kem.decaps(&sk, &ct).expect("decapsulation should succeed");

    // Shared secrets must match
    assert_eq!(ss_encaps, ss_decaps, "shared secrets must match");
}

// ============================================================================
// Cross-suite isolation tests
// ============================================================================

/// Test that attempting to decapsulate ML-KEM ciphertext with toy KEM fails cleanly.
#[test]
fn ml_kem_ciphertext_with_toy_kem_fails_cleanly() {
    let ml_kem = MlKem768Backend::new();
    let toy_kem = ToyKem::new(TOY_KEM_SUITE_ID);

    // Generate ML-KEM-768 keypair
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");

    // Encapsulate with ML-KEM-768
    let (ct, _ss_ml_kem) = ml_kem.encaps(&pk).expect("encapsulation should succeed");

    // Try to decapsulate ML-KEM ciphertext with toy KEM
    // This should fail because ciphertext size doesn't match
    let toy_sk = vec![0u8; 32];
    let result = toy_kem.decaps(&toy_sk, &ct);

    // Should fail with InvalidCiphertext (size mismatch)
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertext)),
        "toy KEM should reject ML-KEM ciphertext: {:?}",
        result
    );
}

/// Test that attempting to decapsulate toy KEM ciphertext with ML-KEM-768 fails cleanly.
#[test]
fn toy_ciphertext_with_ml_kem_768_fails_cleanly() {
    let ml_kem = MlKem768Backend::new();
    let toy_kem = ToyKem::new(TOY_KEM_SUITE_ID);

    // Generate toy keypair and encapsulate
    let toy_pk = vec![42u8; 32];
    let (toy_ct, _ss_toy) = toy_kem
        .encaps(&toy_pk)
        .expect("encapsulation should succeed");

    // Generate ML-KEM-768 keypair
    let (_, ml_kem_sk) = MlKem768Backend::generate_keypair().expect("keygen should succeed");

    // Try to decapsulate toy ciphertext with ML-KEM-768
    // This should fail because ciphertext size doesn't match
    let result = ml_kem.decaps(&ml_kem_sk, &toy_ct);

    // Should fail with InvalidCiphertext (size mismatch)
    assert!(
        matches!(result, Err(CryptoError::InvalidCiphertext)),
        "ML-KEM-768 should reject toy ciphertext: {:?}",
        result
    );
}

/// Test that ML-KEM-768 public key used with toy KEM fails cleanly.
#[test]
fn ml_kem_public_key_with_toy_kem_fails_cleanly() {
    let toy_kem = ToyKem::new(TOY_KEM_SUITE_ID);

    // Generate ML-KEM-768 keypair
    let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen should succeed");

    // Try to encapsulate with ML-KEM public key using toy KEM
    // This should fail because key size doesn't match
    let result = toy_kem.encaps(&pk);

    // Should fail with InvalidKey (size mismatch)
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "toy KEM should reject ML-KEM-768 public key: {:?}",
        result
    );
}

/// Test that toy public key used with ML-KEM-768 fails cleanly.
#[test]
fn toy_public_key_with_ml_kem_768_fails_cleanly() {
    let ml_kem = MlKem768Backend::new();

    // Create toy-sized public key
    let toy_pk = vec![42u8; 32];

    // Try to encapsulate with toy public key using ML-KEM-768
    // This should fail because key size doesn't match
    let result = ml_kem.encaps(&toy_pk);

    // Should fail with InvalidKey (size mismatch)
    assert!(
        matches!(result, Err(CryptoError::InvalidKey)),
        "ML-KEM-768 should reject toy public key: {:?}",
        result
    );
}

// ============================================================================
// Multi-suite registry tests
// ============================================================================

/// Test building a registry with multiple KEM suites.
#[test]
fn multi_suite_registry() {
    let provider = StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(ToyKem::new(1)))
        .with_kem_suite(Arc::new(ToyKem::new(2)))
        .with_kem_suite(Arc::new(MlKem768Backend::new()));

    // All suites should be accessible
    assert!(provider.kem_suite(1).is_some());
    assert!(provider.kem_suite(2).is_some());
    assert!(provider.kem_suite(KEM_SUITE_ML_KEM_768).is_some());

    // Unknown suites should return None
    assert!(provider.kem_suite(50).is_none());
    assert!(provider.kem_suite(200).is_none());
}

/// Test that suite metadata is correctly reported.
#[test]
fn suite_metadata_correctness() {
    let ml_kem = MlKem768Backend::new();
    let toy_kem = ToyKem::new(TOY_KEM_SUITE_ID);

    // ML-KEM-768 metadata
    assert_eq!(ml_kem.suite_id(), KEM_SUITE_ML_KEM_768);
    assert_eq!(ml_kem.public_key_len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    assert_eq!(ml_kem.secret_key_len(), ML_KEM_768_SECRET_KEY_SIZE);
    assert_eq!(ml_kem.ciphertext_len(), ML_KEM_768_CIPHERTEXT_SIZE);
    assert_eq!(ml_kem.shared_secret_len(), ML_KEM_768_SHARED_SECRET_SIZE);

    // Toy KEM metadata
    assert_eq!(toy_kem.suite_id(), TOY_KEM_SUITE_ID);
    assert_eq!(toy_kem.public_key_len(), 32);
    assert_eq!(toy_kem.secret_key_len(), 32);
    assert_eq!(toy_kem.ciphertext_len(), 48);
    assert_eq!(toy_kem.shared_secret_len(), 32);
}

// ============================================================================
// Provider routing tests
// ============================================================================

/// Test that provider correctly routes to the right backend.
#[test]
fn provider_routes_to_correct_backend() {
    let provider = StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(ToyKem::new(TOY_KEM_SUITE_ID)))
        .with_kem_suite(Arc::new(MlKem768Backend::new()));

    // Get both backends via provider
    let kem_100 = provider.kem_suite(KEM_SUITE_ML_KEM_768).unwrap();
    let kem_1 = provider.kem_suite(TOY_KEM_SUITE_ID).unwrap();

    // Verify they have different characteristics
    assert_eq!(kem_100.suite_id(), KEM_SUITE_ML_KEM_768);
    assert_eq!(kem_100.public_key_len(), ML_KEM_768_PUBLIC_KEY_SIZE);

    assert_eq!(kem_1.suite_id(), TOY_KEM_SUITE_ID);
    assert_eq!(kem_1.public_key_len(), 32);
}

// ============================================================================
// Thread safety tests
// ============================================================================

/// Test that provider with ML-KEM-768 is thread-safe.
#[test]
fn provider_thread_safety() {
    use std::thread;

    let provider =
        Arc::new(StaticCryptoProvider::new().with_kem_suite(Arc::new(MlKem768Backend::new())));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let provider = provider.clone();
            thread::spawn(move || {
                for _ in 0..10 {
                    let kem = provider.kem_suite(KEM_SUITE_ML_KEM_768).unwrap();
                    let (pk, sk) =
                        MlKem768Backend::generate_keypair().expect("keygen should succeed");
                    let (ct, ss1) = kem.encaps(&pk).expect("encaps should succeed");
                    let ss2 = kem.decaps(&sk, &ct).expect("decaps should succeed");
                    assert_eq!(ss1, ss2);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
}
