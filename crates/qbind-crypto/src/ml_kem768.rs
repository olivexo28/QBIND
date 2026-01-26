//! ML-KEM-768 Key Encapsulation Mechanism backend.
//!
//! This module provides a real post-quantum KEM backend using ML-KEM-768
//! (FIPS 203, formerly known as Kyber768). The backend implements the
//! `KemSuite` trait for integration with the crypto provider framework
//! used by KEMTLS and other networking components.
//!
//! # Implementation
//!
//! This backend uses the `fips203` crate, which provides a pure Rust implementation
//! of FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard).
//! ML-KEM-768 provides approximately 192-bit classical security (NIST Level 3).
//!
//! # Key Sizes (per FIPS 203)
//!
//! - Public key: 1,184 bytes
//! - Secret key: 2,400 bytes
//! - Ciphertext: 1,088 bytes
//! - Shared secret: 32 bytes
//!
//! # Security Notes
//!
//! - This backend does NOT log secret key material.
//! - Operations are designed to be constant-time per the fips203 crate.
//! - Errors do not leak sensitive information.
//!
//! # Future Work
//!
//! - KEMTLS integration in qbind-net
//! - Performance benchmarks and optimization
//! - Batch encapsulation (if needed for parallel handshakes)

use crate::kem::KemSuite;
use crate::CryptoError;

/// ML-KEM-768 public key size in bytes.
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM-768 secret key size in bytes.
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;

/// ML-KEM-768 ciphertext size in bytes.
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

/// ML-KEM-768 shared secret size in bytes.
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

/// KEM suite ID for ML-KEM-768.
///
/// This ID is used to identify ML-KEM-768 in the crypto provider registry
/// and KEMTLS handshake negotiation.
pub const KEM_SUITE_ML_KEM_768: u8 = 100;

/// A KEM backend using ML-KEM-768 (FIPS 203).
///
/// This backend provides post-quantum key encapsulation using the
/// ML-KEM-768 parameter set, which offers approximately 192-bit classical
/// security (NIST Level 3).
///
/// # Thread Safety
///
/// This backend is `Send + Sync` safe and can be shared across threads.
/// All operations are stateless.
///
/// # Error Handling
///
/// All errors are mapped to `CryptoError` variants:
/// - Malformed public key → `CryptoError::InvalidKey`
/// - Malformed secret key → `CryptoError::InvalidKey`
/// - Malformed ciphertext → `CryptoError::InvalidCiphertext`
/// - Decapsulation failure → `CryptoError::InvalidCiphertext`
#[derive(Debug, Clone, Copy, Default)]
pub struct MlKem768Backend;

impl MlKem768Backend {
    /// Create a new ML-KEM-768 backend instance.
    pub fn new() -> Self {
        MlKem768Backend
    }

    /// Generate a new ML-KEM-768 keypair.
    ///
    /// Returns `(public_key, secret_key)` as byte vectors.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying CSPRNG fails.
    ///
    /// # Security Note
    ///
    /// The secret key must be securely stored and never logged.
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use fips203::ml_kem_768;
        use fips203::traits::{KeyGen, SerDes};

        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|_| CryptoError::InternalError("ML-KEM-768 keygen failed"))?;

        Ok((ek.into_bytes().to_vec(), dk.into_bytes().to_vec()))
    }
}

impl KemSuite for MlKem768Backend {
    fn suite_id(&self) -> u8 {
        KEM_SUITE_ML_KEM_768
    }

    fn public_key_len(&self) -> usize {
        ML_KEM_768_PUBLIC_KEY_SIZE
    }

    fn secret_key_len(&self) -> usize {
        ML_KEM_768_SECRET_KEY_SIZE
    }

    fn ciphertext_len(&self) -> usize {
        ML_KEM_768_CIPHERTEXT_SIZE
    }

    fn shared_secret_len(&self) -> usize {
        ML_KEM_768_SHARED_SECRET_SIZE
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use fips203::ml_kem_768;
        use fips203::traits::{Encaps, SerDes};

        // Check public key size
        if pk.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        // Parse public key
        let pk_array: [u8; ML_KEM_768_PUBLIC_KEY_SIZE] =
            pk.try_into().map_err(|_| CryptoError::InvalidKey)?;

        let encaps_key =
            ml_kem_768::EncapsKey::try_from_bytes(pk_array).map_err(|_| CryptoError::InvalidKey)?;

        // Encapsulate
        let (ss, ct) = encaps_key
            .try_encaps()
            .map_err(|_| CryptoError::InternalError("ML-KEM-768 encapsulation failed"))?;

        Ok((ct.into_bytes().to_vec(), ss.into_bytes().to_vec()))
    }

    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use fips203::ml_kem_768;
        use fips203::traits::{Decaps, SerDes};

        // Check secret key size
        if sk.len() != ML_KEM_768_SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        // Check ciphertext size
        if ct.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Parse secret key
        let sk_array: [u8; ML_KEM_768_SECRET_KEY_SIZE] =
            sk.try_into().map_err(|_| CryptoError::InvalidKey)?;

        let decaps_key =
            ml_kem_768::DecapsKey::try_from_bytes(sk_array).map_err(|_| CryptoError::InvalidKey)?;

        // Parse ciphertext
        let ct_array: [u8; ML_KEM_768_CIPHERTEXT_SIZE] =
            ct.try_into().map_err(|_| CryptoError::InvalidCiphertext)?;

        let ciphertext = ml_kem_768::CipherText::try_from_bytes(ct_array)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        // Decapsulate
        let ss = decaps_key
            .try_decaps(&ciphertext)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        Ok(ss.into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that keypair generation produces keys of correct sizes.
    #[test]
    fn keygen_produces_correct_sizes() {
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        assert_eq!(pk.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), ML_KEM_768_SECRET_KEY_SIZE);
    }

    /// Test encapsulate and decapsulate roundtrip yields identical shared secrets.
    #[test]
    fn encaps_decaps_roundtrip() {
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let backend = MlKem768Backend::new();

        let (ct, ss_encaps) = backend.encaps(&pk).expect("encapsulation failed");
        assert_eq!(ct.len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(ss_encaps.len(), ML_KEM_768_SHARED_SECRET_SIZE);

        let ss_decaps = backend.decaps(&sk, &ct).expect("decapsulation failed");
        assert_eq!(ss_decaps.len(), ML_KEM_768_SHARED_SECRET_SIZE);

        assert_eq!(ss_encaps, ss_decaps, "shared secrets must match");
    }

    /// Test that two encapsulations with the same public key produce different ciphertexts.
    #[test]
    fn encapsulation_is_randomized() {
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let backend = MlKem768Backend::new();

        let (ct1, ss1) = backend.encaps(&pk).expect("first encapsulation failed");
        let (ct2, ss2) = backend.encaps(&pk).expect("second encapsulation failed");

        // Ciphertexts should differ (randomized encapsulation)
        assert_ne!(
            ct1, ct2,
            "ciphertexts should be different for randomized KEM"
        );

        // Both shared secrets should be valid when decapsulated
        let ss1_decaps = backend
            .decaps(&sk, &ct1)
            .expect("first decapsulation failed");
        let ss2_decaps = backend
            .decaps(&sk, &ct2)
            .expect("second decapsulation failed");

        assert_eq!(ss1, ss1_decaps);
        assert_eq!(ss2, ss2_decaps);

        // But the shared secrets should also differ
        assert_ne!(
            ss1, ss2,
            "shared secrets should differ for different encapsulations"
        );
    }

    /// Test that decapsulation with corrupted ciphertext still returns a result
    /// (implicit rejection - KEM property) but the shared secret won't match.
    #[test]
    fn decaps_corrupted_ciphertext_yields_different_secret() {
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let backend = MlKem768Backend::new();

        let (mut ct, ss_original) = backend.encaps(&pk).expect("encapsulation failed");

        // Corrupt the ciphertext
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

    /// Test that malformed (wrong size) public key is rejected.
    #[test]
    fn encaps_rejects_malformed_public_key() {
        let backend = MlKem768Backend::new();
        let bad_pk = vec![0u8; 100]; // Wrong size

        let result = backend.encaps(&bad_pk);
        assert!(
            matches!(result, Err(CryptoError::InvalidKey)),
            "malformed public key should be rejected"
        );
    }

    /// Test that malformed (wrong size) secret key is rejected.
    #[test]
    fn decaps_rejects_malformed_secret_key() {
        let (pk, _) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let backend = MlKem768Backend::new();

        let (ct, _) = backend.encaps(&pk).expect("encapsulation failed");
        let bad_sk = vec![0u8; 100]; // Wrong size

        let result = backend.decaps(&bad_sk, &ct);
        assert!(
            matches!(result, Err(CryptoError::InvalidKey)),
            "malformed secret key should be rejected"
        );
    }

    /// Test that malformed (wrong size) ciphertext is rejected.
    #[test]
    fn decaps_rejects_malformed_ciphertext() {
        let (_, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let backend = MlKem768Backend::new();

        let bad_ct = vec![0u8; 100]; // Wrong size

        let result = backend.decaps(&sk, &bad_ct);
        assert!(
            matches!(result, Err(CryptoError::InvalidCiphertext)),
            "malformed ciphertext should be rejected"
        );
    }

    /// Test that backend is Send + Sync.
    #[test]
    fn backend_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MlKem768Backend>();
    }

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

    /// Test Debug implementation.
    #[test]
    fn backend_debug() {
        let backend = MlKem768Backend::new();
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("MlKem768Backend"));
    }

    /// Test Default implementation.
    #[test]
    fn backend_default() {
        let _backend: MlKem768Backend = Default::default();
    }

    /// Test Clone implementation.
    #[test]
    #[allow(clippy::clone_on_copy)]
    fn backend_clone() {
        let backend1 = MlKem768Backend::new();
        let backend2 = backend1.clone();

        // Both should work identically
        let (pk, sk) = MlKem768Backend::generate_keypair().expect("keygen failed");
        let (ct1, ss1) = backend1.encaps(&pk).expect("encaps failed");
        let ss1_decaps = backend2.decaps(&sk, &ct1).expect("decaps failed");
        assert_eq!(ss1, ss1_decaps);
    }
}
