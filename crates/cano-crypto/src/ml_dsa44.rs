//! ML-DSA-44 consensus signature backend.
//!
//! This module provides a real post-quantum signature backend using ML-DSA-44
//! (FIPS 204, formerly known as Dilithium2). The backend implements the
//! `ConsensusSigVerifier` trait for integration with the multi-suite consensus
//! signature verification framework.
//!
//! # Implementation
//!
//! This backend uses the `fips204` crate, which provides a pure Rust implementation
//! of FIPS 204 (Module-Lattice-Based Digital Signature Standard). ML-DSA-44 provides
//! approximately 128-bit classical security (NIST Level 1).
//!
//! # Key Sizes
//!
//! - Public key: 1,312 bytes
//! - Secret key: 2,560 bytes
//! - Signature: ≤2,420 bytes
//!
//! # Security Notes
//!
//! - This backend does NOT log secret key material.
//! - Signature verification is constant-time per the fips204 crate.
//! - Errors do not leak sensitive information.
//! - `ValidatorSigningKey` wrapper ensures zeroization on drop (T142).
//!
//! # Future Work
//!
//! - Batch verification (when the underlying crate supports it)
//! - Deterministic keygen from seed (for reproducible testing)

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};

/// ML-DSA-44 public key size in bytes.
pub const ML_DSA_44_PUBLIC_KEY_SIZE: usize = 1312;

/// ML-DSA-44 secret key size in bytes.
pub const ML_DSA_44_SECRET_KEY_SIZE: usize = 2560;

/// ML-DSA-44 signature size in bytes.
pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2420;

// ============================================================================
// ValidatorSigningKey Wrapper (T142)
// ============================================================================

/// Validator signing key wrapper with zeroization on drop.
///
/// This wrapper holds the ML-DSA-44 secret key used for signing consensus
/// votes and proposals. It ensures the key material is zeroized when dropped.
///
/// # Security Properties
///
/// - `ZeroizeOnDrop`: Secret key is overwritten with zeros when dropped.
/// - No `Clone`: Prevents accidental key duplication.
/// - No `Copy`: Secret keys should never be implicitly copied.
/// - Custom `Debug`: Never prints actual key bytes.
///
/// # Lifecycle
///
/// The validator signing key is typically long-lived:
/// 1. Loaded from secure storage at node startup
/// 2. Used for signing votes and proposals during consensus
/// 3. Zeroized when the validator config is dropped or node shuts down
///
/// # Usage
///
/// ```ignore
/// use cano_crypto::ValidatorSigningKey;
///
/// let sk = ValidatorSigningKey::new(secret_key_bytes);
/// // Use sk.as_bytes() for signing
/// let signature = MlDsa44Backend::sign(sk.as_bytes(), message)?;
/// drop(sk); // Key is zeroized here
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatorSigningKey {
    bytes: Vec<u8>,
}

impl ValidatorSigningKey {
    /// Create a new validator signing key from a byte vector.
    ///
    /// Takes ownership of the vector to avoid copying key material.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The secret key bytes. For ML-DSA-44, this should be
    ///   `ML_DSA_44_SECRET_KEY_SIZE` (2560) bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the raw secret key bytes.
    ///
    /// # Security Note
    ///
    /// The returned reference should be used immediately for signing
    /// and not stored. The underlying bytes are zeroized when this
    /// wrapper is dropped.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the secret key.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the secret key is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Sign a message using this validator signing key.
    ///
    /// This is a convenience method that calls `MlDsa44Backend::sign`
    /// with the wrapped key bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Errors
    ///
    /// Returns an error if the key is malformed or signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ConsensusSigError> {
        MlDsa44Backend::sign(&self.bytes, message)
    }

    /// Derive the public key from this signing key.
    ///
    /// This method extracts the public key corresponding to this signing key.
    /// This is useful for validating that the signing key matches an expected
    /// public key during node startup (T145 identity self-check).
    ///
    /// # Returns
    ///
    /// The public key bytes as a `Vec<u8>` of length `ML_DSA_44_PUBLIC_KEY_SIZE`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signing key is malformed or wrong size
    /// - The key fails cryptographic validation
    ///
    /// # Security Note
    ///
    /// This method does NOT log the secret key. Only the derived public key
    /// is returned, which is safe to log.
    pub fn derive_public_key(&self) -> Result<Vec<u8>, ConsensusSigError> {
        MlDsa44Backend::derive_public_key(&self.bytes)
    }
}

impl std::fmt::Debug for ValidatorSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorSigningKey")
            .field("bytes", &format!("<redacted:{}>", self.bytes.len()))
            .finish()
    }
}

/// A consensus signature backend using ML-DSA-44 (FIPS 204).
///
/// This backend provides post-quantum signature verification using the
/// ML-DSA-44 parameter set, which offers approximately 128-bit classical
/// security (NIST Level 1).
///
/// # Thread Safety
///
/// This backend is `Send + Sync` safe and can be shared across threads.
/// All operations are stateless.
///
/// # Error Handling
///
/// All errors are mapped to `ConsensusSigError` variants:
/// - Malformed public key → `ConsensusSigError::MalformedSignature`
/// - Malformed signature → `ConsensusSigError::MalformedSignature`
/// - Invalid signature → `ConsensusSigError::InvalidSignature`
#[derive(Debug, Clone, Copy, Default)]
pub struct MlDsa44Backend;

impl MlDsa44Backend {
    /// Create a new ML-DSA-44 backend instance.
    pub fn new() -> Self {
        MlDsa44Backend
    }

    /// Derive the public key from a secret key.
    ///
    /// This function extracts the public key corresponding to the given
    /// ML-DSA-44 secret key. This is useful for validating that a signing key
    /// matches an expected public key during node startup.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be `ML_DSA_44_SECRET_KEY_SIZE` bytes)
    ///
    /// # Returns
    ///
    /// The public key bytes as a `Vec<u8>` of length `ML_DSA_44_PUBLIC_KEY_SIZE`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret key is malformed or wrong size
    /// - The secret key fails cryptographic validation
    ///
    /// # Security Note
    ///
    /// This function does NOT log the secret key. The public key is safe to log.
    pub fn derive_public_key(sk: &[u8]) -> Result<Vec<u8>, ConsensusSigError> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Signer};

        if sk.len() != ML_DSA_44_SECRET_KEY_SIZE {
            return Err(ConsensusSigError::MalformedSignature);
        }

        let sk_array: [u8; ML_DSA_44_SECRET_KEY_SIZE] = sk
            .try_into()
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        let secret_key = ml_dsa_44::PrivateKey::try_from_bytes(sk_array)
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        // Use the get_public_key method from the Signer trait
        let public_key = secret_key.get_public_key();

        Ok(public_key.into_bytes().to_vec())
    }

    /// Generate a new ML-DSA-44 keypair.
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
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), ConsensusSigError> {
        use fips204::ml_dsa_44;
        use fips204::traits::SerDes;

        let (pk, sk) = ml_dsa_44::try_keygen()
            .map_err(|_| ConsensusSigError::Other("ML-DSA-44 keygen failed".to_string()))?;

        Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
    }

    /// Sign a message using an ML-DSA-44 secret key.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be `ML_DSA_44_SECRET_KEY_SIZE` bytes)
    /// * `message` - The message to sign
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret key is malformed or wrong size
    /// - Signing fails for any reason
    ///
    /// # Security Note
    ///
    /// This function does NOT log the secret key.
    pub fn sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>, ConsensusSigError> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Signer};

        if sk.len() != ML_DSA_44_SECRET_KEY_SIZE {
            return Err(ConsensusSigError::MalformedSignature);
        }

        let sk_array: [u8; ML_DSA_44_SECRET_KEY_SIZE] = sk
            .try_into()
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        let secret_key = ml_dsa_44::PrivateKey::try_from_bytes(sk_array)
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        // Sign with empty context string (standard usage)
        let signature = secret_key
            .try_sign(message, &[])
            .map_err(|_| ConsensusSigError::Other("ML-DSA-44 signing failed".to_string()))?;

        Ok(signature.to_vec())
    }

    /// Verify a signature using an ML-DSA-44 public key.
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key bytes (must be `ML_DSA_44_PUBLIC_KEY_SIZE` bytes)
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes (must be `ML_DSA_44_SIGNATURE_SIZE` bytes)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err` otherwise.
    fn verify_internal(
        pk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Verifier};

        // Check public key size
        if pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(ConsensusSigError::MalformedSignature);
        }

        // Check signature size
        if signature.len() != ML_DSA_44_SIGNATURE_SIZE {
            return Err(ConsensusSigError::MalformedSignature);
        }

        // Parse public key
        let pk_array: [u8; ML_DSA_44_PUBLIC_KEY_SIZE] = pk
            .try_into()
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        let public_key = ml_dsa_44::PublicKey::try_from_bytes(pk_array)
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        // Parse signature
        let sig_array: [u8; ML_DSA_44_SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| ConsensusSigError::MalformedSignature)?;

        // Verify with empty context string (standard usage)
        if public_key.verify(message, &sig_array, &[]) {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }
}

impl ConsensusSigVerifier for MlDsa44Backend {
    fn verify_vote(
        &self,
        _validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Self::verify_internal(pk, preimage, signature)
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        Self::verify_internal(pk, preimage, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that keypair generation produces keys of correct sizes.
    #[test]
    fn keygen_produces_correct_sizes() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        assert_eq!(pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), ML_DSA_44_SECRET_KEY_SIZE);
    }

    /// Test sign and verify roundtrip.
    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"test message for ML-DSA-44";

        let signature = MlDsa44Backend::sign(&sk, message).expect("signing failed");
        assert_eq!(signature.len(), ML_DSA_44_SIGNATURE_SIZE);

        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &pk, message, &signature);
        assert!(result.is_ok(), "verification should succeed");
    }

    /// Test that verification fails for modified message.
    #[test]
    fn verify_fails_for_modified_message() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"original message";

        let signature = MlDsa44Backend::sign(&sk, message).expect("signing failed");

        let backend = MlDsa44Backend::new();
        let modified_message = b"modified message";
        let result = backend.verify_vote(1, &pk, modified_message, &signature);
        assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
    }

    /// Test that verification fails for modified signature.
    #[test]
    fn verify_fails_for_modified_signature() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"test message";

        let mut signature = MlDsa44Backend::sign(&sk, message).expect("signing failed");
        // Tamper with signature
        signature[0] ^= 0xff;

        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &pk, message, &signature);
        assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
    }

    /// Test that verification fails with wrong public key.
    #[test]
    fn verify_fails_with_wrong_key() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (wrong_pk, _) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"test message";

        let signature = MlDsa44Backend::sign(&sk, message).expect("signing failed");

        // Verify with wrong key
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &wrong_pk, message, &signature);
        assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));

        // Verify with correct key should work
        let result = backend.verify_vote(1, &pk, message, &signature);
        assert!(result.is_ok());
    }

    /// Test that malformed public key is rejected.
    #[test]
    fn verify_rejects_malformed_public_key() {
        let backend = MlDsa44Backend::new();
        let bad_pk = vec![0u8; 100]; // Wrong size
        let message = b"test message";
        let signature = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];

        let result = backend.verify_vote(1, &bad_pk, message, &signature);
        assert!(matches!(result, Err(ConsensusSigError::MalformedSignature)));
    }

    /// Test that malformed signature is rejected.
    #[test]
    fn verify_rejects_malformed_signature() {
        let (pk, _) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let backend = MlDsa44Backend::new();
        let message = b"test message";
        let bad_signature = vec![0u8; 100]; // Wrong size

        let result = backend.verify_vote(1, &pk, message, &bad_signature);
        assert!(matches!(result, Err(ConsensusSigError::MalformedSignature)));
    }

    /// Test that proposal verification works the same as vote verification.
    #[test]
    fn proposal_verification_works() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"proposal message";

        let signature = MlDsa44Backend::sign(&sk, message).expect("signing failed");

        let backend = MlDsa44Backend::new();
        let result = backend.verify_proposal(1, &pk, message, &signature);
        assert!(result.is_ok(), "proposal verification should succeed");
    }

    /// Test that backend is Send + Sync.
    #[test]
    fn backend_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MlDsa44Backend>();
    }

    /// Test Debug implementation.
    #[test]
    fn backend_debug() {
        let backend = MlDsa44Backend::new();
        let debug_str = format!("{:?}", backend);
        assert!(debug_str.contains("MlDsa44Backend"));
    }

    /// Test Default implementation.
    #[test]
    fn backend_default() {
        let _backend: MlDsa44Backend = Default::default();
    }

    // ------------------------------------------------------------------------
    // T145: Public key derivation tests
    // ------------------------------------------------------------------------

    /// Test that derive_public_key returns the correct public key.
    #[test]
    fn derive_public_key_returns_correct_key() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        let derived_pk = MlDsa44Backend::derive_public_key(&sk).expect("derivation failed");

        assert_eq!(
            derived_pk, pk,
            "derived public key should match generated public key"
        );
        assert_eq!(derived_pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
    }

    /// Test that derive_public_key fails for wrong-sized key.
    #[test]
    fn derive_public_key_rejects_wrong_size() {
        let bad_sk = vec![0u8; 100]; // Wrong size

        let result = MlDsa44Backend::derive_public_key(&bad_sk);

        assert!(matches!(result, Err(ConsensusSigError::MalformedSignature)));
    }

    /// Test that derive_public_key fails for empty key.
    #[test]
    fn derive_public_key_rejects_empty() {
        let empty_sk = vec![];

        let result = MlDsa44Backend::derive_public_key(&empty_sk);

        assert!(matches!(result, Err(ConsensusSigError::MalformedSignature)));
    }

    /// Test that ValidatorSigningKey::derive_public_key returns the correct key.
    #[test]
    fn validator_signing_key_derive_public_key() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        let signing_key = ValidatorSigningKey::new(sk);
        let derived_pk = signing_key.derive_public_key().expect("derivation failed");

        assert_eq!(
            derived_pk, pk,
            "derived public key should match generated public key"
        );
    }

    /// Test that derived public key can verify signatures from the signing key.
    #[test]
    fn derived_public_key_verifies_signatures() {
        let (original_pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        // Create signing key and derive public key
        let signing_key = ValidatorSigningKey::new(sk);
        let derived_pk = signing_key.derive_public_key().expect("derivation failed");

        // Verify derived key matches original
        assert_eq!(derived_pk, original_pk);

        // Sign a message
        let message = b"test message for derivation verification";
        let signature = signing_key.sign(message).expect("signing failed");

        // Verify signature with derived public key
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &derived_pk, message, &signature);
        assert!(result.is_ok(), "signature should verify with derived key");
    }

    /// Test that derive_public_key is consistent across multiple calls.
    #[test]
    fn derive_public_key_is_consistent() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        let signing_key = ValidatorSigningKey::new(sk);

        // Derive multiple times
        let pk1 = signing_key
            .derive_public_key()
            .expect("derivation 1 failed");
        let pk2 = signing_key
            .derive_public_key()
            .expect("derivation 2 failed");
        let pk3 = signing_key
            .derive_public_key()
            .expect("derivation 3 failed");

        assert_eq!(pk1, pk, "first derivation should match original");
        assert_eq!(pk1, pk2, "derivations should be consistent");
        assert_eq!(pk2, pk3, "derivations should be consistent");
    }
}
