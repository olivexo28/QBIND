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
// Bounded signing error for the caller-buffer output path (RUN 422)
// ============================================================================

/// Fixed-size, `Copy` error for the bounded caller-buffer signing path
/// ([`MlDsa44Backend::sign_into`] / [`ValidatorSigningKey::sign_into`]).
///
/// Unlike the legacy [`ConsensusSigError`], this type carries NO owned `String`
/// and allocates nothing when constructed: every variant is a fixed discriminant,
/// so a backend failure is mapped directly to a bounded code rather than a heap
/// diagnostic. It is intentionally small and `Copy`.
///
/// # Scope
///
/// This is only the crypto-layer code set for the new bounded path. It does not
/// replace [`ConsensusSigError`] on the existing `sign`/`verify` methods, which
/// are preserved unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedMlDsa44SignError {
    /// The caller-provided output buffer is smaller than
    /// [`ML_DSA_44_SIGNATURE_SIZE`]. Detected BEFORE key parsing or signing; the
    /// output buffer is left unchanged.
    OutputTooSmall,
    /// The secret key is malformed (wrong length or rejected by the backend
    /// key decoder). Detected BEFORE signing; the output buffer is left unchanged.
    InvalidKey,
    /// The underlying randomized signing operation failed (e.g. RNG failure).
    /// The output buffer is left unchanged.
    BackendFailed,
}

impl std::fmt::Display for BoundedMlDsa44SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundedMlDsa44SignError::OutputTooSmall => write!(f, "output buffer too small"),
            BoundedMlDsa44SignError::InvalidKey => write!(f, "invalid key material"),
            BoundedMlDsa44SignError::BackendFailed => write!(f, "signing backend failed"),
        }
    }
}

impl std::error::Error for BoundedMlDsa44SignError {}

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
/// use qbind_crypto::ValidatorSigningKey;
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

    /// Sign a message into a caller-owned output buffer (RUN 422 bounded path).
    ///
    /// This is the allocation-bounded analogue of [`Self::sign`]: it writes the
    /// signature into `out` (owned by the caller) and returns the exact written
    /// length, instead of returning a freshly-allocated `Vec<u8>`. It forwards to
    /// [`MlDsa44Backend::sign_into`] and uses the SAME ML-DSA-44 algorithm,
    /// message, empty signing context, and randomized signing operation as the
    /// legacy path; it introduces no new signature construction.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `out` - Caller-owned output buffer; must be at least
    ///   [`ML_DSA_44_SIGNATURE_SIZE`] bytes
    ///
    /// # Errors
    ///
    /// Returns a bounded [`BoundedMlDsa44SignError`] (no heap diagnostic) when the
    /// output buffer is too small, the key is malformed, or signing fails. On any
    /// error the output buffer is left unchanged.
    ///
    /// # Security Note
    ///
    /// This method does NOT log the secret key and retains neither the input nor
    /// the output borrow.
    pub fn sign_into(
        &self,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, BoundedMlDsa44SignError> {
        MlDsa44Backend::sign_into(&self.bytes, message, out)
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

    /// Sign a message into a caller-owned output buffer (RUN 422 bounded path).
    ///
    /// This is the allocation-bounded analogue of [`Self::sign`]: instead of
    /// returning a freshly-allocated `Vec<u8>`, it writes the signature into the
    /// caller's `out` buffer and returns the exact written length. It does NOT
    /// call [`Self::sign`] and copy its result — the heap signature-result
    /// conversion of the legacy path is removed here. The ML-DSA-44 algorithm,
    /// message, empty signing context, and randomized `try_sign` operation are
    /// otherwise identical; no new signature construction is introduced.
    ///
    /// # Ordered contract
    ///
    /// 1. Output capacity is checked BEFORE key parsing or signing.
    /// 2. The secret key is validated/decoded via the existing backend decoder.
    /// 3. The existing randomized signing operation runs over `message` with an
    ///    empty context.
    /// 4. The backend's fixed-size signature value is obtained.
    /// 5. The caller's output is written ONLY after a complete signature exists.
    /// 6. The exact signature length is returned.
    ///
    /// On ANY error the caller's output buffer is left unchanged. On success,
    /// only the `[0, ML_DSA_44_SIGNATURE_SIZE)` prefix of `out` is written; any
    /// trailing bytes of an oversized buffer are left unchanged.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be `ML_DSA_44_SECRET_KEY_SIZE` bytes)
    /// * `message` - The message to sign
    /// * `out` - Caller-owned output buffer; must be at least
    ///   [`ML_DSA_44_SIGNATURE_SIZE`] bytes
    ///
    /// # Errors
    ///
    /// Returns [`BoundedMlDsa44SignError`] (no heap diagnostic):
    /// - [`BoundedMlDsa44SignError::OutputTooSmall`] if `out.len() <
    ///   ML_DSA_44_SIGNATURE_SIZE`;
    /// - [`BoundedMlDsa44SignError::InvalidKey`] if the key is the wrong size or
    ///   rejected by the backend decoder;
    /// - [`BoundedMlDsa44SignError::BackendFailed`] if the randomized signing
    ///   operation fails.
    ///
    /// # Security Note
    ///
    /// This function does NOT log the secret key.
    pub fn sign_into(
        sk: &[u8],
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, BoundedMlDsa44SignError> {
        use fips204::ml_dsa_44;
        use fips204::traits::{SerDes, Signer};

        // (1) Output capacity BEFORE key parsing or signing. Leaves `out`
        //     unchanged on refusal.
        if out.len() < ML_DSA_44_SIGNATURE_SIZE {
            return Err(BoundedMlDsa44SignError::OutputTooSmall);
        }

        // (2) Validate/decode the key with the existing backend decoder.
        if sk.len() != ML_DSA_44_SECRET_KEY_SIZE {
            return Err(BoundedMlDsa44SignError::InvalidKey);
        }
        let sk_array: [u8; ML_DSA_44_SECRET_KEY_SIZE] = sk
            .try_into()
            .map_err(|_| BoundedMlDsa44SignError::InvalidKey)?;
        let secret_key = ml_dsa_44::PrivateKey::try_from_bytes(sk_array)
            .map_err(|_| BoundedMlDsa44SignError::InvalidKey)?;

        // (3)/(4) Existing randomized signing with empty context; the backend
        //         returns a fixed-size `[u8; ML_DSA_44_SIGNATURE_SIZE]` value.
        let signature = secret_key
            .try_sign(message, &[])
            .map_err(|_| BoundedMlDsa44SignError::BackendFailed)?;

        // (5) Copy into the caller's output ONLY after a complete signature
        //     exists. Only the signature-length prefix is written.
        out[..ML_DSA_44_SIGNATURE_SIZE].copy_from_slice(&signature);

        // (6) Return the exact signature length.
        Ok(ML_DSA_44_SIGNATURE_SIZE)
    }

    /// Verify a signature using an ML-DSA-44 public key.
    ///
    /// This is a public static method for direct signature verification.
    /// Use this for user transaction signature verification.
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
    pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ConsensusSigError> {
        Self::verify_internal(pk, message, signature)
    }

    /// Internal verify implementation.
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

    // ========================================================================
    // RUN 422 — bounded caller-buffer signing path (`sign_into`) tests.
    // ========================================================================

    /// Real-backend exact-capacity signing succeeds and verifies under the same
    /// key, message, suite, and empty signing context as the legacy path.
    #[test]
    fn sign_into_exact_capacity_signs_and_verifies() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"bounded sign_into message";

        let mut out = [0u8; ML_DSA_44_SIGNATURE_SIZE];
        let n = MlDsa44Backend::sign_into(&sk, message, &mut out).expect("sign_into failed");
        assert_eq!(n, ML_DSA_44_SIGNATURE_SIZE, "returns exact signature length");

        let backend = MlDsa44Backend::new();
        assert!(
            backend.verify_vote(1, &pk, message, &out[..n]).is_ok(),
            "bounded signature should verify"
        );
    }

    /// A signature produced by `sign_into` is rejected for a modified message and
    /// a wrong key (same rejection semantics as the legacy signature).
    #[test]
    fn sign_into_signature_rejects_modified_message_and_wrong_key() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (wrong_pk, _) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"authentic message";

        let mut out = [0u8; ML_DSA_44_SIGNATURE_SIZE];
        let n = MlDsa44Backend::sign_into(&sk, message, &mut out).expect("sign_into failed");

        let backend = MlDsa44Backend::new();
        assert!(
            matches!(
                backend.verify_vote(1, &pk, b"tampered message", &out[..n]),
                Err(ConsensusSigError::InvalidSignature)
            ),
            "modified message must be rejected"
        );
        assert!(
            matches!(
                backend.verify_vote(1, &wrong_pk, message, &out[..n]),
                Err(ConsensusSigError::InvalidSignature)
            ),
            "wrong key must be rejected"
        );
    }

    /// Legacy `sign` and new `sign_into` both produce valid signatures for the
    /// same intended input. Byte equality is NOT required: `fips204` `try_sign`
    /// uses OS randomness, so independent signatures legitimately differ.
    #[test]
    fn sign_into_and_legacy_sign_both_verify_without_byte_equality() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"same intended input";

        let legacy = MlDsa44Backend::sign(&sk, message).expect("legacy sign failed");
        let mut out = [0u8; ML_DSA_44_SIGNATURE_SIZE];
        let n = MlDsa44Backend::sign_into(&sk, message, &mut out).expect("sign_into failed");

        let backend = MlDsa44Backend::new();
        assert!(backend.verify_vote(1, &pk, message, &legacy).is_ok());
        assert!(backend.verify_vote(1, &pk, message, &out[..n]).is_ok());
        assert_eq!(legacy.len(), n, "both produce the exact signature length");
    }

    /// An undersized output buffer is refused before signing and left unchanged.
    #[test]
    fn sign_into_undersized_output_refused_buffer_unchanged() {
        let (_pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"message";

        // Sentinel buffer one byte short of the required capacity.
        let mut out = [0xABu8; ML_DSA_44_SIGNATURE_SIZE - 1];
        let before = out;
        let err = MlDsa44Backend::sign_into(&sk, message, &mut out).unwrap_err();
        assert_eq!(err, BoundedMlDsa44SignError::OutputTooSmall);
        assert_eq!(out, before, "refused output buffer is unchanged");
    }

    /// An oversized output buffer succeeds; only the signature-length prefix is
    /// written and the trailing suffix is left unchanged.
    #[test]
    fn sign_into_oversized_output_suffix_unchanged() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let message = b"oversized buffer message";

        const EXTRA: usize = 64;
        let mut out = [0x5Au8; ML_DSA_44_SIGNATURE_SIZE + EXTRA];
        let n = MlDsa44Backend::sign_into(&sk, message, &mut out).expect("sign_into failed");
        assert_eq!(n, ML_DSA_44_SIGNATURE_SIZE);

        // Suffix sentinel is preserved.
        assert!(
            out[n..].iter().all(|&b| b == 0x5A),
            "oversized suffix must remain unchanged"
        );
        let backend = MlDsa44Backend::new();
        assert!(backend.verify_vote(1, &pk, message, &out[..n]).is_ok());
    }

    /// A malformed (wrong-size) key is refused and the output buffer is unchanged.
    #[test]
    fn sign_into_malformed_key_refused_buffer_unchanged() {
        let message = b"message";
        let short_key = vec![0u8; ML_DSA_44_SECRET_KEY_SIZE - 1];

        let mut out = [0x11u8; ML_DSA_44_SIGNATURE_SIZE];
        let before = out;
        let err = MlDsa44Backend::sign_into(&short_key, message, &mut out).unwrap_err();
        assert_eq!(err, BoundedMlDsa44SignError::InvalidKey);
        assert_eq!(out, before, "refused output buffer is unchanged");
    }

    /// `ValidatorSigningKey::sign_into` forwards to the backend bounded path and
    /// produces a verifiable signature.
    #[test]
    fn validator_signing_key_sign_into_verifies() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let key = ValidatorSigningKey::new(sk);
        let message = b"validator key bounded sign";

        let mut out = [0u8; ML_DSA_44_SIGNATURE_SIZE];
        let n = key.sign_into(message, &mut out).expect("sign_into failed");
        assert_eq!(n, ML_DSA_44_SIGNATURE_SIZE);

        let backend = MlDsa44Backend::new();
        assert!(backend.verify_vote(1, &pk, message, &out[..n]).is_ok());
    }

    /// The bounded error type is a fixed-size `Copy` value (no owned `String`).
    #[test]
    fn bounded_sign_error_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<BoundedMlDsa44SignError>();
        let e = BoundedMlDsa44SignError::BackendFailed;
        let _copy = e; // `e` remains usable because the type is `Copy`.
        assert_eq!(e, BoundedMlDsa44SignError::BackendFailed);
    }
}