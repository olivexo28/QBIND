//! Validator signer abstraction for consensus operations (T148).
//!
//! This module provides an abstraction layer for consensus signing operations,
//! enabling future integration with HSMs or remote signers without modifying
//! the consensus harness code.
//!
//! # Architecture
//!
//! The `ValidatorSigner` trait defines the interface for all consensus signing:
//! - Proposals
//! - Votes
//! - Timeout messages
//!
//! The `LocalKeySigner` implementation wraps an `Arc<ValidatorSigningKey>` and
//! provides the same signing behavior as before, but through the trait interface.
//!
//! # Future Extensions
//!
//! To add an HSM or remote signer, implement `ValidatorSigner` with the appropriate
//! backend. The harness code remains unchanged.
//!
//! # Security Notes
//!
//! - Key material is NEVER logged
//! - `LocalKeySigner` maintains the same security properties as direct key usage:
//!   - Non-Clone key wrapper
//!   - Zeroization on drop
//!   - Debug redaction

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_consensus::timeout::timeout_signing_bytes;
use qbind_crypto::ValidatorSigningKey;

/// Error type for signing operations.
///
/// This error type is designed to be extensible for future signer backends
/// (HSM, remote signer, etc.) while providing useful error information.
///
/// # Security Notes
///
/// Error messages NEVER include key material or sensitive data.
#[derive(Debug)]
pub enum SignError {
    /// The underlying cryptographic operation failed.
    ///
    /// This may indicate:
    /// - Malformed key material
    /// - Internal crypto library error
    CryptoError,

    /// The key material is invalid or corrupted.
    InvalidKey,
    // Future variants for HSM/remote signer:
    // HsmError(String),
    // RemoteSignerError(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::CryptoError => write!(f, "cryptographic signing error"),
            SignError::InvalidKey => write!(f, "invalid key material"),
        }
    }
}

impl std::error::Error for SignError {}

/// Trait for consensus signing operations.
///
/// This trait abstracts all consensus signing operations (proposals, votes,
/// timeout messages) to enable pluggable signer backends.
///
/// # Implementors
///
/// - `LocalKeySigner`: In-process signing using `ValidatorSigningKey`
/// - Future: `HsmSigner`, `RemoteSigner`, etc.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow sharing across
/// async tasks and threads.
///
/// # Security Notes
///
/// Implementations must:
/// - Never log key material
/// - Ensure proper zeroization (where applicable)
/// - Use constant-time operations where security-critical
pub trait ValidatorSigner: Send + Sync {
    /// Get the validator ID for this signer.
    fn validator_id(&self) -> &ValidatorId;

    /// Get the signature suite ID (e.g., 100 for ML-DSA-44).
    fn suite_id(&self) -> u16;

    /// Sign a proposal.
    ///
    /// # Arguments
    ///
    /// * `preimage` - The signing preimage from `BlockProposal::signing_preimage()`
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError>;

    /// Sign a vote.
    ///
    /// # Arguments
    ///
    /// * `preimage` - The signing preimage from `Vote::signing_preimage()`
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError>;

    /// Sign a timeout message.
    ///
    /// # Arguments
    ///
    /// * `view` - The view number being timed out
    /// * `high_qc` - The highest QC known to this validator (optional)
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    ///
    /// # Note
    ///
    /// This method uses `[u8; 32]` for block IDs to maintain dyn-compatibility.
    /// The consensus layer uses `[u8; 32]` as the canonical block ID type.
    fn sign_timeout(
        &self,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError>;
}

/// Local key signer implementation using in-process `ValidatorSigningKey`.
///
/// This signer wraps an `Arc<ValidatorSigningKey>` and provides the same
/// signing behavior as direct key usage, but through the `ValidatorSigner`
/// trait interface.
///
/// # Security Properties
///
/// - The signing key is wrapped in `Arc` (not cloned)
/// - Key zeroization is handled by `ValidatorSigningKey` on drop
/// - Debug output redacts key material
///
/// # Usage
///
/// ```ignore
/// use qbind_node::validator_signer::{LocalKeySigner, ValidatorSigner};
/// use std::sync::Arc;
///
/// let signer = LocalKeySigner::new(
///     validator_id,
///     100, // ML-DSA-44 suite ID
///     signing_key,
/// );
///
/// // Sign via trait
/// let signature = signer.sign_proposal(&preimage)?;
/// ```
pub struct LocalKeySigner {
    /// The validator ID for this signer.
    validator_id: ValidatorId,
    /// The signature suite ID (100 for ML-DSA-44).
    suite_id: u16,
    /// The signing key wrapped in Arc.
    signing_key: Arc<ValidatorSigningKey>,
}

impl LocalKeySigner {
    /// Create a new local key signer.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator ID
    /// * `suite_id` - The signature suite ID (should be 100 for ML-DSA-44)
    /// * `signing_key` - The signing key wrapped in Arc
    ///
    /// # Panics (Debug)
    ///
    /// In debug builds, panics if `suite_id` is not 100 (ML-DSA-44).
    pub fn new(
        validator_id: ValidatorId,
        suite_id: u16,
        signing_key: Arc<ValidatorSigningKey>,
    ) -> Self {
        // In debug builds, verify suite_id matches expected ML-DSA-44 suite
        debug_assert_eq!(
            suite_id, 100,
            "LocalKeySigner expects suite_id 100 (ML-DSA-44), got {}",
            suite_id
        );

        LocalKeySigner {
            validator_id,
            suite_id,
            signing_key,
        }
    }

    /// Get a reference to the underlying signing key.
    ///
    /// This is provided for advanced use cases where direct key access
    /// is needed (e.g., key derivation checks).
    ///
    /// # Security Note
    ///
    /// Use with caution. Prefer using the `ValidatorSigner` trait methods.
    pub fn signing_key(&self) -> &Arc<ValidatorSigningKey> {
        &self.signing_key
    }
}

impl std::fmt::Debug for LocalKeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeySigner")
            .field("validator_id", &self.validator_id)
            .field("suite_id", &self.suite_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl ValidatorSigner for LocalKeySigner {
    fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }

    fn suite_id(&self) -> u16 {
        self.suite_id
    }

    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signing_key
            .sign(preimage)
            .map_err(|_| SignError::CryptoError)
    }

    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signing_key
            .sign(preimage)
            .map_err(|_| SignError::CryptoError)
    }

    fn sign_timeout(
        &self,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError> {
        // Compute signing bytes using the existing helper
        let sign_bytes = timeout_signing_bytes(view, high_qc, self.validator_id);
        self.signing_key
            .sign(&sign_bytes)
            .map_err(|_| SignError::CryptoError)
    }
}

// ============================================================================
// Helper functions for creating signers
// ============================================================================

use crate::validator_config::LocalValidatorIdentity;

/// Create a `LocalKeySigner` from a validator identity and signing key.
///
/// This is the recommended way to construct a signer from existing config
/// structures.
///
/// # Arguments
///
/// * `identity` - The validator identity containing id and suite_id
/// * `signing_key` - The signing key wrapped in Arc
///
/// # Returns
///
/// A new `LocalKeySigner` configured with the identity's parameters.
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_signer::make_local_validator_signer;
///
/// let signer = make_local_validator_signer(&identity, signing_key);
/// let signer_arc: Arc<dyn ValidatorSigner> = Arc::new(signer);
/// ```
pub fn make_local_validator_signer(
    identity: &LocalValidatorIdentity,
    signing_key: Arc<ValidatorSigningKey>,
) -> LocalKeySigner {
    LocalKeySigner::new(
        identity.validator_id,
        identity.suite_id.as_u16(),
        signing_key,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    use qbind_crypto::ml_dsa44::{MlDsa44Backend, ML_DSA_44_SECRET_KEY_SIZE};
    use qbind_crypto::ConsensusSigSuiteId;

    /// Test that LocalKeySigner can be created and has correct identity.
    #[test]
    fn local_key_signer_creation() {
        let validator_id = ValidatorId::new(42);
        let suite_id = 100u16;
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE
        ]));

        let signer = LocalKeySigner::new(validator_id, suite_id, signing_key);

        assert_eq!(*signer.validator_id(), validator_id);
        assert_eq!(signer.suite_id(), 100);
    }

    /// Test that LocalKeySigner Debug does not leak key material.
    #[test]
    fn local_key_signer_debug_redacts_key() {
        let validator_id = ValidatorId::new(1);
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE
        ]));
        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        let debug_str = format!("{:?}", signer);

        assert!(debug_str.contains("LocalKeySigner"));
        assert!(debug_str.contains("validator_id"));
        assert!(debug_str.contains("suite_id"));
        assert!(debug_str.contains("<redacted>"));
        // Should not contain actual key bytes
        assert!(!debug_str.contains("[0, 0, 0"));
    }

    /// Test that LocalKeySigner produces valid signatures.
    #[test]
    fn local_key_signer_signs_correctly() {
        // Generate a real keypair for testing
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(1);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        // Sign a test message
        let message = b"test proposal preimage";
        let signature = signer.sign_proposal(message).expect("signing failed");

        // Verify the signature
        let backend = MlDsa44Backend::new();
        let result = backend.verify_proposal(1, &pk, message, &signature);
        assert!(result.is_ok(), "signature should verify");
    }

    /// Test vote signing produces verifiable signatures.
    #[test]
    fn local_key_signer_signs_votes() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(5);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        let message = b"test vote preimage";
        let signature = signer.sign_vote(message).expect("signing failed");

        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(5, &pk, message, &signature);
        assert!(result.is_ok(), "vote signature should verify");
    }

    /// Test timeout signing produces verifiable signatures.
    #[test]
    fn local_key_signer_signs_timeouts() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(3);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        // Sign timeout without high_qc
        let signature = signer.sign_timeout(10, None);
        assert!(signature.is_ok(), "timeout signing should succeed");

        // Verify by reconstructing signing bytes
        let sign_bytes = timeout_signing_bytes::<[u8; 32]>(10, None, validator_id);
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(3, &pk, &sign_bytes, &signature.unwrap());
        assert!(result.is_ok(), "timeout signature should verify");
    }

    /// Test timeout signing with high_qc.
    #[test]
    fn local_key_signer_signs_timeouts_with_high_qc() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(2);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        // Create a high_qc
        let high_qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId::new(1)]);

        let signature = signer
            .sign_timeout(15, Some(&high_qc))
            .expect("signing failed");

        // Verify
        let sign_bytes = timeout_signing_bytes(15, Some(&high_qc), validator_id);
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(2, &pk, &sign_bytes, &signature);
        assert!(
            result.is_ok(),
            "timeout signature with high_qc should verify"
        );
    }

    /// Test that ValidatorSigner can be used as a trait object.
    #[test]
    fn validator_signer_as_trait_object() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(7);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let signer: Arc<dyn ValidatorSigner> =
            Arc::new(LocalKeySigner::new(validator_id, 100, signing_key));

        // Use through trait object
        assert_eq!(*signer.validator_id(), validator_id);
        assert_eq!(signer.suite_id(), 100);

        let message = b"trait object signing test";
        let signature = signer.sign_proposal(message).expect("signing failed");

        let backend = MlDsa44Backend::new();
        let result = backend.verify_proposal(7, &pk, message, &signature);
        assert!(result.is_ok(), "signature from trait object should verify");
    }

    /// Test make_local_validator_signer helper function.
    #[test]
    fn make_local_validator_signer_works() {
        use qbind_consensus::ValidatorPublicKey;

        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(10);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));

        let identity = LocalValidatorIdentity {
            validator_id,
            public_key: ValidatorPublicKey(pk.clone()),
            suite_id: ConsensusSigSuiteId::new(100),
        };

        let signer = make_local_validator_signer(&identity, signing_key);

        assert_eq!(*signer.validator_id(), validator_id);
        assert_eq!(signer.suite_id(), 100);

        // Verify signing works
        let message = b"helper function test";
        let signature = signer.sign_vote(message).expect("signing failed");

        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(10, &pk, message, &signature);
        assert!(result.is_ok(), "signature should verify");
    }

    /// Test that LocalKeySigner is Send + Sync.
    #[test]
    fn local_key_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalKeySigner>();
        assert_send_sync::<Arc<dyn ValidatorSigner>>();
    }

    /// Test that LocalKeySigner properly wraps errors from invalid key operations.
    ///
    /// Note: ML-DSA-44 may accept malformed keys for signing but produce
    /// signatures that won't verify. This test just verifies the signer
    /// handles the operation without panicking.
    #[test]
    fn local_key_signer_handles_invalid_key() {
        let validator_id = ValidatorId::new(1);
        // Create a dummy key (all zeros)
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE
        ]));

        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        // The signing operation may succeed or fail depending on the backend.
        // What matters is that it doesn't panic and handles the case gracefully.
        let result = signer.sign_proposal(b"test");

        // Either the signing fails (CryptoError) or it "succeeds" but produces
        // an invalid signature. Both are acceptable behaviors.
        match result {
            Err(SignError::CryptoError) => {
                // Expected: backend detected invalid key
            }
            Ok(sig) => {
                // Also acceptable: backend produced a signature (but it won't verify)
                // Just verify we got bytes back
                assert!(!sig.is_empty(), "should produce some signature bytes");
            }
            Err(SignError::InvalidKey) => {
                // Also acceptable error type
            }
        }
    }
}
