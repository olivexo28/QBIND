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
use qbind_consensus::timeout::{timeout_signing_bytes, timeout_signing_bytes_with_chain_id};
use qbind_crypto::{BoundedMlDsa44SignError, ValidatorSigningKey, ML_DSA_44_SIGNATURE_SIZE};
use qbind_types::ChainId;

/// The ML-DSA-44 consensus signature suite ID (FIPS 204). `LocalKeySigner`'s
/// only concrete backend is ML-DSA-44; the bounded caller-buffer path refuses at
/// runtime (effective in release builds) when a signer advertises any other
/// suite. Mirrors the value the legacy constructor asserts in debug builds.
const ML_DSA_44_CONSENSUS_SUITE_ID: u16 = 100;

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

    /// HSM/PKCS#11 signer error (T211).
    ///
    /// This indicates an error from the HSM backend.
    /// The message never contains PIN or key material.
    HsmError(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::CryptoError => write!(f, "cryptographic signing error"),
            SignError::InvalidKey => write!(f, "invalid key material"),
            SignError::HsmError(msg) => write!(f, "HSM signer error: {}", msg),
        }
    }
}

impl std::error::Error for SignError {}

/// Fixed-size, `Copy` error for the bounded caller-buffer signing path
/// ([`ValidatorSigner::sign_vote_into`] /
/// [`ValidatorSigner::signature_output_bound`]) (RUN 422).
///
/// Unlike [`SignError`], which carries an owned `String` in its
/// [`SignError::HsmError`] variant, this type allocates nothing: every variant is
/// a fixed discriminant, so a backend failure is forwarded as a bounded code
/// rather than a heap diagnostic. It is intentionally small and `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedSignError {
    /// The signer advertises a suite its concrete backend does not implement.
    /// Detected by an ordinary runtime check (effective in release builds) BEFORE
    /// any cryptographic signing; the output buffer is left unchanged.
    SuiteMismatch,
    /// The caller-provided output buffer is smaller than
    /// [`ValidatorSigner::signature_output_bound`]. Detected before signing; the
    /// output buffer is left unchanged.
    OutputTooSmall,
    /// The signing backend refused (malformed key or signing failure). The output
    /// buffer is left unchanged. No diagnostic text is allocated.
    BackendFailed,
    /// This signer implementation does not provide the bounded caller-buffer
    /// path. The default trait methods return this WITHOUT invoking legacy
    /// signing and WITHOUT modifying the output buffer.
    Unsupported,
}

impl std::fmt::Display for BoundedSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundedSignError::SuiteMismatch => write!(f, "advertised suite does not match backend"),
            BoundedSignError::OutputTooSmall => write!(f, "output buffer too small"),
            BoundedSignError::BackendFailed => write!(f, "signing backend failed"),
            BoundedSignError::Unsupported => write!(f, "bounded signing path unsupported"),
        }
    }
}

impl std::error::Error for BoundedSignError {}

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

    /// Sign a timeout message for an explicit chain ID.
    fn sign_timeout_with_chain_id(
        &self,
        chain_id: ChainId,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError>;

    /// Returns the exact signature length this signer writes through
    /// [`sign_vote_into`](ValidatorSigner::sign_vote_into), for use by a caller
    /// that must admit/size output storage BEFORE signing (RUN 422).
    ///
    /// The bound is derived from the signer's pinned suite/backend capability, not
    /// from any caller-supplied value. Implementations that do not provide the
    /// bounded path return [`BoundedSignError::Unsupported`] and perform no
    /// signing.
    ///
    /// The default implementation returns [`BoundedSignError::Unsupported`].
    fn signature_output_bound(&self) -> Result<usize, BoundedSignError> {
        Err(BoundedSignError::Unsupported)
    }

    /// Signs `preimage` into the caller-owned `out` buffer, returning the number
    /// of bytes written (RUN 422).
    ///
    /// This is the bounded, caller-buffer counterpart to the legacy
    /// `Vec`-returning sign methods: the signature is written into storage the
    /// caller already owns instead of being returned on the heap. Suite and
    /// capacity are refused before any cryptographic signing, and the
    /// implementation writes into `out` only after a complete signature is
    /// available, so every error path leaves `out` unchanged.
    ///
    /// `preimage` is the already-constructed canonical signing preimage; this
    /// method does not re-derive domain separation. It introduces no new
    /// signature construction and preserves the suite's verification semantics.
    ///
    /// This primitive establishes neither authorization, freshness, D10
    /// eligibility, nor accountant admission: admitting/sizing `out` remains the
    /// caller's obligation.
    ///
    /// The default implementation returns [`BoundedSignError::Unsupported`]
    /// WITHOUT invoking legacy signing and WITHOUT modifying `out`.
    fn sign_vote_into(
        &self,
        preimage: &[u8],
        out: &mut [u8],
    ) -> Result<usize, BoundedSignError> {
        let _ = (preimage, out);
        Err(BoundedSignError::Unsupported)
    }
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

    /// Sign a preimage directly without computing additional context.
    ///
    /// This is an internal helper for use by the loopback remote signer transport,
    /// which receives fully-encoded preimages (including domain separators and
    /// all context) from the RemoteSignerClient.
    ///
    /// # Arguments
    ///
    /// * `preimage` - The complete signing preimage (with domain separator)
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    ///
    /// # Security Note
    ///
    /// This method assumes the preimage is already properly formatted with
    /// domain separators. Use with caution. Prefer using the `ValidatorSigner`
    /// trait methods which ensure proper preimage construction.
    pub fn sign_preimage(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signing_key
            .sign(preimage)
            .map_err(|_| SignError::CryptoError)
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
        let sign_bytes = timeout_signing_bytes(view, high_qc, self.validator_id);
        self.signing_key
            .sign(&sign_bytes)
            .map_err(|_| SignError::CryptoError)
    }

    fn sign_timeout_with_chain_id(
        &self,
        chain_id: ChainId,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError> {
        let sign_bytes =
            timeout_signing_bytes_with_chain_id(chain_id, view, high_qc, self.validator_id);
        self.signing_key
            .sign(&sign_bytes)
            .map_err(|_| SignError::CryptoError)
    }

    fn signature_output_bound(&self) -> Result<usize, BoundedSignError> {
        // Ordinary runtime suite check, effective in release builds (the legacy
        // constructor only asserts the suite in debug builds). Calling this
        // method directly must not bypass the check.
        if self.suite_id != ML_DSA_44_CONSENSUS_SUITE_ID {
            return Err(BoundedSignError::SuiteMismatch);
        }
        Ok(ML_DSA_44_SIGNATURE_SIZE)
    }

    fn sign_vote_into(
        &self,
        preimage: &[u8],
        out: &mut [u8],
    ) -> Result<usize, BoundedSignError> {
        // Suite/capacity refusal occurs before any cryptographic signing; on
        // refusal `out` is left unchanged.
        if self.suite_id != ML_DSA_44_CONSENSUS_SUITE_ID {
            return Err(BoundedSignError::SuiteMismatch);
        }
        // Delegate to the bounded crypto-layer caller-buffer path. The crypto
        // method checks capacity before signing and writes into `out` only after
        // a complete signature is available, so every error leaves `out`
        // unchanged. No diagnostic text is allocated.
        self.signing_key
            .sign_into(preimage, out)
            .map_err(|e| match e {
                BoundedMlDsa44SignError::OutputTooSmall => BoundedSignError::OutputTooSmall,
                BoundedMlDsa44SignError::InvalidKey
                | BoundedMlDsa44SignError::BackendFailed => BoundedSignError::BackendFailed,
            })
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
            Err(SignError::HsmError(_)) => {
                // HSM error type (T211) – acceptable in this context
            }
        }
    }

    // ------------------------------------------------------------------
    // RUN 422: bounded caller-buffer signing primitive (sign_vote_into /
    // signature_output_bound). These tests exercise ONLY the isolated local
    // primitive; no production caller, journal, or accountant admission is
    // involved.
    // ------------------------------------------------------------------

    /// A minimal signer that does NOT override the bounded caller-buffer
    /// methods, used to confirm the default-trait behavior returns `Unsupported`
    /// without invoking legacy signing or touching the output buffer.
    struct UnsupportedSigner {
        validator_id: ValidatorId,
        legacy_called: std::sync::atomic::AtomicBool,
    }

    impl ValidatorSigner for UnsupportedSigner {
        fn validator_id(&self) -> &ValidatorId {
            &self.validator_id
        }
        fn suite_id(&self) -> u16 {
            100
        }
        fn sign_proposal(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
            self.legacy_called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0u8; 8])
        }
        fn sign_vote(&self, _preimage: &[u8]) -> Result<Vec<u8>, SignError> {
            self.legacy_called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0u8; 8])
        }
        fn sign_timeout(
            &self,
            _view: u64,
            _high_qc: Option<&QuorumCertificate<[u8; 32]>>,
        ) -> Result<Vec<u8>, SignError> {
            self.legacy_called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0u8; 8])
        }
        fn sign_timeout_with_chain_id(
            &self,
            _chain_id: ChainId,
            _view: u64,
            _high_qc: Option<&QuorumCertificate<[u8; 32]>>,
        ) -> Result<Vec<u8>, SignError> {
            self.legacy_called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0u8; 8])
        }
    }

    /// Real-backend exact-capacity signing through `sign_vote_into` produces a
    /// signature that verifies under the matching public key.
    #[test]
    fn sign_vote_into_exact_capacity_signs_and_verifies() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let validator_id = ValidatorId::new(5);
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        let signer = LocalKeySigner::new(validator_id, 100, signing_key);

        let bound = signer
            .signature_output_bound()
            .expect("bound should be available");
        assert_eq!(bound, ML_DSA_44_SIGNATURE_SIZE);

        let message = b"test vote preimage";
        let mut out = vec![0u8; bound];
        let written = signer
            .sign_vote_into(message, &mut out)
            .expect("signing failed");
        assert_eq!(written, ML_DSA_44_SIGNATURE_SIZE);

        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(5, &pk, message, &out[..written]);
        assert!(result.is_ok(), "vote signature should verify");
    }

    /// A signature from `sign_vote_into` is rejected for a modified message and
    /// under the wrong key.
    #[test]
    fn sign_vote_into_rejected_for_modified_message_and_wrong_key() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk_other, _sk_other) =
            MlDsa44Backend::generate_keypair().expect("keygen failed");
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        let signer = LocalKeySigner::new(ValidatorId::new(9), 100, signing_key);

        let message = b"authentic vote preimage";
        let mut out = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];
        let written = signer
            .sign_vote_into(message, &mut out)
            .expect("signing failed");

        let backend = MlDsa44Backend::new();
        assert!(
            backend
                .verify_vote(9, &pk, b"tampered vote preimage", &out[..written])
                .is_err(),
            "modified message must be rejected"
        );
        assert!(
            backend
                .verify_vote(9, &pk_other, message, &out[..written])
                .is_err(),
            "wrong key must be rejected"
        );
    }

    /// Legacy `sign_vote` and new `sign_vote_into` each produce valid signatures
    /// for the same intended input. Byte equality is NOT required: ML-DSA-44
    /// signing uses OS randomness, so independent calls differ.
    #[test]
    fn sign_vote_into_and_legacy_sign_vote_both_verify() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        let signer = LocalKeySigner::new(ValidatorId::new(11), 100, signing_key);

        let message = b"shared vote preimage";
        let legacy = signer.sign_vote(message).expect("legacy signing failed");

        let mut out = vec![0u8; ML_DSA_44_SIGNATURE_SIZE];
        let written = signer
            .sign_vote_into(message, &mut out)
            .expect("bounded signing failed");

        let backend = MlDsa44Backend::new();
        assert!(
            backend.verify_vote(11, &pk, message, &legacy).is_ok(),
            "legacy signature should verify"
        );
        assert!(
            backend.verify_vote(11, &pk, message, &out[..written]).is_ok(),
            "bounded signature should verify"
        );
    }

    /// An undersized output buffer is refused before signing and left unchanged.
    #[test]
    fn sign_vote_into_undersized_output_refused_buffer_unchanged() {
        let (_pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        let signer = LocalKeySigner::new(ValidatorId::new(13), 100, signing_key);

        let mut out = vec![0xABu8; ML_DSA_44_SIGNATURE_SIZE - 1];
        let before = out.clone();
        let err = signer
            .sign_vote_into(b"preimage", &mut out)
            .expect_err("undersized output must be refused");
        assert_eq!(err, BoundedSignError::OutputTooSmall);
        assert_eq!(out, before, "output buffer must be unchanged on refusal");
    }

    /// An oversized output buffer succeeds; only the signature prefix is written
    /// and the suffix is left unchanged.
    #[test]
    fn sign_vote_into_oversized_output_suffix_unchanged() {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        let signer = LocalKeySigner::new(ValidatorId::new(15), 100, signing_key);

        let sentinel = 0x5Au8;
        let mut out = vec![sentinel; ML_DSA_44_SIGNATURE_SIZE + 32];
        let message = b"oversized vote preimage";
        let written = signer
            .sign_vote_into(message, &mut out)
            .expect("signing failed");
        assert_eq!(written, ML_DSA_44_SIGNATURE_SIZE);
        assert!(
            out[written..].iter().all(|&b| b == sentinel),
            "suffix beyond the signature must be unchanged"
        );

        let backend = MlDsa44Backend::new();
        assert!(
            backend.verify_vote(15, &pk, message, &out[..written]).is_ok(),
            "prefix signature should verify"
        );
    }

    /// A malformed signing key is refused and the output buffer is left
    /// unchanged.
    #[test]
    fn sign_vote_into_malformed_key_refused_buffer_unchanged() {
        // A key of the wrong length is structurally invalid and cannot decode.
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE - 1
        ]));
        let signer = LocalKeySigner::new(ValidatorId::new(17), 100, signing_key);

        let sentinel = 0xC3u8;
        let mut out = vec![sentinel; ML_DSA_44_SIGNATURE_SIZE];
        let before = out.clone();
        let err = signer
            .sign_vote_into(b"preimage", &mut out)
            .expect_err("malformed key must be refused");
        assert_eq!(err, BoundedSignError::BackendFailed);
        assert_eq!(out, before, "output buffer must be unchanged on refusal");
    }

    /// The default trait methods return `Unsupported` without invoking legacy
    /// signing and without modifying the output buffer.
    #[test]
    fn unsupported_default_methods_leave_output_and_skip_legacy() {
        let signer = UnsupportedSigner {
            validator_id: ValidatorId::new(19),
            legacy_called: std::sync::atomic::AtomicBool::new(false),
        };

        assert_eq!(
            signer.signature_output_bound(),
            Err(BoundedSignError::Unsupported)
        );

        let sentinel = 0x7Eu8;
        let mut out = vec![sentinel; ML_DSA_44_SIGNATURE_SIZE];
        let before = out.clone();
        let err = signer
            .sign_vote_into(b"preimage", &mut out)
            .expect_err("default must be Unsupported");
        assert_eq!(err, BoundedSignError::Unsupported);
        assert_eq!(out, before, "output must be unchanged");
        assert!(
            !signer.legacy_called.load(std::sync::atomic::Ordering::SeqCst),
            "default bounded path must not invoke legacy signing"
        );
    }

    /// `BoundedSignError` is `Copy`.
    #[test]
    fn bounded_sign_error_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<BoundedSignError>();
    }

    /// Runtime suite-mismatch refusal through BOTH bounded methods, effective in
    /// release builds.
    ///
    /// This test is DEBUG-EXCLUDED: `LocalKeySigner::new` asserts `suite_id == 100`
    /// via `debug_assert_eq!`, which panics at construction in debug builds. The
    /// bounded path's suite check is an ORDINARY runtime comparison, so it is only
    /// observable in a release test build (`cargo test --release`), where the
    /// constructor's debug assertion is compiled out.
    #[cfg(not(debug_assertions))]
    #[test]
    fn sign_vote_into_suite_mismatch_refused_release_only() {
        let (_pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let signing_key = Arc::new(ValidatorSigningKey::new(sk));
        // Advertise a non-ML-DSA-44 suite; only reachable without the debug assert.
        let signer = LocalKeySigner::new(ValidatorId::new(21), 101, signing_key);

        assert_eq!(
            signer.signature_output_bound(),
            Err(BoundedSignError::SuiteMismatch),
            "signature_output_bound must refuse a mismatched suite"
        );

        let sentinel = 0x11u8;
        let mut out = vec![sentinel; ML_DSA_44_SIGNATURE_SIZE];
        let before = out.clone();
        let err = signer
            .sign_vote_into(b"preimage", &mut out)
            .expect_err("sign_vote_into must refuse a mismatched suite");
        assert_eq!(err, BoundedSignError::SuiteMismatch);
        assert_eq!(out, before, "output must be unchanged on suite mismatch");
    }
}