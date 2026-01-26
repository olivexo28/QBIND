//! Remote signer client and transport abstraction for consensus operations (T149).
//!
//! This module provides a clean remote signer protocol model and transport abstraction
//! to enable future integration with HSMs or remote signers without modifying the
//! consensus harness code.
//!
//! # Architecture
//!
//! The remote signer architecture consists of three main components:
//!
//! 1. **RPC Model**: Request/response types that define the remote signing protocol
//!    - `RemoteSignRequest`: Signing request with preimage and metadata
//!    - `RemoteSignResponse`: Signature result or error
//!    - `RemoteSignError`: Error types for remote signing operations
//!
//! 2. **Transport Abstraction**: `RemoteSignerTransport` trait for implementing
//!    different transport mechanisms (loopback, Unix socket, TCP, gRPC, etc.)
//!
//! 3. **Client Implementation**: `RemoteSignerClient` implements `ValidatorSigner`
//!    using a pluggable transport backend
//!
//! # Loopback Transport
//!
//! The `LoopbackSignerTransport` provides an in-process implementation that exercises
//! the remote protocol shape while using `LocalKeySigner` for actual signing. This
//! enables testing the remote signer plumbing without requiring real network I/O or HSM.
//!
//! # Security Notes
//!
//! - Private key material NEVER crosses the transport boundary
//! - All signing happens on the remote side (or in LocalKeySigner for loopback)
//! - The client only receives back the signature bytes
//! - Request preimages include domain separators (QBIND_PROPOSAL_V1, etc.)
//!
//! # Future Extensions
//!
//! To add a real network transport or HSM backend:
//! 1. Implement `RemoteSignerTransport` for your transport mechanism
//! 2. Add a new `SignerBackend` variant in `validator_config.rs`
//! 3. Wire it in `NodeHotstuffHarness::new_from_validator_config`
//!
//! The consensus harness code remains unchanged.

use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_consensus::timeout::timeout_signing_bytes;

use crate::validator_signer::{LocalKeySigner, SignError, ValidatorSigner};

// ============================================================================
// Remote Signer RPC Model
// ============================================================================

/// Type of signing operation requested.
///
/// This enum identifies which consensus operation is being signed, allowing
/// the remote signer to apply appropriate validation or policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignRequestKind {
    /// Sign a block proposal.
    Proposal,
    /// Sign a vote.
    Vote,
    /// Sign a timeout message.
    Timeout,
}

/// Request to sign a consensus message.
///
/// This struct contains all information needed by a remote signer to produce
/// a signature, including:
/// - The validator identity and suite ID
/// - The type of message being signed
/// - The canonical signing preimage (with domain separator)
/// - Optional view number (for timeout messages)
///
/// # Security Notes
///
/// - The `preimage` field contains the exact bytes to sign, including domain
///   separators like `QBIND_PROPOSAL_V1`, `QBIND_VOTE_V1`, `QBIND_TIMEOUT_V1`.
/// - Private key material is NEVER included in this request.
/// - The remote signer must validate that it has authority to sign for the
///   given `validator_id` and `suite_id`.
#[derive(Debug, Clone)]
pub struct RemoteSignRequest {
    /// The validator ID for which to sign.
    pub validator_id: ValidatorId,
    /// The signature suite ID (100 for ML-DSA-44).
    pub suite_id: u16,
    /// The type of signing operation.
    pub kind: RemoteSignRequestKind,
    /// The view number (only used for timeout messages).
    pub view: Option<u64>,
    /// The canonical signing preimage (with domain separator).
    pub preimage: Vec<u8>,
}

/// Error types for remote signing operations.
///
/// These errors represent failure modes that can occur during remote signing,
/// including authentication, authorization, transport, and cryptographic errors.
///
/// # Security Notes
///
/// Error variants NEVER include key material or sensitive data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignError {
    /// The key material is invalid or corrupted.
    InvalidKey,
    /// The underlying cryptographic operation failed.
    CryptoError,
    /// The request was not authorized (e.g., wrong validator_id or suite_id).
    Unauthorized,
    /// The transport layer encountered an error.
    TransportError,
    /// The operation timed out.
    Timeout,
}

impl std::fmt::Display for RemoteSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteSignError::InvalidKey => write!(f, "invalid key material"),
            RemoteSignError::CryptoError => write!(f, "cryptographic signing error"),
            RemoteSignError::Unauthorized => write!(f, "unauthorized signing request"),
            RemoteSignError::TransportError => write!(f, "transport error"),
            RemoteSignError::Timeout => write!(f, "signing request timed out"),
        }
    }
}

impl std::error::Error for RemoteSignError {}

/// Response from a remote signing operation.
///
/// On success, contains the signature bytes. On failure, contains an error.
/// Exactly one of `signature` or `error` must be `Some`.
#[derive(Debug, Clone)]
pub struct RemoteSignResponse {
    /// The signature bytes (on success).
    pub signature: Option<Vec<u8>>,
    /// The error (on failure).
    pub error: Option<RemoteSignError>,
}

// ============================================================================
// Transport Abstraction
// ============================================================================

/// Transport abstraction for remote signing operations.
///
/// This trait represents a single logical round trip to a remote signer.
/// Implementations can use different transport mechanisms:
/// - In-process loopback (for testing)
/// - Unix domain sockets
/// - TCP sockets
/// - gRPC
/// - HSM vendor-specific protocols
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow sharing across
/// async tasks and threads.
pub trait RemoteSignerTransport: Send + Sync {
    /// Send a signing request and receive a response.
    ///
    /// This is a synchronous operation that blocks until the signature is
    /// available or an error occurs.
    ///
    /// # Arguments
    ///
    /// * `request` - The signing request
    ///
    /// # Returns
    ///
    /// The signing response (signature or error).
    fn send_sign_request(
        &self,
        request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError>;
}

// ============================================================================
// RemoteSignerClient
// ============================================================================

/// Remote signer client implementing `ValidatorSigner`.
///
/// This client uses a pluggable `RemoteSignerTransport` to delegate signing
/// operations to a remote signer (or loopback for testing).
///
/// # Usage
///
/// ```ignore
/// use qbind_node::remote_signer::{RemoteSignerClient, LoopbackSignerTransport};
/// use std::sync::Arc;
///
/// // Create transport (loopback for testing)
/// let transport = Arc::new(LoopbackSignerTransport::new(local_key_signer));
///
/// // Create client
/// let client = RemoteSignerClient::new(validator_id, 100, transport);
///
/// // Use as ValidatorSigner
/// let signature = client.sign_proposal(&preimage)?;
/// ```
pub struct RemoteSignerClient {
    validator_id: ValidatorId,
    suite_id: u16,
    transport: Arc<dyn RemoteSignerTransport>,
}

impl RemoteSignerClient {
    /// Create a new remote signer client.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator ID
    /// * `suite_id` - The signature suite ID (should be 100 for ML-DSA-44)
    /// * `transport` - The transport implementation
    pub fn new(
        validator_id: ValidatorId,
        suite_id: u16,
        transport: Arc<dyn RemoteSignerTransport>,
    ) -> Self {
        RemoteSignerClient {
            validator_id,
            suite_id,
            transport,
        }
    }

    /// Common signing logic for all message types.
    fn sign_common(
        &self,
        kind: RemoteSignRequestKind,
        preimage: &[u8],
        view: Option<u64>,
    ) -> Result<Vec<u8>, SignError> {
        let req = RemoteSignRequest {
            validator_id: self.validator_id,
            suite_id: self.suite_id,
            kind,
            view,
            preimage: preimage.to_vec(),
        };

        let resp = self
            .transport
            .send_sign_request(req)
            .map_err(|_e| SignError::CryptoError)?;

        match (resp.signature, resp.error) {
            (Some(sig), None) => Ok(sig),
            (_, Some(RemoteSignError::InvalidKey)) => Err(SignError::InvalidKey),
            (_, Some(RemoteSignError::Unauthorized)) => Err(SignError::InvalidKey),
            (_, Some(_)) => Err(SignError::CryptoError),
            (None, None) => Err(SignError::CryptoError),
        }
    }
}

impl std::fmt::Debug for RemoteSignerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSignerClient")
            .field("validator_id", &self.validator_id)
            .field("suite_id", &self.suite_id)
            .field("transport", &"<redacted>")
            .finish()
    }
}

impl ValidatorSigner for RemoteSignerClient {
    fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }

    fn suite_id(&self) -> u16 {
        self.suite_id
    }

    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_common(RemoteSignRequestKind::Proposal, preimage, None)
    }

    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_common(RemoteSignRequestKind::Vote, preimage, None)
    }

    fn sign_timeout(
        &self,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError> {
        // Compute the canonical timeout signing preimage
        let preimage = timeout_signing_bytes(view, high_qc, self.validator_id);
        self.sign_common(RemoteSignRequestKind::Timeout, &preimage, Some(view))
    }
}

// ============================================================================
// Loopback Transport
// ============================================================================

/// Loopback transport that uses `LocalKeySigner` for signing.
///
/// This transport exercises the remote signer protocol shape without requiring
/// real network I/O or HSM. It's useful for:
/// - Testing the remote signer plumbing
/// - Validating that RemoteSignerClient produces identical signatures to LocalKeySigner
/// - Development and debugging
///
/// # Security Notes
///
/// This is an in-process transport. The signing key remains in the same process
/// as the consensus harness. For production HSM support, use a real network
/// transport.
pub struct LoopbackSignerTransport {
    inner: Arc<LocalKeySigner>,
}

impl LoopbackSignerTransport {
    /// Create a new loopback transport wrapping a `LocalKeySigner`.
    ///
    /// # Arguments
    ///
    /// * `inner` - The local key signer to use for actual signing
    pub fn new(inner: Arc<LocalKeySigner>) -> Self {
        LoopbackSignerTransport { inner }
    }
}

impl RemoteSignerTransport for LoopbackSignerTransport {
    fn send_sign_request(
        &self,
        request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        // Validate suite_id matches
        if request.suite_id != self.inner.suite_id() {
            return Ok(RemoteSignResponse {
                signature: None,
                error: Some(RemoteSignError::Unauthorized),
            });
        }

        // Validate validator_id matches
        if request.validator_id != *self.inner.validator_id() {
            return Ok(RemoteSignResponse {
                signature: None,
                error: Some(RemoteSignError::Unauthorized),
            });
        }

        // Perform signing based on request kind
        let result = match request.kind {
            RemoteSignRequestKind::Proposal => self.inner.sign_proposal(&request.preimage),
            RemoteSignRequestKind::Vote => self.inner.sign_vote(&request.preimage),
            RemoteSignRequestKind::Timeout => {
                // For timeout, we already have the fully encoded preimage bytes,
                // so we can just sign the preimage directly
                self.inner.sign_preimage(&request.preimage)
            }
        };

        // Convert result to response
        match result {
            Ok(sig) => Ok(RemoteSignResponse {
                signature: Some(sig),
                error: None,
            }),
            Err(SignError::InvalidKey) => Ok(RemoteSignResponse {
                signature: None,
                error: Some(RemoteSignError::InvalidKey),
            }),
            Err(SignError::CryptoError) => Ok(RemoteSignResponse {
                signature: None,
                error: Some(RemoteSignError::CryptoError),
            }),
        }
    }
}

impl std::fmt::Debug for LoopbackSignerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackSignerTransport")
            .field("inner", &"<redacted>")
            .finish()
    }
}
