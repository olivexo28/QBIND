//! Remote signer client and transport abstraction for consensus operations (T149, M10).
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
//! # Protocol Framing (M10)
//!
//! The remote signer protocol uses domain separation and replay protection:
//!
//! - **Domain separation tag**: `QBIND:remote-signer:v1` prefixed to all requests
//! - **Request ID**: Monotonic u64 per session for replay protection
//! - **Message type**: Identifies the signing operation type
//! - **Payload length**: 4-byte LE length prefix
//! - **Payload**: The actual signing preimage
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
//! - **Fail-closed**: If signer is unavailable, node refuses to sign (no unsafe fallback)
//! - **Replay protection**: Monotonic request_id prevents replay attacks within session
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
// M10: Domain Separation and Protocol Constants
// ============================================================================

/// Domain separation tag for remote signer protocol (M10).
///
/// This tag is prefixed to all remote signer requests to prevent
/// cross-protocol attacks. The "v1" suffix allows for future versioning.
pub const REMOTE_SIGNER_DOMAIN_TAG: &str = "QBIND:remote-signer:v1";

/// Message type identifiers for remote signer protocol (M10).
pub mod message_type {
    /// Sign proposal request.
    pub const SIGN_PROPOSAL: u8 = 0x01;
    /// Sign vote request.
    pub const SIGN_VOTE: u8 = 0x02;
    /// Sign timeout request.
    pub const SIGN_TIMEOUT: u8 = 0x03;
    /// Health check / ping request.
    pub const PING: u8 = 0x10;
}

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

impl RemoteSignRequestKind {
    /// Get the message type byte for this request kind (M10).
    pub fn message_type(&self) -> u8 {
        match self {
            RemoteSignRequestKind::Proposal => message_type::SIGN_PROPOSAL,
            RemoteSignRequestKind::Vote => message_type::SIGN_VOTE,
            RemoteSignRequestKind::Timeout => message_type::SIGN_TIMEOUT,
        }
    }

    /// Parse message type byte into request kind.
    pub fn from_message_type(msg_type: u8) -> Option<Self> {
        match msg_type {
            message_type::SIGN_PROPOSAL => Some(RemoteSignRequestKind::Proposal),
            message_type::SIGN_VOTE => Some(RemoteSignRequestKind::Vote),
            message_type::SIGN_TIMEOUT => Some(RemoteSignRequestKind::Timeout),
            _ => None,
        }
    }
}

/// Request to sign a consensus message.
///
/// This struct contains all information needed by a remote signer to produce
/// a signature, including:
/// - The validator identity and suite ID
/// - The type of message being signed
/// - The canonical signing preimage (with domain separator)
/// - Optional view number (for timeout messages)
/// - Request ID for replay protection (M10)
///
/// # Security Notes
///
/// - The `preimage` field contains the exact bytes to sign, including domain
///   separators like `QBIND_PROPOSAL_V1`, `QBIND_VOTE_V1`, `QBIND_TIMEOUT_V1`.
/// - Private key material is NEVER included in this request.
/// - The remote signer must validate that it has authority to sign for the
///   given `validator_id` and `suite_id`.
/// - The `request_id` must be monotonically increasing within a session (M10).
#[derive(Debug, Clone)]
pub struct RemoteSignRequest {
    /// Request ID for replay protection (M10).
    ///
    /// Must be monotonically increasing within a session.
    /// Server rejects requests with request_id <= last_seen_request_id.
    pub request_id: u64,
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
    /// The request was rate limited (T212).
    RateLimited,
    /// The server encountered an internal error (T212).
    ServerError,
    /// Replay attack detected: request_id not monotonically increasing (M10).
    ///
    /// This indicates the request_id was <= the last seen request_id in this session.
    ReplayDetected,
    /// The signer is unavailable (fail-closed behavior, M10).
    ///
    /// The node should NOT attempt to sign locally as a fallback.
    SignerUnavailable,
    /// Malformed response from the remote signer (M10).
    ///
    /// The response could not be parsed or had invalid structure.
    MalformedResponse,
}

impl std::fmt::Display for RemoteSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteSignError::InvalidKey => write!(f, "invalid key material"),
            RemoteSignError::CryptoError => write!(f, "cryptographic signing error"),
            RemoteSignError::Unauthorized => write!(f, "unauthorized signing request"),
            RemoteSignError::TransportError => write!(f, "transport error"),
            RemoteSignError::Timeout => write!(f, "signing request timed out"),
            RemoteSignError::RateLimited => write!(f, "signing request rate limited"),
            RemoteSignError::ServerError => write!(f, "remote signer server error"),
            RemoteSignError::ReplayDetected => write!(f, "replay detected: request_id not monotonic"),
            RemoteSignError::SignerUnavailable => write!(f, "signer unavailable (fail-closed)"),
            RemoteSignError::MalformedResponse => write!(f, "malformed response from signer"),
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
    /// Request ID echo for correlation (M10).
    pub request_id: u64,
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
/// # Replay Protection (M10)
///
/// The client maintains a monotonic `request_id` counter that is incremented
/// for each signing request. The server must reject any request with a
/// `request_id` that is not strictly greater than the last processed request_id.
///
/// # Fail-Closed Behavior (M10)
///
/// If the signer is unavailable or returns an error, the client returns an error.
/// The node must NOT fall back to local signing as this would defeat key isolation.
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
    /// Monotonic request ID counter for replay protection (M10).
    next_request_id: std::sync::atomic::AtomicU64,
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
            next_request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Get and increment the next request ID (M10).
    ///
    /// Returns a monotonically increasing ID for each call.
    fn next_request_id(&self) -> u64 {
        self.next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Common signing logic for all message types.
    fn sign_common(
        &self,
        kind: RemoteSignRequestKind,
        preimage: &[u8],
        view: Option<u64>,
    ) -> Result<Vec<u8>, SignError> {
        let request_id = self.next_request_id();
        let req = RemoteSignRequest {
            request_id,
            validator_id: self.validator_id,
            suite_id: self.suite_id,
            kind,
            view,
            preimage: preimage.to_vec(),
        };

        // M10: Fail-closed behavior - any transport error is fatal
        let resp = self
            .transport
            .send_sign_request(req)
            .map_err(|e| match e {
                RemoteSignError::SignerUnavailable => SignError::HsmError("signer unavailable".to_string()),
                RemoteSignError::ReplayDetected => SignError::HsmError("replay detected".to_string()),
                RemoteSignError::MalformedResponse => SignError::HsmError("malformed response".to_string()),
                _ => SignError::CryptoError,
            })?;

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
/// # Replay Protection (M10)
///
/// The loopback transport tracks the last seen request_id and rejects any
/// request where request_id <= last_request_id, mimicking production behavior.
///
/// # Security Notes
///
/// This is an in-process transport. The signing key remains in the same process
/// as the consensus harness. For production HSM support, use a real network
/// transport.
pub struct LoopbackSignerTransport {
    inner: Arc<LocalKeySigner>,
    /// Last processed request_id for replay protection (M10).
    last_request_id: std::sync::atomic::AtomicU64,
}

impl LoopbackSignerTransport {
    /// Create a new loopback transport wrapping a `LocalKeySigner`.
    ///
    /// # Arguments
    ///
    /// * `inner` - The local key signer to use for actual signing
    pub fn new(inner: Arc<LocalKeySigner>) -> Self {
        LoopbackSignerTransport {
            inner,
            last_request_id: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl RemoteSignerTransport for LoopbackSignerTransport {
    fn send_sign_request(
        &self,
        request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        // M10: Replay protection - request_id must be strictly greater than last
        let last_id = self.last_request_id.load(std::sync::atomic::Ordering::SeqCst);
        if request.request_id <= last_id {
            return Ok(RemoteSignResponse {
                request_id: request.request_id,
                signature: None,
                error: Some(RemoteSignError::ReplayDetected),
            });
        }
        self.last_request_id.store(request.request_id, std::sync::atomic::Ordering::SeqCst);

        // Validate suite_id matches
        if request.suite_id != self.inner.suite_id() {
            return Ok(RemoteSignResponse {
                request_id: request.request_id,
                signature: None,
                error: Some(RemoteSignError::Unauthorized),
            });
        }

        // Validate validator_id matches
        if request.validator_id != *self.inner.validator_id() {
            return Ok(RemoteSignResponse {
                request_id: request.request_id,
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
                request_id: request.request_id,
                signature: Some(sig),
                error: None,
            }),
            Err(SignError::InvalidKey) => Ok(RemoteSignResponse {
                request_id: request.request_id,
                signature: None,
                error: Some(RemoteSignError::InvalidKey),
            }),
            Err(SignError::CryptoError) | Err(SignError::HsmError(_)) => Ok(RemoteSignResponse {
                request_id: request.request_id,
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

// ============================================================================
// T212: Remote Signer Metrics
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics for remote signer client operations (T212).
///
/// Tracks:
/// - Total sign requests by kind (proposal/vote/timeout)
/// - Failed requests by reason (transport/timeout/server_reject/protocol)
/// - Last observed request latency
///
/// # Security Notes
///
/// No preimages, signatures, or key material is exposed.
/// Only aggregate counts and latency are tracked.
#[derive(Debug, Default)]
pub struct RemoteSignerMetrics {
    /// Total sign requests by kind.
    requests_proposal_total: AtomicU64,
    requests_vote_total: AtomicU64,
    requests_timeout_total: AtomicU64,

    /// Total failed requests by reason.
    failures_transport_total: AtomicU64,
    failures_timeout_total: AtomicU64,
    failures_server_reject_total: AtomicU64,
    failures_protocol_total: AtomicU64,

    /// Last observed request latency in milliseconds.
    last_latency_ms: AtomicU64,
}

impl RemoteSignerMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sign request result.
    ///
    /// # Arguments
    ///
    /// * `kind` - The type of signing operation ("proposal", "vote", or "timeout")
    /// * `ok` - Whether the request succeeded
    /// * `latency_ms` - The request latency in milliseconds
    /// * `reason` - On failure, the reason ("transport", "timeout", "server_reject", "protocol")
    pub fn record_result(&self, kind: &str, ok: bool, latency_ms: u64, reason: Option<&str>) {
        // Update latency
        self.last_latency_ms.store(latency_ms, Ordering::Relaxed);

        // Update request counter by kind
        match kind {
            "proposal" => {
                self.requests_proposal_total.fetch_add(1, Ordering::Relaxed);
            }
            "vote" => {
                self.requests_vote_total.fetch_add(1, Ordering::Relaxed);
            }
            "timeout" => {
                self.requests_timeout_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Update failure counter if not ok
        if !ok {
            if let Some(r) = reason {
                match r {
                    "transport" => {
                        self.failures_transport_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    "timeout" => {
                        self.failures_timeout_total.fetch_add(1, Ordering::Relaxed);
                    }
                    "server_reject" => {
                        self.failures_server_reject_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    "protocol" => {
                        self.failures_protocol_total.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get total proposal sign requests.
    pub fn requests_proposal_total(&self) -> u64 {
        self.requests_proposal_total.load(Ordering::Relaxed)
    }

    /// Get total vote sign requests.
    pub fn requests_vote_total(&self) -> u64 {
        self.requests_vote_total.load(Ordering::Relaxed)
    }

    /// Get total timeout sign requests.
    pub fn requests_timeout_total(&self) -> u64 {
        self.requests_timeout_total.load(Ordering::Relaxed)
    }

    /// Get total transport failures.
    pub fn failures_transport_total(&self) -> u64 {
        self.failures_transport_total.load(Ordering::Relaxed)
    }

    /// Get total timeout failures.
    pub fn failures_timeout_total(&self) -> u64 {
        self.failures_timeout_total.load(Ordering::Relaxed)
    }

    /// Get total server reject failures.
    pub fn failures_server_reject_total(&self) -> u64 {
        self.failures_server_reject_total.load(Ordering::Relaxed)
    }

    /// Get total protocol failures.
    pub fn failures_protocol_total(&self) -> u64 {
        self.failures_protocol_total.load(Ordering::Relaxed)
    }

    /// Get the last observed latency in milliseconds.
    pub fn last_latency_ms(&self) -> u64 {
        self.last_latency_ms.load(Ordering::Relaxed)
    }

    /// Format metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# Remote signer client metrics (T212)\n");
        output.push_str(&format!(
            "qbind_remote_sign_requests_total{{kind=\"proposal\"}} {}\n",
            self.requests_proposal_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_requests_total{{kind=\"vote\"}} {}\n",
            self.requests_vote_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_requests_total{{kind=\"timeout\"}} {}\n",
            self.requests_timeout_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_failures_total{{reason=\"transport\"}} {}\n",
            self.failures_transport_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_failures_total{{reason=\"timeout\"}} {}\n",
            self.failures_timeout_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_failures_total{{reason=\"server_reject\"}} {}\n",
            self.failures_server_reject_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_failures_total{{reason=\"protocol\"}} {}\n",
            self.failures_protocol_total()
        ));
        output.push_str(&format!(
            "qbind_remote_sign_last_latency_ms {}\n",
            self.last_latency_ms()
        ));
        output
    }
}

// ============================================================================
// T212: TcpKemTlsSignerTransport
// ============================================================================

use std::time::{Duration, Instant};

use crate::secure_channel::{ChannelError, SecureChannel};
use qbind_net::ClientConnectionConfig;

/// Default timeout for remote signer requests in milliseconds.
pub const DEFAULT_REMOTE_SIGNER_TIMEOUT_MS: u64 = 2000;

/// Maximum preimage size for remote sign requests (16 KB).
pub const MAX_PREIMAGE_SIZE: usize = 16 * 1024;

/// TCP/KEMTLS transport for remote signing operations (T212).
///
/// This transport establishes a KEMTLS-protected TCP connection to a remote
/// signer service and sends/receives `RemoteSignRequest`/`RemoteSignResponse`
/// messages over the encrypted channel.
///
/// # Security Properties
///
/// - All communication is encrypted via KEMTLS (PQC-only, no classical TLS)
/// - Private key material NEVER crosses the transport boundary
/// - The transport only sends preimages and receives signatures
///
/// # Usage
///
/// ```ignore
/// use qbind_node::remote_signer::TcpKemTlsSignerTransport;
///
/// let transport = TcpKemTlsSignerTransport::new(
///     "kemtls://signer.local:9443",
///     kemtls_config,
/// )?;
///
/// let response = transport.send_sign_request(request)?;
/// ```
pub struct TcpKemTlsSignerTransport {
    /// Remote signer address (host:port).
    addr: String,
    /// KEMTLS client configuration.
    kemtls_config: ClientConnectionConfig,
    /// Request timeout in milliseconds.
    timeout_ms: u64,
    /// Optional metrics.
    metrics: Option<Arc<RemoteSignerMetrics>>,
}

impl TcpKemTlsSignerTransport {
    /// Create a new TCP/KEMTLS transport.
    ///
    /// # Arguments
    ///
    /// * `url` - Remote signer URL (e.g., "kemtls://signer.local:9443")
    /// * `kemtls_config` - KEMTLS client configuration
    ///
    /// # Returns
    ///
    /// A new transport instance, or an error if the URL is invalid.
    pub fn new(url: &str, kemtls_config: ClientConnectionConfig) -> Result<Self, RemoteSignError> {
        let addr = parse_remote_signer_url(url)?;
        Ok(TcpKemTlsSignerTransport {
            addr,
            kemtls_config,
            timeout_ms: DEFAULT_REMOTE_SIGNER_TIMEOUT_MS,
            metrics: None,
        })
    }

    /// Create a new transport with custom timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Create a new transport with metrics.
    pub fn with_metrics(mut self, metrics: Arc<RemoteSignerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get the remote signer address.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Perform a ping/reachability check.
    ///
    /// This attempts to establish a KEMTLS connection and immediately close it.
    /// Used by `validate_mainnet_invariants()` to verify signer reachability.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signer is reachable, `Err(RemoteSignError)` otherwise.
    pub fn ping(&self) -> Result<(), RemoteSignError> {
        let _channel = SecureChannel::connect(&self.addr, self.kemtls_config.clone())
            .map_err(|_| RemoteSignError::TransportError)?;
        Ok(())
    }

    /// Encode a RemoteSignRequest to bytes for wire transmission (M10).
    ///
    /// # Wire Format (M10)
    ///
    /// ```text
    /// domain_tag:     "QBIND:remote-signer:v1" (23 bytes)
    /// request_id:     8 bytes LE
    /// validator_id:   8 bytes LE
    /// suite_id:       2 bytes LE
    /// kind:           1 byte (message type)
    /// view_present:   1 byte flag
    /// view:           8 bytes LE (if present)
    /// preimage_len:   4 bytes LE
    /// preimage:       variable length
    /// ```
    fn encode_request(request: &RemoteSignRequest) -> Vec<u8> {
        // Calculate capacity: domain_tag(23) + request_id(8) + validator_id(8) + suite_id(2)
        //                   + kind(1) + view(9) + preimage_len(4) + preimage
        let domain_tag = REMOTE_SIGNER_DOMAIN_TAG.as_bytes();
        let mut buf = Vec::with_capacity(domain_tag.len() + 32 + request.preimage.len());

        // M10: Domain separation tag
        buf.extend_from_slice(domain_tag);

        // M10: Request ID for replay protection
        buf.extend_from_slice(&request.request_id.to_le_bytes());

        // validator_id: 8 bytes LE
        buf.extend_from_slice(&request.validator_id.as_u64().to_le_bytes());

        // suite_id: 2 bytes LE
        buf.extend_from_slice(&request.suite_id.to_le_bytes());

        // kind: 1 byte (using message_type for clarity)
        buf.push(request.kind.message_type());

        // view: 1 byte present flag + 8 bytes LE if present
        if let Some(v) = request.view {
            buf.push(1u8);
            buf.extend_from_slice(&v.to_le_bytes());
        } else {
            buf.push(0u8);
            buf.extend_from_slice(&[0u8; 8]);
        }

        // preimage_len: 4 bytes LE
        let preimage_len = request.preimage.len() as u32;
        buf.extend_from_slice(&preimage_len.to_le_bytes());

        // preimage
        buf.extend_from_slice(&request.preimage);

        buf
    }

    /// Decode a RemoteSignResponse from bytes (M10).
    ///
    /// # Wire Format (M10)
    ///
    /// Success:
    /// ```text
    /// status:         1 byte (0 = success)
    /// request_id:     8 bytes LE (echo)
    /// signature_len:  4 bytes LE
    /// signature:      variable length
    /// ```
    ///
    /// Error:
    /// ```text
    /// status:         1 byte (non-zero = error)
    /// request_id:     8 bytes LE (echo)
    /// error_code:     1 byte
    /// ```
    ///
    /// # Arguments
    ///
    /// * `data` - The raw response bytes from the remote signer
    /// * `expected_request_id` - The request_id we sent, used to verify the
    ///   response correlation. If the echoed request_id doesn't match,
    ///   returns `MalformedResponse` error.
    fn decode_response(data: &[u8], expected_request_id: u64) -> Result<RemoteSignResponse, RemoteSignError> {
        // Minimum: status(1) + request_id(8) + error_code(1) = 10 bytes
        if data.len() < 10 {
            return Err(RemoteSignError::MalformedResponse);
        }

        let status = data[0];
        let request_id = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);

        // Verify request_id echo matches (M10 correlation)
        if request_id != expected_request_id {
            return Err(RemoteSignError::MalformedResponse);
        }

        if status == 0 {
            // Success: signature follows
            if data.len() < 13 {
                return Err(RemoteSignError::MalformedResponse);
            }
            let sig_len = u32::from_le_bytes([data[9], data[10], data[11], data[12]]) as usize;
            if data.len() < 13 + sig_len {
                return Err(RemoteSignError::MalformedResponse);
            }
            let signature = data[13..13 + sig_len].to_vec();
            Ok(RemoteSignResponse {
                request_id,
                signature: Some(signature),
                error: None,
            })
        } else {
            // Error: error_code follows request_id
            let error_code = data[9];
            let error = match error_code {
                1 => RemoteSignError::InvalidKey,
                2 => RemoteSignError::CryptoError,
                3 => RemoteSignError::Unauthorized,
                4 => RemoteSignError::TransportError,
                5 => RemoteSignError::Timeout,
                6 => RemoteSignError::RateLimited,
                7 => RemoteSignError::ServerError,
                8 => RemoteSignError::ReplayDetected,
                9 => RemoteSignError::SignerUnavailable,
                10 => RemoteSignError::MalformedResponse,
                _ => RemoteSignError::MalformedResponse,
            };
            Ok(RemoteSignResponse {
                request_id,
                signature: None,
                error: Some(error),
            })
        }
    }
}

impl RemoteSignerTransport for TcpKemTlsSignerTransport {
    fn send_sign_request(
        &self,
        request: RemoteSignRequest,
    ) -> Result<RemoteSignResponse, RemoteSignError> {
        let start = Instant::now();
        let kind_str = match request.kind {
            RemoteSignRequestKind::Proposal => "proposal",
            RemoteSignRequestKind::Vote => "vote",
            RemoteSignRequestKind::Timeout => "timeout",
        };
        let expected_request_id = request.request_id;

        // Validate preimage size
        if request.preimage.len() > MAX_PREIMAGE_SIZE {
            if let Some(ref m) = self.metrics {
                m.record_result(kind_str, false, 0, Some("protocol"));
            }
            return Err(RemoteSignError::MalformedResponse);
        }

        // M10: Fail-closed - if we can't connect, return SignerUnavailable
        let mut channel = match SecureChannel::connect(&self.addr, self.kemtls_config.clone()) {
            Ok(ch) => ch,
            Err(_) => {
                let latency = start.elapsed().as_millis() as u64;
                if let Some(ref m) = self.metrics {
                    m.record_result(kind_str, false, latency, Some("transport"));
                }
                return Err(RemoteSignError::SignerUnavailable);
            }
        };

        // Set socket timeout
        let timeout = Duration::from_millis(self.timeout_ms);
        let _ = channel.stream().set_read_timeout(Some(timeout));
        let _ = channel.stream().set_write_timeout(Some(timeout));

        // Encode and send request
        let request_bytes = Self::encode_request(&request);
        if let Err(e) = channel.send_app(&request_bytes) {
            // Log error details without exposing sensitive data
            eprintln!("[WARN] Remote signer send failed: {:?} ({})", e, kind_str);
            let latency = start.elapsed().as_millis() as u64;
            if let Some(ref m) = self.metrics {
                m.record_result(kind_str, false, latency, Some("transport"));
            }
            return Err(RemoteSignError::SignerUnavailable);
        }

        // Receive response
        let response_bytes = match channel.recv_app() {
            Ok(data) => data,
            Err(ChannelError::Io(ref e))
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                let latency = start.elapsed().as_millis() as u64;
                if let Some(ref m) = self.metrics {
                    m.record_result(kind_str, false, latency, Some("timeout"));
                }
                return Err(RemoteSignError::Timeout);
            }
            Err(_) => {
                let latency = start.elapsed().as_millis() as u64;
                if let Some(ref m) = self.metrics {
                    m.record_result(kind_str, false, latency, Some("transport"));
                }
                return Err(RemoteSignError::SignerUnavailable);
            }
        };

        // Decode response with request_id verification (M10)
        let response = match Self::decode_response(&response_bytes, expected_request_id) {
            Ok(r) => r,
            Err(_) => {
                let latency = start.elapsed().as_millis() as u64;
                if let Some(ref m) = self.metrics {
                    m.record_result(kind_str, false, latency, Some("protocol"));
                }
                return Err(RemoteSignError::MalformedResponse);
            }
        };

        let latency = start.elapsed().as_millis() as u64;

        // Record metrics
        if let Some(ref m) = self.metrics {
            let ok = response.signature.is_some();
            let reason = if ok { None } else { Some("server_reject") };
            m.record_result(kind_str, ok, latency, reason);
        }

        if let Some(err) = response.error {
            return Err(err);
        }

        Ok(response)
    }
}

impl std::fmt::Debug for TcpKemTlsSignerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpKemTlsSignerTransport")
            .field("addr", &self.addr)
            .field("timeout_ms", &self.timeout_ms)
            .field("kemtls_config", &"<redacted>")
            .finish()
    }
}

// ============================================================================
// T212: Additional RemoteSignError Variants
// ============================================================================

/// Parse a remote signer URL to extract the host:port.
///
/// Supported URL schemes:
/// - `kemtls://host:port` (preferred)
/// - `host:port` (bare address)
///
/// # Returns
///
/// The host:port string, or an error if the URL is invalid.
fn parse_remote_signer_url(url: &str) -> Result<String, RemoteSignError> {
    // Strip kemtls:// prefix if present
    let addr = if let Some(rest) = url.strip_prefix("kemtls://") {
        rest.to_string()
    } else {
        url.to_string()
    };

    // Validate that it looks like host:port
    if !addr.contains(':') {
        return Err(RemoteSignError::TransportError);
    }

    Ok(addr)
}
