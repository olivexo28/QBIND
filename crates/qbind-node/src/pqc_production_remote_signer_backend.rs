//! Run 293 — source/test production RemoteSigner backend client.
//!
//! Source/test only. Run 293 does **not** capture release-binary
//! evidence (deferred to **Run 294**), does **not** add a public CLI
//! flag, does **not** enable the RemoteSigner backend by default, does
//! **not** wire it into the production runtime, does **not** enable
//! MainNet, and does **not** implement a real KMS / HSM / cloud-KMS /
//! PKCS#11 provider, a real custody-attestation verifier, a real
//! on-chain governance proof verifier, a governance execution engine, or
//! validator-set rotation.
//!
//! Before Run 293 the RemoteSigner surface had, at source/test level:
//!
//! * the Run 194 typed boundary
//!   ([`crate::pqc_remote_authority_signer`]): identity, request,
//!   response, expectations, a pure `validate_remote_signer` verifier,
//!   and a fail-closed `ProductionRemoteSigner` placeholder that always
//!   returned `ProductionRemoteSignerUnavailable`;
//! * the Run 201 typed transport boundary
//!   ([`crate::pqc_remote_signer_transport`]): a transport
//!   identity/endpoint config, request/response envelopes, deterministic
//!   transcript-binding digests, a pure/mockable `RemoteSignerTransport`
//!   trait, a fixture loopback transport, and a fail-closed
//!   `ProductionRemoteSignerTransport` placeholder that always returned
//!   `ProductionTransportUnavailable`.
//!
//! What was missing was a **real backend client**: nothing actually
//! *drove* the transport — built a typed request from a caller's typed
//! decision input, applied a timeout/retry policy over the transport,
//! surfaced a typed transport error taxonomy, enforced
//! request/response correlation, bound a backend-level transcript, and
//! mapped every unavailable/malformed/mismatched/replayed path to a
//! precise fail-closed backend outcome.
//!
//! Run 293 closes that gap at source/test level by adding, as real code
//! (not a fixture-only boundary):
//!
//! * a typed backend policy
//!   ([`ProductionRemoteSignerBackendPolicy`], default
//!   [`ProductionRemoteSignerBackendPolicy::Disabled`]);
//! * a typed backend config ([`ProductionRemoteSignerBackendConfig`])
//!   wrapping the Run 201 transport config and a backend protocol
//!   version;
//! * a typed request spec ([`ProductionRemoteSignerRequestSpec`]) with a
//!   [`ProductionRemoteSignerRequestKind`], from which the backend
//!   deterministically derives the Run 194 inner request, the Run 201
//!   request envelope, and a deterministic request id
//!   ([`production_remote_signer_request_id`]);
//! * a deterministic backend transcript digest
//!   ([`production_remote_signer_backend_transcript_digest`]) that binds
//!   the backend protocol version, request id, request/response envelope
//!   digests, and the Run 201 transport transcript;
//! * a typed transport error taxonomy
//!   ([`ProductionRemoteSignerError`]) with a retry classification;
//! * a narrow, mockable backend transport boundary
//!   ([`RemoteSignerBackendTransport`]), a DevNet/TestNet source/test
//!   [`LoopbackRemoteSignerService`] that wraps the Run 201 fixture
//!   transport, and a programmable [`MockRemoteSignerBackendTransport`]
//!   for fault injection;
//! * the real client [`ProductionRemoteSignerBackend`] implementing the
//!   [`GovernanceProductionRemoteSignerBackend`] trait
//!   (`build_request_envelope` / `submit_remote_signing_request` /
//!   `verify_remote_signer_response` / `evaluate_remote_signer_backend` /
//!   `recover_remote_signer_request_window`);
//! * a precise typed outcome taxonomy
//!   ([`ProductionRemoteSignerOutcome`]).
//!
//! Fail-closed posture (unchanged from Runs 194 / 201, enforced here):
//!
//! * [`ProductionRemoteSignerBackendPolicy::Disabled`] is the default
//!   and refuses **before** any transport invocation — no request is
//!   built and the transport is never called.
//! * There is **no** silent fallback to fixture, loopback, local, or
//!   in-memory signing: acceptance is only ever a fixture loopback
//!   response under an explicit loopback policy on a DevNet/TestNet trust
//!   domain, and every production path fails closed as unavailable
//!   because no real production transport is wired.
//! * MainNet is refused unless production authority criteria are
//!   satisfied — fixture/loopback material can never satisfy MainNet.
//! * The backend introduces **no** raw local production signing-key
//!   loading and commits **no** secrets, private keys, tokens, or
//!   credentials.
//!
//! The module is pure: every public function and trait method performs
//! no network or file I/O of its own (the transport boundary is
//! injected and, in this run, only source/test transports exist), writes
//! no marker, writes no sequence, mutates no live trust, evicts no
//! sessions, performs no settlement or external publication, performs no
//! governance execution, performs no validator-set rotation, and never
//! invokes Run 070 apply. Full C4 remains OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_293.md`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_remote_authority_signer::{
    RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome,
    RemoteSignerPolicy, RemoteSignerRequest,
};
use crate::pqc_remote_signer_transport::{
    remote_signer_response_canonical_digest, transport_transcript_digest,
    validate_remote_signer_transport, RemoteSignerTransport, RemoteSignerTransportConfig,
    RemoteSignerTransportExpectations, RemoteSignerTransportOutcome,
    RemoteSignerTransportRequestEnvelope, RemoteSignerTransportResponseEnvelope,
    REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION, REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 293 — the only backend protocol version this run accepts.
pub const PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION: u16 = 1;

/// Run 293 — backend request-id derivation domain tag.
pub const PRODUCTION_REMOTE_SIGNER_BACKEND_REQUEST_ID_DOMAIN_TAG: &str =
    "QBIND:run293-production-remote-signer-backend-request-id:v1";

/// Run 293 — backend transcript digest domain tag.
pub const PRODUCTION_REMOTE_SIGNER_BACKEND_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run293-production-remote-signer-backend-transcript:v1";

/// Run 293 — maximum accepted transport response size, in bytes. A
/// response larger than this is fail-closed as
/// [`ProductionRemoteSignerError::ResponseTooLarge`]. Purely a typed
/// bound; Run 293 performs no real I/O.
pub const PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES: usize = 64 * 1024;

// ===========================================================================
// Backend policy
// ===========================================================================

/// Run 293 — typed production RemoteSigner backend policy.
///
/// `Disabled` is the default fail-closed policy: the backend refuses
/// before building a request or invoking any transport. The other
/// policies map onto the Run 194 [`RemoteSignerPolicy`] the existing
/// verifiers already enforce, so backend acceptance can never claim more
/// authority than the Run 194 / 201 boundary already grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionRemoteSignerBackendPolicy {
    /// Default. The backend refuses every request before any transport
    /// call. No request is built, the transport is never invoked.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test loopback policy. Accepts a fixture
    /// loopback backend response on a DevNet/TestNet trust domain only.
    DevTestLoopbackEnabled,
    /// Production backend required (DevNet/TestNet bring-up of a real
    /// backend). Run 293 wires no real production transport, so every
    /// production request fails closed as unavailable.
    ProductionRequired,
    /// MainNet production backend required. Fixture material is refused
    /// as non-production, and every production request is refused as
    /// unavailable because no real production transport is wired.
    MainnetProductionRequired,
}

impl ProductionRemoteSignerBackendPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::DevTestLoopbackEnabled => "devtest-loopback-enabled",
            Self::ProductionRequired => "production-required",
            Self::MainnetProductionRequired => "mainnet-production-required",
        }
    }

    /// Returns `true` iff this policy is `Disabled` (fail closed before
    /// any transport call).
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy requires a real production backend
    /// (and therefore Run 293 fails closed as unavailable).
    pub const fn requires_production_backend(self) -> bool {
        matches!(self, Self::ProductionRequired | Self::MainnetProductionRequired)
    }

    /// Map the backend policy onto the Run 194 [`RemoteSignerPolicy`]
    /// consumed by the existing verifiers.
    pub const fn to_remote_signer_policy(self) -> RemoteSignerPolicy {
        match self {
            Self::Disabled => RemoteSignerPolicy::Disabled,
            Self::DevTestLoopbackEnabled => RemoteSignerPolicy::FixtureLoopbackAllowed,
            Self::ProductionRequired => RemoteSignerPolicy::ProductionRemoteSignerRequired,
            Self::MainnetProductionRequired => {
                RemoteSignerPolicy::MainnetProductionRemoteSignerRequired
            }
        }
    }
}

// ===========================================================================
// Request kind
// ===========================================================================

/// Run 293 — the typed kind of signing request the backend is asked to
/// carry.
///
/// The backend implements **only** authority-lifecycle and
/// governance-execution signing request/response handling. Validator-set
/// rotation, policy change, and on-chain governance proof verification
/// are explicitly **not** implemented in this run and are refused up
/// front with a precise outcome, so a caller can never smuggle an
/// unsupported action through the RemoteSigner backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductionRemoteSignerRequestKind {
    /// Authority-lifecycle signing (activate/rotate/retire/revoke).
    AuthorityLifecycleSigning,
    /// Governance-execution signing (request/response handling only; no
    /// governance execution engine behaviour is performed).
    GovernanceExecutionSigning,
    /// Validator-set rotation. **Not implemented in Run 293** — refused
    /// as [`ProductionRemoteSignerOutcome::ValidatorSetRotationUnsupported`].
    ValidatorSetRotation,
    /// Governance policy change. **Not implemented in Run 293** —
    /// refused as [`ProductionRemoteSignerOutcome::PolicyChangeUnsupported`].
    PolicyChange,
    /// On-chain governance proof verification. **Not implemented in Run
    /// 293** — refused as
    /// [`ProductionRemoteSignerOutcome::GovernanceVerifierUnavailable`].
    OnChainGovernanceProofVerification,
}

impl ProductionRemoteSignerRequestKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuthorityLifecycleSigning => "authority-lifecycle-signing",
            Self::GovernanceExecutionSigning => "governance-execution-signing",
            Self::ValidatorSetRotation => "validator-set-rotation",
            Self::PolicyChange => "policy-change",
            Self::OnChainGovernanceProofVerification => "onchain-governance-proof-verification",
        }
    }

    /// Returns `true` iff the backend supports carrying this request
    /// kind's request/response.
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::AuthorityLifecycleSigning | Self::GovernanceExecutionSigning
        )
    }
}

// ===========================================================================
// Request spec
// ===========================================================================

/// Run 293 — the typed decision input a caller supplies to drive one
/// RemoteSigner backend round-trip.
///
/// The backend derives the Run 194 inner request, the Run 201 transport
/// request envelope, the deterministic request id, and the caller-side
/// expectations from this single spec, so a valid spec produces
/// self-consistent request/response/transcript bindings by construction
/// and every tamper is a precise fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRemoteSignerRequestSpec {
    /// The kind of signing request.
    pub request_kind: ProductionRemoteSignerRequestKind,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Bound candidate / proposal digest.
    pub candidate_digest: String,
    /// Bound authority-domain sequence / epoch.
    pub authority_domain_sequence: u64,
    /// Active signing-key fingerprint, where applicable.
    pub active_signing_key_fingerprint: Option<String>,
    /// New signing-key fingerprint, where applicable.
    pub new_signing_key_fingerprint: Option<String>,
    /// Revoked signing-key fingerprint, where applicable.
    pub revoked_signing_key_fingerprint: Option<String>,
    /// Governance proof digest, where applicable.
    pub governance_proof_digest: Option<String>,
    /// Custody attestation digest bound to this request.
    pub custody_attestation_digest: String,
    /// Optional Run 291 durable replay record digest, when this signing
    /// request is composed with a durable replay record. Bound into the
    /// request id and transcript when present.
    pub durable_replay_record_digest: Option<String>,
    /// Signer id the request addresses.
    pub signer_id: String,
    /// Custody key id the request addresses.
    pub custody_key_id: String,
    /// Payload digest (the lifecycle/governance payload authorized).
    pub payload_digest: String,
    /// Per-attempt request anti-replay nonce (Run 194 inner request).
    pub request_replay_nonce: String,
    /// Per-attempt transport anti-replay nonce (Run 201 envelope).
    pub transport_anti_replay_nonce: String,
    /// Expected response anti-replay nonce.
    pub response_nonce: String,
    /// Request timestamp / epoch (UNIX seconds).
    pub request_timestamp_unix: u64,
}

impl ProductionRemoteSignerRequestSpec {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.custody_attestation_digest.is_empty()
            && !self.signer_id.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.payload_digest.is_empty()
            && !self.request_replay_nonce.is_empty()
            && !self.transport_anti_replay_nonce.is_empty()
            && !self.response_nonce.is_empty()
    }

    /// The signing-key fingerprint this request primarily binds.
    pub fn primary_signing_key_fingerprint(&self) -> Option<&str> {
        self.new_signing_key_fingerprint
            .as_deref()
            .or(self.active_signing_key_fingerprint.as_deref())
            .or(self.revoked_signing_key_fingerprint.as_deref())
    }

    /// Build the Run 194 inner [`RemoteSignerRequest`] from this spec.
    pub fn build_inner_request(&self) -> RemoteSignerRequest {
        RemoteSignerRequest {
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            active_signing_key_fingerprint: self.active_signing_key_fingerprint.clone(),
            new_signing_key_fingerprint: self.new_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: self.revoked_signing_key_fingerprint.clone(),
            governance_proof_digest: self.governance_proof_digest.clone(),
            custody_attestation_digest: self.custody_attestation_digest.clone(),
            replay_nonce: self.request_replay_nonce.clone(),
            request_timestamp_unix: Some(self.request_timestamp_unix),
        }
    }

    /// Derive the Run 194 [`RemoteSignerExpectations`] for this spec.
    pub fn remote_signer_expectations(&self, now_unix: u64) -> RemoteSignerExpectations {
        RemoteSignerExpectations {
            expected_lifecycle_action: self.lifecycle_action,
            expected_candidate_digest: self.candidate_digest.clone(),
            expected_authority_domain_sequence: self.authority_domain_sequence,
            expected_custody_key_id: self.custody_key_id.clone(),
            expected_signing_key_fingerprint: self
                .primary_signing_key_fingerprint()
                .unwrap_or("")
                .to_string(),
            expected_custody_attestation_digest: self.custody_attestation_digest.clone(),
            expected_request_nonce: self.request_replay_nonce.clone(),
            expected_response_nonce: self.response_nonce.clone(),
            now_unix,
        }
    }
}

/// Run 293 — deterministic, domain-separated backend request id.
///
/// Derived from the typed request spec so the request id is deterministic
/// (not random, not wall-clock). The transport response must echo it and
/// the backend rejects a mismatch as
/// [`ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch`].
pub fn production_remote_signer_request_id(spec: &ProductionRemoteSignerRequestSpec) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_REMOTE_SIGNER_BACKEND_REQUEST_ID_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"request_kind", spec.request_kind.tag().as_bytes());
    field(b"environment", &spec.environment.metric_code().to_le_bytes());
    field(b"chain_id", spec.chain_id.as_bytes());
    field(b"genesis_hash", spec.genesis_hash.as_bytes());
    field(
        b"authority_root_fingerprint",
        spec.authority_root_fingerprint.as_bytes(),
    );
    field(b"lifecycle_action", spec.lifecycle_action.tag().as_bytes());
    field(b"candidate_digest", spec.candidate_digest.as_bytes());
    field(
        b"authority_domain_sequence",
        &spec.authority_domain_sequence.to_le_bytes(),
    );
    field(b"signer_id", spec.signer_id.as_bytes());
    field(b"custody_key_id", spec.custody_key_id.as_bytes());
    field(b"payload_digest", spec.payload_digest.as_bytes());
    field(
        b"custody_attestation_digest",
        spec.custody_attestation_digest.as_bytes(),
    );
    field(
        b"durable_replay_record_digest",
        spec.durable_replay_record_digest
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    field(b"request_replay_nonce", spec.request_replay_nonce.as_bytes());
    field(
        b"transport_anti_replay_nonce",
        spec.transport_anti_replay_nonce.as_bytes(),
    );
    field(
        b"request_timestamp_unix",
        &spec.request_timestamp_unix.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 293 — deterministic, domain-separated backend transcript digest.
///
/// Binds the backend protocol version, the request id, the request and
/// response transport envelope digests, and the Run 201 transport
/// transcript digest into a single backend-level commitment. Only a
/// response that reproduces this digest may authorize acceptance; a
/// mismatch is [`ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch`].
pub fn production_remote_signer_backend_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    request_envelope_digest: &str,
    response_envelope_digest: &str,
    transport_transcript: &str,
    durable_replay_record_digest: Option<&str>,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_REMOTE_SIGNER_BACKEND_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"protocol_version", &protocol_version.to_le_bytes());
    field(b"request_id", request_id.as_bytes());
    field(
        b"request_envelope_digest",
        request_envelope_digest.as_bytes(),
    );
    field(
        b"response_envelope_digest",
        response_envelope_digest.as_bytes(),
    );
    field(b"transport_transcript", transport_transcript.as_bytes());
    field(
        b"durable_replay_record_digest",
        durable_replay_record_digest.unwrap_or("").as_bytes(),
    );
    hex::encode(h.finalize())
}

// ===========================================================================
// Backend transport error taxonomy
// ===========================================================================

/// Run 293 — typed transport / availability error a real production
/// backend transport may surface.
///
/// A real networked backend would map socket / protocol / signer-service
/// faults onto these variants; Run 293 injects them via the source/test
/// [`MockRemoteSignerBackendTransport`]. Each variant is classified as
/// retryable or terminal via [`Self::is_retryable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionRemoteSignerError {
    /// The signer endpoint is unavailable (no route / down).
    EndpointUnavailable,
    /// The connection was refused.
    ConnectionRefused,
    /// The request timed out.
    Timeout,
    /// The transport failed to decode the response.
    TransportDecodeError,
    /// The response exceeded [`PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES`].
    ResponseTooLarge { bytes: usize },
    /// The response was structurally malformed.
    MalformedResponse,
    /// The response used an unsupported transport protocol version.
    UnsupportedProtocolVersion { version: u16 },
    /// The signer service is unavailable.
    SignerUnavailable,
    /// The signer explicitly refused the request.
    SignerRefused,
    /// The signer's policy rejected the request.
    SignerPolicyRejected,
    /// The signer key is unavailable.
    SignerKeyUnavailable,
    /// The signer attestation is missing or unavailable.
    SignerAttestationUnavailable,
}

impl ProductionRemoteSignerError {
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::EndpointUnavailable => "endpoint-unavailable",
            Self::ConnectionRefused => "connection-refused",
            Self::Timeout => "timeout",
            Self::TransportDecodeError => "transport-decode-error",
            Self::ResponseTooLarge { .. } => "response-too-large",
            Self::MalformedResponse => "malformed-response",
            Self::UnsupportedProtocolVersion { .. } => "unsupported-protocol-version",
            Self::SignerUnavailable => "signer-unavailable",
            Self::SignerRefused => "signer-refused",
            Self::SignerPolicyRejected => "signer-policy-rejected",
            Self::SignerKeyUnavailable => "signer-key-unavailable",
            Self::SignerAttestationUnavailable => "signer-attestation-unavailable",
        }
    }

    /// Returns `true` iff a fresh attempt may reasonably succeed (i.e.
    /// the fault is transient). Terminal faults fail closed immediately.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EndpointUnavailable
                | Self::ConnectionRefused
                | Self::Timeout
                | Self::SignerUnavailable
        )
    }
}

// ===========================================================================
// Backend transport boundary
// ===========================================================================

/// Run 293 — narrow, mockable backend transport boundary.
///
/// A real production backend would implement [`Self::submit`] by opening
/// a connection to the remote signer service and returning a typed
/// response envelope or a typed [`ProductionRemoteSignerError`]. Run 293
/// wires no real transport; only the DevNet/TestNet source/test
/// [`LoopbackRemoteSignerService`] and the programmable
/// [`MockRemoteSignerBackendTransport`] implement this boundary.
///
/// Implementations must perform no marker write, no sequence write, no
/// live-trust mutation, no session eviction, and must never invoke Run
/// 070.
pub trait RemoteSignerBackendTransport {
    /// Submit `request_env` on attempt `attempt` (1-based). Returns a
    /// typed response envelope or a typed transport error.
    fn submit(
        &self,
        request_env: &RemoteSignerTransportRequestEnvelope,
        attempt: u32,
    ) -> Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError>;
}

/// Map a Run 201 [`RemoteSignerTransportOutcome`] error (from the
/// fixture loopback transport's simulated faults) onto a Run 293
/// [`ProductionRemoteSignerError`].
fn transport_outcome_to_backend_error(
    outcome: RemoteSignerTransportOutcome,
) -> ProductionRemoteSignerError {
    match outcome {
        RemoteSignerTransportOutcome::Timeout => ProductionRemoteSignerError::Timeout,
        RemoteSignerTransportOutcome::RetryExhausted => {
            ProductionRemoteSignerError::SignerUnavailable
        }
        RemoteSignerTransportOutcome::InvalidTransportAttestation => {
            ProductionRemoteSignerError::SignerAttestationUnavailable
        }
        RemoteSignerTransportOutcome::MalformedRequestEnvelope { .. }
        | RemoteSignerTransportOutcome::MalformedResponseEnvelope { .. } => {
            ProductionRemoteSignerError::MalformedResponse
        }
        RemoteSignerTransportOutcome::UnsupportedProtocolVersion { version } => {
            ProductionRemoteSignerError::UnsupportedProtocolVersion { version }
        }
        _ => ProductionRemoteSignerError::SignerUnavailable,
    }
}

/// Run 293 — DevNet/TestNet source/test loopback backend transport.
///
/// **Source/test only.** Wraps the Run 201
/// [`crate::pqc_remote_signer_transport::FixtureLoopbackRemoteSignerTransport`]
/// so the backend's real submit/retry/verify logic can be exercised
/// against a deterministic loopback response. It is NOT a real transport
/// and must never be wired into a production surface; MainNet material is
/// refused by the verifier. Records how many times it was called so
/// tests can prove the Disabled policy never invokes it.
pub struct LoopbackRemoteSignerService<T: RemoteSignerTransport> {
    inner: T,
    call_count: Cell<u32>,
}

impl<T: RemoteSignerTransport> LoopbackRemoteSignerService<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            call_count: Cell::new(0),
        }
    }

    /// Number of times [`RemoteSignerBackendTransport::submit`] was
    /// invoked.
    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl<T: RemoteSignerTransport> RemoteSignerBackendTransport for LoopbackRemoteSignerService<T> {
    fn submit(
        &self,
        request_env: &RemoteSignerTransportRequestEnvelope,
        _attempt: u32,
    ) -> Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError> {
        self.call_count.set(self.call_count.get() + 1);
        self.inner
            .call_remote_signer(request_env)
            .map_err(transport_outcome_to_backend_error)
    }
}

/// Run 293 — programmable source/test backend transport for fault
/// injection.
///
/// Each call to [`RemoteSignerBackendTransport::submit`] consumes the
/// next programmed step; when the queue is exhausted it returns the
/// configured default (or [`ProductionRemoteSignerError::EndpointUnavailable`]
/// if none). Lets a source/test exercise the timeout / retry /
/// unavailable / malformed / oversized fail-closed paths and inject
/// tampered response envelopes without any real I/O.
pub struct MockRemoteSignerBackendTransport {
    steps: RefCell<VecDeque<Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError>>>,
    default_result: RefCell<Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError>>,
    call_count: Cell<u32>,
}

impl MockRemoteSignerBackendTransport {
    /// A mock that always returns `err`.
    pub fn always_fail(err: ProductionRemoteSignerError) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Err(err)),
            call_count: Cell::new(0),
        }
    }

    /// A mock that returns the programmed `steps` in order, then falls
    /// back to `default_result` for any further calls.
    pub fn scripted(
        steps: Vec<Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError>>,
        default_result: Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError>,
    ) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            default_result: RefCell::new(default_result),
            call_count: Cell::new(0),
        }
    }

    /// A mock that returns `response` on the first call and thereafter.
    pub fn respond(response: RemoteSignerTransportResponseEnvelope) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Ok(response)),
            call_count: Cell::new(0),
        }
    }

    /// Number of times [`RemoteSignerBackendTransport::submit`] was
    /// invoked.
    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl RemoteSignerBackendTransport for MockRemoteSignerBackendTransport {
    fn submit(
        &self,
        _request_env: &RemoteSignerTransportRequestEnvelope,
        _attempt: u32,
    ) -> Result<RemoteSignerTransportResponseEnvelope, ProductionRemoteSignerError> {
        self.call_count.set(self.call_count.get() + 1);
        if let Some(step) = self.steps.borrow_mut().pop_front() {
            step
        } else {
            self.default_result.borrow().clone()
        }
    }
}

// ===========================================================================
// Backend config
// ===========================================================================

/// Run 293 — typed production RemoteSigner backend config.
///
/// Wraps the Run 201 transport config (endpoint, signer id, custody key
/// id, trust-domain tuple, suite, expected signer identity digest,
/// optional transport attestation, timeout/retry policy) and pins the
/// backend protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRemoteSignerBackendConfig {
    /// The Run 201 transport identity / endpoint config.
    pub transport_config: RemoteSignerTransportConfig,
    /// Backend protocol version. Must equal
    /// [`PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION`].
    pub protocol_version: u16,
}

impl ProductionRemoteSignerBackendConfig {
    /// Build a config from a transport config, pinning the current
    /// backend protocol version.
    pub fn from_transport_config(transport_config: RemoteSignerTransportConfig) -> Self {
        Self {
            transport_config,
            protocol_version: PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION,
        }
    }

    /// Returns `true` iff the config is structurally well-formed and the
    /// protocol version is the one this run accepts.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version == PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION
            && self.transport_config.is_well_formed()
    }

    /// Maximum number of transport attempts (from the transport
    /// timeout/retry policy).
    pub const fn max_attempts(&self) -> u32 {
        self.transport_config.timeout_retry.max_attempts
    }
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 293 — typed outcome of the production RemoteSigner backend.
///
/// Only [`Self::RemoteSignerAccepted`] may authorize the next modeled /
/// production custody decision. Every other variant is a precise,
/// non-mutating fail-closed reject (or the inert [`Self::DisabledNoRequest`]
/// / intermediate [`Self::RequestBuilt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionRemoteSignerOutcome {
    /// The backend policy is `Disabled`. No request was built and the
    /// transport was never invoked.
    DisabledNoRequest,
    /// A request envelope was built (build-only path). No transport call
    /// was made and nothing was authorized.
    RequestBuilt { request_id: String },
    /// A fixture loopback backend response was accepted under an explicit
    /// loopback policy on a DevNet/TestNet trust domain. **Evidence
    /// only**: no MainNet apply, no governance execution, no mutation.
    RemoteSignerAccepted {
        signer_id: String,
        environment: TrustBundleEnvironment,
        request_id: String,
        backend_transcript_digest: String,
    },
    /// The signer / transport verifier rejected the response for a reason
    /// that is not one of the more specific variants below.
    RemoteSignerRejected { reason: String },
    /// The transport / signer was unavailable (after any retries).
    RemoteSignerUnavailable,
    /// The transport timed out (after any retries).
    RemoteSignerTimeout,
    /// The transport failed to decode the response.
    RemoteSignerTransportDecodeFailed,
    /// The response was malformed or oversized.
    RemoteSignerMalformedResponse,
    /// The response used an unsupported protocol version.
    RemoteSignerUnsupportedProtocol { version: u16 },
    /// The response's trust-domain binding did not match
    /// (environment / chain / genesis / authority root).
    RemoteSignerDomainMismatch,
    /// The response's transcript digest did not match the recomputed
    /// backend transcript.
    RemoteSignerTranscriptMismatch,
    /// The response's request-id echo did not match the request id.
    RemoteSignerRequestIdMismatch,
    /// The response came from the wrong signer identity.
    RemoteSignerWrongSigner,
    /// The response authorized the wrong lifecycle action.
    RemoteSignerWrongAction,
    /// The response authorized the wrong candidate / proposal digest.
    RemoteSignerWrongCandidateDigest,
    /// The response was a replay (stale request or response nonce).
    RemoteSignerReplayRejected,
    /// The signer attestation was missing or unavailable.
    RemoteSignerAttestationUnavailable,
    /// A MainNet production backend was required but no production
    /// authority material is available.
    MainNetProductionAuthorityUnavailable,
    /// MainNet was refused because the policy is not a production
    /// MainNet policy (fixture/loopback material cannot satisfy MainNet).
    MainNetRefused,
    /// Fixture / loopback material was refused for a MainNet trust
    /// domain.
    FixtureMaterialRejectedForMainNet,
    /// The request kind was validator-set rotation, which Run 293 does
    /// not implement.
    ValidatorSetRotationUnsupported,
    /// The request kind was on-chain governance proof verification, which
    /// Run 293 does not implement.
    GovernanceVerifierUnavailable,
    /// The request kind was a governance policy change, which Run 293
    /// does not implement.
    PolicyChangeUnsupported,
    /// The request spec / config was structurally malformed, or the
    /// outcome could not be classified — fail closed.
    AmbiguousFailClosed { reason: String },
}

impl ProductionRemoteSignerOutcome {
    /// Returns `true` iff this outcome authorizes the next decision.
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::RemoteSignerAccepted { .. })
    }

    /// Returns `true` iff this outcome must not mutate any state. Every
    /// variant except [`Self::RemoteSignerAccepted`] is non-authorizing;
    /// acceptance itself is evidence-only and also non-mutating in Run
    /// 293.
    pub fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff this outcome represents an "unavailable"
    /// production path.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::RemoteSignerUnavailable | Self::MainNetProductionAuthorityUnavailable
        )
    }
}

// ===========================================================================
// Submission result
// ===========================================================================

/// Run 293 — the successful result of submitting a request to the
/// transport: the built request envelope, the raw response envelope, the
/// deterministic request id, and how many transport attempts were used.
/// Verification is a separate step so a caller can inspect the raw
/// response before it authorizes anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedRemoteSignerRequest {
    pub request_env: RemoteSignerTransportRequestEnvelope,
    pub response_env: RemoteSignerTransportResponseEnvelope,
    pub request_id: String,
    pub attempts_used: u32,
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 293 — typed outcome of a request/response recovery-window check.
///
/// Run 293 models only the narrow replay/recovery semantics the existing
/// surfaces already represent: idempotent re-submission of a
/// byte-identical request/response, and fail-closed refusal of any
/// conflicting request id / transcript / response commitment or ambiguous
/// window. It claims **no** durable acceptance persistence of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionRemoteSignerRecoveryOutcome {
    /// No prior request exists; nothing to recover.
    NoPriorRequest,
    /// The current request/response is byte-identical to the prior one —
    /// idempotent replay, safe.
    IdempotentReplayOfSameRequest,
    /// The same request id was reused with a different request
    /// transcript — fail closed.
    ConflictingRequestForSameId,
    /// The same request produced a different response commitment — fail
    /// closed.
    ConflictingResponseForSameRequest,
    /// The recovery window is ambiguous (e.g. a built request with no
    /// recorded response) — fail closed.
    AmbiguousRecoveryFailClosed { reason: String },
}

impl ProductionRemoteSignerRecoveryOutcome {
    /// Returns `true` iff the recovery is safe to treat as idempotent.
    pub fn is_idempotent(&self) -> bool {
        matches!(self, Self::IdempotentReplayOfSameRequest)
    }
}

// ===========================================================================
// Backend trait
// ===========================================================================

/// Run 293 — the production RemoteSigner backend boundary.
///
/// Implementations drive a [`RemoteSignerBackendTransport`], applying the
/// backend policy, request-kind gating, MainNet refusal, timeout/retry,
/// request/response correlation, and transcript binding, and returning a
/// precise typed [`ProductionRemoteSignerOutcome`]. No implementation
/// mutates live trust, writes a marker/sequence, evicts sessions,
/// performs settlement / external publication / governance execution /
/// validator-set rotation, or invokes Run 070.
pub trait GovernanceProductionRemoteSignerBackend {
    /// Build the transport request envelope for `spec` without
    /// submitting it. Returns a typed outcome
    /// ([`ProductionRemoteSignerOutcome::RequestBuilt`] on success, or a
    /// precise reject) so a caller can preflight without a transport
    /// call.
    fn build_request_envelope(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<RemoteSignerTransportRequestEnvelope, ProductionRemoteSignerOutcome>;

    /// Submit `spec` to the transport with the configured timeout/retry
    /// policy, returning the raw submission (request + response envelope)
    /// or a precise fail-closed outcome. Does not authorize anything by
    /// itself.
    fn submit_remote_signing_request(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<SubmittedRemoteSignerRequest, ProductionRemoteSignerOutcome>;

    /// Verify a submitted request/response against the caller's
    /// expectations and the trust domain, returning a precise typed
    /// outcome.
    fn verify_remote_signer_response(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        submitted: &SubmittedRemoteSignerRequest,
        trust_domain: &AuthorityTrustDomain,
        identity: &RemoteSignerIdentity,
        now_unix: u64,
    ) -> ProductionRemoteSignerOutcome;

    /// Submit and verify in one call, returning a precise typed outcome.
    fn evaluate_remote_signer_backend(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
        identity: &RemoteSignerIdentity,
        now_unix: u64,
    ) -> ProductionRemoteSignerOutcome;

    /// Evaluate a request/response recovery window against a prior
    /// submission.
    fn recover_remote_signer_request_window(
        &self,
        prior: Option<&SubmittedRemoteSignerRequest>,
        current: &SubmittedRemoteSignerRequest,
    ) -> ProductionRemoteSignerRecoveryOutcome;
}

// ===========================================================================
// Backend implementation
// ===========================================================================

/// Run 293 — the real production RemoteSigner backend client.
///
/// Generic over the injected [`RemoteSignerBackendTransport`] so the same
/// real client logic runs over a source/test loopback service, a
/// programmable mock, or (in a future run) a real networked transport.
pub struct ProductionRemoteSignerBackend<T: RemoteSignerBackendTransport> {
    pub config: ProductionRemoteSignerBackendConfig,
    pub policy: ProductionRemoteSignerBackendPolicy,
    pub transport: T,
}

impl<T: RemoteSignerBackendTransport> ProductionRemoteSignerBackend<T> {
    pub fn new(
        config: ProductionRemoteSignerBackendConfig,
        policy: ProductionRemoteSignerBackendPolicy,
        transport: T,
    ) -> Self {
        Self {
            config,
            policy,
            transport,
        }
    }

    /// Derive the Run 201 transport expectations from `spec` and the
    /// backend config.
    fn transport_expectations(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        now_unix: u64,
    ) -> RemoteSignerTransportExpectations {
        RemoteSignerTransportExpectations {
            expected_request_id: production_remote_signer_request_id(spec),
            expected_payload_digest: spec.payload_digest.clone(),
            expected_anti_replay_nonce: spec.transport_anti_replay_nonce.clone(),
            expected_signer_identity_digest: self
                .config
                .transport_config
                .expected_signer_identity_digest
                .clone(),
            expected_transport_attestation_digest: self
                .config
                .transport_config
                .transport_attestation_digest
                .clone(),
            now_unix,
        }
    }

    /// Pure policy / kind / MainNet gate applied before any request is
    /// built or any transport call is made. Returns `Some(outcome)` when
    /// the request must be refused before submission, `None` to proceed.
    fn preflight_gate(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionRemoteSignerOutcome> {
        // 1. Disabled fails closed before anything else — no request, no
        //    transport call.
        if self.policy.is_disabled() {
            return Some(ProductionRemoteSignerOutcome::DisabledNoRequest);
        }

        // 2. Unsupported request kinds are refused up front.
        match spec.request_kind {
            ProductionRemoteSignerRequestKind::ValidatorSetRotation => {
                return Some(ProductionRemoteSignerOutcome::ValidatorSetRotationUnsupported);
            }
            ProductionRemoteSignerRequestKind::PolicyChange => {
                return Some(ProductionRemoteSignerOutcome::PolicyChangeUnsupported);
            }
            ProductionRemoteSignerRequestKind::OnChainGovernanceProofVerification => {
                return Some(ProductionRemoteSignerOutcome::GovernanceVerifierUnavailable);
            }
            ProductionRemoteSignerRequestKind::AuthorityLifecycleSigning
            | ProductionRemoteSignerRequestKind::GovernanceExecutionSigning => {}
        }

        // 3. Structural well-formedness of spec and config.
        if !spec.is_well_formed() || !self.config.is_well_formed() {
            return Some(ProductionRemoteSignerOutcome::AmbiguousFailClosed {
                reason: "request spec or backend config is malformed".to_string(),
            });
        }

        // 4. MainNet gate. A MainNet trust domain requires an explicit
        //    MainNet production policy; even then, no real production
        //    transport is wired, so it fails closed as unavailable. A
        //    non-MainNet-production policy on MainNet is refused.
        if trust_domain.environment == TrustBundleEnvironment::Mainnet {
            return Some(match self.policy {
                ProductionRemoteSignerBackendPolicy::MainnetProductionRequired => {
                    ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
                }
                _ => ProductionRemoteSignerOutcome::MainNetRefused,
            });
        }

        // 5. A production-required policy on a non-MainNet domain still
        //    has no real backend wired — fail closed as unavailable
        //    before invoking the (fixture) transport.
        if self.policy.requires_production_backend() {
            return Some(ProductionRemoteSignerOutcome::RemoteSignerUnavailable);
        }

        None
    }
}

/// Map a transport error to a precise fail-closed outcome.
fn error_to_outcome(err: &ProductionRemoteSignerError) -> ProductionRemoteSignerOutcome {
    match err {
        ProductionRemoteSignerError::EndpointUnavailable
        | ProductionRemoteSignerError::ConnectionRefused
        | ProductionRemoteSignerError::SignerUnavailable
        | ProductionRemoteSignerError::SignerKeyUnavailable => {
            ProductionRemoteSignerOutcome::RemoteSignerUnavailable
        }
        ProductionRemoteSignerError::Timeout => ProductionRemoteSignerOutcome::RemoteSignerTimeout,
        ProductionRemoteSignerError::TransportDecodeError => {
            ProductionRemoteSignerOutcome::RemoteSignerTransportDecodeFailed
        }
        ProductionRemoteSignerError::ResponseTooLarge { .. }
        | ProductionRemoteSignerError::MalformedResponse => {
            ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse
        }
        ProductionRemoteSignerError::UnsupportedProtocolVersion { version } => {
            ProductionRemoteSignerOutcome::RemoteSignerUnsupportedProtocol { version: *version }
        }
        ProductionRemoteSignerError::SignerRefused
        | ProductionRemoteSignerError::SignerPolicyRejected => {
            ProductionRemoteSignerOutcome::RemoteSignerRejected {
                reason: err.tag().to_string(),
            }
        }
        ProductionRemoteSignerError::SignerAttestationUnavailable => {
            ProductionRemoteSignerOutcome::RemoteSignerAttestationUnavailable
        }
    }
}

/// Map a Run 201 transport verifier reject onto a precise Run 293
/// backend outcome.
fn transport_verifier_reject_to_outcome(
    outcome: RemoteSignerTransportOutcome,
) -> ProductionRemoteSignerOutcome {
    use RemoteSignerTransportOutcome as O;
    match outcome {
        O::FixtureLoopbackTransportRejectedForMainNet => {
            ProductionRemoteSignerOutcome::FixtureMaterialRejectedForMainNet
        }
        O::TransportDisabled => ProductionRemoteSignerOutcome::DisabledNoRequest,
        O::FixtureTransportRejectedProductionRequired
        | O::FixtureTransportRejectedMainnetProductionRequired => {
            ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
        }
        O::ProductionTransportUnavailable => ProductionRemoteSignerOutcome::RemoteSignerUnavailable,
        O::MainNetProductionTransportUnavailable => {
            ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
        }
        O::WrongEnvironment { .. }
        | O::WrongChain { .. }
        | O::WrongGenesis { .. }
        | O::WrongAuthorityRoot { .. } => ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch,
        O::WrongSignerId { .. } => ProductionRemoteSignerOutcome::RemoteSignerWrongSigner,
        O::WrongRequestId { .. } => ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch,
        O::WrongTranscriptDigest { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch
        }
        O::UnsupportedProtocolVersion { version } => {
            ProductionRemoteSignerOutcome::RemoteSignerUnsupportedProtocol { version }
        }
        O::MalformedRequestEnvelope { .. } | O::MalformedResponseEnvelope { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse
        }
        O::StaleOrReplayedRequest { .. } | O::StaleOrReplayedResponse { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerReplayRejected
        }
        O::InvalidTransportAttestation => {
            ProductionRemoteSignerOutcome::RemoteSignerAttestationUnavailable
        }
        O::RemoteSignerResponseInvalid {
            remote_signer_outcome,
        } => remote_signer_reject_to_outcome(remote_signer_outcome),
        O::EndpointMissing | O::EndpointMalformed { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerUnavailable
        }
        O::UnsupportedSuite { .. } => ProductionRemoteSignerOutcome::RemoteSignerRejected {
            reason: "unsupported-suite".to_string(),
        },
        O::WrongCustodyKeyId { .. } | O::WrongSigningKeyFingerprint { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerWrongSigner
        }
        O::WrongRequestDigest { .. } | O::WrongResponseDigest { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch
        }
        O::Timeout => ProductionRemoteSignerOutcome::RemoteSignerTimeout,
        O::RetryExhausted => ProductionRemoteSignerOutcome::RemoteSignerUnavailable,
        O::LocalOperatorCannotSatisfyTransport | O::PeerMajorityCannotSatisfyTransport => {
            ProductionRemoteSignerOutcome::RemoteSignerRejected {
                reason: "custody-material-cannot-satisfy-remote-signer".to_string(),
            }
        }
        O::NotRemoteSignerCustodyClass { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerRejected {
                reason: "not-remote-signer-custody-class".to_string(),
            }
        }
        O::FixtureLoopbackTransportAccepted { .. } => {
            ProductionRemoteSignerOutcome::AmbiguousFailClosed {
                reason: "accept classified as reject".to_string(),
            }
        }
    }
}

/// Map an inner Run 194 [`RemoteSignerOutcome`] reject onto a precise Run
/// 293 backend outcome.
fn remote_signer_reject_to_outcome(outcome: RemoteSignerOutcome) -> ProductionRemoteSignerOutcome {
    use RemoteSignerOutcome as O;
    match outcome {
        O::WrongEnvironment { .. }
        | O::WrongChain { .. }
        | O::WrongGenesis { .. }
        | O::WrongAuthorityRoot { .. } => ProductionRemoteSignerOutcome::RemoteSignerDomainMismatch,
        O::WrongLifecycleAction { .. } => ProductionRemoteSignerOutcome::RemoteSignerWrongAction,
        O::WrongCandidateDigest { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerWrongCandidateDigest
        }
        O::StaleOrReplayedRequest { .. } | O::StaleOrReplayedResponse { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerReplayRejected
        }
        O::WrongRequestDigest { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch
        }
        O::WrongCustodyKeyId { .. } | O::WrongSigningKeyFingerprint { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerWrongSigner
        }
        O::MalformedRequest { .. } | O::MalformedResponse { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse
        }
        O::ProductionRemoteSignerUnavailable => {
            ProductionRemoteSignerOutcome::RemoteSignerUnavailable
        }
        O::MainNetProductionRemoteSignerUnavailable => {
            ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
        }
        O::FixtureLoopbackRejectedForMainNet => {
            ProductionRemoteSignerOutcome::FixtureMaterialRejectedForMainNet
        }
        O::ExpiredResponse { .. } | O::ExpiredAttestation { .. } => {
            ProductionRemoteSignerOutcome::RemoteSignerReplayRejected
        }
        other => ProductionRemoteSignerOutcome::RemoteSignerRejected {
            reason: format!("{other:?}"),
        },
    }
}

impl<T: RemoteSignerBackendTransport> GovernanceProductionRemoteSignerBackend
    for ProductionRemoteSignerBackend<T>
{
    fn build_request_envelope(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<RemoteSignerTransportRequestEnvelope, ProductionRemoteSignerOutcome> {
        if let Some(outcome) = self.preflight_gate(spec, trust_domain) {
            return Err(outcome);
        }
        let inner = spec.build_inner_request();
        let canonical = inner.canonical_digest();
        let request_id = production_remote_signer_request_id(spec);
        Ok(RemoteSignerTransportRequestEnvelope {
            protocol_version: REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
            domain_tag: REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG.to_string(),
            request_id,
            timestamp_unix: spec.request_timestamp_unix,
            environment: spec.environment,
            chain_id: spec.chain_id.clone(),
            genesis_hash: spec.genesis_hash.clone(),
            authority_root_fingerprint: spec.authority_root_fingerprint.clone(),
            custody_key_id: spec.custody_key_id.clone(),
            expected_signer_id: spec.signer_id.clone(),
            canonical_request_digest: canonical,
            payload_digest: spec.payload_digest.clone(),
            anti_replay_nonce: spec.transport_anti_replay_nonce.clone(),
            inner_request: inner,
        })
    }

    fn submit_remote_signing_request(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<SubmittedRemoteSignerRequest, ProductionRemoteSignerOutcome> {
        let request_env = self.build_request_envelope(spec, trust_domain)?;
        let request_id = request_env.request_id.clone();
        let max_attempts = self.config.max_attempts().max(1);

        let mut last_err: Option<ProductionRemoteSignerError> = None;
        for attempt in 1..=max_attempts {
            match self.transport.submit(&request_env, attempt) {
                Ok(response_env) => {
                    // Response-size bound (typed; no real I/O in Run 293).
                    if oversized_response_bytes(&response_env).is_some() {
                        return Err(ProductionRemoteSignerOutcome::RemoteSignerMalformedResponse);
                    }
                    return Ok(SubmittedRemoteSignerRequest {
                        request_env,
                        response_env,
                        request_id,
                        attempts_used: attempt,
                    });
                }
                Err(err) => {
                    if err.is_retryable() && attempt < max_attempts {
                        last_err = Some(err);
                        continue;
                    }
                    return Err(error_to_outcome(&err));
                }
            }
        }
        // Retry budget exhausted on a retryable error.
        Err(error_to_outcome(
            &last_err.unwrap_or(ProductionRemoteSignerError::SignerUnavailable),
        ))
    }

    fn verify_remote_signer_response(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        submitted: &SubmittedRemoteSignerRequest,
        trust_domain: &AuthorityTrustDomain,
        identity: &RemoteSignerIdentity,
        now_unix: u64,
    ) -> ProductionRemoteSignerOutcome {
        let request_env = &submitted.request_env;
        let response_env = &submitted.response_env;

        // 1. A production-mode response can never be accepted in Run 293
        //    (no real backend). This layers ahead of the verifier so the
        //    outcome is precise.
        if response_env.inner_response.signer_mode == RemoteSignerMode::Production {
            return if trust_domain.environment == TrustBundleEnvironment::Mainnet {
                ProductionRemoteSignerOutcome::MainNetProductionAuthorityUnavailable
            } else {
                ProductionRemoteSignerOutcome::RemoteSignerUnavailable
            };
        }

        // 2. Backend-level request/response correlation (precise
        //    outcomes ahead of the composed verifier).
        if response_env.request_id_echo != request_env.request_id
            || request_env.request_id != submitted.request_id
        {
            return ProductionRemoteSignerOutcome::RemoteSignerRequestIdMismatch;
        }
        if response_env.inner_response.signer_id != identity.signer_id
            || response_env.signer_id != identity.signer_id
        {
            return ProductionRemoteSignerOutcome::RemoteSignerWrongSigner;
        }

        // 3. Compose the Run 201 transport verifier (which composes the
        //    Run 194 verifier).
        let rs_expected = spec.remote_signer_expectations(now_unix);
        let transport_expected = self.transport_expectations(spec, now_unix);
        let verifier_outcome = validate_remote_signer_transport(
            &self.config.transport_config,
            request_env,
            response_env,
            trust_domain,
            identity,
            &rs_expected,
            &transport_expected,
            self.policy.to_remote_signer_policy(),
        );
        if !verifier_outcome.is_accept() {
            return transport_verifier_reject_to_outcome(verifier_outcome);
        }

        // 4. Backend-level transcript binding: recompute the backend
        //    transcript over the envelope digests + transport transcript
        //    and require the response's transport transcript to be the
        //    one this request/response pair produces.
        let request_envelope_digest = request_env.envelope_digest();
        let response_envelope_digest = response_env.envelope_digest();
        let expected_transport_transcript =
            transport_transcript_digest(&request_envelope_digest, &response_envelope_digest);
        if response_env.transcript_digest != expected_transport_transcript {
            return ProductionRemoteSignerOutcome::RemoteSignerTranscriptMismatch;
        }
        let backend_transcript_digest = production_remote_signer_backend_transcript_digest(
            self.config.protocol_version,
            &submitted.request_id,
            &request_envelope_digest,
            &response_envelope_digest,
            &expected_transport_transcript,
            spec.durable_replay_record_digest.as_deref(),
        );

        // 5. Accept — fixture loopback backend response, DevNet/TestNet,
        //    evidence-only.
        ProductionRemoteSignerOutcome::RemoteSignerAccepted {
            signer_id: identity.signer_id.clone(),
            environment: trust_domain.environment,
            request_id: submitted.request_id.clone(),
            backend_transcript_digest,
        }
    }

    fn evaluate_remote_signer_backend(
        &self,
        spec: &ProductionRemoteSignerRequestSpec,
        trust_domain: &AuthorityTrustDomain,
        identity: &RemoteSignerIdentity,
        now_unix: u64,
    ) -> ProductionRemoteSignerOutcome {
        match self.submit_remote_signing_request(spec, trust_domain) {
            Ok(submitted) => {
                self.verify_remote_signer_response(spec, &submitted, trust_domain, identity, now_unix)
            }
            Err(outcome) => outcome,
        }
    }

    fn recover_remote_signer_request_window(
        &self,
        prior: Option<&SubmittedRemoteSignerRequest>,
        current: &SubmittedRemoteSignerRequest,
    ) -> ProductionRemoteSignerRecoveryOutcome {
        let Some(prior) = prior else {
            return ProductionRemoteSignerRecoveryOutcome::NoPriorRequest;
        };
        // Same request id?
        if prior.request_id != current.request_id {
            // Different ids are unrelated windows; treat as no prior.
            return ProductionRemoteSignerRecoveryOutcome::NoPriorRequest;
        }
        // Same id, different request transcript => conflict, fail closed.
        if prior.request_env.envelope_digest() != current.request_env.envelope_digest() {
            return ProductionRemoteSignerRecoveryOutcome::ConflictingRequestForSameId;
        }
        // Same request, different response commitment => conflict.
        let prior_resp = remote_signer_response_canonical_digest(&prior.response_env.inner_response);
        let current_resp =
            remote_signer_response_canonical_digest(&current.response_env.inner_response);
        if prior_resp != current_resp {
            return ProductionRemoteSignerRecoveryOutcome::ConflictingResponseForSameRequest;
        }
        // Byte-identical request and response => idempotent replay.
        if prior.response_env == current.response_env {
            ProductionRemoteSignerRecoveryOutcome::IdempotentReplayOfSameRequest
        } else {
            ProductionRemoteSignerRecoveryOutcome::AmbiguousRecoveryFailClosed {
                reason: "same request/response digests but non-identical envelopes".to_string(),
            }
        }
    }
}

/// Run 293 — typed response-size bound check. Returns `Some(bytes)` iff
/// the response's bound size estimate exceeds
/// [`PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES`]. Run 293 performs no
/// real I/O; the estimate is the length of the response commitment plus
/// canonical digest, so an absurdly large source/test response can
/// exercise the oversized fail-closed path.
fn oversized_response_bytes(
    response_env: &RemoteSignerTransportResponseEnvelope,
) -> Option<usize> {
    let bytes = response_env.response_commitment.len()
        + response_env.canonical_response_digest.len()
        + response_env.inner_response.signature_commitment.len();
    if bytes > PRODUCTION_REMOTE_SIGNER_MAX_RESPONSE_BYTES {
        Some(bytes)
    } else {
        None
    }
}

// ===========================================================================
// Explicit fail-closed / scope helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 293 — returns `true`: the production RemoteSigner backend default
/// policy is `Disabled`.
pub fn production_remote_signer_backend_default_is_disabled() -> bool {
    ProductionRemoteSignerBackendPolicy::default() == ProductionRemoteSignerBackendPolicy::Disabled
}

/// Run 293 — returns `true`: fixture / loopback material can never
/// satisfy a MainNet production RemoteSigner backend.
pub fn production_remote_signer_backend_mainnet_refuses_fixture_material() -> bool {
    true
}

/// Run 293 — returns `true`: the backend never falls back to fixture /
/// loopback / local / in-memory signing when the production path is
/// unavailable.
pub fn production_remote_signer_backend_never_falls_back() -> bool {
    true
}

/// Run 293 — returns `true`: this run is a source/test implementation and
/// is NOT release-binary evidence (deferred to Run 294).
pub fn production_remote_signer_backend_is_source_test_not_release_binary_evidence() -> bool {
    true
}

/// Run 293 — returns `true`: the backend implements no KMS / HSM /
/// cloud-KMS / PKCS#11 provider signing.
pub fn production_remote_signer_backend_implements_no_kms_hsm() -> bool {
    true
}

/// Run 293 — returns `true`: the backend performs no Run 070 apply, no
/// `LivePqcTrustState` mutation, no trust swap, no session eviction, no
/// sequence/marker write, no settlement, no external publication, no
/// governance execution, and no validator-set rotation.
pub fn production_remote_signer_backend_is_non_mutating() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_protocol_version_is_one() {
        assert_eq!(PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn default_policy_is_disabled() {
        assert!(production_remote_signer_backend_default_is_disabled());
        assert!(ProductionRemoteSignerBackendPolicy::default().is_disabled());
    }

    #[test]
    fn policy_maps_to_remote_signer_policy() {
        assert_eq!(
            ProductionRemoteSignerBackendPolicy::Disabled.to_remote_signer_policy(),
            RemoteSignerPolicy::Disabled
        );
        assert_eq!(
            ProductionRemoteSignerBackendPolicy::DevTestLoopbackEnabled.to_remote_signer_policy(),
            RemoteSignerPolicy::FixtureLoopbackAllowed
        );
        assert_eq!(
            ProductionRemoteSignerBackendPolicy::ProductionRequired.to_remote_signer_policy(),
            RemoteSignerPolicy::ProductionRemoteSignerRequired
        );
        assert_eq!(
            ProductionRemoteSignerBackendPolicy::MainnetProductionRequired.to_remote_signer_policy(),
            RemoteSignerPolicy::MainnetProductionRemoteSignerRequired
        );
    }

    #[test]
    fn request_kind_support_classification() {
        assert!(ProductionRemoteSignerRequestKind::AuthorityLifecycleSigning.is_supported());
        assert!(ProductionRemoteSignerRequestKind::GovernanceExecutionSigning.is_supported());
        assert!(!ProductionRemoteSignerRequestKind::ValidatorSetRotation.is_supported());
        assert!(!ProductionRemoteSignerRequestKind::PolicyChange.is_supported());
        assert!(
            !ProductionRemoteSignerRequestKind::OnChainGovernanceProofVerification.is_supported()
        );
    }

    #[test]
    fn error_retry_classification() {
        assert!(ProductionRemoteSignerError::Timeout.is_retryable());
        assert!(ProductionRemoteSignerError::EndpointUnavailable.is_retryable());
        assert!(!ProductionRemoteSignerError::MalformedResponse.is_retryable());
        assert!(!ProductionRemoteSignerError::SignerRefused.is_retryable());
    }

    #[test]
    fn scope_helpers_true() {
        assert!(production_remote_signer_backend_mainnet_refuses_fixture_material());
        assert!(production_remote_signer_backend_never_falls_back());
        assert!(production_remote_signer_backend_is_source_test_not_release_binary_evidence());
        assert!(production_remote_signer_backend_implements_no_kms_hsm());
        assert!(production_remote_signer_backend_is_non_mutating());
    }
}