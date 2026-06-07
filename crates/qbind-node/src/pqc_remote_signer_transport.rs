//! Run 201 — source/test production RemoteSigner transport boundary.
//!
//! Source/test only. Run 201 does **not** implement a real remote
//! signer service, a networked signer daemon, a real KMS, a real HSM, a
//! cloud-KMS integration, or a PKCS#11 integration; nor does it enable
//! MainNet peer-driven apply, real on-chain governance proof
//! verification, governance execution, or validator-set rotation.
//!
//! Before Run 201 the Run 194 RemoteSigner had typed
//! request/response/policy/payload/carrying types and a release-binary
//! selector, but there was **no production transport boundary**: no
//! network/service protocol boundary for communicating with a real
//! remote signer backend, even in fail-closed form. Run 201 closes that
//! gap at the source/test level by adding:
//!
//! * A typed transport identity / endpoint config
//!   ([`RemoteSignerTransportConfig`]) binding the endpoint, signer id,
//!   custody key id, authority root fingerprint, bundle-signing key
//!   fingerprint, environment, chain id, genesis hash, suite id, the
//!   expected signer identity digest, an optional transport
//!   certificate / attestation placeholder digest, and a
//!   timeout/retry policy ([`TransportTimeoutRetryPolicy`]).
//! * A typed [`RemoteSignerTransportRequestEnvelope`] that wraps and
//!   binds the Run 194 [`RemoteSignerRequest`] with a protocol version,
//!   a domain tag, a request id / nonce, a timestamp/epoch, the trust
//!   domain tuple, the custody key id, the expected signer id, the
//!   canonical request digest, the payload digest, and an anti-replay
//!   nonce.
//! * A typed [`RemoteSignerTransportResponseEnvelope`] that wraps and
//!   binds the Run 194 [`RemoteSignerResponse`] with a protocol
//!   version, a domain tag, a request id echo, the signer id, custody
//!   key id, a response timestamp/expiry, the canonical response
//!   digest, the signature suite, a response commitment placeholder,
//!   and the transcript digest.
//! * Deterministic, domain-separated transcript-binding digest helpers
//!   ([`RemoteSignerTransportRequestEnvelope::envelope_digest`],
//!   [`RemoteSignerTransportResponseEnvelope::envelope_digest`], and
//!   [`transport_transcript_digest`]).
//! * A pure / mockable [`RemoteSignerTransport`] trait with a
//!   [`RemoteSignerTransport::call_remote_signer`] method (plus the
//!   free [`send_remote_signer_request`] helper), a DevNet/TestNet
//!   source/test-only [`FixtureLoopbackRemoteSignerTransport`], and a
//!   [`ProductionRemoteSignerTransport`] that is callable but fails
//!   closed as unavailable.
//! * A pure typed verifier [`validate_remote_signer_transport`] and a
//!   typed [`RemoteSignerTransportOutcome`] that distinguishes every
//!   accept/reject case the task enumerates.
//! * A composition helper
//!   [`validate_lifecycle_custody_remote_signer_and_transport`] that
//!   layers the transport boundary on top of the Run 194
//!   [`validate_lifecycle_governance_custody_and_remote_signer`]
//!   composition while preserving the MainNet peer-driven-apply
//!   refusal.
//!
//! Release-binary RemoteSigner transport-boundary evidence is
//! **deferred to Run 202**. KMS/HSM remain unimplemented, governance
//! execution remains unimplemented, real on-chain proof verification
//! remains unimplemented, validator-set rotation remains open, full C4
//! remains open, and C5 remains open.
//!
//! The module is pure: every public function and trait method performs
//! no network or file I/O, writes no marker, writes no sequence,
//! mutates no live trust, evicts no sessions, and never invokes Run
//! 070 apply.

use crate::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use crate::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_remote_authority_signer::{
    validate_lifecycle_governance_custody_and_remote_signer, validate_remote_signer,
    LifecycleCustodyRemoteSignerOutcome, RemoteSignerExpectations, RemoteSignerIdentity,
    RemoteSignerMode, RemoteSignerPolicy, RemoteSignerRequest, RemoteSignerResponse,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 201 — transport request-envelope digest domain tag.
pub const REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG: &str =
    "QBIND:run201-remote-signer-transport-request-envelope:v1";

/// Run 201 — transport response-envelope digest domain tag.
pub const REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG: &str =
    "QBIND:run201-remote-signer-transport-response-envelope:v1";

/// Run 201 — request/response transport transcript digest domain tag.
pub const REMOTE_SIGNER_TRANSPORT_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run201-remote-signer-transport-transcript:v1";

/// Run 201 — placeholder response-commitment derivation domain tag for
/// the source/test fixture loopback transport. Never a real signature.
pub const REMOTE_SIGNER_TRANSPORT_FIXTURE_COMMITMENT_DOMAIN_TAG: &str =
    "QBIND:run201-remote-signer-transport-fixture-commitment:v1";

/// Run 201 — the only transport protocol version this run accepts.
pub const REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION: u16 = 1;

/// Run 201 — explicit invalid transport-attestation sentinel for
/// source/test rejection vectors. A config carrying this attestation
/// digest is rejected as
/// [`RemoteSignerTransportOutcome::InvalidTransportAttestation`].
pub const REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL: &str = "INVALID-TRANSPORT-ATTESTATION";

// ===========================================================================
// Timeout / retry policy
// ===========================================================================

/// Run 201 — typed transport timeout/retry policy.
///
/// Pure data describing the per-attempt timeout budget and the maximum
/// number of attempts a future production transport is permitted. Run
/// 201 performs no real I/O; the policy is validated for
/// well-formedness and is bound into the config digest so a malformed
/// policy fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportTimeoutRetryPolicy {
    /// Per-attempt timeout budget, in milliseconds. Must be non-zero.
    pub per_attempt_timeout_ms: u64,
    /// Maximum number of attempts (including the first). Must be at
    /// least 1.
    pub max_attempts: u32,
}

impl Default for TransportTimeoutRetryPolicy {
    fn default() -> Self {
        Self {
            per_attempt_timeout_ms: 5_000,
            max_attempts: 3,
        }
    }
}

impl TransportTimeoutRetryPolicy {
    /// Returns `true` iff the policy is structurally well-formed.
    pub const fn is_well_formed(&self) -> bool {
        self.per_attempt_timeout_ms != 0 && self.max_attempts >= 1
    }
}

// ===========================================================================
// Transport identity / endpoint config
// ===========================================================================

/// Run 201 — typed transport identity / endpoint config.
///
/// Pure data describing *which* remote signer service endpoint a future
/// production transport would address, bound to the same trust-domain
/// tuple the Run 194 boundary already enforces, plus a transport-level
/// expected signer identity digest, an optional transport
/// certificate/attestation placeholder digest, and a timeout/retry
/// policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerTransportConfig {
    /// Signer endpoint URI or abstract endpoint id. Must be non-empty
    /// and well-formed (see [`endpoint_is_well_formed`]).
    pub endpoint: String,
    /// Stable, opaque identifier of the remote signer.
    pub signer_id: String,
    /// Stable, opaque identifier of the custody-held key.
    pub custody_key_id: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound bundle-signing key fingerprint.
    pub bundle_signing_key_fingerprint: String,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Suite id this transport supports (placeholder; only the Run 159
    /// PQC signing suite is currently accepted).
    pub suite_id: u8,
    /// Expected signer identity digest (transport-level binding to the
    /// signer's published identity). Must be non-empty.
    pub expected_signer_identity_digest: String,
    /// Optional transport certificate / attestation placeholder digest.
    /// When present, must be non-empty and must not be the explicit
    /// invalid sentinel.
    pub transport_attestation_digest: Option<String>,
    /// Timeout / retry policy.
    pub timeout_retry: TransportTimeoutRetryPolicy,
}

impl RemoteSignerTransportConfig {
    /// Returns `true` iff every mandatory field is structurally present
    /// and the timeout/retry policy is well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.endpoint.is_empty()
            && !self.signer_id.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.bundle_signing_key_fingerprint.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.expected_signer_identity_digest.is_empty()
            && self.timeout_retry.is_well_formed()
    }
}

/// Run 201 — endpoint well-formedness check.
///
/// A well-formed endpoint is non-empty, contains no whitespace, and is
/// either a URI with an explicit scheme separator (`scheme://...`) or an
/// abstract endpoint id with one of the recognized abstract prefixes
/// (`abstract:` / `fixture:`). Run 201 does not open a socket; this is a
/// pure structural check so a missing or malformed endpoint fails
/// closed.
pub fn endpoint_is_well_formed(endpoint: &str) -> bool {
    if endpoint.is_empty() {
        return false;
    }
    if endpoint.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    endpoint.contains("://")
        || endpoint.starts_with("abstract:")
        || endpoint.starts_with("fixture:")
}

// ===========================================================================
// Request envelope
// ===========================================================================

/// Run 201 — typed transport request envelope.
///
/// Wraps and binds the Run 194 [`RemoteSignerRequest`] with transport
/// framing. [`Self::envelope_digest`] is a deterministic, domain-
/// separated SHA3-256 hex commitment over every framing field plus the
/// inner request canonical digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerTransportRequestEnvelope {
    /// Transport protocol version.
    pub protocol_version: u16,
    /// Domain tag. Must equal
    /// [`REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG`].
    pub domain_tag: String,
    /// Request id / nonce. Must be non-empty.
    pub request_id: String,
    /// Request timestamp / epoch (UNIX seconds).
    pub timestamp_unix: u64,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound custody key id.
    pub custody_key_id: String,
    /// Expected signer id (the signer this envelope addresses).
    pub expected_signer_id: String,
    /// Canonical request digest. Must equal
    /// `inner_request.canonical_digest()`.
    pub canonical_request_digest: String,
    /// Payload digest (the lifecycle/governance payload this request
    /// authorizes). Must be non-empty.
    pub payload_digest: String,
    /// Anti-replay nonce. Must be non-empty.
    pub anti_replay_nonce: String,
    /// The wrapped Run 194 request.
    pub inner_request: RemoteSignerRequest,
}

impl RemoteSignerTransportRequestEnvelope {
    /// Returns `true` iff every mandatory framing field is structurally
    /// present.
    pub fn is_well_formed(&self) -> bool {
        !self.domain_tag.is_empty()
            && !self.request_id.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.expected_signer_id.is_empty()
            && !self.canonical_request_digest.is_empty()
            && !self.payload_digest.is_empty()
            && !self.anti_replay_nonce.is_empty()
            && self.inner_request.is_well_formed()
    }

    /// Deterministic, domain-separated SHA3-256 hex digest over every
    /// framing field plus the inner request canonical digest.
    pub fn envelope_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"protocol_version", &self.protocol_version.to_le_bytes());
        field(b"domain_tag", self.domain_tag.as_bytes());
        field(b"request_id", self.request_id.as_bytes());
        field(b"timestamp_unix", &self.timestamp_unix.to_le_bytes());
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(b"custody_key_id", self.custody_key_id.as_bytes());
        field(b"expected_signer_id", self.expected_signer_id.as_bytes());
        field(
            b"canonical_request_digest",
            self.canonical_request_digest.as_bytes(),
        );
        field(b"payload_digest", self.payload_digest.as_bytes());
        field(b"anti_replay_nonce", self.anti_replay_nonce.as_bytes());
        field(
            b"inner_request_canonical_digest",
            self.inner_request.canonical_digest().as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Response envelope
// ===========================================================================

/// Run 201 — typed transport response envelope.
///
/// Wraps and binds the Run 194 [`RemoteSignerResponse`] with transport
/// framing. [`Self::envelope_digest`] is a deterministic, domain-
/// separated SHA3-256 hex commitment over every framing field **except**
/// the `transcript_digest` (which is computed *from* the request and
/// response envelope digests via [`transport_transcript_digest`], so it
/// cannot be part of the response envelope digest without circularity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerTransportResponseEnvelope {
    /// Transport protocol version.
    pub protocol_version: u16,
    /// Domain tag. Must equal
    /// [`REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG`].
    pub domain_tag: String,
    /// Request id echo. Must equal the request envelope `request_id`.
    pub request_id_echo: String,
    /// Signer id that produced this response.
    pub signer_id: String,
    /// Custody key id that produced this response.
    pub custody_key_id: String,
    /// Response timestamp (UNIX seconds).
    pub response_timestamp_unix: u64,
    /// Response expiry (UNIX seconds, exclusive). Must be strictly
    /// greater than `response_timestamp_unix`.
    pub response_expiry_unix: u64,
    /// Canonical response digest. Must equal
    /// [`remote_signer_response_canonical_digest`] of the inner
    /// response.
    pub canonical_response_digest: String,
    /// Signature suite id.
    pub signature_suite_id: u8,
    /// Response commitment / signature bytes placeholder. Must be
    /// non-empty.
    pub response_commitment: String,
    /// Request/response transcript digest. Must equal
    /// [`transport_transcript_digest`] of the request and response
    /// envelope digests.
    pub transcript_digest: String,
    /// The wrapped Run 194 response.
    pub inner_response: RemoteSignerResponse,
}

impl RemoteSignerTransportResponseEnvelope {
    /// Returns `true` iff every mandatory framing field is structurally
    /// present.
    pub fn is_well_formed(&self) -> bool {
        !self.domain_tag.is_empty()
            && !self.request_id_echo.is_empty()
            && !self.signer_id.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.canonical_response_digest.is_empty()
            && !self.response_commitment.is_empty()
            && !self.transcript_digest.is_empty()
            && self.inner_response.is_well_formed()
    }

    /// Deterministic, domain-separated SHA3-256 hex digest over every
    /// framing field **except** `transcript_digest`, plus the inner
    /// response canonical digest.
    pub fn envelope_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"protocol_version", &self.protocol_version.to_le_bytes());
        field(b"domain_tag", self.domain_tag.as_bytes());
        field(b"request_id_echo", self.request_id_echo.as_bytes());
        field(b"signer_id", self.signer_id.as_bytes());
        field(b"custody_key_id", self.custody_key_id.as_bytes());
        field(
            b"response_timestamp_unix",
            &self.response_timestamp_unix.to_le_bytes(),
        );
        field(
            b"response_expiry_unix",
            &self.response_expiry_unix.to_le_bytes(),
        );
        field(
            b"canonical_response_digest",
            self.canonical_response_digest.as_bytes(),
        );
        field(b"signature_suite_id", &[self.signature_suite_id]);
        field(b"response_commitment", self.response_commitment.as_bytes());
        field(
            b"inner_response_canonical_digest",
            remote_signer_response_canonical_digest(&self.inner_response).as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Canonical digests / transcript binding
// ===========================================================================

/// Run 201 — deterministic, domain-separated canonical digest over a
/// Run 194 [`RemoteSignerResponse`].
///
/// Run 194 binds a response by echoing the request digest, but does not
/// expose a single canonical response digest. Run 201 adds one here so
/// the transport response envelope can bind it.
pub fn remote_signer_response_canonical_digest(response: &RemoteSignerResponse) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"QBIND:run201-remote-signer-response-canonical:v1");
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"request_digest", response.request_digest.as_bytes());
    field(b"signer_id", response.signer_id.as_bytes());
    field(b"custody_key_id", response.custody_key_id.as_bytes());
    field(b"signature_suite_id", &[response.signature_suite_id]);
    field(
        b"signature_commitment",
        response.signature_commitment.as_bytes(),
    );
    field(b"response_nonce", response.response_nonce.as_bytes());
    field(
        b"freshness_unix",
        &response.freshness_unix.unwrap_or(0).to_le_bytes(),
    );
    field(
        b"freshness_present",
        &[response.freshness_unix.is_some() as u8],
    );
    field(
        b"expires_at_unix",
        &response.expires_at_unix.unwrap_or(0).to_le_bytes(),
    );
    field(
        b"expires_present",
        &[response.expires_at_unix.is_some() as u8],
    );
    field(b"signer_mode", response.signer_mode.tag().as_bytes());
    hex::encode(h.finalize())
}

/// Run 201 — deterministic, domain-separated request/response transport
/// transcript digest.
///
/// Binds the request envelope digest and the response envelope digest
/// into a single transcript commitment. The response envelope carries
/// this value in its `transcript_digest` field; the verifier recomputes
/// it and rejects a mismatch as
/// [`RemoteSignerTransportOutcome::WrongTranscriptDigest`].
pub fn transport_transcript_digest(
    request_envelope_digest: &str,
    response_envelope_digest: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(REMOTE_SIGNER_TRANSPORT_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"request_envelope_digest", request_envelope_digest.as_bytes());
    field(
        b"response_envelope_digest",
        response_envelope_digest.as_bytes(),
    );
    hex::encode(h.finalize())
}

// ===========================================================================
// Typed outcome
// ===========================================================================

/// Run 201 — typed outcome of the RemoteSigner transport boundary.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching the
/// inner envelopes. Acceptance is **always** of a fixture loopback
/// transport response under the explicit
/// [`RemoteSignerPolicy::FixtureLoopbackAllowed`] policy on a
/// DevNet/TestNet trust domain — production transport is refused as
/// unavailable regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerTransportOutcome {
    /// DevNet/TestNet fixture loopback transport accepted under the
    /// explicit `FixtureLoopbackAllowed` policy. Acceptance is
    /// evidence-only; no MainNet apply, no governance execution, no
    /// mutation.
    FixtureLoopbackTransportAccepted {
        signer_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy is `Disabled`. Every transport call fails
    /// closed.
    TransportDisabled,
    /// Fixture transport rejected because the active policy is
    /// `ProductionRemoteSignerRequired`.
    FixtureTransportRejectedProductionRequired,
    /// Fixture transport rejected because the active policy is
    /// `MainnetProductionRemoteSignerRequired`.
    FixtureTransportRejectedMainnetProductionRequired,
    /// Production transport is unavailable. Run 201 has no real backend;
    /// every production transport call fails closed here.
    ProductionTransportUnavailable,
    /// MainNet production transport is unavailable. Distinct from
    /// [`Self::ProductionTransportUnavailable`] so the calling surface
    /// can log a precise "MainNet production transport unavailable" line
    /// layered ahead of the Run 147 / 148 / 152 FATAL peer-driven-apply
    /// refusal.
    MainNetProductionTransportUnavailable,
    /// Fixture loopback transport rejected because the trust domain is
    /// MainNet. Fixture loopback transport is DevNet/TestNet source/test
    /// only.
    FixtureLoopbackTransportRejectedForMainNet,
    /// The endpoint is missing (empty).
    EndpointMissing,
    /// The endpoint is structurally malformed.
    EndpointMalformed { endpoint: String },
    /// Trust-domain environment does not match the config/envelope.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        attested: TrustBundleEnvironment,
    },
    /// Trust-domain chain id does not match the config/envelope.
    WrongChain { expected: String, attested: String },
    /// Trust-domain genesis hash does not match the config/envelope.
    WrongGenesis { expected: String, attested: String },
    /// Trust-domain authority root fingerprint does not match.
    WrongAuthorityRoot { expected: String, attested: String },
    /// Signer id does not match between config / envelope / response.
    WrongSignerId { expected: String, attested: String },
    /// Custody key id does not match between config / envelope /
    /// response.
    WrongCustodyKeyId { expected: String, attested: String },
    /// Signing-key fingerprint does not match the expected value.
    WrongSigningKeyFingerprint { expected: String, attested: String },
    /// Request id does not match between the request envelope and the
    /// response echo (or the expected request id).
    WrongRequestId { expected: String, attested: String },
    /// The request envelope canonical request digest does not match the
    /// inner request canonical digest.
    WrongRequestDigest { expected: String, attested: String },
    /// The response envelope canonical response digest does not match
    /// the inner response canonical digest.
    WrongResponseDigest { expected: String, attested: String },
    /// The response envelope transcript digest does not match the
    /// recomputed request/response transcript digest.
    WrongTranscriptDigest { expected: String, attested: String },
    /// Request anti-replay nonce did not match the expected fresh nonce
    /// (stale or replayed request).
    StaleOrReplayedRequest { expected: String, attested: String },
    /// Response request-id echo / commitment did not match the expected
    /// fresh response material (stale or replayed response).
    StaleOrReplayedResponse { expected: String, attested: String },
    /// The transport timed out.
    Timeout,
    /// The transport exhausted its retry budget.
    RetryExhausted,
    /// The request envelope is structurally malformed.
    MalformedRequestEnvelope { reason: String },
    /// The response envelope is structurally malformed.
    MalformedResponseEnvelope { reason: String },
    /// The transport protocol version is not supported.
    UnsupportedProtocolVersion { version: u16 },
    /// The signature suite id is not supported.
    UnsupportedSuite { suite_id: u8 },
    /// The transport certificate / attestation placeholder is invalid.
    InvalidTransportAttestation,
    /// A local operator cannot satisfy a remote signer transport policy.
    LocalOperatorCannotSatisfyTransport,
    /// Peer majority / gossip count cannot satisfy a remote signer
    /// transport policy.
    PeerMajorityCannotSatisfyTransport,
    /// The transport framing validated but the wrapped Run 194
    /// RemoteSigner response was invalid (carries the inner reject).
    RemoteSignerResponseInvalid {
        remote_signer_outcome: crate::pqc_remote_authority_signer::RemoteSignerOutcome,
    },
    /// The custody class routed in is not `RemoteSigner`.
    NotRemoteSignerCustodyClass { class: AuthorityCustodyClass },
}

impl RemoteSignerTransportOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::FixtureLoopbackTransportAccepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production transport" rejection.
    pub fn is_production_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionTransportUnavailable | Self::MainNetProductionTransportUnavailable
        )
    }
}

// ===========================================================================
// Transport trait + implementations
// ===========================================================================

/// Run 201 — pure / mockable RemoteSigner transport boundary.
///
/// Implementations perform no network or file I/O, write no marker,
/// write no sequence, mutate no live trust, evict no sessions, and never
/// invoke Run 070. A production implementation fails closed by returning
/// [`RemoteSignerTransportOutcome::ProductionTransportUnavailable`]
/// (or the MainNet variant) until a real backend lands.
pub trait RemoteSignerTransport {
    /// The transport config this implementation presents.
    fn config(&self) -> &RemoteSignerTransportConfig;

    /// Attempt to call the remote signer with `request_env`. Returns a
    /// typed response envelope on success, or a typed
    /// [`RemoteSignerTransportOutcome`] reject. No I/O is performed.
    fn call_remote_signer(
        &self,
        request_env: &RemoteSignerTransportRequestEnvelope,
    ) -> Result<RemoteSignerTransportResponseEnvelope, RemoteSignerTransportOutcome>;
}

/// Run 201 — free helper that dispatches to
/// [`RemoteSignerTransport::call_remote_signer`]. Grep-verifiable named
/// entry point.
pub fn send_remote_signer_request<T: RemoteSignerTransport + ?Sized>(
    transport: &T,
    request_env: &RemoteSignerTransportRequestEnvelope,
) -> Result<RemoteSignerTransportResponseEnvelope, RemoteSignerTransportOutcome> {
    transport.call_remote_signer(request_env)
}

/// Run 201 — typed simulated transport fault for the source/test fixture
/// loopback transport.
///
/// Lets a source/test exercise the timeout / retry-exhausted / invalid-
/// attestation fail-closed paths without any real I/O. The production
/// transport never consults this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimulatedTransportFault {
    /// The transport timed out.
    Timeout,
    /// The transport exhausted its retry budget.
    RetryExhausted,
    /// The transport certificate / attestation placeholder is invalid.
    InvalidTransportAttestation,
}

/// Run 201 — DevNet/TestNet fixture loopback transport.
///
/// **Source/test only.** Produces a deterministic, well-formed response
/// envelope that echoes the request id and binds the transcript digest.
/// It is NOT a real transport; it exists only so DevNet/TestNet
/// source/test vectors can exercise the accepted path. The fixture
/// loopback transport must never be wired into a production surface, and
/// is refused on a MainNet trust domain by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureLoopbackRemoteSignerTransport {
    pub config: RemoteSignerTransportConfig,
    /// The wrapped Run 194 fixture signer identity used to produce the
    /// inner response.
    pub identity: RemoteSignerIdentity,
    pub response_nonce: String,
    pub response_freshness_unix: Option<u64>,
    pub response_expires_at_unix: Option<u64>,
    pub response_timestamp_unix: u64,
    pub response_expiry_unix: u64,
    /// Optional simulated fault for source/test fail-closed coverage.
    pub simulated_fault: Option<SimulatedTransportFault>,
}

impl FixtureLoopbackRemoteSignerTransport {
    /// Build the deterministic response envelope for `request_env`
    /// without consulting any simulated fault. Pure; no I/O.
    pub fn build_response_envelope(
        &self,
        request_env: &RemoteSignerTransportRequestEnvelope,
    ) -> RemoteSignerTransportResponseEnvelope {
        // Deterministic placeholder signature commitment derived from
        // the request envelope digest and signer id. Never a real
        // signature.
        let request_envelope_digest = request_env.envelope_digest();
        let signature_commitment = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(REMOTE_SIGNER_TRANSPORT_FIXTURE_COMMITMENT_DOMAIN_TAG.as_bytes());
            h.update(self.identity.signer_id.as_bytes());
            h.update(request_envelope_digest.as_bytes());
            hex::encode(h.finalize())
        };
        let inner_response = RemoteSignerResponse {
            request_digest: request_env.inner_request.canonical_digest(),
            signer_id: self.identity.signer_id.clone(),
            custody_key_id: self.identity.custody_key_id.clone(),
            signature_suite_id: self.identity.supported_suite_id,
            signature_commitment: signature_commitment.clone(),
            response_nonce: self.response_nonce.clone(),
            freshness_unix: self.response_freshness_unix,
            expires_at_unix: self.response_expires_at_unix,
            signer_mode: RemoteSignerMode::FixtureLoopback,
        };
        let canonical_response_digest = remote_signer_response_canonical_digest(&inner_response);
        // Build the response envelope without the transcript digest
        // first so its envelope digest is stable, then bind the
        // transcript.
        let mut response_env = RemoteSignerTransportResponseEnvelope {
            protocol_version: REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
            domain_tag: REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG.to_string(),
            request_id_echo: request_env.request_id.clone(),
            signer_id: self.identity.signer_id.clone(),
            custody_key_id: self.identity.custody_key_id.clone(),
            response_timestamp_unix: self.response_timestamp_unix,
            response_expiry_unix: self.response_expiry_unix,
            canonical_response_digest,
            signature_suite_id: self.identity.supported_suite_id,
            response_commitment: signature_commitment,
            transcript_digest: String::new(),
            inner_response,
        };
        let response_envelope_digest = response_env.envelope_digest();
        response_env.transcript_digest =
            transport_transcript_digest(&request_envelope_digest, &response_envelope_digest);
        response_env
    }
}

impl RemoteSignerTransport for FixtureLoopbackRemoteSignerTransport {
    fn config(&self) -> &RemoteSignerTransportConfig {
        &self.config
    }

    fn call_remote_signer(
        &self,
        request_env: &RemoteSignerTransportRequestEnvelope,
    ) -> Result<RemoteSignerTransportResponseEnvelope, RemoteSignerTransportOutcome> {
        if !request_env.is_well_formed() {
            return Err(RemoteSignerTransportOutcome::MalformedRequestEnvelope {
                reason: "request envelope missing one or more mandatory fields".to_string(),
            });
        }
        if let Some(fault) = self.simulated_fault {
            return Err(match fault {
                SimulatedTransportFault::Timeout => RemoteSignerTransportOutcome::Timeout,
                SimulatedTransportFault::RetryExhausted => {
                    RemoteSignerTransportOutcome::RetryExhausted
                }
                SimulatedTransportFault::InvalidTransportAttestation => {
                    RemoteSignerTransportOutcome::InvalidTransportAttestation
                }
            });
        }
        Ok(self.build_response_envelope(request_env))
    }
}

/// Run 201 — production remote signer transport placeholder.
///
/// Callable but fails closed:
/// [`RemoteSignerTransport::call_remote_signer`] always returns
/// [`RemoteSignerTransportOutcome::ProductionTransportUnavailable`]
/// (or the MainNet variant for a MainNet config) because Run 201 wires
/// no real production transport backend. A future run that lands a real
/// backend MUST replace this implementation and cannot silently elevate
/// the fixture loopback transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRemoteSignerTransport {
    pub config: RemoteSignerTransportConfig,
}

impl RemoteSignerTransport for ProductionRemoteSignerTransport {
    fn config(&self) -> &RemoteSignerTransportConfig {
        &self.config
    }

    fn call_remote_signer(
        &self,
        _request_env: &RemoteSignerTransportRequestEnvelope,
    ) -> Result<RemoteSignerTransportResponseEnvelope, RemoteSignerTransportOutcome> {
        if self.config.environment == TrustBundleEnvironment::Mainnet {
            Err(RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable)
        } else {
            Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
        }
    }
}

// ===========================================================================
// Transport expectations
// ===========================================================================

/// Run 201 — caller-supplied transport-level binding expectations for
/// [`validate_remote_signer_transport`].
///
/// Pure data, typically derived from the persisted candidate metadata
/// and the per-attempt anti-replay / request-id material the calling
/// surface generated for this transport round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerTransportExpectations {
    pub expected_request_id: String,
    pub expected_payload_digest: String,
    pub expected_anti_replay_nonce: String,
    pub expected_signer_identity_digest: String,
    pub expected_transport_attestation_digest: Option<String>,
    pub now_unix: u64,
}

// ===========================================================================
// Verifier
// ===========================================================================

/// Run 201 — pure typed RemoteSigner transport verifier.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust. Evicts no sessions. Never invokes Run 070.
///
/// The verifier gates by policy, then binds the transport config and
/// both envelopes to the trust domain, the signer id, the custody key
/// id, the signing-key fingerprint, the request id, the canonical
/// request/response digests, the anti-replay nonce, the transport
/// attestation, the protocol version, and the suite; then it composes
/// the Run 194 [`validate_remote_signer`] verifier over the wrapped
/// request/response; and finally it binds the request/response
/// transcript digest. Acceptance is only ever a fixture loopback
/// transport response under `FixtureLoopbackAllowed` on a DevNet/TestNet
/// trust domain.
#[allow(clippy::too_many_arguments)]
pub fn validate_remote_signer_transport(
    config: &RemoteSignerTransportConfig,
    request_env: &RemoteSignerTransportRequestEnvelope,
    response_env: &RemoteSignerTransportResponseEnvelope,
    trust_domain: &AuthorityTrustDomain,
    identity: &RemoteSignerIdentity,
    remote_signer_expected: &RemoteSignerExpectations,
    transport_expected: &RemoteSignerTransportExpectations,
    policy: RemoteSignerPolicy,
) -> RemoteSignerTransportOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies
    //    fail closed before any binding check — but the production
    //    policies still distinguish fixture material (rejected as
    //    "fixture rejected") from production material (rejected as
    //    "unavailable").
    match policy {
        RemoteSignerPolicy::Disabled => return RemoteSignerTransportOutcome::TransportDisabled,
        RemoteSignerPolicy::ProductionRemoteSignerRequired => {
            return match response_env.inner_response.signer_mode {
                RemoteSignerMode::FixtureLoopback => {
                    RemoteSignerTransportOutcome::FixtureTransportRejectedProductionRequired
                }
                RemoteSignerMode::Production => {
                    RemoteSignerTransportOutcome::ProductionTransportUnavailable
                }
            };
        }
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired => {
            return match response_env.inner_response.signer_mode {
                RemoteSignerMode::FixtureLoopback => {
                    RemoteSignerTransportOutcome::FixtureTransportRejectedMainnetProductionRequired
                }
                RemoteSignerMode::Production => {
                    RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable
                }
            };
        }
        RemoteSignerPolicy::FixtureLoopbackAllowed => {}
    }

    // 2. Under `FixtureLoopbackAllowed`, a production-mode response is
    //    still unavailable (no real backend exists).
    if response_env.inner_response.signer_mode == RemoteSignerMode::Production {
        return RemoteSignerTransportOutcome::ProductionTransportUnavailable;
    }

    // 3. Fixture loopback transport is DevNet/TestNet source/test only —
    //    never MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return RemoteSignerTransportOutcome::FixtureLoopbackTransportRejectedForMainNet;
    }

    // 4. Endpoint presence / well-formedness.
    if config.endpoint.is_empty() {
        return RemoteSignerTransportOutcome::EndpointMissing;
    }
    if !endpoint_is_well_formed(&config.endpoint) {
        return RemoteSignerTransportOutcome::EndpointMalformed {
            endpoint: config.endpoint.clone(),
        };
    }

    // 5. Structural well-formedness of config and envelopes.
    if !config.is_well_formed() {
        return RemoteSignerTransportOutcome::MalformedRequestEnvelope {
            reason: "transport config missing one or more mandatory fields".to_string(),
        };
    }
    if !request_env.is_well_formed() {
        return RemoteSignerTransportOutcome::MalformedRequestEnvelope {
            reason: "request envelope missing one or more mandatory fields".to_string(),
        };
    }
    if !response_env.is_well_formed() {
        return RemoteSignerTransportOutcome::MalformedResponseEnvelope {
            reason: "response envelope missing one or more mandatory fields".to_string(),
        };
    }

    // 6. Protocol version (both envelopes).
    if request_env.protocol_version != REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION {
        return RemoteSignerTransportOutcome::UnsupportedProtocolVersion {
            version: request_env.protocol_version,
        };
    }
    if response_env.protocol_version != REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION {
        return RemoteSignerTransportOutcome::UnsupportedProtocolVersion {
            version: response_env.protocol_version,
        };
    }

    // 7. Domain-tag framing (treated as structural).
    if request_env.domain_tag != REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG {
        return RemoteSignerTransportOutcome::MalformedRequestEnvelope {
            reason: "request envelope domain tag mismatch".to_string(),
        };
    }
    if response_env.domain_tag != REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG {
        return RemoteSignerTransportOutcome::MalformedResponseEnvelope {
            reason: "response envelope domain tag mismatch".to_string(),
        };
    }

    // 8. Trust-domain environment binding (config + both envelopes +
    //    identity).
    if config.environment != trust_domain.environment
        || request_env.environment != trust_domain.environment
        || identity.environment != trust_domain.environment
    {
        return RemoteSignerTransportOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: config.environment,
        };
    }

    // 9. Trust-domain chain binding.
    if config.chain_id != trust_domain.chain_id
        || request_env.chain_id != trust_domain.chain_id
        || identity.chain_id != trust_domain.chain_id
    {
        return RemoteSignerTransportOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: config.chain_id.clone(),
        };
    }

    // 10. Trust-domain genesis binding.
    if config.genesis_hash != trust_domain.genesis_hash
        || request_env.genesis_hash != trust_domain.genesis_hash
        || identity.genesis_hash != trust_domain.genesis_hash
    {
        return RemoteSignerTransportOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: config.genesis_hash.clone(),
        };
    }

    // 11. Authority root binding.
    if config.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || request_env.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || identity.authority_root_fingerprint != trust_domain.authority_root_fingerprint
    {
        return RemoteSignerTransportOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: config.authority_root_fingerprint.clone(),
        };
    }

    // 12. Signer-id binding (config + envelope expected + response echo
    //     + identity).
    if config.signer_id != identity.signer_id
        || request_env.expected_signer_id != identity.signer_id
        || response_env.signer_id != identity.signer_id
    {
        return RemoteSignerTransportOutcome::WrongSignerId {
            expected: identity.signer_id.clone(),
            attested: response_env.signer_id.clone(),
        };
    }

    // 13. Custody-key-id binding (config + envelopes + identity).
    if config.custody_key_id != identity.custody_key_id
        || request_env.custody_key_id != identity.custody_key_id
        || response_env.custody_key_id != identity.custody_key_id
    {
        return RemoteSignerTransportOutcome::WrongCustodyKeyId {
            expected: identity.custody_key_id.clone(),
            attested: response_env.custody_key_id.clone(),
        };
    }

    // 14. Signing-key fingerprint binding (config + request).
    let request_signing_fp = request_env
        .inner_request
        .primary_signing_key_fingerprint()
        .unwrap_or("")
        .to_string();
    if config.bundle_signing_key_fingerprint != remote_signer_expected.expected_signing_key_fingerprint
        || request_signing_fp != remote_signer_expected.expected_signing_key_fingerprint
    {
        return RemoteSignerTransportOutcome::WrongSigningKeyFingerprint {
            expected: remote_signer_expected.expected_signing_key_fingerprint.clone(),
            attested: config.bundle_signing_key_fingerprint.clone(),
        };
    }

    // 15. Suite binding (config + response envelope + identity). The
    //     request envelope carries no suite of its own; the suite is
    //     bound through the config, the response envelope, and the
    //     identity.
    if config.suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || response_env.signature_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || identity.supported_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
    {
        return RemoteSignerTransportOutcome::UnsupportedSuite {
            suite_id: response_env.signature_suite_id,
        };
    }

    // 16. Request-id binding (expected + response echo).
    if request_env.request_id != transport_expected.expected_request_id
        || response_env.request_id_echo != request_env.request_id
    {
        return RemoteSignerTransportOutcome::WrongRequestId {
            expected: transport_expected.expected_request_id.clone(),
            attested: response_env.request_id_echo.clone(),
        };
    }

    // 17. Payload-digest binding.
    if request_env.payload_digest != transport_expected.expected_payload_digest {
        return RemoteSignerTransportOutcome::MalformedRequestEnvelope {
            reason: "payload_digest does not match expected".to_string(),
        };
    }

    // 18. Anti-replay request nonce.
    if request_env.anti_replay_nonce != transport_expected.expected_anti_replay_nonce {
        return RemoteSignerTransportOutcome::StaleOrReplayedRequest {
            expected: transport_expected.expected_anti_replay_nonce.clone(),
            attested: request_env.anti_replay_nonce.clone(),
        };
    }

    // 19. Canonical request-digest binding (envelope ↔ inner request).
    let inner_request_digest = request_env.inner_request.canonical_digest();
    if request_env.canonical_request_digest != inner_request_digest {
        return RemoteSignerTransportOutcome::WrongRequestDigest {
            expected: inner_request_digest,
            attested: request_env.canonical_request_digest.clone(),
        };
    }

    // 20. Canonical response-digest binding (envelope ↔ inner response).
    let inner_response_digest = remote_signer_response_canonical_digest(&response_env.inner_response);
    if response_env.canonical_response_digest != inner_response_digest {
        return RemoteSignerTransportOutcome::WrongResponseDigest {
            expected: inner_response_digest,
            attested: response_env.canonical_response_digest.clone(),
        };
    }

    // 21. Response freshness window (timestamp < expiry, now within).
    if response_env.response_expiry_unix <= response_env.response_timestamp_unix
        || transport_expected.now_unix < response_env.response_timestamp_unix
        || transport_expected.now_unix >= response_env.response_expiry_unix
    {
        return RemoteSignerTransportOutcome::StaleOrReplayedResponse {
            expected: response_env.request_id_echo.clone(),
            attested: response_env.request_id_echo.clone(),
        };
    }

    // 22. Transport attestation validity.
    //     The config attestation, when present, must be non-empty and
    //     not the explicit invalid sentinel, and must match the caller's
    //     expectation.
    if let Some(att) = config.transport_attestation_digest.as_deref() {
        if att.is_empty() || att == REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL {
            return RemoteSignerTransportOutcome::InvalidTransportAttestation;
        }
    }
    if config.transport_attestation_digest != transport_expected.expected_transport_attestation_digest
    {
        return RemoteSignerTransportOutcome::InvalidTransportAttestation;
    }
    if config.expected_signer_identity_digest != transport_expected.expected_signer_identity_digest {
        return RemoteSignerTransportOutcome::InvalidTransportAttestation;
    }

    // 23. Compose the Run 194 RemoteSigner verifier over the wrapped
    //     request/response. R30: transport valid but RemoteSigner
    //     response invalid.
    let remote_signer_outcome = validate_remote_signer(
        identity,
        &request_env.inner_request,
        &response_env.inner_response,
        trust_domain,
        remote_signer_expected,
        policy,
    );
    if !remote_signer_outcome.is_accept() {
        return RemoteSignerTransportOutcome::RemoteSignerResponseInvalid {
            remote_signer_outcome,
        };
    }

    // 24. Transcript binding. R31: RemoteSigner response valid but
    //     transport transcript invalid.
    let request_envelope_digest = request_env.envelope_digest();
    let response_envelope_digest = response_env.envelope_digest();
    let expected_transcript =
        transport_transcript_digest(&request_envelope_digest, &response_envelope_digest);
    if response_env.transcript_digest != expected_transcript {
        return RemoteSignerTransportOutcome::WrongTranscriptDigest {
            expected: expected_transcript,
            attested: response_env.transcript_digest.clone(),
        };
    }

    // 25. Accept — fixture loopback transport only, DevNet/TestNet,
    //     evidence-only.
    RemoteSignerTransportOutcome::FixtureLoopbackTransportAccepted {
        signer_id: identity.signer_id.clone(),
        environment: trust_domain.environment,
    }
}

// ===========================================================================
// Custody-class routing
// ===========================================================================

/// Run 201 — returns `true` iff the custody class routes into the
/// remote-signer transport boundary (i.e.
/// `AuthorityCustodyClass::RemoteSigner`).
pub const fn custody_class_routes_to_remote_signer_transport(class: AuthorityCustodyClass) -> bool {
    matches!(class, AuthorityCustodyClass::RemoteSigner)
}

/// Run 201 — route a Run 188 custody class into the remote-signer
/// transport boundary.
///
/// * `AuthorityCustodyClass::RemoteSigner` is dispatched to
///   [`validate_remote_signer_transport`].
/// * `AuthorityCustodyClass::LocalOperatorKey` is refused as
///   [`RemoteSignerTransportOutcome::LocalOperatorCannotSatisfyTransport`]
///   — a local operator key can never satisfy a remote signer transport
///   policy.
/// * every other class is refused as
///   [`RemoteSignerTransportOutcome::NotRemoteSignerCustodyClass`].
#[allow(clippy::too_many_arguments)]
pub fn validate_remote_signer_transport_for_custody_class(
    custody_class: AuthorityCustodyClass,
    config: &RemoteSignerTransportConfig,
    request_env: &RemoteSignerTransportRequestEnvelope,
    response_env: &RemoteSignerTransportResponseEnvelope,
    trust_domain: &AuthorityTrustDomain,
    identity: &RemoteSignerIdentity,
    remote_signer_expected: &RemoteSignerExpectations,
    transport_expected: &RemoteSignerTransportExpectations,
    policy: RemoteSignerPolicy,
) -> RemoteSignerTransportOutcome {
    match custody_class {
        AuthorityCustodyClass::RemoteSigner => validate_remote_signer_transport(
            config,
            request_env,
            response_env,
            trust_domain,
            identity,
            remote_signer_expected,
            transport_expected,
            policy,
        ),
        AuthorityCustodyClass::LocalOperatorKey => {
            RemoteSignerTransportOutcome::LocalOperatorCannotSatisfyTransport
        }
        other => RemoteSignerTransportOutcome::NotRemoteSignerCustodyClass { class: other },
    }
}

// ===========================================================================
// Composition helper
// ===========================================================================

/// Run 201 — typed combined decision for a lifecycle + governance +
/// custody + remote-signer + transport preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleCustodyRemoteSignerTransportOutcome {
    /// The Run 194 lifecycle + governance + custody + remote-signer
    /// composition validated AND the Run 201 transport boundary
    /// validated. Carries both typed outcomes. **Acceptance is
    /// evidence-only.** It does not enable MainNet apply, does not
    /// perform a Run 070 call, does not write a marker, does not burn a
    /// sequence number, does not swap live trust, and does not evict
    /// sessions.
    Accepted {
        lifecycle_custody_remote_signer_outcome: LifecycleCustodyRemoteSignerOutcome,
        transport_outcome: RemoteSignerTransportOutcome,
    },
    /// The Run 194 lifecycle/custody/remote-signer composition rejected.
    /// The transport boundary was not consulted.
    LifecycleCustodyOrRemoteSignerRejected(LifecycleCustodyRemoteSignerOutcome),
    /// The Run 194 composition accepted but the Run 201 transport
    /// boundary rejected. Carries both so the operator log line can
    /// record "remote signer valid + transport invalid".
    TransportRejected {
        lifecycle_custody_remote_signer_outcome: LifecycleCustodyRemoteSignerOutcome,
        transport_outcome: RemoteSignerTransportOutcome,
    },
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of any custody, remote-signer,
    /// or transport outcome.
    MainNetPeerDrivenApplyRefused,
}

impl LifecycleCustodyRemoteSignerTransportOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 201 — pure composition helper.
///
/// Calls the Run 194 lifecycle + governance + custody + remote-signer
/// composition, then (if accepted) calls the Run 201 transport verifier,
/// and returns a typed combined decision. Performs no I/O, writes no
/// marker, writes no sequence, mutates no live trust, evicts no
/// sessions, never invokes Run 070.
///
/// `is_peer_driven_apply_preflight` lets the calling surface request the
/// MainNet peer-driven-apply refusal short-circuit: when set and the
/// trust domain is MainNet, the helper returns
/// [`LifecycleCustodyRemoteSignerTransportOutcome::MainNetPeerDrivenApplyRefused`]
/// without consulting custody, the remote signer, or the transport — the
/// fixture loopback transport can never enable a MainNet apply.
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_custody_remote_signer_and_transport(
    custody_attestation: &AuthorityCustodyAttestation,
    candidate: &PersistentAuthorityStateRecordV2,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    custody_policy: AuthorityCustodyPolicy,
    identity: &RemoteSignerIdentity,
    request: &RemoteSignerRequest,
    response: &RemoteSignerResponse,
    remote_signer_expected: &RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    transport_config: &RemoteSignerTransportConfig,
    request_env: &RemoteSignerTransportRequestEnvelope,
    response_env: &RemoteSignerTransportResponseEnvelope,
    transport_expected: &RemoteSignerTransportExpectations,
    now_unix: u64,
    is_peer_driven_apply_preflight: bool,
) -> LifecycleCustodyRemoteSignerTransportOutcome {
    // MainNet peer-driven apply remains refused regardless of any
    // fixture loopback transport success.
    if is_peer_driven_apply_preflight && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return LifecycleCustodyRemoteSignerTransportOutcome::MainNetPeerDrivenApplyRefused;
    }

    let inner = validate_lifecycle_governance_custody_and_remote_signer(
        custody_attestation,
        candidate,
        persisted,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        identity,
        request,
        response,
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
        is_peer_driven_apply_preflight,
    );

    if !inner.is_accept() {
        return LifecycleCustodyRemoteSignerTransportOutcome::LifecycleCustodyOrRemoteSignerRejected(
            inner,
        );
    }

    let transport_outcome = validate_remote_signer_transport(
        transport_config,
        request_env,
        response_env,
        trust_domain,
        identity,
        remote_signer_expected,
        transport_expected,
        remote_signer_policy,
    );

    if transport_outcome.is_accept() {
        LifecycleCustodyRemoteSignerTransportOutcome::Accepted {
            lifecycle_custody_remote_signer_outcome: inner,
            transport_outcome,
        }
    } else {
        LifecycleCustodyRemoteSignerTransportOutcome::TransportRejected {
            lifecycle_custody_remote_signer_outcome: inner,
            transport_outcome,
        }
    }
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 201 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes,
/// at the typed Run 201 boundary, the rule that MainNet peer-driven
/// apply remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// remote-signer transport response — even a fixture loopback transport
/// response that returns successfully. Pure data; never reads transport
/// material.
pub fn mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 201 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a remote
/// signer transport policy. Run 201 always returns `true`: a remote
/// signer transport is a custody-held authority service and is never
/// satisfiable by a local operator key. Grep-verifiable named symbol for
/// an operator-log line.
pub fn local_operator_cannot_satisfy_remote_signer_transport() -> bool {
    true
}

/// Run 201 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// remote signer transport policy. Run 201 always returns `true`: a
/// remote signer transport is a per-key authority decision and is never
/// satisfiable by counting peers. Grep-verifiable named symbol for an
/// operator-log line.
pub fn peer_majority_cannot_satisfy_remote_signer_transport() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn endpoint_well_formedness() {
        assert!(endpoint_is_well_formed("qbind-signer://signer.example:8443"));
        assert!(endpoint_is_well_formed("abstract:signer-1"));
        assert!(endpoint_is_well_formed("fixture:loopback"));
        assert!(!endpoint_is_well_formed(""));
        assert!(!endpoint_is_well_formed("no-scheme-here"));
        assert!(!endpoint_is_well_formed("has space://x"));
    }

    #[test]
    fn timeout_retry_well_formedness() {
        assert!(TransportTimeoutRetryPolicy::default().is_well_formed());
        assert!(!TransportTimeoutRetryPolicy {
            per_attempt_timeout_ms: 0,
            max_attempts: 3
        }
        .is_well_formed());
        assert!(!TransportTimeoutRetryPolicy {
            per_attempt_timeout_ms: 10,
            max_attempts: 0
        }
        .is_well_formed());
    }

    #[test]
    fn fail_closed_helpers_are_true() {
        assert!(local_operator_cannot_satisfy_remote_signer_transport());
        assert!(peer_majority_cannot_satisfy_remote_signer_transport());
        assert!(
            mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
                TrustBundleEnvironment::Mainnet
            )
        );
        assert!(
            !mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
                TrustBundleEnvironment::Devnet
            )
        );
    }

    #[test]
    fn custody_class_routing_predicate() {
        assert!(custody_class_routes_to_remote_signer_transport(
            AuthorityCustodyClass::RemoteSigner
        ));
        assert!(!custody_class_routes_to_remote_signer_transport(
            AuthorityCustodyClass::LocalOperatorKey
        ));
    }
}
