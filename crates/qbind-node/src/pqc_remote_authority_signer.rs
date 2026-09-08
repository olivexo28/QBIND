//! Run 194 — source/test RemoteSigner production-custody interface
//! boundary for authority-lifecycle signing/custody.
//!
//! Source/test only. Run 194 does **not** wire a real remote signer
//! backend, a networked signer service, a real KMS, a real HSM, a
//! cloud-KMS integration, or a PKCS#11 integration; nor does it enable
//! MainNet peer-driven apply, real on-chain governance proof
//! verification, governance execution, or validator-set rotation. The
//! purpose of this module is to replace the vague Run 188
//! [`AuthorityCustodyClass::RemoteSigner`] placeholder with a *precise*
//! production-custody boundary that a later run can implement safely:
//!
//! * Define a typed remote-signer identity, request, and response that
//!   bind every authority decision to the same `(environment, chain_id,
//!   genesis_hash, authority_root_fingerprint, signing_key_fingerprint,
//!   lifecycle_action, candidate_digest, authority_domain_sequence,
//!   custody_key_id, custody_attestation_digest, request/response
//!   anti-replay nonces, freshness/expiry)` tuple that the Run 159 /
//!   163 / 178 / 186 / 188 verifiers already enforce, so a remote
//!   signer acceptance can never claim authority over a different
//!   lifecycle transition or trust domain.
//! * Provide a pure [`RemoteAuthoritySigner`] trait boundary, a
//!   DevNet/TestNet-only [`FixtureLoopbackRemoteSigner`], and a
//!   [`ProductionRemoteSigner`] that is callable but fails closed with
//!   [`RemoteSignerOutcome::ProductionRemoteSignerUnavailable`] until a
//!   real backend lands.
//! * Make `Disabled` the typed default policy and refuse, by symbol,
//!   every attempt to satisfy a production remote signer with fixture,
//!   local-operator, or peer-majority material.
//! * Refuse, by symbol, MainNet peer-driven apply even when a fixture
//!   loopback remote signer signs successfully.
//!
//! Release-binary RemoteSigner boundary evidence is **deferred to Run
//! 195**. KMS/HSM remain unimplemented, governance execution remains
//! unimplemented, real on-chain proof verification remains
//! unimplemented, validator-set rotation remains open, full C4 remains
//! open, and C5 remains open.
//!
//! The module is pure: every public function and trait method performs
//! no I/O, writes no marker, writes no sequence, mutates no live trust,
//! evicts no sessions, and never invokes Run 070 apply.

use crate::pqc_authority_custody::{
    validate_lifecycle_governance_and_custody, AuthorityCustodyAttestation, AuthorityCustodyClass,
    AuthorityCustodyPolicy, LifecycleGovernanceCustodyOutcome,
};
use crate::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Remote signer policy
// ===========================================================================

/// Run 194 — typed remote-signer custody policy.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// remote signer request regardless of contents, preserving the
/// Run 050–193 conservative defaults. `FixtureLoopbackAllowed` is a
/// DevNet/TestNet source/test-only policy that accepts a fixture
/// loopback remote signer. `ProductionRemoteSignerRequired` and
/// `MainnetProductionRemoteSignerRequired` REQUIRE a real production
/// remote signer backend — and Run 194 has none, so they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RemoteSignerPolicy {
    /// Default. Refuses every remote signer request. Used by every
    /// production surface unless a more specific policy is explicitly
    /// set.
    #[default]
    Disabled,
    /// Source/test fixture loopback policy. Accepts a fixture loopback
    /// remote signer on DevNet or TestNet trust domains only.
    FixtureLoopbackAllowed,
    /// Production remote signer required (DevNet/TestNet bring-up of a
    /// real backend). Run 194 fails closed because no real backend is
    /// implemented.
    ProductionRemoteSignerRequired,
    /// MainNet production remote signer required. Run 194 fails closed
    /// for every request — fixture material is rejected as
    /// non-production, and every production request is rejected as
    /// unavailable. MainNet peer-driven apply also remains the Run 147
    /// FATAL refusal regardless of this policy.
    MainnetProductionRemoteSignerRequired,
}

impl RemoteSignerPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureLoopbackAllowed => "fixture-loopback-allowed",
            Self::ProductionRemoteSignerRequired => "production-remote-signer-required",
            Self::MainnetProductionRemoteSignerRequired => {
                "mainnet-production-remote-signer-required"
            }
        }
    }

    /// Returns `true` iff this policy requires a real production remote
    /// signer backend (and therefore Run 194 fails closed).
    pub const fn requires_production_remote_signer(self) -> bool {
        matches!(
            self,
            Self::ProductionRemoteSignerRequired | Self::MainnetProductionRemoteSignerRequired
        )
    }
}

// ===========================================================================
// Remote signer mode
// ===========================================================================

/// Run 194 — typed marker recording which signer produced a response.
///
/// A response carries its mode so the verifier can distinguish, by
/// symbol, fixture loopback material (DevNet/TestNet source/test only)
/// from production material — without inspecting signature bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteSignerMode {
    /// DevNet/TestNet fixture loopback signer. Source/test only.
    FixtureLoopback,
    /// Real production remote signer. Run 194 has no real backend; the
    /// production signer is callable but never yields a response.
    Production,
}

impl RemoteSignerMode {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureLoopback => "fixture-loopback",
            Self::Production => "production",
        }
    }
}

// ===========================================================================
// Remote signer identity
// ===========================================================================

/// Run 194 — typed remote-signer identity.
///
/// Pure data describing *which* remote signer is presenting custody for
/// *which* trust domain over *which* authority root, plus the suite and
/// lifecycle actions it claims to support, a placeholder attestation
/// commitment, and an optional freshness/expiry window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerIdentity {
    /// Stable, opaque identifier of the remote signer.
    pub signer_id: String,
    /// Public identity material / fingerprint of the remote signer
    /// (placeholder; Run 194 only enforces non-emptiness).
    pub signer_public_identity: String,
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
    /// Suite id this signer supports (placeholder; only the Run 159 PQC
    /// signing suite is currently accepted).
    pub supported_suite_id: u8,
    /// Lifecycle actions this signer is authorized to sign.
    pub supported_lifecycle_actions: Vec<LocalLifecycleAction>,
    /// Placeholder custody attestation digest / commitment. Must be
    /// non-empty. Run 194 does not interpret the bytes.
    pub attestation_digest: String,
    /// Optional freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional attestation expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
}

impl RemoteSignerIdentity {
    /// Returns `true` iff this identity claims to support `action`.
    pub fn supports_lifecycle_action(&self, action: LocalLifecycleAction) -> bool {
        self.supported_lifecycle_actions.contains(&action)
    }
}

// ===========================================================================
// Remote signer request
// ===========================================================================

/// Run 194 — typed remote-signer request.
///
/// Binds the full authority-decision tuple the signer is being asked to
/// authorize, plus per-attempt anti-replay material. The
/// [`Self::canonical_digest`] is a deterministic SHA3-256 hex commitment
/// over every field; the response MUST echo it back as
/// `request_digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerRequest {
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
    /// Bound candidate digest (next persistent authority record digest).
    pub candidate_digest: String,
    /// Bound authority-domain sequence (next sequence number this
    /// request authorizes).
    pub authority_domain_sequence: u64,
    /// Active signing-key fingerprint, where applicable.
    pub active_signing_key_fingerprint: Option<String>,
    /// New signing-key fingerprint, where applicable.
    pub new_signing_key_fingerprint: Option<String>,
    /// Revoked signing-key fingerprint, where applicable.
    pub revoked_signing_key_fingerprint: Option<String>,
    /// Governance proof digest, where applicable.
    pub governance_proof_digest: Option<String>,
    /// Custody attestation digest bound to this request. Must be
    /// non-empty.
    pub custody_attestation_digest: String,
    /// Per-attempt anti-replay nonce. Must be non-empty.
    pub replay_nonce: String,
    /// Optional request timestamp / epoch (UNIX seconds).
    pub request_timestamp_unix: Option<u64>,
}

impl RemoteSignerRequest {
    /// The signing-key fingerprint this request primarily binds: the
    /// new key when present (rotation/activation), otherwise the active
    /// key, otherwise the revoked key.
    pub fn primary_signing_key_fingerprint(&self) -> Option<&str> {
        self.new_signing_key_fingerprint
            .as_deref()
            .or(self.active_signing_key_fingerprint.as_deref())
            .or(self.revoked_signing_key_fingerprint.as_deref())
    }

    /// Deterministic SHA3-256 hex digest over every request field. The
    /// digest is domain-separated so it can never collide with any
    /// other QBIND canonical digest.
    pub fn canonical_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"QBIND:run194-remote-signer-request:v1");
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        field(b"candidate_digest", self.candidate_digest.as_bytes());
        field(
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        field(
            b"active_signing_key_fingerprint",
            self.active_signing_key_fingerprint
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"new_signing_key_fingerprint",
            self.new_signing_key_fingerprint
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"revoked_signing_key_fingerprint",
            self.revoked_signing_key_fingerprint
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"governance_proof_digest",
            self.governance_proof_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"custody_attestation_digest",
            self.custody_attestation_digest.as_bytes(),
        );
        field(b"replay_nonce", self.replay_nonce.as_bytes());
        field(
            b"request_timestamp_unix",
            &self.request_timestamp_unix.unwrap_or(0).to_le_bytes(),
        );
        field(
            b"request_timestamp_present",
            &[self.request_timestamp_unix.is_some() as u8],
        );
        hex::encode(h.finalize())
    }

    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.custody_attestation_digest.is_empty()
            && !self.replay_nonce.is_empty()
    }
}

// ===========================================================================
// Remote signer response
// ===========================================================================

/// Run 194 — typed remote-signer response.
///
/// Binds the request digest, the signer identity, custody key id, the
/// signature suite, the placeholder signature commitment, anti-replay
/// material, and an optional freshness/expiry window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerResponse {
    /// Echoed canonical digest of the request this response signs.
    pub request_digest: String,
    /// Signer id that produced this response.
    pub signer_id: String,
    /// Custody key id that produced this response.
    pub custody_key_id: String,
    /// Signature suite id (placeholder; only the Run 159 PQC suite is
    /// accepted).
    pub signature_suite_id: u8,
    /// Placeholder signature commitment bytes. Must be non-empty and
    /// must not be the explicit invalid sentinel.
    pub signature_commitment: String,
    /// Per-response anti-replay nonce. Must be non-empty.
    pub response_nonce: String,
    /// Optional response freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional response expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
    /// Which signer mode produced this response.
    pub signer_mode: RemoteSignerMode,
}

impl RemoteSignerResponse {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.request_digest.is_empty()
            && !self.signer_id.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.signature_commitment.is_empty()
            && !self.response_nonce.is_empty()
    }
}

/// Explicit invalid-signature sentinel for source/test rejection
/// vectors. A response carrying this commitment is rejected as
/// [`RemoteSignerOutcome::InvalidSignature`].
pub const REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL: &str = "INVALID-SIGNATURE";

// ===========================================================================
// Expectations
// ===========================================================================

/// Run 194 — caller-supplied binding expectations for
/// [`validate_remote_signer`].
///
/// Pure data, typically derived from the persisted candidate metadata
/// and the per-attempt anti-replay material the calling surface
/// generated for this request/response round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerExpectations {
    pub expected_lifecycle_action: LocalLifecycleAction,
    pub expected_candidate_digest: String,
    pub expected_authority_domain_sequence: u64,
    pub expected_custody_key_id: String,
    pub expected_signing_key_fingerprint: String,
    pub expected_custody_attestation_digest: String,
    pub expected_request_nonce: String,
    pub expected_response_nonce: String,
    pub now_unix: u64,
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 194 — typed outcome of the remote-signer boundary.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching the
/// inner request/response. Acceptance is **always** of a fixture
/// loopback response under the explicit `FixtureLoopbackAllowed` policy
/// on a DevNet/TestNet trust domain — production requests are refused
/// as unavailable regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerOutcome {
    /// DevNet/TestNet fixture loopback remote signer accepted under the
    /// explicit `FixtureLoopbackAllowed` policy. Acceptance is
    /// evidence-only; no MainNet apply, no governance execution, no
    /// mutation.
    FixtureLoopbackAccepted {
        signer_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy is `Disabled`. Every request fails closed.
    Disabled,
    /// Fixture loopback rejected because the active policy is
    /// `ProductionRemoteSignerRequired`.
    FixtureRejectedProductionRequired,
    /// Fixture loopback rejected because the active policy is
    /// `MainnetProductionRemoteSignerRequired`.
    FixtureRejectedMainnetProductionRequired,
    /// Production remote signer is unavailable. Run 194 has no real
    /// backend; every production request fails closed here.
    ProductionRemoteSignerUnavailable,
    /// MainNet production remote signer is unavailable. Distinct from
    /// [`Self::ProductionRemoteSignerUnavailable`] so the calling
    /// surface can log a precise "MainNet production remote signer
    /// unavailable" line layered ahead of the Run 147 / 148 / 152 FATAL
    /// peer-driven-apply refusal.
    MainNetProductionRemoteSignerUnavailable,
    /// Fixture loopback rejected because the trust domain is MainNet.
    /// Fixture loopback is DevNet/TestNet source/test only.
    FixtureLoopbackRejectedForMainNet,
    /// Trust-domain environment does not match the request/identity.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        attested: TrustBundleEnvironment,
    },
    /// Trust-domain chain id does not match the request/identity.
    WrongChain { expected: String, attested: String },
    /// Trust-domain genesis hash does not match the request/identity.
    WrongGenesis { expected: String, attested: String },
    /// Trust-domain authority root fingerprint does not match.
    WrongAuthorityRoot { expected: String, attested: String },
    /// Custody key id does not match the expected value.
    WrongCustodyKeyId { expected: String, attested: String },
    /// Signing-key fingerprint does not match the expected value.
    WrongSigningKeyFingerprint { expected: String, attested: String },
    /// Lifecycle action does not match the expected value (or the
    /// identity does not support it).
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        attested: LocalLifecycleAction,
    },
    /// Candidate digest does not match the expected value.
    WrongCandidateDigest { expected: String, attested: String },
    /// Authority-domain sequence does not match the expected next
    /// sequence.
    WrongAuthorityDomainSequence { expected: u64, attested: u64 },
    /// The response `request_digest` does not match the canonical
    /// digest of the request.
    WrongRequestDigest { expected: String, attested: String },
    /// Request anti-replay nonce did not match the expected fresh
    /// nonce (stale or replayed request).
    StaleOrReplayedRequest { expected: String, attested: String },
    /// Response anti-replay nonce did not match the expected fresh
    /// nonce (stale or replayed response).
    StaleOrReplayedResponse { expected: String, attested: String },
    /// The identity attestation has expired (now_unix outside the
    /// identity freshness/expiry window).
    ExpiredAttestation { now_unix: u64 },
    /// The response has expired (now_unix outside the response
    /// freshness/expiry window).
    ExpiredResponse { now_unix: u64 },
    /// The signature suite id is not the Run 159 PQC suite (or the
    /// suite the identity declared).
    UnsupportedSuite { suite_id: u8 },
    /// The placeholder signature commitment is empty or the explicit
    /// invalid sentinel.
    InvalidSignature,
    /// The request is structurally malformed (missing mandatory field).
    MalformedRequest { reason: String },
    /// The response is structurally malformed (missing mandatory field).
    MalformedResponse { reason: String },
    /// A local operator key cannot satisfy a remote signer policy.
    LocalOperatorKeyCannotSatisfyRemoteSigner,
    /// Peer majority / gossip count cannot satisfy a remote signer
    /// policy.
    PeerMajorityCannotSatisfyRemoteSigner,
    /// The custody class routed in is not `RemoteSigner`.
    NotRemoteSignerCustodyClass { class: AuthorityCustodyClass },
}

impl RemoteSignerOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::FixtureLoopbackAccepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production remote signer" rejection.
    pub fn is_production_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionRemoteSignerUnavailable
                | Self::MainNetProductionRemoteSignerUnavailable
        )
    }
}

// ===========================================================================
// Remote signer trait + implementations
// ===========================================================================

/// Run 194 — pure remote-authority-signer boundary.
///
/// Implementations perform no I/O, write no marker, write no sequence,
/// mutate no live trust, evict no sessions, and never invoke Run 070.
/// A production implementation fails closed by returning
/// [`RemoteSignerOutcome::ProductionRemoteSignerUnavailable`] until a
/// real backend lands.
pub trait RemoteAuthoritySigner {
    /// The identity this signer presents.
    fn identity(&self) -> &RemoteSignerIdentity;

    /// Attempt to sign `request`. Returns a typed response on success,
    /// or a typed [`RemoteSignerOutcome`] reject. No I/O is performed.
    fn sign(&self, request: &RemoteSignerRequest) -> Result<RemoteSignerResponse, RemoteSignerOutcome>;
}

/// Run 194 — DevNet/TestNet fixture loopback remote signer.
///
/// **Source/test only.** Produces a deterministic, well-formed response
/// that echoes the request canonical digest. It is NOT a real signer;
/// it exists only so DevNet/TestNet source/test vectors can exercise
/// the accepted path. The fixture loopback signer must never be wired
/// into a production surface, and is refused on a MainNet trust domain
/// by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureLoopbackRemoteSigner {
    pub identity: RemoteSignerIdentity,
    pub response_nonce: String,
    pub response_freshness_unix: Option<u64>,
    pub response_expires_at_unix: Option<u64>,
}

impl RemoteAuthoritySigner for FixtureLoopbackRemoteSigner {
    fn identity(&self) -> &RemoteSignerIdentity {
        &self.identity
    }

    fn sign(&self, request: &RemoteSignerRequest) -> Result<RemoteSignerResponse, RemoteSignerOutcome> {
        if !request.is_well_formed() {
            return Err(RemoteSignerOutcome::MalformedRequest {
                reason: "request missing one or more mandatory fields".to_string(),
            });
        }
        let request_digest = request.canonical_digest();
        // Deterministic placeholder signature commitment derived from
        // the request digest and signer id. Never a real signature.
        let signature_commitment = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"QBIND:run194-fixture-loopback-signature:v1");
            h.update(self.identity.signer_id.as_bytes());
            h.update(request_digest.as_bytes());
            hex::encode(h.finalize())
        };
        Ok(RemoteSignerResponse {
            request_digest,
            signer_id: self.identity.signer_id.clone(),
            custody_key_id: self.identity.custody_key_id.clone(),
            signature_suite_id: self.identity.supported_suite_id,
            signature_commitment,
            response_nonce: self.response_nonce.clone(),
            freshness_unix: self.response_freshness_unix,
            expires_at_unix: self.response_expires_at_unix,
            signer_mode: RemoteSignerMode::FixtureLoopback,
        })
    }
}

/// Run 194 — production remote signer placeholder.
///
/// Callable but fails closed: [`Self::sign`] always returns
/// [`RemoteSignerOutcome::ProductionRemoteSignerUnavailable`] because
/// Run 194 wires no real production remote signer backend. A future run
/// that lands a real backend MUST replace this implementation and
/// cannot silently elevate the fixture loopback signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionRemoteSigner {
    pub identity: RemoteSignerIdentity,
}

impl RemoteAuthoritySigner for ProductionRemoteSigner {
    fn identity(&self) -> &RemoteSignerIdentity {
        &self.identity
    }

    fn sign(
        &self,
        _request: &RemoteSignerRequest,
    ) -> Result<RemoteSignerResponse, RemoteSignerOutcome> {
        Err(RemoteSignerOutcome::ProductionRemoteSignerUnavailable)
    }
}

// ===========================================================================
// Verifier
// ===========================================================================

fn within_optional_window(
    now_unix: u64,
    freshness_unix: Option<u64>,
    expires_at_unix: Option<u64>,
) -> Result<(), ()> {
    match (freshness_unix, expires_at_unix) {
        (Some(fresh), Some(expires)) => {
            if expires <= fresh || now_unix < fresh || now_unix >= expires {
                Err(())
            } else {
                Ok(())
            }
        }
        (None, None) => Ok(()),
        // Exactly one bound present is treated as out-of-window.
        _ => Err(()),
    }
}

/// Run 194 — pure typed remote-signer verifier.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust. Evicts no sessions. Never invokes Run 070.
///
/// The verifier binds every decision to the trust domain, the candidate
/// signing-key fingerprint, the lifecycle action, the candidate digest,
/// the next authority-domain sequence, the custody key id, the request
/// canonical digest, the per-attempt request/response anti-replay
/// nonces, and the identity/response freshness windows. Acceptance is
/// only ever a fixture loopback response under `FixtureLoopbackAllowed`
/// on a DevNet/TestNet trust domain.
pub fn validate_remote_signer(
    identity: &RemoteSignerIdentity,
    request: &RemoteSignerRequest,
    response: &RemoteSignerResponse,
    trust_domain: &AuthorityTrustDomain,
    expected: &RemoteSignerExpectations,
    policy: RemoteSignerPolicy,
) -> RemoteSignerOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies
    //    fail closed before any binding check — but the production
    //    policies still distinguish fixture material (rejected as
    //    "fixture rejected") from production material (rejected as
    //    "unavailable").
    match policy {
        RemoteSignerPolicy::Disabled => return RemoteSignerOutcome::Disabled,
        RemoteSignerPolicy::ProductionRemoteSignerRequired => {
            return match response.signer_mode {
                RemoteSignerMode::FixtureLoopback => {
                    RemoteSignerOutcome::FixtureRejectedProductionRequired
                }
                RemoteSignerMode::Production => {
                    RemoteSignerOutcome::ProductionRemoteSignerUnavailable
                }
            };
        }
        RemoteSignerPolicy::MainnetProductionRemoteSignerRequired => {
            return match response.signer_mode {
                RemoteSignerMode::FixtureLoopback => {
                    RemoteSignerOutcome::FixtureRejectedMainnetProductionRequired
                }
                RemoteSignerMode::Production => {
                    RemoteSignerOutcome::MainNetProductionRemoteSignerUnavailable
                }
            };
        }
        RemoteSignerPolicy::FixtureLoopbackAllowed => {}
    }

    // 2. Under `FixtureLoopbackAllowed`, a production-mode response is
    //    still unavailable (no real backend exists).
    if response.signer_mode == RemoteSignerMode::Production {
        return RemoteSignerOutcome::ProductionRemoteSignerUnavailable;
    }

    // 3. Fixture loopback is DevNet/TestNet source/test only — never
    //    MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return RemoteSignerOutcome::FixtureLoopbackRejectedForMainNet;
    }

    // 4. Structural well-formedness.
    if !request.is_well_formed() {
        return RemoteSignerOutcome::MalformedRequest {
            reason: "request missing one or more mandatory fields".to_string(),
        };
    }
    if !response.is_well_formed() {
        return RemoteSignerOutcome::MalformedResponse {
            reason: "response missing one or more mandatory fields".to_string(),
        };
    }
    if identity.signer_id.is_empty()
        || identity.signer_public_identity.is_empty()
        || identity.attestation_digest.is_empty()
        || identity.custody_key_id.is_empty()
    {
        return RemoteSignerOutcome::MalformedResponse {
            reason: "identity missing one or more mandatory fields".to_string(),
        };
    }

    // 5. Trust-domain environment binding (request + identity).
    if request.environment != trust_domain.environment
        || identity.environment != trust_domain.environment
    {
        return RemoteSignerOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: request.environment,
        };
    }

    // 6. Trust-domain chain binding.
    if request.chain_id != trust_domain.chain_id || identity.chain_id != trust_domain.chain_id {
        return RemoteSignerOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: request.chain_id.clone(),
        };
    }

    // 7. Trust-domain genesis binding.
    if request.genesis_hash != trust_domain.genesis_hash
        || identity.genesis_hash != trust_domain.genesis_hash
    {
        return RemoteSignerOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: request.genesis_hash.clone(),
        };
    }

    // 8. Authority root binding.
    if request.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || identity.authority_root_fingerprint != trust_domain.authority_root_fingerprint
    {
        return RemoteSignerOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: request.authority_root_fingerprint.clone(),
        };
    }

    // 9. Custody key id binding (identity + response + expected).
    if identity.custody_key_id != expected.expected_custody_key_id
        || response.custody_key_id != expected.expected_custody_key_id
    {
        return RemoteSignerOutcome::WrongCustodyKeyId {
            expected: expected.expected_custody_key_id.clone(),
            attested: response.custody_key_id.clone(),
        };
    }

    // 10. Signing-key fingerprint binding.
    let attested_signing_fp = request
        .primary_signing_key_fingerprint()
        .unwrap_or("")
        .to_string();
    if attested_signing_fp != expected.expected_signing_key_fingerprint {
        return RemoteSignerOutcome::WrongSigningKeyFingerprint {
            expected: expected.expected_signing_key_fingerprint.clone(),
            attested: attested_signing_fp,
        };
    }

    // 11. Lifecycle action binding (expected + identity-supported).
    if request.lifecycle_action != expected.expected_lifecycle_action
        || !identity.supports_lifecycle_action(request.lifecycle_action)
    {
        return RemoteSignerOutcome::WrongLifecycleAction {
            expected: expected.expected_lifecycle_action,
            attested: request.lifecycle_action,
        };
    }

    // 12. Candidate digest binding.
    if request.candidate_digest != expected.expected_candidate_digest {
        return RemoteSignerOutcome::WrongCandidateDigest {
            expected: expected.expected_candidate_digest.clone(),
            attested: request.candidate_digest.clone(),
        };
    }

    // 13. Authority-domain sequence binding.
    if request.authority_domain_sequence != expected.expected_authority_domain_sequence {
        return RemoteSignerOutcome::WrongAuthorityDomainSequence {
            expected: expected.expected_authority_domain_sequence,
            attested: request.authority_domain_sequence,
        };
    }

    // 14. Custody attestation digest binding (request + expected).
    if request.custody_attestation_digest != expected.expected_custody_attestation_digest {
        return RemoteSignerOutcome::MalformedRequest {
            reason: "custody_attestation_digest does not match expected".to_string(),
        };
    }

    // 15. Request canonical-digest binding (response echoes request).
    let canonical = request.canonical_digest();
    if response.request_digest != canonical {
        return RemoteSignerOutcome::WrongRequestDigest {
            expected: canonical,
            attested: response.request_digest.clone(),
        };
    }

    // 16. Signer-id binding (response echoes identity).
    if response.signer_id != identity.signer_id {
        return RemoteSignerOutcome::MalformedResponse {
            reason: "response signer_id does not match identity".to_string(),
        };
    }

    // 17. Suite binding.
    if response.signature_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || identity.supported_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || response.signature_suite_id != identity.supported_suite_id
    {
        return RemoteSignerOutcome::UnsupportedSuite {
            suite_id: response.signature_suite_id,
        };
    }

    // 18. Placeholder signature validity.
    if response.signature_commitment.is_empty()
        || response.signature_commitment == REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL
    {
        return RemoteSignerOutcome::InvalidSignature;
    }

    // 19. Request anti-replay nonce.
    if request.replay_nonce != expected.expected_request_nonce {
        return RemoteSignerOutcome::StaleOrReplayedRequest {
            expected: expected.expected_request_nonce.clone(),
            attested: request.replay_nonce.clone(),
        };
    }

    // 20. Response anti-replay nonce.
    if response.response_nonce != expected.expected_response_nonce {
        return RemoteSignerOutcome::StaleOrReplayedResponse {
            expected: expected.expected_response_nonce.clone(),
            attested: response.response_nonce.clone(),
        };
    }

    // 21. Identity attestation freshness/expiry window.
    if within_optional_window(expected.now_unix, identity.freshness_unix, identity.expires_at_unix)
        .is_err()
    {
        return RemoteSignerOutcome::ExpiredAttestation {
            now_unix: expected.now_unix,
        };
    }

    // 22. Response freshness/expiry window.
    if within_optional_window(expected.now_unix, response.freshness_unix, response.expires_at_unix)
        .is_err()
    {
        return RemoteSignerOutcome::ExpiredResponse {
            now_unix: expected.now_unix,
        };
    }

    // 23. Accept — fixture loopback only, DevNet/TestNet, evidence-only.
    RemoteSignerOutcome::FixtureLoopbackAccepted {
        signer_id: identity.signer_id.clone(),
        environment: trust_domain.environment,
    }
}

// ===========================================================================
// Custody-class routing
// ===========================================================================

/// Run 194 — returns `true` iff the custody class routes into the
/// remote-signer boundary (i.e. `AuthorityCustodyClass::RemoteSigner`).
pub const fn custody_class_routes_to_remote_signer(class: AuthorityCustodyClass) -> bool {
    matches!(class, AuthorityCustodyClass::RemoteSigner)
}

/// Run 194 — route a Run 188 custody class into the remote-signer
/// boundary.
///
/// * `AuthorityCustodyClass::RemoteSigner` is dispatched to
///   [`validate_remote_signer`].
/// * `AuthorityCustodyClass::LocalOperatorKey` is refused as
///   [`RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner`]
///   — a local operator key can never satisfy a remote signer policy.
/// * every other class is refused as
///   [`RemoteSignerOutcome::NotRemoteSignerCustodyClass`].
#[allow(clippy::too_many_arguments)]
pub fn validate_remote_signer_for_custody_class(
    custody_class: AuthorityCustodyClass,
    identity: &RemoteSignerIdentity,
    request: &RemoteSignerRequest,
    response: &RemoteSignerResponse,
    trust_domain: &AuthorityTrustDomain,
    expected: &RemoteSignerExpectations,
    policy: RemoteSignerPolicy,
) -> RemoteSignerOutcome {
    match custody_class {
        AuthorityCustodyClass::RemoteSigner => {
            validate_remote_signer(identity, request, response, trust_domain, expected, policy)
        }
        AuthorityCustodyClass::LocalOperatorKey => {
            RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner
        }
        other => RemoteSignerOutcome::NotRemoteSignerCustodyClass { class: other },
    }
}

// ===========================================================================
// Composition helper
// ===========================================================================

/// Run 194 — typed combined decision for a lifecycle + governance +
/// custody + remote-signer preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleCustodyRemoteSignerOutcome {
    /// The lifecycle transition validates, the Run 188 custody
    /// attestation validates under the active custody policy, AND the
    /// remote-signer response validates under the active remote-signer
    /// policy. Carries all three typed outcomes. **Acceptance is
    /// evidence-only.** It does not enable MainNet apply, does not
    /// perform a Run 070 call, does not write a marker, does not burn a
    /// sequence number, does not swap live trust, and does not evict
    /// sessions.
    Accepted {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        remote_signer_outcome: RemoteSignerOutcome,
    },
    /// The Run 188 lifecycle/custody composition rejected. The remote
    /// signer was not consulted.
    LifecycleOrCustodyRejected(LifecycleGovernanceCustodyOutcome),
    /// The Run 188 lifecycle/custody composition accepted but the
    /// remote-signer validation rejected. Carries both so the operator
    /// log line can record "custody valid + remote signer invalid".
    RemoteSignerRejected {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        remote_signer_outcome: RemoteSignerOutcome,
    },
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of any custody or remote
    /// signer outcome.
    MainNetPeerDrivenApplyRefused,
}

impl LifecycleCustodyRemoteSignerOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 194 — pure composition helper.
///
/// Calls the Run 188 lifecycle + governance + custody validator, then
/// (if accepted) calls the Run 194 remote-signer verifier, and returns a
/// typed combined decision. Performs no I/O, writes no marker, writes no
/// sequence, mutates no live trust, evicts no sessions, never invokes
/// Run 070.
///
/// `is_peer_driven_apply_preflight` lets the calling surface request the
/// MainNet peer-driven-apply refusal short-circuit: when set and the
/// trust domain is MainNet, the helper returns
/// [`LifecycleCustodyRemoteSignerOutcome::MainNetPeerDrivenApplyRefused`]
/// without consulting custody or the remote signer — the fixture
/// loopback remote signer can never enable a MainNet apply.
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_governance_custody_and_remote_signer(
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
    now_unix: u64,
    is_peer_driven_apply_preflight: bool,
) -> LifecycleCustodyRemoteSignerOutcome {
    // MainNet peer-driven apply remains refused regardless of any
    // fixture loopback remote signer success.
    if is_peer_driven_apply_preflight
        && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return LifecycleCustodyRemoteSignerOutcome::MainNetPeerDrivenApplyRefused;
    }

    let lifecycle_custody_outcome = validate_lifecycle_governance_and_custody(
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
        now_unix,
    );

    if !lifecycle_custody_outcome.is_accept() {
        return LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(
            lifecycle_custody_outcome,
        );
    }

    let remote_signer_outcome = validate_remote_signer(
        identity,
        request,
        response,
        trust_domain,
        remote_signer_expected,
        remote_signer_policy,
    );

    if remote_signer_outcome.is_accept() {
        LifecycleCustodyRemoteSignerOutcome::Accepted {
            lifecycle_custody_outcome,
            remote_signer_outcome,
        }
    } else {
        LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected {
            lifecycle_custody_outcome,
            remote_signer_outcome,
        }
    }
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 194 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes,
/// at the typed Run 194 boundary, the rule that MainNet peer-driven
/// apply remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// remote-signer response — even a fixture loopback response that signs
/// successfully. Pure data; never reads signer material.
pub fn mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 194 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a remote
/// signer policy. Run 194 always returns `true`: a remote signer is a
/// custody-held authority and is never satisfiable by a local operator
/// key. Grep-verifiable named symbol for an operator-log line.
pub fn local_operator_key_cannot_satisfy_remote_signer() -> bool {
    true
}

/// Run 194 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// remote signer policy. Run 194 always returns `true`: a remote signer
/// is a per-key authority decision and is never satisfiable by counting
/// peers. Grep-verifiable named symbol for an operator-log line.
pub fn peer_majority_cannot_satisfy_remote_signer() -> bool {
    true
}