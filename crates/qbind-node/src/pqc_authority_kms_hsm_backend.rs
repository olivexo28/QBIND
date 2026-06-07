//! Run 203 — source/test KMS/HSM backend abstraction boundary for
//! production authority custody.
//!
//! Source/test only. Run 203 does **not** implement a real KMS backend,
//! a real HSM backend, a cloud-KMS integration, a PKCS#11 integration, a
//! networked signer daemon, or a real RemoteSigner backend; nor does it
//! enable MainNet peer-driven apply, real on-chain governance proof
//! verification, governance execution, or validator-set rotation.
//!
//! Before Run 203 the Run 188 [`AuthorityCustodyClass::Kms`] and
//! [`AuthorityCustodyClass::Hsm`] variants were typed placeholders only:
//! the custody validator failed them closed as "unavailable" but there
//! was **no backend abstraction** describing a future KMS/HSM provider,
//! key identity, attestation, request/response binding, or fail-closed
//! production dispatch. Run 203 closes that gap at the source/test level
//! by adding:
//!
//! * A typed [`BackendKind`] (`Disabled`, `FixtureKms`, `FixtureHsm`,
//!   `CloudKmsUnavailable`, `Pkcs11HsmUnavailable`,
//!   `ProductionKmsUnavailable`, `ProductionHsmUnavailable`, `Unknown`)
//!   and a typed [`BackendPolicy`] (`Disabled` default,
//!   `FixtureKmsAllowed`, `FixtureHsmAllowed`, `ProductionKmsRequired`,
//!   `ProductionHsmRequired`, `MainnetProductionCustodyRequired`).
//! * A typed backend identity/config ([`BackendIdentity`]) binding the
//!   backend id, provider id, key id / key label, authority root
//!   fingerprint, bundle-signing key fingerprint, environment, chain id,
//!   genesis hash, suite id, attestation / certificate digest
//!   placeholder, key usage policy, allowed lifecycle actions, and a
//!   freshness/expiry window.
//! * A typed [`BackendRequest`] and [`BackendResponse`] binding the full
//!   authority-decision tuple plus anti-replay material.
//! * Deterministic, domain-separated digest helpers
//!   ([`BackendIdentity::identity_digest`],
//!   [`BackendRequest::request_digest`],
//!   [`BackendResponse::response_digest`], and
//!   [`backend_transcript_digest`]).
//! * A pure / mockable [`AuthorityCustodyBackend`] trait with a
//!   [`AuthorityCustodyBackend::sign_authority_lifecycle_request`]
//!   method, DevNet/TestNet source/test-only fixture backends
//!   ([`FixtureKmsBackend`] / [`FixtureHsmBackend`]), and production /
//!   cloud / PKCS#11 backends that are callable but fail closed as
//!   unavailable.
//! * A pure typed verifier [`verify_authority_custody_backend_response`]
//!   and a typed [`BackendOutcome`] distinguishing every accept/reject
//!   case the task enumerates.
//! * A custody-class router
//!   [`validate_backend_for_custody_class`] composing the Run 188
//!   [`AuthorityCustodyClass::Kms`] / [`AuthorityCustodyClass::Hsm`]
//!   classes, and a composition helper
//!   [`validate_lifecycle_governance_custody_and_backend`] that layers
//!   the KMS/HSM boundary on top of the Run 188 lifecycle + governance +
//!   custody validator while preserving the MainNet peer-driven-apply
//!   refusal.
//!
//! The RemoteSigner path (Runs 194–202) remains a **separate** custody
//! option, not a replacement for KMS/HSM, and is unchanged by this run.
//!
//! Release-binary KMS/HSM backend-boundary evidence is **deferred to Run
//! 204**. Governance execution remains unimplemented, real on-chain
//! proof verification remains unimplemented, validator-set rotation
//! remains open, full C4 remains open, and C5 remains open.
//!
//! The module is pure: every public function and trait method performs
//! no network or file I/O, writes no marker, writes no sequence,
//! mutates no live trust, evicts no sessions, and never invokes Run 070
//! apply.

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
// Domain tags / sentinels
// ===========================================================================

/// Run 203 — backend-identity digest domain tag.
pub const KMS_HSM_BACKEND_IDENTITY_DOMAIN_TAG: &str = "QBIND:run203-kms-hsm-backend-identity:v1";

/// Run 203 — backend-request digest domain tag.
pub const KMS_HSM_BACKEND_REQUEST_DOMAIN_TAG: &str = "QBIND:run203-kms-hsm-backend-request:v1";

/// Run 203 — backend-response digest domain tag.
pub const KMS_HSM_BACKEND_RESPONSE_DOMAIN_TAG: &str = "QBIND:run203-kms-hsm-backend-response:v1";

/// Run 203 — backend request/response transcript digest domain tag.
pub const KMS_HSM_BACKEND_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run203-kms-hsm-backend-transcript:v1";

/// Run 203 — placeholder fixture signature-commitment derivation domain
/// tag for the source/test fixture backends. Never a real signature.
pub const KMS_HSM_BACKEND_FIXTURE_SIGNATURE_DOMAIN_TAG: &str =
    "QBIND:run203-kms-hsm-backend-fixture-signature:v1";

/// Run 203 — explicit invalid placeholder-signature sentinel for
/// source/test rejection vectors. A response carrying this commitment is
/// rejected as [`BackendOutcome::InvalidSignature`].
pub const KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL: &str = "INVALID-KMS-HSM-SIGNATURE";

/// Run 203 — explicit invalid attestation sentinel for source/test
/// rejection vectors. An identity or response carrying this attestation
/// digest is rejected as [`BackendOutcome::InvalidAttestation`].
pub const KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL: &str = "INVALID-KMS-HSM-ATTESTATION";

// ===========================================================================
// Backend kind
// ===========================================================================

/// Run 203 — typed KMS/HSM backend kind.
///
/// `Disabled` is the inert default kind. `FixtureKms` / `FixtureHsm` are
/// DevNet/TestNet source/test-only fixtures. `CloudKmsUnavailable`,
/// `Pkcs11HsmUnavailable`, `ProductionKmsUnavailable`, and
/// `ProductionHsmUnavailable` are production-class placeholders that are
/// callable but fail closed as unavailable because Run 203 wires no real
/// backend. `Unknown` is always fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BackendKind {
    /// Inert default. No backend is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture KMS backend.
    FixtureKms,
    /// DevNet/TestNet source/test fixture HSM backend.
    FixtureHsm,
    /// Cloud-KMS production placeholder. Callable, fails closed.
    CloudKmsUnavailable,
    /// PKCS#11 HSM production placeholder. Callable, fails closed.
    Pkcs11HsmUnavailable,
    /// Production KMS placeholder. Callable, fails closed.
    ProductionKmsUnavailable,
    /// Production HSM placeholder. Callable, fails closed.
    ProductionHsmUnavailable,
    /// Unknown / unsupported backend. Always fail-closed.
    Unknown,
}

impl BackendKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKms => "fixture-kms",
            Self::FixtureHsm => "fixture-hsm",
            Self::CloudKmsUnavailable => "cloud-kms-unavailable",
            Self::Pkcs11HsmUnavailable => "pkcs11-hsm-unavailable",
            Self::ProductionKmsUnavailable => "production-kms-unavailable",
            Self::ProductionHsmUnavailable => "production-hsm-unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this kind is a DevNet/TestNet source/test
    /// fixture backend.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureKms | Self::FixtureHsm)
    }

    /// Returns `true` iff this kind is a production-class backend that
    /// Run 203 fails closed as unavailable.
    pub const fn is_production_unavailable(self) -> bool {
        matches!(
            self,
            Self::CloudKmsUnavailable
                | Self::Pkcs11HsmUnavailable
                | Self::ProductionKmsUnavailable
                | Self::ProductionHsmUnavailable
        )
    }

    /// Returns the Run 188 custody class this backend kind presents, or
    /// `None` for the inert / unknown kinds.
    pub const fn custody_class(self) -> Option<AuthorityCustodyClass> {
        match self {
            Self::FixtureKms
            | Self::CloudKmsUnavailable
            | Self::ProductionKmsUnavailable => Some(AuthorityCustodyClass::Kms),
            Self::FixtureHsm
            | Self::Pkcs11HsmUnavailable
            | Self::ProductionHsmUnavailable => Some(AuthorityCustodyClass::Hsm),
            Self::Disabled | Self::Unknown => None,
        }
    }
}

// ===========================================================================
// Backend policy
// ===========================================================================

/// Run 203 — typed KMS/HSM backend policy.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// backend request regardless of contents, preserving the Run 050–202
/// conservative defaults. `FixtureKmsAllowed` / `FixtureHsmAllowed` are
/// DevNet/TestNet source/test-only policies that accept the matching
/// fixture backend. `ProductionKmsRequired`, `ProductionHsmRequired`,
/// and `MainnetProductionCustodyRequired` REQUIRE a real production
/// backend — and Run 203 has none, so they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BackendPolicy {
    /// Default. Refuses every backend request.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture-KMS policy.
    FixtureKmsAllowed,
    /// DevNet/TestNet source/test fixture-HSM policy.
    FixtureHsmAllowed,
    /// Production KMS required (DevNet/TestNet bring-up of a real
    /// backend). Run 203 fails closed because no real backend exists.
    ProductionKmsRequired,
    /// Production HSM required (DevNet/TestNet bring-up of a real
    /// backend). Run 203 fails closed because no real backend exists.
    ProductionHsmRequired,
    /// MainNet production custody required. Run 203 fails closed for
    /// every request — fixture material is rejected as non-production
    /// and every production request is rejected as unavailable.
    MainnetProductionCustodyRequired,
}

impl BackendPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKmsAllowed => "fixture-kms-allowed",
            Self::FixtureHsmAllowed => "fixture-hsm-allowed",
            Self::ProductionKmsRequired => "production-kms-required",
            Self::ProductionHsmRequired => "production-hsm-required",
            Self::MainnetProductionCustodyRequired => "mainnet-production-custody-required",
        }
    }

    /// Returns `true` iff this policy requires a real production backend
    /// (and therefore Run 203 fails closed).
    pub const fn requires_production_backend(self) -> bool {
        matches!(
            self,
            Self::ProductionKmsRequired
                | Self::ProductionHsmRequired
                | Self::MainnetProductionCustodyRequired
        )
    }

    /// Returns the fixture backend kind this policy accepts, or `None`
    /// for the disabled / production-required policies.
    pub const fn allowed_fixture_kind(self) -> Option<BackendKind> {
        match self {
            Self::FixtureKmsAllowed => Some(BackendKind::FixtureKms),
            Self::FixtureHsmAllowed => Some(BackendKind::FixtureHsm),
            _ => None,
        }
    }
}

// ===========================================================================
// Backend identity / config
// ===========================================================================

/// Run 203 — typed KMS/HSM backend identity / configuration.
///
/// Pure data describing *which* backend is presenting custody for
/// *which* trust domain over *which* authority root, the key it holds,
/// the suite and lifecycle actions it supports, a placeholder
/// attestation / certificate digest, a key usage policy, and an optional
/// freshness/expiry window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendIdentity {
    /// Which backend kind this identity describes.
    pub backend_kind: BackendKind,
    /// Stable, opaque identifier of the backend.
    pub backend_id: String,
    /// Stable, opaque identifier of the backend provider.
    pub provider_id: String,
    /// Stable, opaque identifier / label of the custody-held key.
    pub key_id: String,
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
    /// Suite id this backend supports (placeholder; only the Run 159 PQC
    /// signing suite is currently accepted).
    pub suite_id: u8,
    /// Placeholder attestation / certificate digest. Must be non-empty
    /// and must not be the explicit invalid sentinel.
    pub attestation_digest: String,
    /// Opaque key usage policy descriptor. Must be non-empty.
    pub key_usage_policy: String,
    /// Lifecycle actions this backend is authorized to sign.
    pub allowed_lifecycle_actions: Vec<LocalLifecycleAction>,
    /// Optional freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional attestation expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
}

impl BackendIdentity {
    /// Returns `true` iff this identity claims to support `action`.
    pub fn supports_lifecycle_action(&self, action: LocalLifecycleAction) -> bool {
        self.allowed_lifecycle_actions.contains(&action)
    }

    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.backend_id.is_empty()
            && !self.provider_id.is_empty()
            && !self.key_id.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.bundle_signing_key_fingerprint.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.attestation_digest.is_empty()
            && !self.key_usage_policy.is_empty()
            && !self.allowed_lifecycle_actions.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every identity field. The
    /// digest is domain-separated so it can never collide with any other
    /// QBIND canonical digest.
    pub fn identity_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(KMS_HSM_BACKEND_IDENTITY_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"backend_kind", self.backend_kind.tag().as_bytes());
        field(b"backend_id", self.backend_id.as_bytes());
        field(b"provider_id", self.provider_id.as_bytes());
        field(b"key_id", self.key_id.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(
            b"bundle_signing_key_fingerprint",
            self.bundle_signing_key_fingerprint.as_bytes(),
        );
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(b"suite_id", &[self.suite_id]);
        field(b"attestation_digest", self.attestation_digest.as_bytes());
        field(b"key_usage_policy", self.key_usage_policy.as_bytes());
        field(
            b"allowed_lifecycle_actions_count",
            &(self.allowed_lifecycle_actions.len() as u64).to_le_bytes(),
        );
        for action in &self.allowed_lifecycle_actions {
            field(b"allowed_lifecycle_action", action.tag().as_bytes());
        }
        field(
            b"freshness_unix",
            &self.freshness_unix.unwrap_or(0).to_le_bytes(),
        );
        field(b"freshness_present", &[self.freshness_unix.is_some() as u8]);
        field(
            b"expires_at_unix",
            &self.expires_at_unix.unwrap_or(0).to_le_bytes(),
        );
        field(b"expires_present", &[self.expires_at_unix.is_some() as u8]);
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Backend request
// ===========================================================================

/// Run 203 — typed KMS/HSM backend signing request.
///
/// Binds the full authority-decision tuple the backend is being asked to
/// authorize, plus per-attempt anti-replay material. The
/// [`Self::request_digest`] is a deterministic SHA3-256 hex commitment
/// over every field; the response MUST echo it back as
/// `bound_request_digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRequest {
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
    /// Bound Run 188 custody class. Must be `Kms` or `Hsm`.
    pub custody_class: AuthorityCustodyClass,
    /// Stable, opaque identifier / label of the custody-held key.
    pub key_id: String,
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
    pub request_nonce: String,
    /// Optional request timestamp / epoch (UNIX seconds).
    pub request_timestamp_unix: Option<u64>,
}

impl BackendRequest {
    /// The signing-key fingerprint this request primarily binds: the new
    /// key when present (rotation/activation), otherwise the active key,
    /// otherwise the revoked key.
    pub fn primary_signing_key_fingerprint(&self) -> Option<&str> {
        self.new_signing_key_fingerprint
            .as_deref()
            .or(self.active_signing_key_fingerprint.as_deref())
            .or(self.revoked_signing_key_fingerprint.as_deref())
    }

    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.key_id.is_empty()
            && !self.custody_attestation_digest.is_empty()
            && !self.request_nonce.is_empty()
            && matches!(
                self.custody_class,
                AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm
            )
    }

    /// Deterministic SHA3-256 hex digest over every request field.
    pub fn request_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(KMS_HSM_BACKEND_REQUEST_DOMAIN_TAG.as_bytes());
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
        field(b"custody_class", self.custody_class.tag().as_bytes());
        field(b"key_id", self.key_id.as_bytes());
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
        field(b"request_nonce", self.request_nonce.as_bytes());
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
}

// ===========================================================================
// Backend response
// ===========================================================================

/// Run 203 — typed KMS/HSM backend signing response.
///
/// Binds the request digest, the backend id, provider id, key id, the
/// signature suite, a placeholder signature commitment, the attestation
/// digest, anti-replay material, and an optional freshness/expiry
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendResponse {
    /// Which backend kind produced this response.
    pub backend_kind: BackendKind,
    /// Echoed canonical digest of the request this response signs.
    pub bound_request_digest: String,
    /// Backend id that produced this response.
    pub backend_id: String,
    /// Provider id that produced this response.
    pub provider_id: String,
    /// Key id / label that produced this response.
    pub key_id: String,
    /// Signature suite id (placeholder; only the Run 159 PQC suite is
    /// accepted).
    pub signature_suite_id: u8,
    /// Placeholder signature commitment bytes. Must be non-empty and
    /// must not be the explicit invalid sentinel.
    pub signature_commitment: String,
    /// Placeholder attestation digest. Must be non-empty and must not be
    /// the explicit invalid sentinel.
    pub attestation_digest: String,
    /// Per-response anti-replay nonce. Must be non-empty.
    pub response_nonce: String,
    /// Optional response freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional response expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
}

impl BackendResponse {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.bound_request_digest.is_empty()
            && !self.backend_id.is_empty()
            && !self.provider_id.is_empty()
            && !self.key_id.is_empty()
            && !self.signature_commitment.is_empty()
            && !self.attestation_digest.is_empty()
            && !self.response_nonce.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every response field.
    pub fn response_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(KMS_HSM_BACKEND_RESPONSE_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"backend_kind", self.backend_kind.tag().as_bytes());
        field(b"bound_request_digest", self.bound_request_digest.as_bytes());
        field(b"backend_id", self.backend_id.as_bytes());
        field(b"provider_id", self.provider_id.as_bytes());
        field(b"key_id", self.key_id.as_bytes());
        field(b"signature_suite_id", &[self.signature_suite_id]);
        field(b"signature_commitment", self.signature_commitment.as_bytes());
        field(b"attestation_digest", self.attestation_digest.as_bytes());
        field(b"response_nonce", self.response_nonce.as_bytes());
        field(
            b"freshness_unix",
            &self.freshness_unix.unwrap_or(0).to_le_bytes(),
        );
        field(b"freshness_present", &[self.freshness_unix.is_some() as u8]);
        field(
            b"expires_at_unix",
            &self.expires_at_unix.unwrap_or(0).to_le_bytes(),
        );
        field(b"expires_present", &[self.expires_at_unix.is_some() as u8]);
        hex::encode(h.finalize())
    }
}

/// Run 203 — deterministic, domain-separated request/response transcript
/// digest. Binds the backend identity digest, the request digest, and
/// the response digest into a single commitment that the calling surface
/// can log and a future backend implementation can sign over.
pub fn backend_transcript_digest(
    identity_digest: &str,
    request_digest: &str,
    response_digest: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(KMS_HSM_BACKEND_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"identity_digest", identity_digest.as_bytes());
    field(b"request_digest", request_digest.as_bytes());
    field(b"response_digest", response_digest.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Expectations
// ===========================================================================

/// Run 203 — caller-supplied binding expectations for
/// [`verify_authority_custody_backend_response`].
///
/// Pure data, typically derived from the persisted candidate metadata
/// and the per-attempt anti-replay material the calling surface
/// generated for this request/response round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendExpectations {
    pub expected_custody_class: AuthorityCustodyClass,
    pub expected_lifecycle_action: LocalLifecycleAction,
    pub expected_candidate_digest: String,
    pub expected_authority_domain_sequence: u64,
    pub expected_key_id: String,
    pub expected_signing_key_fingerprint: String,
    pub expected_custody_attestation_digest: String,
    pub expected_request_nonce: String,
    pub expected_response_nonce: String,
    pub expected_request_digest: String,
    pub expected_response_digest: String,
    pub expected_transcript_digest: String,
    pub now_unix: u64,
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 203 — typed outcome of the KMS/HSM backend boundary.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching the
/// inner request/response. Acceptance is **always** of a fixture KMS/HSM
/// response under the matching explicit fixture policy on a
/// DevNet/TestNet trust domain — production requests are refused as
/// unavailable regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendOutcome {
    /// DevNet/TestNet fixture KMS backend accepted under the explicit
    /// `FixtureKmsAllowed` policy. Acceptance is evidence-only.
    FixtureKmsAccepted {
        backend_id: String,
        environment: TrustBundleEnvironment,
    },
    /// DevNet/TestNet fixture HSM backend accepted under the explicit
    /// `FixtureHsmAllowed` policy. Acceptance is evidence-only.
    FixtureHsmAccepted {
        backend_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy is `Disabled`. Every request fails closed.
    Disabled,
    /// Fixture material rejected because the active policy requires a
    /// production backend (`ProductionKmsRequired` /
    /// `ProductionHsmRequired`).
    FixtureRejectedProductionRequired,
    /// Fixture material rejected because the active policy is
    /// `MainnetProductionCustodyRequired`.
    FixtureRejectedMainnetProductionRequired,
    /// Production KMS backend is unavailable. Run 203 has no real
    /// backend.
    ProductionKmsUnavailable,
    /// Production HSM backend is unavailable. Run 203 has no real
    /// backend.
    ProductionHsmUnavailable,
    /// Cloud-KMS backend is unavailable. Run 203 wires no cloud-KMS
    /// integration.
    CloudKmsUnavailable,
    /// PKCS#11 HSM backend is unavailable. Run 203 wires no PKCS#11
    /// integration.
    Pkcs11HsmUnavailable,
    /// MainNet production custody is unavailable.
    MainNetProductionCustodyUnavailable,
    /// Fixture backend rejected because the trust domain is MainNet.
    /// Fixture KMS/HSM is DevNet/TestNet source/test only.
    FixtureRejectedForMainNet,
    /// The response backend kind does not match the fixture kind the
    /// active fixture policy allows.
    BackendKindPolicyMismatch {
        policy_tag: &'static str,
        backend_tag: &'static str,
    },
    /// Unknown / unsupported backend kind.
    UnknownBackendRejected { backend_tag: &'static str },
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
    /// Key id / key label does not match the expected value.
    WrongKeyId { expected: String, attested: String },
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
    /// The request canonical digest does not match the expected value
    /// (or the response did not echo it).
    WrongRequestDigest { expected: String, attested: String },
    /// The response canonical digest does not match the expected value.
    WrongResponseDigest { expected: String, attested: String },
    /// The transcript digest does not match the expected value.
    WrongTranscriptDigest { expected: String, attested: String },
    /// Request anti-replay nonce did not match the expected fresh nonce
    /// (stale or replayed request).
    StaleOrReplayedRequest { expected: String, attested: String },
    /// Response anti-replay nonce did not match the expected fresh nonce
    /// (stale or replayed response).
    StaleOrReplayedResponse { expected: String, attested: String },
    /// The identity attestation has expired.
    ExpiredAttestation { now_unix: u64 },
    /// The response has expired.
    ExpiredResponse { now_unix: u64 },
    /// The signature suite id is not the Run 159 PQC suite.
    UnsupportedSuite { suite_id: u8 },
    /// The identity / response attestation is the explicit invalid
    /// sentinel.
    InvalidAttestation,
    /// The placeholder signature commitment is empty or the explicit
    /// invalid sentinel.
    InvalidSignature,
    /// The backend identity is structurally malformed.
    MalformedIdentity { reason: String },
    /// The request is structurally malformed.
    MalformedRequest { reason: String },
    /// The response is structurally malformed.
    MalformedResponse { reason: String },
    /// A local operator key cannot satisfy a backend policy.
    LocalOperatorCannotSatisfyBackendPolicy,
    /// Peer majority / gossip count cannot satisfy a backend policy.
    PeerMajorityCannotSatisfyBackendPolicy,
    /// The custody class routed in is not `Kms` or `Hsm`.
    NotKmsHsmCustodyClass { class: AuthorityCustodyClass },
}

impl BackendOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FixtureKmsAccepted { .. } | Self::FixtureHsmAccepted { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production/cloud/PKCS#11/MainNet backend" rejection.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionKmsUnavailable
                | Self::ProductionHsmUnavailable
                | Self::CloudKmsUnavailable
                | Self::Pkcs11HsmUnavailable
                | Self::MainNetProductionCustodyUnavailable
        )
    }
}

// ===========================================================================
// Backend trait + implementations
// ===========================================================================

/// Run 203 — pure authority-custody KMS/HSM backend boundary.
///
/// Implementations perform no I/O, write no marker, write no sequence,
/// mutate no live trust, evict no sessions, and never invoke Run 070. A
/// production / cloud / PKCS#11 implementation fails closed by returning
/// the matching unavailable [`BackendOutcome`] until a real backend
/// lands.
pub trait AuthorityCustodyBackend {
    /// The backend kind this implementation presents.
    fn kind(&self) -> BackendKind;

    /// The identity / config this backend presents.
    fn identity(&self) -> &BackendIdentity;

    /// Attempt to sign `request`. Returns a typed response on success,
    /// or a typed [`BackendOutcome`] reject. No I/O is performed.
    fn sign_authority_lifecycle_request(
        &self,
        request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome>;
}

/// Shared deterministic fixture response builder. Source/test only;
/// never produces a real signature.
fn build_fixture_response(
    identity: &BackendIdentity,
    request: &BackendRequest,
    response_nonce: &str,
    freshness_unix: Option<u64>,
    expires_at_unix: Option<u64>,
) -> Result<BackendResponse, BackendOutcome> {
    if !request.is_well_formed() {
        return Err(BackendOutcome::MalformedRequest {
            reason: "request missing one or more mandatory fields".to_string(),
        });
    }
    let request_digest = request.request_digest();
    // Deterministic placeholder signature commitment derived from the
    // request digest and backend id. Never a real signature.
    let signature_commitment = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(KMS_HSM_BACKEND_FIXTURE_SIGNATURE_DOMAIN_TAG.as_bytes());
        h.update(identity.backend_id.as_bytes());
        h.update(request_digest.as_bytes());
        hex::encode(h.finalize())
    };
    Ok(BackendResponse {
        backend_kind: identity.backend_kind,
        bound_request_digest: request_digest,
        backend_id: identity.backend_id.clone(),
        provider_id: identity.provider_id.clone(),
        key_id: identity.key_id.clone(),
        signature_suite_id: identity.suite_id,
        signature_commitment,
        attestation_digest: identity.attestation_digest.clone(),
        response_nonce: response_nonce.to_string(),
        freshness_unix,
        expires_at_unix,
    })
}

/// Run 203 — DevNet/TestNet fixture KMS backend.
///
/// **Source/test only.** Produces a deterministic, well-formed response
/// that echoes the request canonical digest. It is NOT a real KMS; it
/// exists only so DevNet/TestNet source/test vectors can exercise the
/// accepted path, and is refused on a MainNet trust domain by the
/// verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureKmsBackend {
    pub identity: BackendIdentity,
    pub response_nonce: String,
    pub response_freshness_unix: Option<u64>,
    pub response_expires_at_unix: Option<u64>,
}

impl AuthorityCustodyBackend for FixtureKmsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::FixtureKms
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        build_fixture_response(
            &self.identity,
            request,
            &self.response_nonce,
            self.response_freshness_unix,
            self.response_expires_at_unix,
        )
    }
}

/// Run 203 — DevNet/TestNet fixture HSM backend. Source/test only; see
/// [`FixtureKmsBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureHsmBackend {
    pub identity: BackendIdentity,
    pub response_nonce: String,
    pub response_freshness_unix: Option<u64>,
    pub response_expires_at_unix: Option<u64>,
}

impl AuthorityCustodyBackend for FixtureHsmBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::FixtureHsm
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        build_fixture_response(
            &self.identity,
            request,
            &self.response_nonce,
            self.response_freshness_unix,
            self.response_expires_at_unix,
        )
    }
}

/// Run 203 — production KMS backend placeholder. Callable but fails
/// closed: [`Self::sign_authority_lifecycle_request`] always returns
/// [`BackendOutcome::ProductionKmsUnavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionKmsBackend {
    pub identity: BackendIdentity,
}

impl AuthorityCustodyBackend for ProductionKmsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::ProductionKmsUnavailable
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        _request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        Err(BackendOutcome::ProductionKmsUnavailable)
    }
}

/// Run 203 — production HSM backend placeholder. Callable but fails
/// closed with [`BackendOutcome::ProductionHsmUnavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHsmBackend {
    pub identity: BackendIdentity,
}

impl AuthorityCustodyBackend for ProductionHsmBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::ProductionHsmUnavailable
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        _request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        Err(BackendOutcome::ProductionHsmUnavailable)
    }
}

/// Run 203 — cloud-KMS backend placeholder. Callable but fails closed
/// with [`BackendOutcome::CloudKmsUnavailable`]. Run 203 wires no cloud
/// KMS integration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudKmsBackend {
    pub identity: BackendIdentity,
}

impl AuthorityCustodyBackend for CloudKmsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::CloudKmsUnavailable
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        _request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        Err(BackendOutcome::CloudKmsUnavailable)
    }
}

/// Run 203 — PKCS#11 HSM backend placeholder. Callable but fails closed
/// with [`BackendOutcome::Pkcs11HsmUnavailable`]. Run 203 wires no
/// PKCS#11 integration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11HsmBackend {
    pub identity: BackendIdentity,
}

impl AuthorityCustodyBackend for Pkcs11HsmBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Pkcs11HsmUnavailable
    }

    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn sign_authority_lifecycle_request(
        &self,
        _request: &BackendRequest,
    ) -> Result<BackendResponse, BackendOutcome> {
        Err(BackendOutcome::Pkcs11HsmUnavailable)
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

/// Classify a production-required / MainNet-required policy rejection for
/// the response backend kind. Fixture material is rejected as
/// non-production; production/cloud/PKCS#11 material is rejected as
/// unavailable; unknown/disabled material is rejected as unknown.
fn classify_production_policy_rejection(
    policy: BackendPolicy,
    backend_kind: BackendKind,
) -> BackendOutcome {
    match backend_kind {
        BackendKind::FixtureKms | BackendKind::FixtureHsm => {
            if policy == BackendPolicy::MainnetProductionCustodyRequired {
                BackendOutcome::FixtureRejectedMainnetProductionRequired
            } else {
                BackendOutcome::FixtureRejectedProductionRequired
            }
        }
        BackendKind::ProductionKmsUnavailable => {
            if policy == BackendPolicy::MainnetProductionCustodyRequired {
                BackendOutcome::MainNetProductionCustodyUnavailable
            } else {
                BackendOutcome::ProductionKmsUnavailable
            }
        }
        BackendKind::ProductionHsmUnavailable => {
            if policy == BackendPolicy::MainnetProductionCustodyRequired {
                BackendOutcome::MainNetProductionCustodyUnavailable
            } else {
                BackendOutcome::ProductionHsmUnavailable
            }
        }
        BackendKind::CloudKmsUnavailable => {
            if policy == BackendPolicy::MainnetProductionCustodyRequired {
                BackendOutcome::MainNetProductionCustodyUnavailable
            } else {
                BackendOutcome::CloudKmsUnavailable
            }
        }
        BackendKind::Pkcs11HsmUnavailable => {
            if policy == BackendPolicy::MainnetProductionCustodyRequired {
                BackendOutcome::MainNetProductionCustodyUnavailable
            } else {
                BackendOutcome::Pkcs11HsmUnavailable
            }
        }
        BackendKind::Disabled | BackendKind::Unknown => BackendOutcome::UnknownBackendRejected {
            backend_tag: backend_kind.tag(),
        },
    }
}

/// Run 203 — pure typed KMS/HSM backend verifier.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust. Evicts no sessions. Never invokes Run 070.
///
/// The verifier binds every decision to the trust domain, the candidate
/// signing-key fingerprint, the lifecycle action, the candidate digest,
/// the next authority-domain sequence, the key id, the request/response
/// canonical digests, the transcript digest, the per-attempt
/// request/response anti-replay nonces, and the identity/response
/// freshness windows. Acceptance is only ever a fixture KMS/HSM response
/// under the matching fixture policy on a DevNet/TestNet trust domain.
pub fn verify_authority_custody_backend_response(
    identity: &BackendIdentity,
    request: &BackendRequest,
    response: &BackendResponse,
    trust_domain: &AuthorityTrustDomain,
    expected: &BackendExpectations,
    policy: BackendPolicy,
) -> BackendOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies
    //    fail closed before any binding check.
    match policy {
        BackendPolicy::Disabled => return BackendOutcome::Disabled,
        BackendPolicy::ProductionKmsRequired
        | BackendPolicy::ProductionHsmRequired
        | BackendPolicy::MainnetProductionCustodyRequired => {
            return classify_production_policy_rejection(policy, response.backend_kind);
        }
        BackendPolicy::FixtureKmsAllowed | BackendPolicy::FixtureHsmAllowed => {}
    }

    // 2. Under a fixture-allowed policy, a production/cloud/PKCS#11
    //    response is still unavailable (no real backend exists), and an
    //    unknown/disabled response is rejected.
    match response.backend_kind {
        BackendKind::ProductionKmsUnavailable => {
            return BackendOutcome::ProductionKmsUnavailable
        }
        BackendKind::ProductionHsmUnavailable => {
            return BackendOutcome::ProductionHsmUnavailable
        }
        BackendKind::CloudKmsUnavailable => return BackendOutcome::CloudKmsUnavailable,
        BackendKind::Pkcs11HsmUnavailable => return BackendOutcome::Pkcs11HsmUnavailable,
        BackendKind::Disabled | BackendKind::Unknown => {
            return BackendOutcome::UnknownBackendRejected {
                backend_tag: response.backend_kind.tag(),
            }
        }
        BackendKind::FixtureKms | BackendKind::FixtureHsm => {}
    }

    // 3. The fixture kind must match the fixture policy and the identity.
    let allowed_fixture = policy
        .allowed_fixture_kind()
        .expect("fixture-allowed policy has an allowed fixture kind");
    if response.backend_kind != allowed_fixture || identity.backend_kind != allowed_fixture {
        return BackendOutcome::BackendKindPolicyMismatch {
            policy_tag: policy.tag(),
            backend_tag: response.backend_kind.tag(),
        };
    }

    // 4. Fixture KMS/HSM is DevNet/TestNet source/test only — never
    //    MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return BackendOutcome::FixtureRejectedForMainNet;
    }

    // 5. Structural well-formedness.
    if !identity.is_well_formed() {
        return BackendOutcome::MalformedIdentity {
            reason: "identity missing one or more mandatory fields".to_string(),
        };
    }
    if !request.is_well_formed() {
        return BackendOutcome::MalformedRequest {
            reason: "request missing one or more mandatory fields".to_string(),
        };
    }
    if !response.is_well_formed() {
        return BackendOutcome::MalformedResponse {
            reason: "response missing one or more mandatory fields".to_string(),
        };
    }

    // 6. Custody-class binding (request + expected). Must be Kms/Hsm and
    //    must match the backend kind's custody class.
    let kind_class = response.backend_kind.custody_class();
    if request.custody_class != expected.expected_custody_class
        || Some(request.custody_class) != kind_class
    {
        return BackendOutcome::NotKmsHsmCustodyClass {
            class: request.custody_class,
        };
    }

    // 7. Trust-domain environment binding (request + identity).
    if request.environment != trust_domain.environment
        || identity.environment != trust_domain.environment
    {
        return BackendOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: request.environment,
        };
    }

    // 8. Trust-domain chain binding.
    if request.chain_id != trust_domain.chain_id || identity.chain_id != trust_domain.chain_id {
        return BackendOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: request.chain_id.clone(),
        };
    }

    // 9. Trust-domain genesis binding.
    if request.genesis_hash != trust_domain.genesis_hash
        || identity.genesis_hash != trust_domain.genesis_hash
    {
        return BackendOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: request.genesis_hash.clone(),
        };
    }

    // 10. Authority root binding.
    if request.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || identity.authority_root_fingerprint != trust_domain.authority_root_fingerprint
    {
        return BackendOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: request.authority_root_fingerprint.clone(),
        };
    }

    // 11. Key id binding (identity + request + response + expected).
    if identity.key_id != expected.expected_key_id
        || request.key_id != expected.expected_key_id
        || response.key_id != expected.expected_key_id
    {
        return BackendOutcome::WrongKeyId {
            expected: expected.expected_key_id.clone(),
            attested: response.key_id.clone(),
        };
    }

    // 12. Signing-key fingerprint binding.
    let attested_signing_fp = request
        .primary_signing_key_fingerprint()
        .unwrap_or("")
        .to_string();
    if attested_signing_fp != expected.expected_signing_key_fingerprint {
        return BackendOutcome::WrongSigningKeyFingerprint {
            expected: expected.expected_signing_key_fingerprint.clone(),
            attested: attested_signing_fp,
        };
    }

    // 13. Lifecycle action binding (expected + identity-supported).
    if request.lifecycle_action != expected.expected_lifecycle_action
        || !identity.supports_lifecycle_action(request.lifecycle_action)
    {
        return BackendOutcome::WrongLifecycleAction {
            expected: expected.expected_lifecycle_action,
            attested: request.lifecycle_action,
        };
    }

    // 14. Candidate digest binding.
    if request.candidate_digest != expected.expected_candidate_digest {
        return BackendOutcome::WrongCandidateDigest {
            expected: expected.expected_candidate_digest.clone(),
            attested: request.candidate_digest.clone(),
        };
    }

    // 15. Authority-domain sequence binding.
    if request.authority_domain_sequence != expected.expected_authority_domain_sequence {
        return BackendOutcome::WrongAuthorityDomainSequence {
            expected: expected.expected_authority_domain_sequence,
            attested: request.authority_domain_sequence,
        };
    }

    // 16. Custody attestation digest binding (request + expected).
    if request.custody_attestation_digest != expected.expected_custody_attestation_digest {
        return BackendOutcome::MalformedRequest {
            reason: "custody_attestation_digest does not match expected".to_string(),
        };
    }

    // 17. Request canonical-digest binding (computed + expected +
    //     response echo).
    let computed_request_digest = request.request_digest();
    if computed_request_digest != expected.expected_request_digest
        || response.bound_request_digest != computed_request_digest
    {
        return BackendOutcome::WrongRequestDigest {
            expected: expected.expected_request_digest.clone(),
            attested: response.bound_request_digest.clone(),
        };
    }

    // 18. Backend id / provider id binding (response echoes identity).
    if response.backend_id != identity.backend_id {
        return BackendOutcome::MalformedResponse {
            reason: "response backend_id does not match identity".to_string(),
        };
    }
    if response.provider_id != identity.provider_id {
        return BackendOutcome::MalformedResponse {
            reason: "response provider_id does not match identity".to_string(),
        };
    }

    // 19. Suite binding.
    if response.signature_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || identity.suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || response.signature_suite_id != identity.suite_id
    {
        return BackendOutcome::UnsupportedSuite {
            suite_id: response.signature_suite_id,
        };
    }

    // 20. Attestation validity (identity + response).
    if identity.attestation_digest == KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL
        || response.attestation_digest == KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL
    {
        return BackendOutcome::InvalidAttestation;
    }

    // 21. Placeholder signature validity.
    if response.signature_commitment.is_empty()
        || response.signature_commitment == KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL
    {
        return BackendOutcome::InvalidSignature;
    }

    // 22. Request anti-replay nonce.
    if request.request_nonce != expected.expected_request_nonce {
        return BackendOutcome::StaleOrReplayedRequest {
            expected: expected.expected_request_nonce.clone(),
            attested: request.request_nonce.clone(),
        };
    }

    // 23. Response anti-replay nonce.
    if response.response_nonce != expected.expected_response_nonce {
        return BackendOutcome::StaleOrReplayedResponse {
            expected: expected.expected_response_nonce.clone(),
            attested: response.response_nonce.clone(),
        };
    }

    // 24. Response canonical-digest binding (computed + expected).
    let computed_response_digest = response.response_digest();
    if computed_response_digest != expected.expected_response_digest {
        return BackendOutcome::WrongResponseDigest {
            expected: expected.expected_response_digest.clone(),
            attested: computed_response_digest,
        };
    }

    // 25. Transcript-digest binding (computed + expected).
    let computed_transcript_digest = backend_transcript_digest(
        &identity.identity_digest(),
        &computed_request_digest,
        &computed_response_digest,
    );
    if computed_transcript_digest != expected.expected_transcript_digest {
        return BackendOutcome::WrongTranscriptDigest {
            expected: expected.expected_transcript_digest.clone(),
            attested: computed_transcript_digest,
        };
    }

    // 26. Identity attestation freshness/expiry window.
    if within_optional_window(expected.now_unix, identity.freshness_unix, identity.expires_at_unix)
        .is_err()
    {
        return BackendOutcome::ExpiredAttestation {
            now_unix: expected.now_unix,
        };
    }

    // 27. Response freshness/expiry window.
    if within_optional_window(expected.now_unix, response.freshness_unix, response.expires_at_unix)
        .is_err()
    {
        return BackendOutcome::ExpiredResponse {
            now_unix: expected.now_unix,
        };
    }

    // 28. Accept — fixture KMS/HSM only, DevNet/TestNet, evidence-only.
    match response.backend_kind {
        BackendKind::FixtureKms => BackendOutcome::FixtureKmsAccepted {
            backend_id: identity.backend_id.clone(),
            environment: trust_domain.environment,
        },
        BackendKind::FixtureHsm => BackendOutcome::FixtureHsmAccepted {
            backend_id: identity.backend_id.clone(),
            environment: trust_domain.environment,
        },
        // Unreachable: every other kind was handled in step 2.
        other => BackendOutcome::UnknownBackendRejected {
            backend_tag: other.tag(),
        },
    }
}

// ===========================================================================
// Custody-class routing
// ===========================================================================

/// Run 203 — returns `true` iff the custody class routes into the
/// KMS/HSM backend boundary (i.e. `Kms` or `Hsm`).
pub const fn custody_class_routes_to_kms_hsm_backend(class: AuthorityCustodyClass) -> bool {
    matches!(class, AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm)
}

/// Run 203 — route a Run 188 custody class into the KMS/HSM backend
/// boundary.
///
/// * `AuthorityCustodyClass::Kms` / `AuthorityCustodyClass::Hsm` are
///   dispatched to [`verify_authority_custody_backend_response`].
/// * `AuthorityCustodyClass::LocalOperatorKey` /
///   `AuthorityCustodyClass::FixtureLocalKey` are refused as
///   [`BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy`] — local
///   material can never satisfy a KMS/HSM backend policy.
/// * `AuthorityCustodyClass::RemoteSigner` is refused as
///   [`BackendOutcome::NotKmsHsmCustodyClass`] — the RemoteSigner path
///   (Runs 194–202) remains a separate custody option.
/// * every other class is refused as
///   [`BackendOutcome::NotKmsHsmCustodyClass`].
#[allow(clippy::too_many_arguments)]
pub fn validate_backend_for_custody_class(
    custody_class: AuthorityCustodyClass,
    identity: &BackendIdentity,
    request: &BackendRequest,
    response: &BackendResponse,
    trust_domain: &AuthorityTrustDomain,
    expected: &BackendExpectations,
    policy: BackendPolicy,
) -> BackendOutcome {
    match custody_class {
        AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm => {
            verify_authority_custody_backend_response(
                identity,
                request,
                response,
                trust_domain,
                expected,
                policy,
            )
        }
        AuthorityCustodyClass::LocalOperatorKey | AuthorityCustodyClass::FixtureLocalKey => {
            BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy
        }
        other => BackendOutcome::NotKmsHsmCustodyClass { class: other },
    }
}

// ===========================================================================
// Composition helper
// ===========================================================================

/// Run 203 — typed combined decision for a lifecycle + governance +
/// custody + KMS/HSM backend preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleCustodyBackendOutcome {
    /// The lifecycle transition validates, the Run 188 custody
    /// attestation validates under the active custody policy, AND the
    /// backend response validates under the active backend policy.
    /// **Acceptance is evidence-only.** It does not enable MainNet
    /// apply, does not perform a Run 070 call, does not write a marker,
    /// does not burn a sequence number, does not swap live trust, and
    /// does not evict sessions.
    Accepted {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        backend_outcome: BackendOutcome,
    },
    /// The Run 188 lifecycle/custody composition rejected. The backend
    /// was not consulted.
    LifecycleOrCustodyRejected(LifecycleGovernanceCustodyOutcome),
    /// The Run 188 lifecycle/custody composition accepted but the
    /// backend validation rejected. Carries both so the operator log
    /// line can record "custody valid + backend invalid".
    BackendRejected {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        backend_outcome: BackendOutcome,
    },
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of any custody or backend
    /// outcome.
    MainNetPeerDrivenApplyRefused,
}

impl LifecycleCustodyBackendOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 203 — pure composition helper.
///
/// Calls the Run 188 lifecycle + governance + custody validator, then
/// (if accepted) calls the Run 203 KMS/HSM backend verifier, and returns
/// a typed combined decision. Performs no I/O, writes no marker, writes
/// no sequence, mutates no live trust, evicts no sessions, never invokes
/// Run 070.
///
/// `is_peer_driven_apply_preflight` lets the calling surface request the
/// MainNet peer-driven-apply refusal short-circuit: when set and the
/// trust domain is MainNet, the helper returns
/// [`LifecycleCustodyBackendOutcome::MainNetPeerDrivenApplyRefused`]
/// without consulting custody or the backend — a fixture KMS/HSM backend
/// can never enable a MainNet apply.
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_governance_custody_and_backend(
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
    identity: &BackendIdentity,
    request: &BackendRequest,
    response: &BackendResponse,
    backend_expected: &BackendExpectations,
    backend_policy: BackendPolicy,
    now_unix: u64,
    is_peer_driven_apply_preflight: bool,
) -> LifecycleCustodyBackendOutcome {
    // MainNet peer-driven apply remains refused regardless of any
    // fixture KMS/HSM backend success.
    if is_peer_driven_apply_preflight && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return LifecycleCustodyBackendOutcome::MainNetPeerDrivenApplyRefused;
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
        return LifecycleCustodyBackendOutcome::LifecycleOrCustodyRejected(
            lifecycle_custody_outcome,
        );
    }

    let backend_outcome = verify_authority_custody_backend_response(
        identity,
        request,
        response,
        trust_domain,
        backend_expected,
        backend_policy,
    );

    if backend_outcome.is_accept() {
        LifecycleCustodyBackendOutcome::Accepted {
            lifecycle_custody_outcome,
            backend_outcome,
        }
    } else {
        LifecycleCustodyBackendOutcome::BackendRejected {
            lifecycle_custody_outcome,
            backend_outcome,
        }
    }
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 203 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes,
/// at the typed Run 203 boundary, the rule that MainNet peer-driven
/// apply remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// backend response — even a fixture KMS/HSM response that signs
/// successfully. Pure data; never reads backend material.
pub fn mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 203 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a KMS/HSM
/// backend policy. Run 203 always returns `true`: a KMS/HSM backend is a
/// custody-held authority and is never satisfiable by a local operator
/// key. Grep-verifiable named symbol for an operator-log line.
pub fn local_operator_cannot_satisfy_backend_policy() -> bool {
    true
}

/// Run 203 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// KMS/HSM backend policy. Run 203 always returns `true`: a KMS/HSM
/// backend is a per-key authority decision and is never satisfiable by
/// counting peers. Grep-verifiable named symbol for an operator-log
/// line.
pub fn peer_majority_cannot_satisfy_backend_policy() -> bool {
    true
}
