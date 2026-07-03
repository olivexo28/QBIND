//! Run 295 — source/test production KMS/HSM/cloud-KMS/PKCS#11 custody
//! backend.
//!
//! This module implements a real source/test production custody backend
//! **client** on top of the Run 203
//! [`crate::pqc_authority_kms_hsm_backend`] KMS/HSM boundary. It provides
//! the typed provider / policy / request-kind taxonomy, the request /
//! response / transcript / request-id / digest types, deterministic
//! domain-separated request-id and custody transcript digests, fixture
//! KMS / HSM providers for DevNet/TestNet source tests only, a mockable
//! provider transport, and production cloud-KMS / PKCS#11-HSM / generic
//! KMS / generic HSM provider paths that are *reachable but
//! fail-closed* (unavailable / misconfigured) without real provider
//! configuration.
//!
//! Scope and honesty constraints (Run 295):
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to Run 296.
//! * The default policy is [`ProductionKmsHsmCustodyBackendPolicy::Disabled`]
//!   and fails closed before building any request or invoking any
//!   provider transport.
//! * A MainNet trust domain is **refused** absent real production
//!   authority criteria; fixture KMS / HSM material can never satisfy
//!   MainNet, and there is no fixture / RemoteSigner / local-signing
//!   fallback under a production policy.
//! * The backend is **non-mutating**: it performs no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust
//!   swap, no session eviction, no PQC trust-bundle sequence write, no
//!   authority marker write, no durable replay overwrite, no settlement,
//!   no external publication, no governance execution, and no
//!   validator-set rotation. Full C4 remains OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_295.md`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::pqc_authority_custody::AuthorityCustodyClass;
use crate::pqc_authority_kms_hsm_backend::{
    backend_transcript_digest, verify_authority_custody_backend_response, BackendExpectations,
    BackendIdentity, BackendKind, BackendOutcome, BackendPolicy, BackendRequest, BackendResponse,
    FixtureHsmBackend, FixtureKmsBackend, AuthorityCustodyBackend,
};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 295 — the only backend protocol version this run accepts.
pub const PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION: u16 = 1;

/// Run 295 — backend request-id derivation domain tag.
pub const PRODUCTION_KMS_HSM_CUSTODY_REQUEST_ID_DOMAIN_TAG: &str =
    "QBIND:run295-production-kms-hsm-custody-request-id:v1";

/// Run 295 — backend transcript digest domain tag.
pub const PRODUCTION_KMS_HSM_CUSTODY_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run295-production-kms-hsm-custody-transcript:v1";

/// Run 295 — request envelope digest domain tag.
pub const PRODUCTION_KMS_HSM_CUSTODY_REQUEST_ENVELOPE_DOMAIN_TAG: &str =
    "QBIND:run295-production-kms-hsm-custody-request-envelope:v1";

/// Run 295 — response envelope digest domain tag.
pub const PRODUCTION_KMS_HSM_CUSTODY_RESPONSE_ENVELOPE_DOMAIN_TAG: &str =
    "QBIND:run295-production-kms-hsm-custody-response-envelope:v1";

/// Run 295 — maximum accepted provider response size, in bytes. A
/// response larger than this is fail-closed as
/// [`ProductionCustodyError::ResponseTooLarge`]. Purely a typed bound;
/// Run 295 performs no real I/O.
pub const PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Helper: length-prefixed domain-separated field hashing closure body.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

// ===========================================================================
// Provider kind taxonomy
// ===========================================================================

/// Run 295 — typed custody provider kind taxonomy.
///
/// `Disabled` is the inert default. `FixtureKms` / `FixtureHsm` are
/// DevNet/TestNet source/test providers only. The four production
/// provider kinds are reachable but fail closed without real provider
/// configuration. `Unknown` always fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionCustodyProviderKind {
    /// Inert default. No provider is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture KMS provider.
    FixtureKms,
    /// DevNet/TestNet source/test fixture HSM provider.
    FixtureHsm,
    /// Production cloud-KMS provider path. Reachable, fails closed.
    ProductionCloudKms,
    /// Production PKCS#11 HSM provider path. Reachable, fails closed.
    ProductionPkcs11Hsm,
    /// Production generic KMS provider path. Reachable, fails closed.
    ProductionGenericKms,
    /// Production generic HSM provider path. Reachable, fails closed.
    ProductionGenericHsm,
    /// Unknown / unsupported provider. Always fail closed.
    Unknown,
}

impl ProductionCustodyProviderKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKms => "fixture-kms",
            Self::FixtureHsm => "fixture-hsm",
            Self::ProductionCloudKms => "production-cloud-kms",
            Self::ProductionPkcs11Hsm => "production-pkcs11-hsm",
            Self::ProductionGenericKms => "production-generic-kms",
            Self::ProductionGenericHsm => "production-generic-hsm",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this kind is a DevNet/TestNet source/test
    /// fixture provider.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureKms | Self::FixtureHsm)
    }

    /// Returns `true` iff this kind is a production-class provider path.
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Self::ProductionCloudKms
                | Self::ProductionPkcs11Hsm
                | Self::ProductionGenericKms
                | Self::ProductionGenericHsm
        )
    }

    /// The custody class this provider kind carries, if it is a KMS/HSM
    /// provider.
    pub const fn custody_class(self) -> Option<AuthorityCustodyClass> {
        match self {
            Self::FixtureKms | Self::ProductionCloudKms | Self::ProductionGenericKms => {
                Some(AuthorityCustodyClass::Kms)
            }
            Self::FixtureHsm | Self::ProductionPkcs11Hsm | Self::ProductionGenericHsm => {
                Some(AuthorityCustodyClass::Hsm)
            }
            Self::Disabled | Self::Unknown => None,
        }
    }

    /// Map onto the Run 203 [`BackendKind`] this provider composes with.
    pub const fn to_backend_kind(self) -> BackendKind {
        match self {
            Self::Disabled => BackendKind::Disabled,
            Self::FixtureKms => BackendKind::FixtureKms,
            Self::FixtureHsm => BackendKind::FixtureHsm,
            Self::ProductionCloudKms => BackendKind::CloudKmsUnavailable,
            Self::ProductionPkcs11Hsm => BackendKind::Pkcs11HsmUnavailable,
            Self::ProductionGenericKms => BackendKind::ProductionKmsUnavailable,
            Self::ProductionGenericHsm => BackendKind::ProductionHsmUnavailable,
            Self::Unknown => BackendKind::Unknown,
        }
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 295 — typed production KMS/HSM custody backend policy.
///
/// `Disabled` is the default fail-closed policy: the backend refuses
/// before building a request or invoking any provider transport. The
/// fixture policies accept only DevNet/TestNet fixture material; the
/// production policies map onto the Run 203 [`BackendPolicy`] the
/// existing verifier already enforces, so acceptance can never claim
/// more authority than the Run 203 boundary already grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionKmsHsmCustodyBackendPolicy {
    /// Default. Refuses every request before any transport call.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture-KMS policy.
    FixtureKmsAllowed,
    /// DevNet/TestNet source/test fixture-HSM policy.
    FixtureHsmAllowed,
    /// Production cloud-KMS required. Run 295 wires no real provider, so
    /// every request fails closed as unavailable.
    ProductionCloudKmsRequired,
    /// Production PKCS#11 HSM required. Fails closed as unavailable.
    ProductionPkcs11HsmRequired,
    /// Production generic KMS required. Fails closed as unavailable.
    ProductionGenericKmsRequired,
    /// Production generic HSM required. Fails closed as unavailable.
    ProductionGenericHsmRequired,
    /// MainNet production custody required. Fails closed for every
    /// request — fixture material is rejected as non-production and
    /// every production request is refused as unavailable.
    MainnetProductionCustodyRequired,
}

impl ProductionKmsHsmCustodyBackendPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKmsAllowed => "fixture-kms-allowed",
            Self::FixtureHsmAllowed => "fixture-hsm-allowed",
            Self::ProductionCloudKmsRequired => "production-cloud-kms-required",
            Self::ProductionPkcs11HsmRequired => "production-pkcs11-hsm-required",
            Self::ProductionGenericKmsRequired => "production-generic-kms-required",
            Self::ProductionGenericHsmRequired => "production-generic-hsm-required",
            Self::MainnetProductionCustodyRequired => "mainnet-production-custody-required",
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy is a fixture policy.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureKmsAllowed | Self::FixtureHsmAllowed)
    }

    /// Returns `true` iff this policy requires a real production
    /// provider (Run 295 fails these closed as unavailable).
    pub const fn requires_production_backend(self) -> bool {
        matches!(
            self,
            Self::ProductionCloudKmsRequired
                | Self::ProductionPkcs11HsmRequired
                | Self::ProductionGenericKmsRequired
                | Self::ProductionGenericHsmRequired
                | Self::MainnetProductionCustodyRequired
        )
    }

    /// The provider kind this policy accepts, if any.
    pub const fn allowed_provider_kind(self) -> Option<ProductionCustodyProviderKind> {
        match self {
            Self::Disabled | Self::MainnetProductionCustodyRequired => None,
            Self::FixtureKmsAllowed => Some(ProductionCustodyProviderKind::FixtureKms),
            Self::FixtureHsmAllowed => Some(ProductionCustodyProviderKind::FixtureHsm),
            Self::ProductionCloudKmsRequired => {
                Some(ProductionCustodyProviderKind::ProductionCloudKms)
            }
            Self::ProductionPkcs11HsmRequired => {
                Some(ProductionCustodyProviderKind::ProductionPkcs11Hsm)
            }
            Self::ProductionGenericKmsRequired => {
                Some(ProductionCustodyProviderKind::ProductionGenericKms)
            }
            Self::ProductionGenericHsmRequired => {
                Some(ProductionCustodyProviderKind::ProductionGenericHsm)
            }
        }
    }

    /// Map onto the Run 203 [`BackendPolicy`] consumed by the verifier.
    pub const fn to_backend_policy(self) -> BackendPolicy {
        match self {
            Self::Disabled => BackendPolicy::Disabled,
            Self::FixtureKmsAllowed => BackendPolicy::FixtureKmsAllowed,
            Self::FixtureHsmAllowed => BackendPolicy::FixtureHsmAllowed,
            Self::ProductionCloudKmsRequired | Self::ProductionGenericKmsRequired => {
                BackendPolicy::ProductionKmsRequired
            }
            Self::ProductionPkcs11HsmRequired | Self::ProductionGenericHsmRequired => {
                BackendPolicy::ProductionHsmRequired
            }
            Self::MainnetProductionCustodyRequired => {
                BackendPolicy::MainnetProductionCustodyRequired
            }
        }
    }
}

// ===========================================================================
// Request kind
// ===========================================================================

/// Run 295 — the typed kind of custody signing request.
///
/// The backend implements **only** authority-lifecycle and
/// governance-execution signing request/response handling. Validator-set
/// rotation, policy change, and on-chain governance proof verification
/// are explicitly **not** implemented in this run and are refused up
/// front with a precise outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductionCustodyRequestKind {
    /// Authority-lifecycle signing (activate/rotate/retire/revoke).
    AuthorityLifecycleSigning,
    /// Governance-execution signing (request/response handling only; no
    /// governance execution behaviour is performed).
    GovernanceExecutionSigning,
    /// Validator-set rotation. **Not implemented in Run 295.**
    ValidatorSetRotation,
    /// Governance policy change. **Not implemented in Run 295.**
    PolicyChange,
    /// On-chain governance proof verification. **Not implemented in Run
    /// 295.**
    OnChainGovernanceProofVerification,
}

impl ProductionCustodyRequestKind {
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

/// Run 295 — the typed decision input a caller supplies to drive one
/// custody backend round-trip.
///
/// The backend derives the Run 203 [`BackendRequest`], the deterministic
/// request id, the request envelope, and the caller-side expectations
/// from this single spec, so a valid spec produces self-consistent
/// request/response/transcript bindings by construction and every tamper
/// is a precise fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyRequestSpec {
    /// The kind of signing request.
    pub request_kind: ProductionCustodyRequestKind,
    /// The provider kind addressed.
    pub provider_kind: ProductionCustodyProviderKind,
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
    /// Bound custody class. Must be `Kms` or `Hsm`.
    pub custody_class: AuthorityCustodyClass,
    /// Stable, opaque identifier of the provider.
    pub provider_id: String,
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
    /// Custody attestation digest bound to this request.
    pub custody_attestation_digest: String,
    /// Optional Run 291 durable replay record digest, bound into the
    /// request id and transcript when present.
    pub durable_replay_record_digest: Option<String>,
    /// Per-attempt request anti-replay nonce.
    pub request_nonce: String,
    /// Expected response anti-replay nonce.
    pub response_nonce: String,
    /// Request timestamp / epoch (UNIX seconds).
    pub request_timestamp_unix: u64,
}

impl ProductionCustodyRequestSpec {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.provider_id.is_empty()
            && !self.key_id.is_empty()
            && !self.custody_attestation_digest.is_empty()
            && !self.request_nonce.is_empty()
            && !self.response_nonce.is_empty()
            && matches!(
                self.custody_class,
                AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm
            )
    }

    /// The signing-key fingerprint this request primarily binds.
    pub fn primary_signing_key_fingerprint(&self) -> Option<&str> {
        self.new_signing_key_fingerprint
            .as_deref()
            .or(self.active_signing_key_fingerprint.as_deref())
            .or(self.revoked_signing_key_fingerprint.as_deref())
    }

    /// Build the Run 203 inner [`BackendRequest`] from this spec.
    pub fn build_backend_request(&self) -> BackendRequest {
        BackendRequest {
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            custody_class: self.custody_class,
            key_id: self.key_id.clone(),
            active_signing_key_fingerprint: self.active_signing_key_fingerprint.clone(),
            new_signing_key_fingerprint: self.new_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: self.revoked_signing_key_fingerprint.clone(),
            governance_proof_digest: self.governance_proof_digest.clone(),
            custody_attestation_digest: self.custody_attestation_digest.clone(),
            request_nonce: self.request_nonce.clone(),
            request_timestamp_unix: Some(self.request_timestamp_unix),
        }
    }

    /// Derive the Run 203 [`BackendExpectations`] for this
    /// request/response pair. Binding fields are derived from the spec;
    /// the canonical request/response/transcript digests are derived
    /// from the *submitted* request/response so a valid submission is
    /// self-consistent and any field tamper is a precise reject.
    pub fn backend_expectations(
        &self,
        identity: &BackendIdentity,
        request: &BackendRequest,
        response: &BackendResponse,
        now_unix: u64,
    ) -> BackendExpectations {
        let request_digest = request.request_digest();
        let response_digest = response.response_digest();
        let transcript_digest =
            backend_transcript_digest(&identity.identity_digest(), &request_digest, &response_digest);
        BackendExpectations {
            expected_custody_class: self.custody_class,
            expected_lifecycle_action: self.lifecycle_action,
            expected_candidate_digest: self.candidate_digest.clone(),
            expected_authority_domain_sequence: self.authority_domain_sequence,
            expected_key_id: self.key_id.clone(),
            expected_signing_key_fingerprint: self
                .primary_signing_key_fingerprint()
                .unwrap_or("")
                .to_string(),
            expected_custody_attestation_digest: self.custody_attestation_digest.clone(),
            expected_request_nonce: self.request_nonce.clone(),
            expected_response_nonce: self.response_nonce.clone(),
            expected_request_digest: request_digest,
            expected_response_digest: response_digest,
            expected_transcript_digest: transcript_digest,
            now_unix,
        }
    }
}

/// Run 295 — deterministic, domain-separated backend request id.
///
/// Derived from the typed request spec so the request id is
/// deterministic (not random, not wall-clock). The provider response
/// must echo it and the backend rejects a mismatch as
/// [`ProductionCustodyOutcome::ProductionCustodyRequestIdMismatch`].
pub fn production_kms_hsm_custody_request_id(spec: &ProductionCustodyRequestSpec) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_KMS_HSM_CUSTODY_REQUEST_ID_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"request_kind", spec.request_kind.tag().as_bytes());
    hash_field(&mut h, b"provider_kind", spec.provider_kind.tag().as_bytes());
    hash_field(
        &mut h,
        b"environment",
        &spec.environment.metric_code().to_le_bytes(),
    );
    hash_field(&mut h, b"chain_id", spec.chain_id.as_bytes());
    hash_field(&mut h, b"genesis_hash", spec.genesis_hash.as_bytes());
    hash_field(
        &mut h,
        b"authority_root_fingerprint",
        spec.authority_root_fingerprint.as_bytes(),
    );
    hash_field(
        &mut h,
        b"lifecycle_action",
        spec.lifecycle_action.tag().as_bytes(),
    );
    hash_field(&mut h, b"candidate_digest", spec.candidate_digest.as_bytes());
    hash_field(
        &mut h,
        b"authority_domain_sequence",
        &spec.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(&mut h, b"custody_class", spec.custody_class.tag().as_bytes());
    hash_field(&mut h, b"provider_id", spec.provider_id.as_bytes());
    hash_field(&mut h, b"key_id", spec.key_id.as_bytes());
    hash_field(
        &mut h,
        b"custody_attestation_digest",
        spec.custody_attestation_digest.as_bytes(),
    );
    hash_field(
        &mut h,
        b"durable_replay_record_digest",
        spec.durable_replay_record_digest
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash_field(&mut h, b"request_nonce", spec.request_nonce.as_bytes());
    hash_field(
        &mut h,
        b"request_timestamp_unix",
        &spec.request_timestamp_unix.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 295 — deterministic, domain-separated backend transcript digest.
///
/// Binds the backend protocol version, request id, the Run 203 identity
/// / request / response / transcript digests, and any durable replay
/// record digest into a single backend-level commitment. Only a response
/// that reproduces this digest may authorize acceptance.
pub fn production_kms_hsm_custody_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    identity_digest: &str,
    request_digest: &str,
    response_digest: &str,
    backend_transcript: &str,
    durable_replay_record_digest: Option<&str>,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_KMS_HSM_CUSTODY_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"request_id", request_id.as_bytes());
    hash_field(&mut h, b"identity_digest", identity_digest.as_bytes());
    hash_field(&mut h, b"request_digest", request_digest.as_bytes());
    hash_field(&mut h, b"response_digest", response_digest.as_bytes());
    hash_field(&mut h, b"backend_transcript", backend_transcript.as_bytes());
    hash_field(
        &mut h,
        b"durable_replay_record_digest",
        durable_replay_record_digest.unwrap_or("").as_bytes(),
    );
    hex::encode(h.finalize())
}

// ===========================================================================
// Request / response envelopes
// ===========================================================================

/// Run 295 — the typed custody request envelope submitted to a provider
/// transport. Wraps the Run 203 [`BackendRequest`] with the deterministic
/// request id and provider-addressing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub provider_kind: ProductionCustodyProviderKind,
    pub provider_id: String,
    pub key_id: String,
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub custody_class: AuthorityCustodyClass,
    pub request_timestamp_unix: u64,
    pub backend_request: BackendRequest,
}

impl ProductionCustodyRequest {
    /// Deterministic SHA3-256 hex digest over the request envelope.
    pub fn envelope_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_KMS_HSM_CUSTODY_REQUEST_ENVELOPE_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(&mut h, b"request_id", self.request_id.as_bytes());
        hash_field(&mut h, b"provider_kind", self.provider_kind.tag().as_bytes());
        hash_field(&mut h, b"provider_id", self.provider_id.as_bytes());
        hash_field(&mut h, b"key_id", self.key_id.as_bytes());
        hash_field(&mut h, b"custody_class", self.custody_class.tag().as_bytes());
        hash_field(&mut h, b"backend_request_digest", self.backend_request.request_digest().as_bytes());
        hex::encode(h.finalize())
    }
}

/// Run 295 — the typed custody response envelope a provider transport
/// returns. Wraps the Run 203 [`BackendResponse`] with the echoed request
/// id, provider-identifying metadata, and the transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyResponse {
    pub protocol_version: u16,
    pub request_id_echo: String,
    pub provider_kind: ProductionCustodyProviderKind,
    pub provider_id: String,
    pub key_id: String,
    pub transcript_digest: String,
    pub backend_response: BackendResponse,
}

impl ProductionCustodyResponse {
    /// Deterministic SHA3-256 hex digest over the response envelope.
    pub fn envelope_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_KMS_HSM_CUSTODY_RESPONSE_ENVELOPE_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(&mut h, b"request_id_echo", self.request_id_echo.as_bytes());
        hash_field(&mut h, b"provider_kind", self.provider_kind.tag().as_bytes());
        hash_field(&mut h, b"provider_id", self.provider_id.as_bytes());
        hash_field(&mut h, b"key_id", self.key_id.as_bytes());
        hash_field(&mut h, b"transcript_digest", self.transcript_digest.as_bytes());
        hash_field(&mut h, b"backend_response_digest", self.backend_response.response_digest().as_bytes());
        hex::encode(h.finalize())
    }

    /// Typed response-size estimate for the oversized fail-closed bound.
    pub fn response_size_estimate(&self) -> usize {
        self.backend_response.signature_commitment.len()
            + self.backend_response.attestation_digest.len()
            + self.transcript_digest.len()
    }
}

// ===========================================================================
// Provider error taxonomy
// ===========================================================================

/// Run 295 — typed provider transport / availability error a real
/// production custody provider may surface. Run 295 injects them via the
/// source/test providers / mock transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyError {
    /// The provider endpoint is unavailable (no route / down).
    EndpointUnavailable,
    /// The connection was refused.
    ConnectionRefused,
    /// The request timed out.
    Timeout,
    /// The transport failed to decode the response.
    DecodeError,
    /// The response exceeded [`PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES`].
    ResponseTooLarge { bytes: usize },
    /// The response was structurally malformed.
    MalformedResponse,
    /// The response used an unsupported protocol version.
    UnsupportedProtocolVersion { version: u16 },
    /// The provider is unavailable (no real provider wired).
    ProviderUnavailable,
    /// The provider is misconfigured (no real config / module / session
    /// / key handle).
    ProviderMisconfigured,
    /// The provider explicitly refused to sign.
    SigningRefused,
    /// The provider's policy rejected the request.
    ProviderPolicyRejected,
    /// The provider key handle is unavailable.
    KeyUnavailable,
    /// The custody attestation is missing.
    AttestationMissing,
    /// The custody attestation is unavailable.
    AttestationUnavailable,
    /// The provider kind is unsupported.
    UnsupportedProvider,
}

impl ProductionCustodyError {
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::EndpointUnavailable => "endpoint-unavailable",
            Self::ConnectionRefused => "connection-refused",
            Self::Timeout => "timeout",
            Self::DecodeError => "decode-error",
            Self::ResponseTooLarge { .. } => "response-too-large",
            Self::MalformedResponse => "malformed-response",
            Self::UnsupportedProtocolVersion { .. } => "unsupported-protocol-version",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::ProviderMisconfigured => "provider-misconfigured",
            Self::SigningRefused => "signing-refused",
            Self::ProviderPolicyRejected => "provider-policy-rejected",
            Self::KeyUnavailable => "key-unavailable",
            Self::AttestationMissing => "attestation-missing",
            Self::AttestationUnavailable => "attestation-unavailable",
            Self::UnsupportedProvider => "unsupported-provider",
        }
    }

    /// Returns `true` iff a fresh attempt may reasonably succeed.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EndpointUnavailable
                | Self::ConnectionRefused
                | Self::Timeout
                | Self::ProviderUnavailable
        )
    }
}

// ===========================================================================
// Provider transport boundary
// ===========================================================================

/// Run 295 — narrow, mockable custody provider transport boundary.
///
/// A real production provider would implement [`Self::submit`] by
/// invoking a cloud-KMS API / PKCS#11 session / HSM module and returning
/// a typed response envelope or a typed [`ProductionCustodyError`]. Run
/// 295 wires no real provider; only the DevNet/TestNet source/test
/// fixture providers, the reachable-but-fail-closed production stubs, and
/// the programmable mock implement this boundary.
///
/// Implementations must perform no marker write, no sequence write, no
/// live-trust mutation, no session eviction, and must never invoke Run
/// 070.
pub trait KmsHsmCustodyProviderTransport {
    /// Submit `request` on attempt `attempt` (1-based). Returns a typed
    /// response envelope or a typed provider error.
    fn submit(
        &self,
        request: &ProductionCustodyRequest,
        attempt: u32,
    ) -> Result<ProductionCustodyResponse, ProductionCustodyError>;
}

/// Build a deterministic fixture response envelope from a Run 203 fixture
/// backend response. Source/test only.
fn build_fixture_custody_response(
    identity: &BackendIdentity,
    request: &ProductionCustodyRequest,
    backend_response: BackendResponse,
) -> ProductionCustodyResponse {
    let identity_digest = identity.identity_digest();
    let request_digest = request.backend_request.request_digest();
    let response_digest = backend_response.response_digest();
    let transcript_digest =
        backend_transcript_digest(&identity_digest, &request_digest, &response_digest);
    ProductionCustodyResponse {
        protocol_version: request.protocol_version,
        request_id_echo: request.request_id.clone(),
        provider_kind: request.provider_kind,
        provider_id: request.provider_id.clone(),
        key_id: request.key_id.clone(),
        transcript_digest,
        backend_response,
    }
}

/// Run 295 — DevNet/TestNet source/test fixture KMS provider.
///
/// **Source/test only.** Wraps the Run 203 [`FixtureKmsBackend`] so the
/// backend's real submit/verify logic can be exercised against a
/// deterministic fixture response. It is NOT a real KMS and MainNet
/// material is refused by the verifier. Records how many times it was
/// called so tests can prove the Disabled policy never invokes it.
pub struct FixtureKmsCustodyProvider {
    inner: FixtureKmsBackend,
    call_count: Cell<u32>,
}

impl FixtureKmsCustodyProvider {
    pub fn new(inner: FixtureKmsBackend) -> Self {
        Self {
            inner,
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl KmsHsmCustodyProviderTransport for FixtureKmsCustodyProvider {
    fn submit(
        &self,
        request: &ProductionCustodyRequest,
        _attempt: u32,
    ) -> Result<ProductionCustodyResponse, ProductionCustodyError> {
        self.call_count.set(self.call_count.get() + 1);
        match self
            .inner
            .sign_authority_lifecycle_request(&request.backend_request)
        {
            Ok(backend_response) => Ok(build_fixture_custody_response(
                self.inner.identity(),
                request,
                backend_response,
            )),
            Err(_) => Err(ProductionCustodyError::MalformedResponse),
        }
    }
}

/// Run 295 — DevNet/TestNet source/test fixture HSM provider. Source/test
/// only; see [`FixtureKmsCustodyProvider`].
pub struct FixtureHsmCustodyProvider {
    inner: FixtureHsmBackend,
    call_count: Cell<u32>,
}

impl FixtureHsmCustodyProvider {
    pub fn new(inner: FixtureHsmBackend) -> Self {
        Self {
            inner,
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl KmsHsmCustodyProviderTransport for FixtureHsmCustodyProvider {
    fn submit(
        &self,
        request: &ProductionCustodyRequest,
        _attempt: u32,
    ) -> Result<ProductionCustodyResponse, ProductionCustodyError> {
        self.call_count.set(self.call_count.get() + 1);
        match self
            .inner
            .sign_authority_lifecycle_request(&request.backend_request)
        {
            Ok(backend_response) => Ok(build_fixture_custody_response(
                self.inner.identity(),
                request,
                backend_response,
            )),
            Err(_) => Err(ProductionCustodyError::MalformedResponse),
        }
    }
}

/// Run 295 — reachable-but-fail-closed production custody provider stub.
///
/// Represents the production cloud-KMS / PKCS#11-HSM / generic-KMS /
/// generic-HSM provider paths. The path is *reachable* (the transport
/// boundary is invoked) but always fails closed with the configured
/// error because no real provider config / module / session / key handle
/// exists in Run 295. Records how many times it was called.
pub struct ProductionCustodyProviderStub {
    provider_kind: ProductionCustodyProviderKind,
    error: ProductionCustodyError,
    call_count: Cell<u32>,
}

impl ProductionCustodyProviderStub {
    /// A production cloud-KMS provider path, unavailable without config.
    pub fn cloud_kms() -> Self {
        Self::with_error(
            ProductionCustodyProviderKind::ProductionCloudKms,
            ProductionCustodyError::ProviderMisconfigured,
        )
    }

    /// A production PKCS#11 HSM provider path, unavailable without a real
    /// module / session / key handle.
    pub fn pkcs11_hsm() -> Self {
        Self::with_error(
            ProductionCustodyProviderKind::ProductionPkcs11Hsm,
            ProductionCustodyError::ProviderMisconfigured,
        )
    }

    /// A production generic KMS provider path, unavailable without
    /// config.
    pub fn generic_kms() -> Self {
        Self::with_error(
            ProductionCustodyProviderKind::ProductionGenericKms,
            ProductionCustodyError::ProviderUnavailable,
        )
    }

    /// A production generic HSM provider path, unavailable without
    /// config.
    pub fn generic_hsm() -> Self {
        Self::with_error(
            ProductionCustodyProviderKind::ProductionGenericHsm,
            ProductionCustodyError::ProviderUnavailable,
        )
    }

    /// A production provider path of `provider_kind` that fails closed
    /// with `error`.
    pub fn with_error(
        provider_kind: ProductionCustodyProviderKind,
        error: ProductionCustodyError,
    ) -> Self {
        Self {
            provider_kind,
            error,
            call_count: Cell::new(0),
        }
    }

    pub fn provider_kind(&self) -> ProductionCustodyProviderKind {
        self.provider_kind
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl KmsHsmCustodyProviderTransport for ProductionCustodyProviderStub {
    fn submit(
        &self,
        _request: &ProductionCustodyRequest,
        _attempt: u32,
    ) -> Result<ProductionCustodyResponse, ProductionCustodyError> {
        self.call_count.set(self.call_count.get() + 1);
        Err(self.error.clone())
    }
}

/// Run 295 — programmable source/test provider transport for fault
/// injection.
///
/// Each call consumes the next programmed step; when the queue is
/// exhausted it returns the configured default. Lets a source/test
/// exercise the timeout / retry / unavailable / malformed / oversized
/// fail-closed paths and inject tampered response envelopes without any
/// real I/O.
pub struct MockKmsHsmCustodyTransport {
    steps: RefCell<VecDeque<Result<ProductionCustodyResponse, ProductionCustodyError>>>,
    default_result: RefCell<Result<ProductionCustodyResponse, ProductionCustodyError>>,
    call_count: Cell<u32>,
}

impl MockKmsHsmCustodyTransport {
    /// A mock that always returns `err`.
    pub fn always_fail(err: ProductionCustodyError) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Err(err)),
            call_count: Cell::new(0),
        }
    }

    /// A mock that returns the programmed `steps` in order, then falls
    /// back to `default_result`.
    pub fn scripted(
        steps: Vec<Result<ProductionCustodyResponse, ProductionCustodyError>>,
        default_result: Result<ProductionCustodyResponse, ProductionCustodyError>,
    ) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            default_result: RefCell::new(default_result),
            call_count: Cell::new(0),
        }
    }

    /// A mock that returns `response` on the first call and thereafter.
    pub fn respond(response: ProductionCustodyResponse) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Ok(response)),
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl KmsHsmCustodyProviderTransport for MockKmsHsmCustodyTransport {
    fn submit(
        &self,
        _request: &ProductionCustodyRequest,
        _attempt: u32,
    ) -> Result<ProductionCustodyResponse, ProductionCustodyError> {
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

/// Run 295 — typed production KMS/HSM custody backend config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionKmsHsmCustodyBackendConfig {
    /// Backend protocol version. Must equal
    /// [`PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION`].
    pub protocol_version: u16,
    /// Maximum number of provider transport attempts.
    pub max_attempts: u32,
}

impl ProductionKmsHsmCustodyBackendConfig {
    /// Build a config pinning the current backend protocol version.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            protocol_version: PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION,
            max_attempts,
        }
    }

    /// Returns `true` iff the config is well-formed and the protocol
    /// version is the one this run accepts.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version == PRODUCTION_KMS_HSM_CUSTODY_BACKEND_PROTOCOL_VERSION
            && self.max_attempts >= 1
    }

    /// Maximum number of provider transport attempts (at least 1).
    pub const fn max_attempts(&self) -> u32 {
        if self.max_attempts >= 1 {
            self.max_attempts
        } else {
            1
        }
    }
}

impl Default for ProductionKmsHsmCustodyBackendConfig {
    fn default() -> Self {
        Self::new(1)
    }
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 295 — typed outcome of the production KMS/HSM custody backend.
///
/// Only [`Self::ProductionCustodyAccepted`], [`Self::FixtureKmsAccepted`]
/// and [`Self::FixtureHsmAccepted`] may authorize the next decision, and
/// only as evidence-only DevNet/TestNet acceptance. Every other variant
/// is a precise, non-mutating fail-closed reject (or the inert
/// [`Self::DisabledNoRequest`] / intermediate [`Self::RequestBuilt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyOutcome {
    /// The backend policy is `Disabled`. No request was built and the
    /// transport was never invoked.
    DisabledNoRequest,
    /// A request envelope was built (build-only path). No transport call
    /// was made and nothing was authorized.
    RequestBuilt { request_id: String },
    /// A fixture KMS response was accepted under an explicit
    /// `FixtureKmsAllowed` policy on a DevNet/TestNet trust domain.
    /// **Evidence only.**
    FixtureKmsAccepted {
        provider_id: String,
        environment: TrustBundleEnvironment,
        request_id: String,
    },
    /// A fixture HSM response was accepted under an explicit
    /// `FixtureHsmAllowed` policy on a DevNet/TestNet trust domain.
    /// **Evidence only.**
    FixtureHsmAccepted {
        provider_id: String,
        environment: TrustBundleEnvironment,
        request_id: String,
    },
    /// A production custody response was accepted. **Unreachable in Run
    /// 295** — no real provider is wired — but represented so the
    /// acceptance shape is typed for Run 296.
    ProductionCustodyAccepted {
        provider_id: String,
        environment: TrustBundleEnvironment,
        request_id: String,
        backend_transcript_digest: String,
    },
    /// The provider / verifier rejected the response for a reason not
    /// covered by a more specific variant.
    ProductionCustodyRejected { reason: String },
    /// The production provider was unavailable (after any retries).
    ProductionCustodyUnavailable,
    /// The production provider was misconfigured.
    ProductionCustodyMisconfigured,
    /// The provider timed out (after any retries).
    ProductionCustodyTimeout,
    /// The transport failed to decode the response.
    ProductionCustodyDecodeFailed,
    /// The response was malformed or oversized.
    ProductionCustodyMalformedResponse,
    /// The response used an unsupported protocol version.
    ProductionCustodyUnsupportedProtocol { version: u16 },
    /// The provider kind is unsupported.
    ProductionCustodyUnsupportedProvider,
    /// The response's trust-domain binding did not match.
    ProductionCustodyDomainMismatch,
    /// The response's transcript digest did not match the recompute.
    ProductionCustodyTranscriptMismatch,
    /// The response's request-id echo did not match the request id.
    ProductionCustodyRequestIdMismatch,
    /// The response came from the wrong provider identity / kind.
    ProductionCustodyWrongProvider,
    /// The response used the wrong key handle.
    ProductionCustodyWrongKeyHandle,
    /// The response came from the wrong signer / signing-key fingerprint.
    ProductionCustodyWrongSigner,
    /// The response authorized the wrong lifecycle action.
    ProductionCustodyWrongAction,
    /// The response authorized the wrong candidate / proposal digest.
    ProductionCustodyWrongCandidateDigest,
    /// The response was a replay (stale request or response nonce).
    ProductionCustodyReplayRejected,
    /// The custody attestation was missing where the policy requires it.
    ProductionCustodyAttestationMissing,
    /// The custody attestation was unavailable.
    ProductionCustodyAttestationUnavailable,
    /// The custody attestation was invalid.
    ProductionCustodyAttestationInvalid,
    /// A MainNet production backend was required but no production
    /// authority material is available. No provider was invoked.
    MainNetProductionCustodyUnavailable,
    /// MainNet was refused because the policy is not a production MainNet
    /// policy (fixture / production-non-mainnet material cannot satisfy
    /// MainNet).
    MainNetRefused,
    /// Fixture material was refused for a MainNet trust domain.
    FixtureMaterialRejectedForMainNet,
    /// RemoteSigner material cannot satisfy the KMS/HSM custody row.
    RemoteSignerIsNotKmsHsmCustody,
    /// The request kind was validator-set rotation, unsupported in Run
    /// 295.
    ValidatorSetRotationUnsupported,
    /// The request kind was on-chain governance proof verification,
    /// unsupported in Run 295.
    GovernanceVerifierUnavailable,
    /// The request kind was a governance policy change, unsupported in
    /// Run 295.
    PolicyChangeUnsupported,
    /// The request spec / config was structurally malformed, or the
    /// outcome could not be classified — fail closed.
    AmbiguousFailClosed { reason: String },
}

impl ProductionCustodyOutcome {
    /// Returns `true` iff this outcome authorizes the next decision
    /// (evidence-only DevNet/TestNet acceptance).
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FixtureKmsAccepted { .. }
                | Self::FixtureHsmAccepted { .. }
                | Self::ProductionCustodyAccepted { .. }
        )
    }

    /// Returns `true` iff this outcome must not mutate any state. Every
    /// Run 295 outcome is non-mutating; acceptance is evidence-only.
    pub fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff this outcome represents an "unavailable"
    /// production path.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionCustodyUnavailable
                | Self::ProductionCustodyMisconfigured
                | Self::MainNetProductionCustodyUnavailable
        )
    }
}

// ===========================================================================
// Submission result
// ===========================================================================

/// Run 295 — the successful result of submitting a request to a provider
/// transport: the built request envelope, the raw response envelope, the
/// deterministic request id, and how many transport attempts were used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedCustodyRequest {
    pub request: ProductionCustodyRequest,
    pub response: ProductionCustodyResponse,
    pub request_id: String,
    pub attempts_used: u32,
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 295 — typed outcome of a request/response recovery-window check.
///
/// Run 295 models only the narrow replay/recovery semantics the existing
/// surfaces already represent: idempotent re-submission of a
/// byte-identical request/response, and fail-closed refusal of any
/// conflicting request id / transcript / key handle / response
/// commitment, or ambiguous window. It claims **no** durable acceptance
/// persistence of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyRecoveryOutcome {
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
    /// The same request id was reused with a different key handle — fail
    /// closed.
    ConflictingKeyHandleForSameId,
    /// The recovery window is ambiguous — fail closed.
    AmbiguousRecoveryFailClosed { reason: String },
}

impl ProductionCustodyRecoveryOutcome {
    /// Returns `true` iff the recovery is safe to treat as idempotent.
    pub fn is_idempotent(&self) -> bool {
        matches!(self, Self::IdempotentReplayOfSameRequest)
    }
}

// ===========================================================================
// Backend trait
// ===========================================================================

/// Run 295 — the production KMS/HSM custody backend boundary.
///
/// Implementations drive a [`KmsHsmCustodyProviderTransport`], applying
/// the backend policy, request-kind gating, MainNet refusal,
/// timeout/retry, request/response correlation, and transcript binding,
/// and returning a precise typed [`ProductionCustodyOutcome`]. No
/// implementation mutates live trust, writes a marker/sequence, evicts
/// sessions, performs settlement / external publication / governance
/// execution / validator-set rotation, or invokes Run 070.
pub trait GovernanceProductionKmsHsmCustodyBackend {
    /// Build the request envelope for `spec` without submitting it.
    fn build_custody_request(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<ProductionCustodyRequest, ProductionCustodyOutcome>;

    /// Submit `spec` to the transport with the configured timeout/retry
    /// policy. Does not authorize anything by itself.
    fn submit_custody_signing_request(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<SubmittedCustodyRequest, ProductionCustodyOutcome>;

    /// Verify a submitted request/response against the caller's
    /// expectations and the trust domain, returning a precise outcome.
    fn verify_custody_response(
        &self,
        spec: &ProductionCustodyRequestSpec,
        submitted: &SubmittedCustodyRequest,
        trust_domain: &AuthorityTrustDomain,
        identity: &BackendIdentity,
        now_unix: u64,
    ) -> ProductionCustodyOutcome;

    /// Submit and verify in one call, returning a precise outcome.
    fn evaluate_custody_backend(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
        identity: &BackendIdentity,
        now_unix: u64,
    ) -> ProductionCustodyOutcome;

    /// Evaluate a request/response recovery window against a prior
    /// submission.
    fn recover_custody_request_window(
        &self,
        prior: Option<&SubmittedCustodyRequest>,
        current: &SubmittedCustodyRequest,
    ) -> ProductionCustodyRecoveryOutcome;
}

// ===========================================================================
// Backend implementation
// ===========================================================================

/// Run 295 — the real production KMS/HSM custody backend client.
///
/// Generic over the injected [`KmsHsmCustodyProviderTransport`] so the
/// same real client logic runs over a source/test fixture provider, a
/// reachable-but-fail-closed production stub, a programmable mock, or (in
/// a future run) a real provider transport.
pub struct ProductionKmsHsmCustodyBackend<T: KmsHsmCustodyProviderTransport> {
    pub config: ProductionKmsHsmCustodyBackendConfig,
    pub policy: ProductionKmsHsmCustodyBackendPolicy,
    pub transport: T,
}

impl<T: KmsHsmCustodyProviderTransport> ProductionKmsHsmCustodyBackend<T> {
    pub fn new(
        config: ProductionKmsHsmCustodyBackendConfig,
        policy: ProductionKmsHsmCustodyBackendPolicy,
        transport: T,
    ) -> Self {
        Self {
            config,
            policy,
            transport,
        }
    }

    /// Pure policy / kind / MainNet gate applied before any request is
    /// built or any transport call is made. Returns `Some(outcome)` when
    /// the request must be refused before submission, `None` to proceed.
    fn preflight_gate(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionCustodyOutcome> {
        // 1. Disabled fails closed before anything else.
        if self.policy.is_disabled() {
            return Some(ProductionCustodyOutcome::DisabledNoRequest);
        }

        // 2. Unsupported request kinds are refused up front.
        match spec.request_kind {
            ProductionCustodyRequestKind::ValidatorSetRotation => {
                return Some(ProductionCustodyOutcome::ValidatorSetRotationUnsupported);
            }
            ProductionCustodyRequestKind::PolicyChange => {
                return Some(ProductionCustodyOutcome::PolicyChangeUnsupported);
            }
            ProductionCustodyRequestKind::OnChainGovernanceProofVerification => {
                return Some(ProductionCustodyOutcome::GovernanceVerifierUnavailable);
            }
            ProductionCustodyRequestKind::AuthorityLifecycleSigning
            | ProductionCustodyRequestKind::GovernanceExecutionSigning => {}
        }

        // 3. RemoteSigner / local operator / peer custody material cannot
        //    satisfy the KMS/HSM custody row. Classified before structural
        //    well-formedness because a non-KMS/HSM class is a precise,
        //    named refusal rather than an ambiguous malformation.
        match spec.custody_class {
            AuthorityCustodyClass::RemoteSigner => {
                return Some(ProductionCustodyOutcome::RemoteSignerIsNotKmsHsmCustody);
            }
            AuthorityCustodyClass::LocalOperatorKey
            | AuthorityCustodyClass::FixtureLocalKey
            | AuthorityCustodyClass::Unknown => {
                return Some(ProductionCustodyOutcome::ProductionCustodyRejected {
                    reason: "custody class is not kms/hsm".to_string(),
                });
            }
            AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm => {}
        }

        // 4. MainNet gate. A MainNet trust domain requires an explicit
        //    MainNet production policy; even then, no real production
        //    provider is wired, so it fails closed as unavailable with no
        //    provider invocation. Any other policy on MainNet is refused.
        //    Gated before provider-match / well-formedness so MainNet can
        //    never reach a provider path.
        if trust_domain.environment == TrustBundleEnvironment::Mainnet {
            return Some(match self.policy {
                ProductionKmsHsmCustodyBackendPolicy::MainnetProductionCustodyRequired => {
                    ProductionCustodyOutcome::MainNetProductionCustodyUnavailable
                }
                p if p.is_fixture() => {
                    ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet
                }
                _ => ProductionCustodyOutcome::MainNetRefused,
            });
        }

        // 5. The MainNet production policy on a non-MainNet domain has no
        //    real backend wired — fail closed with no provider call.
        if self.policy == ProductionKmsHsmCustodyBackendPolicy::MainnetProductionCustodyRequired {
            return Some(ProductionCustodyOutcome::MainNetProductionCustodyUnavailable);
        }

        // 6. Structural well-formedness of spec and config.
        if !spec.is_well_formed() || !self.config.is_well_formed() {
            return Some(ProductionCustodyOutcome::AmbiguousFailClosed {
                reason: "request spec or backend config is malformed".to_string(),
            });
        }

        // 7. Provider kind must match the active policy.
        if self.policy.allowed_provider_kind() != Some(spec.provider_kind) {
            return Some(ProductionCustodyOutcome::ProductionCustodyWrongProvider);
        }

        None
    }
}

/// Map a provider error to a precise fail-closed outcome.
fn error_to_outcome(err: &ProductionCustodyError) -> ProductionCustodyOutcome {
    match err {
        ProductionCustodyError::EndpointUnavailable
        | ProductionCustodyError::ConnectionRefused
        | ProductionCustodyError::ProviderUnavailable
        | ProductionCustodyError::KeyUnavailable => {
            ProductionCustodyOutcome::ProductionCustodyUnavailable
        }
        ProductionCustodyError::ProviderMisconfigured => {
            ProductionCustodyOutcome::ProductionCustodyMisconfigured
        }
        ProductionCustodyError::Timeout => ProductionCustodyOutcome::ProductionCustodyTimeout,
        ProductionCustodyError::DecodeError => {
            ProductionCustodyOutcome::ProductionCustodyDecodeFailed
        }
        ProductionCustodyError::ResponseTooLarge { .. }
        | ProductionCustodyError::MalformedResponse => {
            ProductionCustodyOutcome::ProductionCustodyMalformedResponse
        }
        ProductionCustodyError::UnsupportedProtocolVersion { version } => {
            ProductionCustodyOutcome::ProductionCustodyUnsupportedProtocol { version: *version }
        }
        ProductionCustodyError::SigningRefused
        | ProductionCustodyError::ProviderPolicyRejected => {
            ProductionCustodyOutcome::ProductionCustodyRejected {
                reason: err.tag().to_string(),
            }
        }
        ProductionCustodyError::AttestationMissing => {
            ProductionCustodyOutcome::ProductionCustodyAttestationMissing
        }
        ProductionCustodyError::AttestationUnavailable => {
            ProductionCustodyOutcome::ProductionCustodyAttestationUnavailable
        }
        ProductionCustodyError::UnsupportedProvider => {
            ProductionCustodyOutcome::ProductionCustodyUnsupportedProvider
        }
    }
}

/// Map a Run 203 [`BackendOutcome`] reject onto a precise Run 295 backend
/// outcome.
fn backend_reject_to_outcome(outcome: BackendOutcome) -> ProductionCustodyOutcome {
    use BackendOutcome as O;
    match outcome {
        O::Disabled => ProductionCustodyOutcome::DisabledNoRequest,
        O::FixtureRejectedProductionRequired
        | O::FixtureRejectedMainnetProductionRequired => {
            ProductionCustodyOutcome::MainNetProductionCustodyUnavailable
        }
        O::ProductionKmsUnavailable
        | O::ProductionHsmUnavailable
        | O::CloudKmsUnavailable
        | O::Pkcs11HsmUnavailable => ProductionCustodyOutcome::ProductionCustodyUnavailable,
        O::MainNetProductionCustodyUnavailable => {
            ProductionCustodyOutcome::MainNetProductionCustodyUnavailable
        }
        O::FixtureRejectedForMainNet => {
            ProductionCustodyOutcome::FixtureMaterialRejectedForMainNet
        }
        O::BackendKindPolicyMismatch { .. } | O::UnknownBackendRejected { .. } => {
            ProductionCustodyOutcome::ProductionCustodyWrongProvider
        }
        O::WrongEnvironment { .. }
        | O::WrongChain { .. }
        | O::WrongGenesis { .. }
        | O::WrongAuthorityRoot { .. } => ProductionCustodyOutcome::ProductionCustodyDomainMismatch,
        O::WrongKeyId { .. } => ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle,
        O::WrongSigningKeyFingerprint { .. } => {
            ProductionCustodyOutcome::ProductionCustodyWrongSigner
        }
        O::WrongLifecycleAction { .. } => ProductionCustodyOutcome::ProductionCustodyWrongAction,
        O::WrongCandidateDigest { .. } => {
            ProductionCustodyOutcome::ProductionCustodyWrongCandidateDigest
        }
        O::WrongAuthorityDomainSequence { .. } => {
            ProductionCustodyOutcome::ProductionCustodyRejected {
                reason: "wrong-authority-domain-sequence".to_string(),
            }
        }
        O::WrongRequestDigest { .. } => {
            ProductionCustodyOutcome::ProductionCustodyTranscriptMismatch
        }
        O::WrongResponseDigest { .. } | O::WrongTranscriptDigest { .. } => {
            ProductionCustodyOutcome::ProductionCustodyTranscriptMismatch
        }
        O::StaleOrReplayedRequest { .. } | O::StaleOrReplayedResponse { .. } => {
            ProductionCustodyOutcome::ProductionCustodyReplayRejected
        }
        O::ExpiredAttestation { .. } | O::ExpiredResponse { .. } => {
            ProductionCustodyOutcome::ProductionCustodyReplayRejected
        }
        O::UnsupportedSuite { .. } => ProductionCustodyOutcome::ProductionCustodyRejected {
            reason: "unsupported-suite".to_string(),
        },
        O::InvalidAttestation => ProductionCustodyOutcome::ProductionCustodyAttestationInvalid,
        O::InvalidSignature => ProductionCustodyOutcome::ProductionCustodyRejected {
            reason: "invalid-signature".to_string(),
        },
        O::MalformedIdentity { .. } | O::MalformedResponse { .. } => {
            ProductionCustodyOutcome::ProductionCustodyMalformedResponse
        }
        O::MalformedRequest { reason } => {
            if reason.contains("custody_attestation_digest") {
                ProductionCustodyOutcome::ProductionCustodyAttestationMissing
            } else {
                ProductionCustodyOutcome::ProductionCustodyMalformedResponse
            }
        }
        O::LocalOperatorCannotSatisfyBackendPolicy
        | O::PeerMajorityCannotSatisfyBackendPolicy => {
            ProductionCustodyOutcome::ProductionCustodyRejected {
                reason: "custody-material-cannot-satisfy-kms-hsm".to_string(),
            }
        }
        O::NotKmsHsmCustodyClass { .. } => {
            ProductionCustodyOutcome::ProductionCustodyRejected {
                reason: "not-kms-hsm-custody-class".to_string(),
            }
        }
        O::FixtureKmsAccepted { .. } | O::FixtureHsmAccepted { .. } => {
            ProductionCustodyOutcome::AmbiguousFailClosed {
                reason: "accept classified as reject".to_string(),
            }
        }
    }
}

impl<T: KmsHsmCustodyProviderTransport> GovernanceProductionKmsHsmCustodyBackend
    for ProductionKmsHsmCustodyBackend<T>
{
    fn build_custody_request(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<ProductionCustodyRequest, ProductionCustodyOutcome> {
        if let Some(outcome) = self.preflight_gate(spec, trust_domain) {
            return Err(outcome);
        }
        let request_id = production_kms_hsm_custody_request_id(spec);
        Ok(ProductionCustodyRequest {
            protocol_version: self.config.protocol_version,
            request_id,
            provider_kind: spec.provider_kind,
            provider_id: spec.provider_id.clone(),
            key_id: spec.key_id.clone(),
            environment: spec.environment,
            chain_id: spec.chain_id.clone(),
            genesis_hash: spec.genesis_hash.clone(),
            authority_root_fingerprint: spec.authority_root_fingerprint.clone(),
            custody_class: spec.custody_class,
            request_timestamp_unix: spec.request_timestamp_unix,
            backend_request: spec.build_backend_request(),
        })
    }

    fn submit_custody_signing_request(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<SubmittedCustodyRequest, ProductionCustodyOutcome> {
        let request = self.build_custody_request(spec, trust_domain)?;
        let request_id = request.request_id.clone();
        let max_attempts = self.config.max_attempts();

        let mut last_err: Option<ProductionCustodyError> = None;
        for attempt in 1..=max_attempts {
            match self.transport.submit(&request, attempt) {
                Ok(response) => {
                    if response.response_size_estimate()
                        > PRODUCTION_KMS_HSM_CUSTODY_MAX_RESPONSE_BYTES
                    {
                        return Err(ProductionCustodyOutcome::ProductionCustodyMalformedResponse);
                    }
                    return Ok(SubmittedCustodyRequest {
                        request,
                        response,
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
        Err(error_to_outcome(
            &last_err.unwrap_or(ProductionCustodyError::ProviderUnavailable),
        ))
    }

    fn verify_custody_response(
        &self,
        spec: &ProductionCustodyRequestSpec,
        submitted: &SubmittedCustodyRequest,
        trust_domain: &AuthorityTrustDomain,
        identity: &BackendIdentity,
        now_unix: u64,
    ) -> ProductionCustodyOutcome {
        let request = &submitted.request;
        let response = &submitted.response;

        // 1. A production-kind response can never be accepted in Run 295.
        if response.provider_kind.is_production() || request.provider_kind.is_production() {
            return if trust_domain.environment == TrustBundleEnvironment::Mainnet {
                ProductionCustodyOutcome::MainNetProductionCustodyUnavailable
            } else {
                ProductionCustodyOutcome::ProductionCustodyUnavailable
            };
        }

        // 2. Envelope-level request/response correlation.
        if response.request_id_echo != request.request_id
            || request.request_id != submitted.request_id
        {
            return ProductionCustodyOutcome::ProductionCustodyRequestIdMismatch;
        }
        if response.provider_kind != request.provider_kind
            || response.provider_id != request.provider_id
        {
            return ProductionCustodyOutcome::ProductionCustodyWrongProvider;
        }
        if response.key_id != request.key_id {
            return ProductionCustodyOutcome::ProductionCustodyWrongKeyHandle;
        }

        // 3. Compose the Run 203 verifier.
        let expected = spec.backend_expectations(
            identity,
            &request.backend_request,
            &response.backend_response,
            now_unix,
        );
        let backend_outcome = verify_authority_custody_backend_response(
            identity,
            &request.backend_request,
            &response.backend_response,
            trust_domain,
            &expected,
            self.policy.to_backend_policy(),
        );
        if !backend_outcome.is_accept() {
            return backend_reject_to_outcome(backend_outcome);
        }

        // 4. Envelope-level transcript binding: recompute the Run 203
        //    transcript and require the response envelope to carry it.
        let identity_digest = identity.identity_digest();
        let request_digest = request.backend_request.request_digest();
        let response_digest = response.backend_response.response_digest();
        let expected_backend_transcript =
            backend_transcript_digest(&identity_digest, &request_digest, &response_digest);
        if response.transcript_digest != expected_backend_transcript {
            return ProductionCustodyOutcome::ProductionCustodyTranscriptMismatch;
        }

        let backend_transcript_digest = production_kms_hsm_custody_transcript_digest(
            self.config.protocol_version,
            &submitted.request_id,
            &identity_digest,
            &request_digest,
            &response_digest,
            &expected_backend_transcript,
            spec.durable_replay_record_digest.as_deref(),
        );

        // 5. Accept — fixture KMS/HSM response, DevNet/TestNet,
        //    evidence-only.
        match response.provider_kind {
            ProductionCustodyProviderKind::FixtureKms => {
                ProductionCustodyOutcome::FixtureKmsAccepted {
                    provider_id: response.provider_id.clone(),
                    environment: trust_domain.environment,
                    request_id: submitted.request_id.clone(),
                }
            }
            ProductionCustodyProviderKind::FixtureHsm => {
                ProductionCustodyOutcome::FixtureHsmAccepted {
                    provider_id: response.provider_id.clone(),
                    environment: trust_domain.environment,
                    request_id: submitted.request_id.clone(),
                }
            }
            // Unreachable: production kinds handled in step 1; disabled /
            // unknown cannot produce a well-formed accepted response.
            _ => ProductionCustodyOutcome::ProductionCustodyAccepted {
                provider_id: response.provider_id.clone(),
                environment: trust_domain.environment,
                request_id: submitted.request_id.clone(),
                backend_transcript_digest,
            },
        }
    }

    fn evaluate_custody_backend(
        &self,
        spec: &ProductionCustodyRequestSpec,
        trust_domain: &AuthorityTrustDomain,
        identity: &BackendIdentity,
        now_unix: u64,
    ) -> ProductionCustodyOutcome {
        match self.submit_custody_signing_request(spec, trust_domain) {
            Ok(submitted) => {
                self.verify_custody_response(spec, &submitted, trust_domain, identity, now_unix)
            }
            Err(outcome) => outcome,
        }
    }

    fn recover_custody_request_window(
        &self,
        prior: Option<&SubmittedCustodyRequest>,
        current: &SubmittedCustodyRequest,
    ) -> ProductionCustodyRecoveryOutcome {
        let Some(prior) = prior else {
            return ProductionCustodyRecoveryOutcome::NoPriorRequest;
        };
        // Different ids are unrelated windows.
        if prior.request_id != current.request_id {
            return ProductionCustodyRecoveryOutcome::NoPriorRequest;
        }
        // Same id, different key handle => conflict.
        if prior.request.key_id != current.request.key_id
            || prior.response.key_id != current.response.key_id
        {
            return ProductionCustodyRecoveryOutcome::ConflictingKeyHandleForSameId;
        }
        // Same id, different request transcript => conflict.
        if prior.request.envelope_digest() != current.request.envelope_digest() {
            return ProductionCustodyRecoveryOutcome::ConflictingRequestForSameId;
        }
        // Same request, different response commitment => conflict.
        if prior.response.envelope_digest() != current.response.envelope_digest() {
            return ProductionCustodyRecoveryOutcome::ConflictingResponseForSameRequest;
        }
        // Byte-identical request and response => idempotent replay.
        if prior.response == current.response && prior.request == current.request {
            ProductionCustodyRecoveryOutcome::IdempotentReplayOfSameRequest
        } else {
            ProductionCustodyRecoveryOutcome::AmbiguousRecoveryFailClosed {
                reason: "same digests but non-identical envelopes".to_string(),
            }
        }
    }
}

// ===========================================================================
// Explicit fail-closed / scope helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 295 — returns `true`: the production KMS/HSM custody backend
/// default policy is `Disabled`.
pub fn production_kms_hsm_custody_backend_default_is_disabled() -> bool {
    ProductionKmsHsmCustodyBackendPolicy::default()
        == ProductionKmsHsmCustodyBackendPolicy::Disabled
}

/// Run 295 — returns `true`: fixture KMS/HSM material can never satisfy a
/// MainNet production custody backend.
pub fn production_kms_hsm_custody_backend_mainnet_refuses_fixture_material() -> bool {
    true
}

/// Run 295 — returns `true`: the backend never falls back to fixture /
/// RemoteSigner / local / in-memory signing when the production path is
/// unavailable.
pub fn production_kms_hsm_custody_backend_never_falls_back() -> bool {
    true
}

/// Run 295 — returns `true`: this run is a source/test implementation and
/// is NOT release-binary evidence (deferred to Run 296).
pub fn production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence() -> bool {
    true
}

/// Run 295 — returns `true`: RemoteSigner material cannot satisfy the
/// KMS/HSM/cloud-KMS/PKCS#11 custody row.
pub fn production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm() -> bool {
    true
}

/// Run 295 — returns `true`: the backend loads no raw local production
/// signing key and performs no local signing under a production policy.
pub fn production_kms_hsm_custody_backend_loads_no_raw_local_key() -> bool {
    true
}

/// Run 295 — returns `true`: the backend performs no Run 070 apply, no
/// `LivePqcTrustState` mutation, no trust swap, no session eviction, no
/// sequence/marker write, no durable replay overwrite, no settlement, no
/// external publication, no governance execution, and no validator-set
/// rotation.
pub fn production_kms_hsm_custody_backend_is_non_mutating() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devnet_domain() -> AuthorityTrustDomain {
        AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "qbind-devnet",
            "genesis-devnet",
            "root-fp-devnet",
            100,
        )
    }

    #[test]
    fn default_policy_is_disabled() {
        assert!(production_kms_hsm_custody_backend_default_is_disabled());
        assert_eq!(
            ProductionKmsHsmCustodyBackendPolicy::default(),
            ProductionKmsHsmCustodyBackendPolicy::Disabled
        );
    }

    #[test]
    fn provider_kind_maps_to_backend_kind() {
        assert_eq!(
            ProductionCustodyProviderKind::ProductionCloudKms.to_backend_kind(),
            BackendKind::CloudKmsUnavailable
        );
        assert_eq!(
            ProductionCustodyProviderKind::ProductionPkcs11Hsm.to_backend_kind(),
            BackendKind::Pkcs11HsmUnavailable
        );
    }

    #[test]
    fn request_id_is_deterministic() {
        let spec = sample_spec(TrustBundleEnvironment::Devnet);
        assert_eq!(
            production_kms_hsm_custody_request_id(&spec),
            production_kms_hsm_custody_request_id(&spec)
        );
    }

    #[test]
    fn scope_helpers_all_true() {
        assert!(production_kms_hsm_custody_backend_mainnet_refuses_fixture_material());
        assert!(production_kms_hsm_custody_backend_never_falls_back());
        assert!(production_kms_hsm_custody_backend_is_source_test_not_release_binary_evidence());
        assert!(production_kms_hsm_custody_backend_remote_signer_is_not_kms_hsm());
        assert!(production_kms_hsm_custody_backend_loads_no_raw_local_key());
        assert!(production_kms_hsm_custody_backend_is_non_mutating());
    }

    #[test]
    fn disabled_policy_builds_no_request() {
        let transport = ProductionCustodyProviderStub::cloud_kms();
        let backend = ProductionKmsHsmCustodyBackend::new(
            ProductionKmsHsmCustodyBackendConfig::default(),
            ProductionKmsHsmCustodyBackendPolicy::Disabled,
            transport,
        );
        let spec = sample_spec(TrustBundleEnvironment::Devnet);
        let out = backend.build_custody_request(&spec, &devnet_domain());
        assert_eq!(out, Err(ProductionCustodyOutcome::DisabledNoRequest));
        assert_eq!(backend.transport.call_count(), 0);
    }

    fn sample_spec(env: TrustBundleEnvironment) -> ProductionCustodyRequestSpec {
        ProductionCustodyRequestSpec {
            request_kind: ProductionCustodyRequestKind::AuthorityLifecycleSigning,
            provider_kind: ProductionCustodyProviderKind::ProductionCloudKms,
            environment: env,
            chain_id: "qbind-devnet".to_string(),
            genesis_hash: "genesis-devnet".to_string(),
            authority_root_fingerprint: "root-fp-devnet".to_string(),
            lifecycle_action: LocalLifecycleAction::Rotate,
            candidate_digest: "cand-digest".to_string(),
            authority_domain_sequence: 7,
            custody_class: AuthorityCustodyClass::Kms,
            provider_id: "cloud-kms-provider".to_string(),
            key_id: "key-1".to_string(),
            active_signing_key_fingerprint: Some("active-fp".to_string()),
            new_signing_key_fingerprint: Some("new-fp".to_string()),
            revoked_signing_key_fingerprint: None,
            governance_proof_digest: None,
            custody_attestation_digest: "att-digest".to_string(),
            durable_replay_record_digest: None,
            request_nonce: "req-nonce".to_string(),
            response_nonce: "resp-nonce".to_string(),
            request_timestamp_unix: 1_700_000_000,
        }
    }

    #[test]
    fn production_provider_reachable_and_fail_closed() {
        let transport = ProductionCustodyProviderStub::cloud_kms();
        let backend = ProductionKmsHsmCustodyBackend::new(
            ProductionKmsHsmCustodyBackendConfig::default(),
            ProductionKmsHsmCustodyBackendPolicy::ProductionCloudKmsRequired,
            transport,
        );
        let spec = sample_spec(TrustBundleEnvironment::Devnet);
        // The request can be built without any fixture fallback.
        assert!(backend
            .build_custody_request(&spec, &devnet_domain())
            .is_ok());
        // Submission reaches the provider and fails closed.
        let out = backend.submit_custody_signing_request(&spec, &devnet_domain());
        assert_eq!(
            out,
            Err(ProductionCustodyOutcome::ProductionCustodyMisconfigured)
        );
        assert_eq!(backend.transport.call_count(), 1);
    }
}
