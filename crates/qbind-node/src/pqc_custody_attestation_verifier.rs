//! Run 205 — source/test production custody attestation verifier
//! skeleton.
//!
//! Source/test only. Run 205 does **not** implement a real cloud-KMS
//! attestation verifier, a real PKCS#11 attestation verifier, a real HSM
//! vendor attestation verifier, or a real RemoteSigner attestation
//! verifier; nor does it enable MainNet peer-driven apply, real on-chain
//! governance proof verification, governance execution, or validator-set
//! rotation.
//!
//! Before Run 205 a production custody attestation was only a placeholder
//! digest / commitment carried inside the Run 188 custody attestation
//! ([`crate::pqc_authority_custody::AuthorityCustodyAttestation::custody_attestation_digest`])
//! or the Run 203 backend identity / response attestation digest. There
//! was **no typed verifier skeleton** for validating a production custody
//! attestation *chain*: its attestation class, evidence binding,
//! freshness, replay protection, provider identity, or device / module
//! identity. Run 205 closes that gap at the source/test level by adding:
//!
//! * A typed [`CustodyAttestationClass`] (`Disabled`,
//!   `FixtureAttestation`, `RemoteSignerAttestation`, `KmsAttestation`,
//!   `HsmAttestation`, `CloudKmsAttestationUnavailable`,
//!   `Pkcs11HsmAttestationUnavailable`, `ProductionAttestationUnavailable`,
//!   `Unknown`) and a typed [`CustodyAttestationPolicy`] (`Disabled`
//!   default, `FixtureAttestationAllowed`, `RemoteSignerAttestationRequired`,
//!   `KmsAttestationRequired`, `HsmAttestationRequired`,
//!   `ProductionAttestationRequired`, `MainnetProductionAttestationRequired`).
//! * A typed [`CustodyAttestationEvidence`] binding the full
//!   trust-domain + custody + lifecycle tuple plus attestation nonce,
//!   issuance timestamp, freshness/expiry window, and a placeholder
//!   evidence / certificate commitment.
//! * A typed [`CustodyAttestationInput`] carrying the caller-supplied
//!   expectations and the freshness/replay window.
//! * Deterministic, domain-separated digest helpers
//!   ([`CustodyAttestationEvidence::evidence_digest`],
//!   [`CustodyAttestationInput::input_digest`],
//!   [`attestation_transcript_digest`], and
//!   [`CustodyAttestationEvidence::provider_identity_digest`]).
//! * A pure / mockable [`CustodyAttestationVerifier`] trait with a
//!   [`CustodyAttestationVerifier::verify_custody_attestation`] method, a
//!   DevNet/TestNet source/test-only [`FixtureCustodyAttestationVerifier`],
//!   and production / cloud / PKCS#11 verifiers that are callable but fail
//!   closed as unavailable.
//! * A pure typed verifier [`verify_custody_attestation`] and a typed
//!   [`CustodyAttestationOutcome`] distinguishing every accept/reject
//!   case the task enumerates.
//! * Composition helpers
//!   ([`validate_custody_metadata_and_attestation`],
//!   [`validate_lifecycle_custody_and_attestation`]) that layer the
//!   attestation boundary on top of the Run 188 custody metadata
//!   validator while preserving the MainNet peer-driven-apply refusal.
//!
//! The RemoteSigner path (Runs 194–202) and the KMS/HSM backend path
//! (Runs 203–204) remain **separate** custody options; Run 205 binds
//! their transcripts only as opaque evidence fields and changes neither.
//!
//! Release-binary custody-attestation verifier-boundary evidence is
//! **deferred to Run 206**. Governance execution remains unimplemented,
//! real on-chain proof verification remains unimplemented, validator-set
//! rotation remains open, full C4 remains open, and C5 remains open.
//!
//! The module is pure: every public function and trait method performs
//! no network or file I/O, writes no marker, writes no sequence, mutates
//! no live trust, evicts no sessions, and never invokes Run 070 apply.

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
// Domain tags / sentinels / versioning
// ===========================================================================

/// Run 205 — attestation-evidence digest domain tag.
pub const CUSTODY_ATTESTATION_EVIDENCE_DOMAIN_TAG: &str =
    "QBIND:run205-custody-attestation-evidence:v1";

/// Run 205 — attestation-input digest domain tag.
pub const CUSTODY_ATTESTATION_INPUT_DOMAIN_TAG: &str = "QBIND:run205-custody-attestation-input:v1";

/// Run 205 — attestation transcript digest domain tag.
pub const CUSTODY_ATTESTATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run205-custody-attestation-transcript:v1";

/// Run 205 — provider-identity digest domain tag.
pub const CUSTODY_ATTESTATION_PROVIDER_IDENTITY_DOMAIN_TAG: &str =
    "QBIND:run205-custody-attestation-provider-identity:v1";

/// Run 205 — explicit invalid attestation-commitment sentinel for
/// source/test rejection vectors. Evidence carrying this commitment is
/// rejected as [`CustodyAttestationOutcome::InvalidAttestationCommitment`].
pub const CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL: &str =
    "INVALID-CUSTODY-ATTESTATION-COMMITMENT";

/// Run 205 — the only attestation-evidence schema version this skeleton
/// supports. Evidence carrying any other version is rejected as
/// [`CustodyAttestationOutcome::UnsupportedAttestationVersion`].
pub const CUSTODY_ATTESTATION_SUPPORTED_VERSION: u16 = 1;

// ===========================================================================
// Attestation class
// ===========================================================================

/// Run 205 — typed custody attestation class.
///
/// `Disabled` is the inert default. `FixtureAttestation` is a
/// DevNet/TestNet source/test-only attestation. `RemoteSignerAttestation`,
/// `KmsAttestation`, `HsmAttestation`, `CloudKmsAttestationUnavailable`,
/// `Pkcs11HsmAttestationUnavailable`, and `ProductionAttestationUnavailable`
/// are production-class attestations that are callable but fail closed as
/// unavailable because Run 205 wires no real attestation verifier.
/// `Unknown` is always fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CustodyAttestationClass {
    /// Inert default. No attestation is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture attestation.
    FixtureAttestation,
    /// RemoteSigner production attestation. Callable, fails closed.
    RemoteSignerAttestation,
    /// KMS production attestation. Callable, fails closed.
    KmsAttestation,
    /// HSM production attestation. Callable, fails closed.
    HsmAttestation,
    /// Cloud-KMS production attestation. Callable, fails closed.
    CloudKmsAttestationUnavailable,
    /// PKCS#11 HSM production attestation. Callable, fails closed.
    Pkcs11HsmAttestationUnavailable,
    /// Generic production attestation. Callable, fails closed.
    ProductionAttestationUnavailable,
    /// Unknown / unsupported attestation class. Always fail-closed.
    Unknown,
}

impl CustodyAttestationClass {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAttestation => "fixture-attestation",
            Self::RemoteSignerAttestation => "remote-signer-attestation",
            Self::KmsAttestation => "kms-attestation",
            Self::HsmAttestation => "hsm-attestation",
            Self::CloudKmsAttestationUnavailable => "cloud-kms-attestation-unavailable",
            Self::Pkcs11HsmAttestationUnavailable => "pkcs11-hsm-attestation-unavailable",
            Self::ProductionAttestationUnavailable => "production-attestation-unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this class is the DevNet/TestNet source/test
    /// fixture attestation.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureAttestation)
    }

    /// Returns `true` iff this class is a production-class attestation
    /// that Run 205 fails closed as unavailable.
    pub const fn is_production_unavailable(self) -> bool {
        matches!(
            self,
            Self::RemoteSignerAttestation
                | Self::KmsAttestation
                | Self::HsmAttestation
                | Self::CloudKmsAttestationUnavailable
                | Self::Pkcs11HsmAttestationUnavailable
                | Self::ProductionAttestationUnavailable
        )
    }
}

// ===========================================================================
// Attestation policy
// ===========================================================================

/// Run 205 — typed custody attestation policy.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// attestation regardless of contents, preserving the Run 050–204
/// conservative defaults. `FixtureAttestationAllowed` is a DevNet/TestNet
/// source/test-only policy that accepts a fixture attestation.
/// `RemoteSignerAttestationRequired`, `KmsAttestationRequired`,
/// `HsmAttestationRequired`, `ProductionAttestationRequired`, and
/// `MainnetProductionAttestationRequired` REQUIRE a real production
/// attestation verifier — and Run 205 has none, so they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CustodyAttestationPolicy {
    /// Default. Refuses every attestation.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture-attestation policy.
    FixtureAttestationAllowed,
    /// RemoteSigner production attestation required. Run 205 fails closed
    /// because no real verifier exists.
    RemoteSignerAttestationRequired,
    /// KMS production attestation required. Run 205 fails closed.
    KmsAttestationRequired,
    /// HSM production attestation required. Run 205 fails closed.
    HsmAttestationRequired,
    /// Generic production attestation required. Run 205 fails closed.
    ProductionAttestationRequired,
    /// MainNet production attestation required. Run 205 fails closed for
    /// every attestation — fixture material is rejected as non-production
    /// and every production attestation is rejected as unavailable.
    MainnetProductionAttestationRequired,
}

impl CustodyAttestationPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureAttestationAllowed => "fixture-attestation-allowed",
            Self::RemoteSignerAttestationRequired => "remote-signer-attestation-required",
            Self::KmsAttestationRequired => "kms-attestation-required",
            Self::HsmAttestationRequired => "hsm-attestation-required",
            Self::ProductionAttestationRequired => "production-attestation-required",
            Self::MainnetProductionAttestationRequired => {
                "mainnet-production-attestation-required"
            }
        }
    }

    /// Returns `true` iff this policy requires a real production
    /// attestation verifier (and therefore Run 205 fails closed).
    pub const fn requires_production_attestation(self) -> bool {
        matches!(
            self,
            Self::RemoteSignerAttestationRequired
                | Self::KmsAttestationRequired
                | Self::HsmAttestationRequired
                | Self::ProductionAttestationRequired
                | Self::MainnetProductionAttestationRequired
        )
    }

    /// Returns the fixture attestation class this policy accepts, or
    /// `None` for the disabled / production-required policies.
    pub const fn allowed_fixture_class(self) -> Option<CustodyAttestationClass> {
        match self {
            Self::FixtureAttestationAllowed => Some(CustodyAttestationClass::FixtureAttestation),
            _ => None,
        }
    }
}

// ===========================================================================
// Attestation evidence
// ===========================================================================

/// Run 205 — typed production custody attestation evidence.
///
/// Pure data describing a single custody attestation: which class /
/// backend produced it, the trust domain and authority it is bound to,
/// the lifecycle transition it authorizes, optional bound RemoteSigner
/// (Run 201) / KMS-HSM (Run 203) request/response/transcript digests,
/// anti-replay material, an issuance timestamp, a freshness/expiry
/// window, and a placeholder evidence / certificate commitment.
///
/// `attestation_commitment` is the placeholder a future production
/// verifier will replace with a real attestation signature / quote /
/// certificate chain. Run 205 only enforces presence, non-emptiness, and
/// the explicit invalid sentinel; it does not interpret the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyAttestationEvidence {
    /// Attestation class declared by this evidence.
    pub attestation_class: CustodyAttestationClass,
    /// Attestation-evidence schema version.
    pub attestation_version: u16,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound bundle-signing key fingerprint.
    pub bundle_signing_key_fingerprint: String,
    /// Bound Run 188 custody class.
    pub custody_class: AuthorityCustodyClass,
    /// Custody backend kind tag where applicable (e.g. the Run 203
    /// `BackendKind` tag or the Run 201 transport tag). Optional.
    pub custody_backend_kind: Option<String>,
    /// Backend id / provider id / signer id presenting this attestation.
    pub backend_provider_signer_id: String,
    /// Custody key id / key label.
    pub custody_key_id: String,
    /// Suite id (placeholder; only the Run 159 PQC signing suite is
    /// currently accepted).
    pub suite_id: u8,
    /// Bound lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Bound candidate digest (next persistent authority record digest).
    pub candidate_digest: String,
    /// Bound authority-domain sequence (next sequence number).
    pub authority_domain_sequence: u64,
    /// Bound governance proof digest, where applicable.
    pub governance_proof_digest: Option<String>,
    /// Bound Run 201 / Run 203 request digest, where applicable.
    pub request_digest: Option<String>,
    /// Bound Run 201 / Run 203 response digest, where applicable.
    pub response_digest: Option<String>,
    /// Bound Run 201 / Run 203 transcript digest, where applicable.
    pub transcript_digest: Option<String>,
    /// Per-attestation anti-replay nonce. Must be non-empty.
    pub attestation_nonce: String,
    /// Optional issuance timestamp / epoch (UNIX seconds).
    pub issued_at_unix: Option<u64>,
    /// Optional freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
    /// Placeholder evidence / certificate commitment. Must be non-empty
    /// and must not be the explicit invalid sentinel.
    pub attestation_commitment: String,
}

impl CustodyAttestationEvidence {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.bundle_signing_key_fingerprint.is_empty()
            && !self.backend_provider_signer_id.is_empty()
            && !self.custody_key_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.attestation_nonce.is_empty()
            && !self.attestation_commitment.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every evidence field. The
    /// digest is domain-separated so it can never collide with any other
    /// QBIND canonical digest.
    pub fn evidence_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(CUSTODY_ATTESTATION_EVIDENCE_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"attestation_class", self.attestation_class.tag().as_bytes());
        field(
            b"attestation_version",
            &self.attestation_version.to_le_bytes(),
        );
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(
            b"bundle_signing_key_fingerprint",
            self.bundle_signing_key_fingerprint.as_bytes(),
        );
        field(b"custody_class", self.custody_class.tag().as_bytes());
        field(
            b"custody_backend_kind",
            self.custody_backend_kind.as_deref().unwrap_or("").as_bytes(),
        );
        field(
            b"custody_backend_kind_present",
            &[self.custody_backend_kind.is_some() as u8],
        );
        field(
            b"backend_provider_signer_id",
            self.backend_provider_signer_id.as_bytes(),
        );
        field(b"custody_key_id", self.custody_key_id.as_bytes());
        field(b"suite_id", &[self.suite_id]);
        field(b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        field(b"candidate_digest", self.candidate_digest.as_bytes());
        field(
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        field(
            b"governance_proof_digest",
            self.governance_proof_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"request_digest",
            self.request_digest.as_deref().unwrap_or("").as_bytes(),
        );
        field(
            b"response_digest",
            self.response_digest.as_deref().unwrap_or("").as_bytes(),
        );
        field(
            b"transcript_digest",
            self.transcript_digest.as_deref().unwrap_or("").as_bytes(),
        );
        field(b"attestation_nonce", self.attestation_nonce.as_bytes());
        field(
            b"issued_at_unix",
            &self.issued_at_unix.unwrap_or(0).to_le_bytes(),
        );
        field(b"issued_present", &[self.issued_at_unix.is_some() as u8]);
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
        field(
            b"attestation_commitment",
            self.attestation_commitment.as_bytes(),
        );
        hex::encode(h.finalize())
    }

    /// Deterministic SHA3-256 hex digest over the *provider identity*
    /// projection of this evidence: the attestation class, backend kind,
    /// backend/provider/signer id, custody key id, and suite. Lets a
    /// calling surface log "which provider/device presented attestation"
    /// without leaking the full evidence.
    pub fn provider_identity_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(CUSTODY_ATTESTATION_PROVIDER_IDENTITY_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"attestation_class", self.attestation_class.tag().as_bytes());
        field(
            b"custody_backend_kind",
            self.custody_backend_kind.as_deref().unwrap_or("").as_bytes(),
        );
        field(
            b"backend_provider_signer_id",
            self.backend_provider_signer_id.as_bytes(),
        );
        field(b"custody_class", self.custody_class.tag().as_bytes());
        field(b"custody_key_id", self.custody_key_id.as_bytes());
        field(b"suite_id", &[self.suite_id]);
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Attestation verifier input / expectations
// ===========================================================================

/// Run 205 — caller-supplied verifier input / binding expectations for
/// [`verify_custody_attestation`].
///
/// Pure data, typically derived from the persisted candidate metadata
/// and the per-attempt anti-replay material the calling surface
/// generated for this attestation round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyAttestationInput {
    pub expected_environment: TrustBundleEnvironment,
    pub expected_chain_id: String,
    pub expected_genesis_hash: String,
    pub expected_authority_root_fingerprint: String,
    pub expected_bundle_signing_key_fingerprint: String,
    pub expected_custody_class: AuthorityCustodyClass,
    pub expected_backend_provider_signer_id: String,
    pub expected_custody_key_id: String,
    pub expected_suite_id: u8,
    pub expected_lifecycle_action: LocalLifecycleAction,
    pub expected_candidate_digest: String,
    pub expected_authority_domain_sequence: u64,
    pub expected_governance_proof_digest: Option<String>,
    pub expected_request_digest: Option<String>,
    pub expected_response_digest: Option<String>,
    pub expected_transcript_digest: Option<String>,
    pub expected_attestation_nonce: String,
    /// Lower bound of the accepted freshness/replay window (UNIX
    /// seconds). When both this and [`Self::replay_window_until_unix`]
    /// are present, the attestation nonce must be fresh and the issuance
    /// timestamp must fall inside `[since, until)`.
    pub replay_window_since_unix: Option<u64>,
    /// Upper bound (exclusive) of the accepted freshness/replay window.
    pub replay_window_until_unix: Option<u64>,
    /// Current timestamp / logical epoch (UNIX seconds).
    pub now_unix: u64,
}

impl CustodyAttestationInput {
    /// Deterministic SHA3-256 hex digest over every input field.
    pub fn input_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(CUSTODY_ATTESTATION_INPUT_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(
            b"expected_environment",
            &self.expected_environment.metric_code().to_le_bytes(),
        );
        field(b"expected_chain_id", self.expected_chain_id.as_bytes());
        field(b"expected_genesis_hash", self.expected_genesis_hash.as_bytes());
        field(
            b"expected_authority_root_fingerprint",
            self.expected_authority_root_fingerprint.as_bytes(),
        );
        field(
            b"expected_bundle_signing_key_fingerprint",
            self.expected_bundle_signing_key_fingerprint.as_bytes(),
        );
        field(
            b"expected_custody_class",
            self.expected_custody_class.tag().as_bytes(),
        );
        field(
            b"expected_backend_provider_signer_id",
            self.expected_backend_provider_signer_id.as_bytes(),
        );
        field(
            b"expected_custody_key_id",
            self.expected_custody_key_id.as_bytes(),
        );
        field(b"expected_suite_id", &[self.expected_suite_id]);
        field(
            b"expected_lifecycle_action",
            self.expected_lifecycle_action.tag().as_bytes(),
        );
        field(
            b"expected_candidate_digest",
            self.expected_candidate_digest.as_bytes(),
        );
        field(
            b"expected_authority_domain_sequence",
            &self.expected_authority_domain_sequence.to_le_bytes(),
        );
        field(
            b"expected_governance_proof_digest",
            self.expected_governance_proof_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"expected_request_digest",
            self.expected_request_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"expected_response_digest",
            self.expected_response_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"expected_transcript_digest",
            self.expected_transcript_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"expected_attestation_nonce",
            self.expected_attestation_nonce.as_bytes(),
        );
        field(
            b"replay_window_since_unix",
            &self.replay_window_since_unix.unwrap_or(0).to_le_bytes(),
        );
        field(
            b"replay_window_since_present",
            &[self.replay_window_since_unix.is_some() as u8],
        );
        field(
            b"replay_window_until_unix",
            &self.replay_window_until_unix.unwrap_or(0).to_le_bytes(),
        );
        field(
            b"replay_window_until_present",
            &[self.replay_window_until_unix.is_some() as u8],
        );
        field(b"now_unix", &self.now_unix.to_le_bytes());
        hex::encode(h.finalize())
    }
}

/// Run 205 — deterministic, domain-separated attestation transcript
/// digest. Binds the evidence digest and the input digest into a single
/// commitment that the calling surface can log and a future production
/// verifier can sign over.
pub fn attestation_transcript_digest(evidence_digest: &str, input_digest: &str) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(CUSTODY_ATTESTATION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"evidence_digest", evidence_digest.as_bytes());
    field(b"input_digest", input_digest.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 205 — typed outcome of the custody attestation verifier boundary.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching the
/// inner evidence. Acceptance is **always** of a fixture attestation
/// under the explicit `FixtureAttestationAllowed` policy on a
/// DevNet/TestNet trust domain — production attestations are refused as
/// unavailable regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationOutcome {
    /// DevNet/TestNet fixture attestation accepted under the explicit
    /// `FixtureAttestationAllowed` policy. Acceptance is evidence-only.
    FixtureAttestationAccepted {
        backend_provider_signer_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy is `Disabled`. Every attestation fails closed.
    AttestationDisabled,
    /// Fixture attestation rejected because the active policy is
    /// `ProductionAttestationRequired` (or another production-required
    /// policy other than MainNet).
    FixtureRejectedProductionRequired,
    /// Fixture attestation rejected because the active policy is
    /// `MainnetProductionAttestationRequired`.
    FixtureRejectedMainnetProductionRequired,
    /// RemoteSigner attestation unavailable. Run 205 has no real verifier.
    RemoteSignerAttestationUnavailable,
    /// KMS attestation unavailable. Run 205 has no real verifier.
    KmsAttestationUnavailable,
    /// HSM attestation unavailable. Run 205 has no real verifier.
    HsmAttestationUnavailable,
    /// Cloud-KMS attestation unavailable. Run 205 wires no cloud-KMS
    /// attestation verifier.
    CloudKmsAttestationUnavailable,
    /// PKCS#11 HSM attestation unavailable. Run 205 wires no PKCS#11
    /// attestation verifier.
    Pkcs11HsmAttestationUnavailable,
    /// Generic production attestation unavailable.
    ProductionAttestationUnavailable,
    /// MainNet production attestation unavailable.
    MainNetProductionAttestationUnavailable,
    /// Fixture attestation rejected because the trust domain is MainNet.
    /// Fixture attestation is DevNet/TestNet source/test only.
    FixtureRejectedForMainNet,
    /// The evidence attestation class does not match the fixture class
    /// the active fixture policy allows.
    AttestationClassPolicyMismatch {
        policy_tag: &'static str,
        class_tag: &'static str,
    },
    /// Unknown / unsupported attestation class.
    UnknownAttestationClassRejected { class_tag: &'static str },
    /// Trust-domain environment does not match the evidence.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        attested: TrustBundleEnvironment,
    },
    /// Trust-domain chain id does not match the evidence.
    WrongChain { expected: String, attested: String },
    /// Trust-domain genesis hash does not match the evidence.
    WrongGenesis { expected: String, attested: String },
    /// Trust-domain authority root fingerprint does not match.
    WrongAuthorityRoot { expected: String, attested: String },
    /// Bundle-signing key fingerprint does not match the expected value.
    WrongSigningKeyFingerprint { expected: String, attested: String },
    /// Custody class does not match the expected value.
    WrongCustodyClass {
        expected: AuthorityCustodyClass,
        attested: AuthorityCustodyClass,
    },
    /// Backend / provider / signer id does not match the expected value.
    WrongBackendProviderSignerId { expected: String, attested: String },
    /// Custody key id / key label does not match the expected value.
    WrongKeyId { expected: String, attested: String },
    /// The suite id is not the Run 159 PQC suite (or does not match the
    /// expected value).
    WrongSuite { expected: u8, attested: u8 },
    /// Lifecycle action does not match the expected value.
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        attested: LocalLifecycleAction,
    },
    /// Candidate digest does not match the expected value.
    WrongCandidateDigest { expected: String, attested: String },
    /// Authority-domain sequence does not match the expected value.
    WrongAuthorityDomainSequence { expected: u64, attested: u64 },
    /// Governance proof digest does not match the expected value.
    WrongGovernanceProofDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Bound request digest does not match the expected value.
    WrongRequestDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Bound response digest does not match the expected value.
    WrongResponseDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Bound transcript digest does not match the expected value.
    WrongTranscriptDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Attestation anti-replay nonce did not match the expected fresh
    /// nonce, or the issuance timestamp fell outside the replay window
    /// (stale or replayed attestation).
    StaleOrReplayedAttestation,
    /// The attestation freshness/expiry window has elapsed.
    ExpiredAttestation { now_unix: u64 },
    /// The attestation evidence is structurally malformed.
    MalformedAttestationEvidence { reason: String },
    /// The attestation-evidence schema version is unsupported.
    UnsupportedAttestationVersion { version: u16 },
    /// The placeholder attestation commitment is empty or the explicit
    /// invalid sentinel.
    InvalidAttestationCommitment,
    /// A local operator key cannot satisfy a production attestation
    /// policy.
    LocalOperatorCannotSatisfyProductionAttestation,
    /// Peer majority / gossip count cannot satisfy a production
    /// attestation policy.
    PeerMajorityCannotSatisfyProductionAttestation,
}

impl CustodyAttestationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::FixtureAttestationAccepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production/cloud/PKCS#11/MainNet attestation" rejection.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::RemoteSignerAttestationUnavailable
                | Self::KmsAttestationUnavailable
                | Self::HsmAttestationUnavailable
                | Self::CloudKmsAttestationUnavailable
                | Self::Pkcs11HsmAttestationUnavailable
                | Self::ProductionAttestationUnavailable
                | Self::MainNetProductionAttestationUnavailable
        )
    }
}

// ===========================================================================
// Verifier trait + implementations
// ===========================================================================

/// Run 205 — pure custody attestation verifier boundary.
///
/// Implementations perform no I/O, write no marker, write no sequence,
/// mutate no live trust, evict no sessions, and never invoke Run 070. A
/// production / cloud / PKCS#11 / HSM-vendor / RemoteSigner implementation
/// fails closed by returning the matching unavailable
/// [`CustodyAttestationOutcome`] until a real verifier lands.
pub trait CustodyAttestationVerifier {
    /// The attestation class this implementation presents.
    fn class(&self) -> CustodyAttestationClass;

    /// Verify `evidence` against `input` for `trust_domain` under
    /// `policy`. No I/O is performed.
    fn verify_custody_attestation(
        &self,
        evidence: &CustodyAttestationEvidence,
        input: &CustodyAttestationInput,
        trust_domain: &AuthorityTrustDomain,
        policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome;
}

/// Run 205 — DevNet/TestNet fixture custody attestation verifier.
///
/// **Source/test only.** Delegates to the pure
/// [`verify_custody_attestation`] function. It is NOT a real attestation
/// verifier; it exists only so DevNet/TestNet source/test vectors can
/// exercise the accepted path, and the underlying verifier refuses a
/// fixture attestation on a MainNet trust domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixtureCustodyAttestationVerifier;

impl CustodyAttestationVerifier for FixtureCustodyAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::FixtureAttestation
    }

    fn verify_custody_attestation(
        &self,
        evidence: &CustodyAttestationEvidence,
        input: &CustodyAttestationInput,
        trust_domain: &AuthorityTrustDomain,
        policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        verify_custody_attestation(evidence, input, trust_domain, policy)
    }
}

/// Run 205 — production RemoteSigner attestation verifier placeholder.
/// Callable but fails closed with
/// [`CustodyAttestationOutcome::RemoteSignerAttestationUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemoteSignerAttestationVerifier;

impl CustodyAttestationVerifier for RemoteSignerAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::RemoteSignerAttestation
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::RemoteSignerAttestationUnavailable
    }
}

/// Run 205 — production KMS attestation verifier placeholder. Callable
/// but fails closed with
/// [`CustodyAttestationOutcome::KmsAttestationUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KmsAttestationVerifier;

impl CustodyAttestationVerifier for KmsAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::KmsAttestation
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::KmsAttestationUnavailable
    }
}

/// Run 205 — production HSM attestation verifier placeholder. Callable
/// but fails closed with
/// [`CustodyAttestationOutcome::HsmAttestationUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HsmAttestationVerifier;

impl CustodyAttestationVerifier for HsmAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::HsmAttestation
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::HsmAttestationUnavailable
    }
}

/// Run 205 — cloud-KMS attestation verifier placeholder. Callable but
/// fails closed with
/// [`CustodyAttestationOutcome::CloudKmsAttestationUnavailable`]. Run 205
/// wires no cloud-KMS attestation verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloudKmsAttestationVerifier;

impl CustodyAttestationVerifier for CloudKmsAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::CloudKmsAttestationUnavailable
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::CloudKmsAttestationUnavailable
    }
}

/// Run 205 — PKCS#11 HSM attestation verifier placeholder. Callable but
/// fails closed with
/// [`CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable`]. Run 205
/// wires no PKCS#11 attestation verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pkcs11HsmAttestationVerifier;

impl CustodyAttestationVerifier for Pkcs11HsmAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::Pkcs11HsmAttestationUnavailable
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable
    }
}

/// Run 205 — generic production attestation verifier placeholder.
/// Callable but fails closed with
/// [`CustodyAttestationOutcome::ProductionAttestationUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProductionAttestationVerifier;

impl CustodyAttestationVerifier for ProductionAttestationVerifier {
    fn class(&self) -> CustodyAttestationClass {
        CustodyAttestationClass::ProductionAttestationUnavailable
    }

    fn verify_custody_attestation(
        &self,
        _evidence: &CustodyAttestationEvidence,
        _input: &CustodyAttestationInput,
        _trust_domain: &AuthorityTrustDomain,
        _policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationOutcome {
        CustodyAttestationOutcome::ProductionAttestationUnavailable
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

/// Map a production class to its unavailable outcome.
fn production_class_unavailable(class: CustodyAttestationClass) -> CustodyAttestationOutcome {
    match class {
        CustodyAttestationClass::RemoteSignerAttestation => {
            CustodyAttestationOutcome::RemoteSignerAttestationUnavailable
        }
        CustodyAttestationClass::KmsAttestation => {
            CustodyAttestationOutcome::KmsAttestationUnavailable
        }
        CustodyAttestationClass::HsmAttestation => {
            CustodyAttestationOutcome::HsmAttestationUnavailable
        }
        CustodyAttestationClass::CloudKmsAttestationUnavailable => {
            CustodyAttestationOutcome::CloudKmsAttestationUnavailable
        }
        CustodyAttestationClass::Pkcs11HsmAttestationUnavailable => {
            CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable
        }
        CustodyAttestationClass::ProductionAttestationUnavailable => {
            CustodyAttestationOutcome::ProductionAttestationUnavailable
        }
        // Non-production classes never reach here.
        _ => CustodyAttestationOutcome::UnknownAttestationClassRejected {
            class_tag: class.tag(),
        },
    }
}

/// Classify a production-required / MainNet-required policy rejection for
/// the evidence attestation class. Fixture material is rejected as
/// non-production; production/cloud/PKCS#11 material is rejected as
/// unavailable; unknown/disabled material is rejected as unknown.
fn classify_production_policy_rejection(
    policy: CustodyAttestationPolicy,
    class: CustodyAttestationClass,
) -> CustodyAttestationOutcome {
    let mainnet = policy == CustodyAttestationPolicy::MainnetProductionAttestationRequired;
    match class {
        CustodyAttestationClass::FixtureAttestation => {
            if mainnet {
                CustodyAttestationOutcome::FixtureRejectedMainnetProductionRequired
            } else {
                CustodyAttestationOutcome::FixtureRejectedProductionRequired
            }
        }
        CustodyAttestationClass::RemoteSignerAttestation
        | CustodyAttestationClass::KmsAttestation
        | CustodyAttestationClass::HsmAttestation
        | CustodyAttestationClass::CloudKmsAttestationUnavailable
        | CustodyAttestationClass::Pkcs11HsmAttestationUnavailable
        | CustodyAttestationClass::ProductionAttestationUnavailable => {
            if mainnet {
                CustodyAttestationOutcome::MainNetProductionAttestationUnavailable
            } else {
                production_class_unavailable(class)
            }
        }
        CustodyAttestationClass::Disabled | CustodyAttestationClass::Unknown => {
            CustodyAttestationOutcome::UnknownAttestationClassRejected {
                class_tag: class.tag(),
            }
        }
    }
}

/// Run 205 — pure typed custody attestation verifier.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no live
/// trust. Evicts no sessions. Never invokes Run 070.
///
/// The verifier binds every decision to the trust domain, the
/// bundle-signing key fingerprint, the custody class, the
/// backend/provider/signer id, the custody key id, the suite, the
/// lifecycle action, the candidate digest, the authority-domain
/// sequence, the optional governance/request/response/transcript digests,
/// the per-attestation anti-replay nonce, the issuance/freshness window,
/// and the attestation commitment. Acceptance is only ever a fixture
/// attestation under the `FixtureAttestationAllowed` policy on a
/// DevNet/TestNet trust domain — production attestation paths are refused
/// as unavailable regardless of contents.
pub fn verify_custody_attestation(
    evidence: &CustodyAttestationEvidence,
    input: &CustodyAttestationInput,
    trust_domain: &AuthorityTrustDomain,
    policy: CustodyAttestationPolicy,
) -> CustodyAttestationOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies
    //    fail closed before any binding check.
    match policy {
        CustodyAttestationPolicy::Disabled => {
            return CustodyAttestationOutcome::AttestationDisabled
        }
        CustodyAttestationPolicy::RemoteSignerAttestationRequired
        | CustodyAttestationPolicy::KmsAttestationRequired
        | CustodyAttestationPolicy::HsmAttestationRequired
        | CustodyAttestationPolicy::ProductionAttestationRequired
        | CustodyAttestationPolicy::MainnetProductionAttestationRequired => {
            return classify_production_policy_rejection(policy, evidence.attestation_class);
        }
        CustodyAttestationPolicy::FixtureAttestationAllowed => {}
    }

    // 2. Under the fixture-allowed policy, a production/cloud/PKCS#11
    //    attestation is still unavailable (no real verifier exists), and
    //    an unknown/disabled attestation is rejected.
    match evidence.attestation_class {
        CustodyAttestationClass::RemoteSignerAttestation
        | CustodyAttestationClass::KmsAttestation
        | CustodyAttestationClass::HsmAttestation
        | CustodyAttestationClass::CloudKmsAttestationUnavailable
        | CustodyAttestationClass::Pkcs11HsmAttestationUnavailable
        | CustodyAttestationClass::ProductionAttestationUnavailable => {
            return production_class_unavailable(evidence.attestation_class);
        }
        CustodyAttestationClass::Disabled | CustodyAttestationClass::Unknown => {
            return CustodyAttestationOutcome::UnknownAttestationClassRejected {
                class_tag: evidence.attestation_class.tag(),
            };
        }
        CustodyAttestationClass::FixtureAttestation => {}
    }

    // 3. The fixture class must match the fixture policy.
    let allowed_fixture = policy
        .allowed_fixture_class()
        .expect("fixture-allowed policy has an allowed fixture class");
    if evidence.attestation_class != allowed_fixture {
        return CustodyAttestationOutcome::AttestationClassPolicyMismatch {
            policy_tag: policy.tag(),
            class_tag: evidence.attestation_class.tag(),
        };
    }

    // 4. Fixture attestation is DevNet/TestNet source/test only — never
    //    MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return CustodyAttestationOutcome::FixtureRejectedForMainNet;
    }

    // 5. Structural well-formedness.
    if !evidence.is_well_formed() {
        return CustodyAttestationOutcome::MalformedAttestationEvidence {
            reason: "evidence missing one or more mandatory fields".to_string(),
        };
    }

    // 6. Schema version.
    if evidence.attestation_version != CUSTODY_ATTESTATION_SUPPORTED_VERSION {
        return CustodyAttestationOutcome::UnsupportedAttestationVersion {
            version: evidence.attestation_version,
        };
    }

    // 7. Trust-domain environment binding (evidence + expected).
    if evidence.environment != trust_domain.environment
        || input.expected_environment != trust_domain.environment
    {
        return CustodyAttestationOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: evidence.environment,
        };
    }

    // 8. Trust-domain chain binding.
    if evidence.chain_id != trust_domain.chain_id
        || input.expected_chain_id != trust_domain.chain_id
    {
        return CustodyAttestationOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: evidence.chain_id.clone(),
        };
    }

    // 9. Trust-domain genesis binding.
    if evidence.genesis_hash != trust_domain.genesis_hash
        || input.expected_genesis_hash != trust_domain.genesis_hash
    {
        return CustodyAttestationOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: evidence.genesis_hash.clone(),
        };
    }

    // 10. Authority root binding.
    if evidence.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || input.expected_authority_root_fingerprint != trust_domain.authority_root_fingerprint
    {
        return CustodyAttestationOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: evidence.authority_root_fingerprint.clone(),
        };
    }

    // 11. Bundle-signing key fingerprint binding.
    if evidence.bundle_signing_key_fingerprint != input.expected_bundle_signing_key_fingerprint {
        return CustodyAttestationOutcome::WrongSigningKeyFingerprint {
            expected: input.expected_bundle_signing_key_fingerprint.clone(),
            attested: evidence.bundle_signing_key_fingerprint.clone(),
        };
    }

    // 12. Custody class binding.
    if evidence.custody_class != input.expected_custody_class {
        return CustodyAttestationOutcome::WrongCustodyClass {
            expected: input.expected_custody_class,
            attested: evidence.custody_class,
        };
    }

    // 13. Backend / provider / signer id binding.
    if evidence.backend_provider_signer_id != input.expected_backend_provider_signer_id {
        return CustodyAttestationOutcome::WrongBackendProviderSignerId {
            expected: input.expected_backend_provider_signer_id.clone(),
            attested: evidence.backend_provider_signer_id.clone(),
        };
    }

    // 14. Custody key id / label binding.
    if evidence.custody_key_id != input.expected_custody_key_id {
        return CustodyAttestationOutcome::WrongKeyId {
            expected: input.expected_custody_key_id.clone(),
            attested: evidence.custody_key_id.clone(),
        };
    }

    // 15. Suite binding (must be the Run 159 PQC suite and match
    //     expected).
    if evidence.suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || input.expected_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || evidence.suite_id != input.expected_suite_id
    {
        return CustodyAttestationOutcome::WrongSuite {
            expected: input.expected_suite_id,
            attested: evidence.suite_id,
        };
    }

    // 16. Lifecycle action binding.
    if evidence.lifecycle_action != input.expected_lifecycle_action {
        return CustodyAttestationOutcome::WrongLifecycleAction {
            expected: input.expected_lifecycle_action,
            attested: evidence.lifecycle_action,
        };
    }

    // 17. Candidate digest binding.
    if evidence.candidate_digest != input.expected_candidate_digest {
        return CustodyAttestationOutcome::WrongCandidateDigest {
            expected: input.expected_candidate_digest.clone(),
            attested: evidence.candidate_digest.clone(),
        };
    }

    // 18. Authority-domain sequence binding.
    if evidence.authority_domain_sequence != input.expected_authority_domain_sequence {
        return CustodyAttestationOutcome::WrongAuthorityDomainSequence {
            expected: input.expected_authority_domain_sequence,
            attested: evidence.authority_domain_sequence,
        };
    }

    // 19. Governance proof digest binding (where applicable).
    if evidence.governance_proof_digest != input.expected_governance_proof_digest {
        return CustodyAttestationOutcome::WrongGovernanceProofDigest {
            expected: input.expected_governance_proof_digest.clone(),
            attested: evidence.governance_proof_digest.clone(),
        };
    }

    // 20. Request digest binding (where applicable).
    if evidence.request_digest != input.expected_request_digest {
        return CustodyAttestationOutcome::WrongRequestDigest {
            expected: input.expected_request_digest.clone(),
            attested: evidence.request_digest.clone(),
        };
    }

    // 21. Response digest binding (where applicable).
    if evidence.response_digest != input.expected_response_digest {
        return CustodyAttestationOutcome::WrongResponseDigest {
            expected: input.expected_response_digest.clone(),
            attested: evidence.response_digest.clone(),
        };
    }

    // 22. Transcript digest binding (where applicable).
    if evidence.transcript_digest != input.expected_transcript_digest {
        return CustodyAttestationOutcome::WrongTranscriptDigest {
            expected: input.expected_transcript_digest.clone(),
            attested: evidence.transcript_digest.clone(),
        };
    }

    // 23. Attestation commitment validity.
    if evidence.attestation_commitment.is_empty()
        || evidence.attestation_commitment == CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL
    {
        return CustodyAttestationOutcome::InvalidAttestationCommitment;
    }

    // 24. Anti-replay nonce binding.
    if evidence.attestation_nonce != input.expected_attestation_nonce {
        return CustodyAttestationOutcome::StaleOrReplayedAttestation;
    }

    // 25. Replay window: when both bounds are present, the issuance
    //     timestamp must fall inside `[since, until)`.
    if let (Some(since), Some(until)) =
        (input.replay_window_since_unix, input.replay_window_until_unix)
    {
        let issued = evidence.issued_at_unix.unwrap_or(0);
        if until <= since || issued < since || issued >= until {
            return CustodyAttestationOutcome::StaleOrReplayedAttestation;
        }
    }

    // 26. Freshness/expiry window.
    if within_optional_window(input.now_unix, evidence.freshness_unix, evidence.expires_at_unix)
        .is_err()
    {
        return CustodyAttestationOutcome::ExpiredAttestation {
            now_unix: input.now_unix,
        };
    }

    // 27. Accept — fixture attestation only, DevNet/TestNet, evidence-only.
    CustodyAttestationOutcome::FixtureAttestationAccepted {
        backend_provider_signer_id: evidence.backend_provider_signer_id.clone(),
        environment: trust_domain.environment,
    }
}

// ===========================================================================
// Composition helpers
// ===========================================================================

/// Run 205 — typed combined decision for a Run 188 custody-metadata +
/// Run 205 attestation preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyMetadataAttestationOutcome {
    /// The Run 188 custody metadata validates under the active custody
    /// policy AND the Run 205 attestation validates under the active
    /// attestation policy. **Acceptance is evidence-only.**
    Accepted {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        attestation_outcome: CustodyAttestationOutcome,
    },
    /// The Run 188 lifecycle/custody composition rejected. The
    /// attestation verifier was not consulted.
    LifecycleOrCustodyRejected(LifecycleGovernanceCustodyOutcome),
    /// The Run 188 lifecycle/custody composition accepted but the Run 205
    /// attestation rejected. Carries both so the operator log line can
    /// record "custody valid + attestation invalid".
    AttestationRejected {
        lifecycle_custody_outcome: LifecycleGovernanceCustodyOutcome,
        attestation_outcome: CustodyAttestationOutcome,
    },
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of any custody or attestation
    /// outcome.
    MainNetPeerDrivenApplyRefused,
}

impl CustodyMetadataAttestationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 205 — pure composition helper.
///
/// Calls the Run 188 custody validator under the active custody policy,
/// then (if accepted) calls the Run 205 attestation verifier under the
/// active attestation policy, and returns a typed combined decision.
/// Performs no I/O, writes no marker, writes no sequence, mutates no live
/// trust, evicts no sessions, never invokes Run 070.
#[allow(clippy::too_many_arguments)]
pub fn validate_custody_metadata_and_attestation(
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
    attestation_evidence: &CustodyAttestationEvidence,
    attestation_input: &CustodyAttestationInput,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    is_peer_driven_apply_preflight: bool,
) -> CustodyMetadataAttestationOutcome {
    // MainNet peer-driven apply remains refused regardless of any fixture
    // attestation success.
    if is_peer_driven_apply_preflight && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return CustodyMetadataAttestationOutcome::MainNetPeerDrivenApplyRefused;
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
        return CustodyMetadataAttestationOutcome::LifecycleOrCustodyRejected(
            lifecycle_custody_outcome,
        );
    }

    let attestation_outcome = verify_custody_attestation(
        attestation_evidence,
        attestation_input,
        trust_domain,
        attestation_policy,
    );

    if attestation_outcome.is_accept() {
        CustodyMetadataAttestationOutcome::Accepted {
            lifecycle_custody_outcome,
            attestation_outcome,
        }
    } else {
        CustodyMetadataAttestationOutcome::AttestationRejected {
            lifecycle_custody_outcome,
            attestation_outcome,
        }
    }
}

/// Run 205 — alias of [`validate_custody_metadata_and_attestation`] kept
/// as a grep-verifiable named symbol describing a full lifecycle +
/// governance + custody + attestation preflight.
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_custody_and_attestation(
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
    attestation_evidence: &CustodyAttestationEvidence,
    attestation_input: &CustodyAttestationInput,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
    is_peer_driven_apply_preflight: bool,
) -> CustodyMetadataAttestationOutcome {
    validate_custody_metadata_and_attestation(
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
        attestation_evidence,
        attestation_input,
        attestation_policy,
        now_unix,
        is_peer_driven_apply_preflight,
    )
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 205 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes,
/// at the typed Run 205 boundary, the rule that MainNet peer-driven apply
/// remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// attestation evidence — even a fixture attestation that verifies
/// successfully. Pure data; never reads attestation material.
pub fn mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 205 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a production
/// attestation policy. Run 205 always returns `true`: a production
/// custody attestation is a custody-held authority attestation and is
/// never satisfiable by a local operator key. Grep-verifiable named
/// symbol for an operator-log line.
pub fn local_operator_cannot_satisfy_production_attestation() -> bool {
    true
}

/// Run 205 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// production attestation policy. Run 205 always returns `true`: a
/// production custody attestation is a per-key authority decision and is
/// never satisfiable by counting peers. Grep-verifiable named symbol for
/// an operator-log line.
pub fn peer_majority_cannot_satisfy_production_attestation() -> bool {
    true
}
