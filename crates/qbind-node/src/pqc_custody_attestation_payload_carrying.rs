//! Run 207 — source/test custody-attestation payload carrying and
//! production-context preflight wiring.
//!
//! ## Strict scope (Run 207)
//!
//! * **Source/test only.** Run 207 does **not** capture release-binary
//!   evidence; release-binary custody-attestation payload/carrying
//!   evidence is deferred to **Run 208**.
//! * **No real cloud-KMS attestation verifier, no real PKCS#11
//!   attestation verifier, no real HSM vendor attestation verifier, no
//!   real RemoteSigner backend.** The Run 205
//!   [`crate::pqc_custody_attestation_verifier`] production /
//!   cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation verifiers
//!   remain callable but fail closed as unavailable.
//! * **No MainNet peer-driven apply enablement.** The
//!   Run 147/148/152 MainNet refusal at the peer-driven apply surface
//!   remains intact even with a fully-valid DevNet/TestNet fixture
//!   custody attestation carried through this Run 207 payload layer.
//! * **No governance execution engine, no real on-chain proof
//!   verifier, no validator-set rotation, no autonomous apply / apply
//!   on receipt / peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core schema change.** The carrier is a strictly additive,
//!   optional sibling on the existing v2 ratification sidecar JSON
//!   alongside the Run 167 `governance_authority_proof`, Run 184
//!   `onchain_governance_proof`, Run 190 `authority_custody_attestation`,
//!   and Run 196 `remote_signer_attestation` siblings: legacy
//!   no-attestation payloads continue to parse and to be accepted under
//!   the default [`CustodyAttestationPolicy::Disabled`] policy
//!   bit-for-bit.
//!
//! Run 207 does **not** weaken any prior run (Runs 070, 130–206) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 207 the Run 205 typed [`CustodyAttestationEvidence`] and
//! [`CustodyAttestationInput`] could only reach the Run 205 verifier via
//! in-process source/test construction: every production payload/context
//! delivered the call-site context with no custody-attestation material,
//! and neither [`verify_custody_attestation`],
//! [`validate_custody_metadata_and_attestation`], nor
//! [`validate_lifecycle_custody_and_attestation`] was ever reached from a
//! production call site.
//!
//! Run 207 closes that gap at the source/test level by adding:
//!
//! 1. An **additive optional sibling field** —
//!    [`CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD`] — on the same v2
//!    ratification sidecar JSON document already used by the Run 167 /
//!    Run 184 / Run 190 / Run 196 siblings.
//! 2. A wire/context representation —
//!    [`CustodyAttestationPayloadWire`] (combining
//!    [`CustodyAttestationEvidenceWire`] and
//!    [`CustodyAttestationInputWire`]) — with an explicit
//!    `schema_version` plus a string-tagged [`CustodyAttestationClassWire`].
//!    The wire form converts into the internal Run 205 types via
//!    [`CustodyAttestationPayloadWire::to_parts`]; an unknown
//!    `schema_version` or an empty required field fails closed.
//! 3. A typed [`CustodyAttestationLoadStatus`] (`Absent` / `Available` /
//!    `Malformed`) parallel to the Run 196
//!    [`crate::pqc_remote_signer_payload_carrying::RemoteSignerLoadStatus`].
//! 4. A typed [`CustodyAttestationPayloadParseError`] separating
//!    JSON-shape failures from wire-form structural failures.
//! 5. A pure
//!    [`parse_optional_custody_attestation_sibling_from_json_value`]
//!    helper that extracts the optional sibling from a generic
//!    `serde_json::Value` envelope.
//! 6. A combined v2 sidecar loader
//!    [`load_v2_ratification_sidecar_with_custody_attestation_from_path`]
//!    (and bytes variant) returning the typed
//!    [`qbind_ledger::BundleSigningRatificationV2`] together with the
//!    Run 207 [`CustodyAttestationLoadStatus`].
//! 7. A typed [`CustodyAttestationCallsiteContext`] — the natural
//!    production call-site inputs already available at every Run 205
//!    custody-attestation decision (the in-process Run 188 custody
//!    attestation, the candidate / persisted v2 records, the trust
//!    domain, the custody policy, the lifecycle/governance bindings, and
//!    the Run 205 attestation policy).
//! 8. Seven typed per-surface routing helpers
//!    ([`route_loaded_custody_attestation_to_*_callsite_decision`])
//!    binding a parsed [`CustodyAttestationLoadStatus`] to the seven
//!    production v2 marker-decision surfaces (reload-check / reload-apply
//!    / startup `--p2p-trust-bundle` / SIGHUP / local
//!    peer-candidate-check / live inbound `0x05` / peer-driven drain)
//!    with:
//!      * a typed
//!        [`CustodyAttestationPayloadCarryingDecisionOutcome::MalformedCustodyAttestationPayload`]
//!        variant placed *in front of* the Run 205 boundary so a
//!        malformed carrier fails closed BEFORE the verifier is invoked,
//!        BEFORE any sequence/marker write, BEFORE any live trust swap,
//!        BEFORE any session eviction, and BEFORE any Run 070 call;
//!      * a typed
//!        [`CustodyAttestationPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent`]
//!        variant when the active attestation policy requires material
//!        and the carrier is absent;
//!      * a typed
//!        [`CustodyAttestationPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied`]
//!        bypass variant when the active attestation policy is
//!        `Disabled` and the carrier is absent — the legacy
//!        no-attestation payload compatibility variant;
//!      * a typed
//!        [`CustodyAttestationPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
//!        variant on the peer-driven drain surface that fires *before*
//!        the verifier regardless of attestation contents, mirroring the
//!        Run 147 / 148 / 152 MainNet refusal;
//!      * an inner Run 205
//!        [`CustodyMetadataAttestationOutcome`] for every parsed, present
//!        carrier.
//!
//! ## Pure / non-mutating
//!
//! The loaders perform read-only file I/O. The routing helpers perform
//! no I/O. No marker write, no sequence write, no live trust swap, no
//! session eviction, no Run 070 call.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pqc_authority_custody::{AuthorityCustodyAttestation, AuthorityCustodyPolicy};
use crate::pqc_authority_custody_payload_carrying::AuthorityCustodyClassWire;
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_custody_attestation_verifier::{
    validate_custody_metadata_and_attestation, validate_lifecycle_custody_and_attestation,
    verify_custody_attestation, CustodyAttestationClass, CustodyAttestationEvidence,
    CustodyAttestationInput, CustodyAttestationOutcome, CustodyAttestationPolicy,
    CustodyMetadataAttestationOutcome,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_ratification_input::VersionedRatificationInputError;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Sibling field name + schema version
// ===========================================================================

/// JSON sibling field name carrying the Run 207 optional
/// [`CustodyAttestationPayloadWire`] on the v2 ratification sidecar
/// envelope.
///
/// The field is strictly additive: legacy sidecars without this sibling
/// parse exactly as before and yield [`CustodyAttestationLoadStatus::Absent`].
pub const CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: &str = "custody_attestation";

/// Run 207 — wire schema version for the additive optional
/// [`CustodyAttestationPayloadWire`] sibling. Versioning is additive: a
/// future run extending the wire shape MUST bump this constant. Run 207
/// rejects unknown versions with
/// [`CustodyAttestationWireParseError::UnknownSchemaVersion`].
pub const CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION: u32 = 1;

// ===========================================================================
// Wire-tagged attestation class
// ===========================================================================

/// Run 207 — wire-tagged form of the Run 205
/// [`CustodyAttestationClass`].
///
/// The Run 205 [`CustodyAttestationClass`] does not derive `Serialize` /
/// `Deserialize` (it is an internal symbol), so Run 207 mirrors it as a
/// string-tagged wire enum and converts in
/// [`CustodyAttestationEvidenceWire::to_evidence`]. Unknown tag values
/// map to [`CustodyAttestationClass::Unknown`] which the Run 205 verifier
/// already rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyAttestationClassWire {
    Disabled,
    FixtureAttestation,
    RemoteSignerAttestation,
    KmsAttestation,
    HsmAttestation,
    CloudKmsAttestationUnavailable,
    Pkcs11HsmAttestationUnavailable,
    ProductionAttestationUnavailable,
    Unknown,
}

impl CustodyAttestationClassWire {
    pub const fn to_class(self) -> CustodyAttestationClass {
        match self {
            Self::Disabled => CustodyAttestationClass::Disabled,
            Self::FixtureAttestation => CustodyAttestationClass::FixtureAttestation,
            Self::RemoteSignerAttestation => CustodyAttestationClass::RemoteSignerAttestation,
            Self::KmsAttestation => CustodyAttestationClass::KmsAttestation,
            Self::HsmAttestation => CustodyAttestationClass::HsmAttestation,
            Self::CloudKmsAttestationUnavailable => {
                CustodyAttestationClass::CloudKmsAttestationUnavailable
            }
            Self::Pkcs11HsmAttestationUnavailable => {
                CustodyAttestationClass::Pkcs11HsmAttestationUnavailable
            }
            Self::ProductionAttestationUnavailable => {
                CustodyAttestationClass::ProductionAttestationUnavailable
            }
            Self::Unknown => CustodyAttestationClass::Unknown,
        }
    }

    pub const fn from_class(c: CustodyAttestationClass) -> Self {
        match c {
            CustodyAttestationClass::Disabled => Self::Disabled,
            CustodyAttestationClass::FixtureAttestation => Self::FixtureAttestation,
            CustodyAttestationClass::RemoteSignerAttestation => Self::RemoteSignerAttestation,
            CustodyAttestationClass::KmsAttestation => Self::KmsAttestation,
            CustodyAttestationClass::HsmAttestation => Self::HsmAttestation,
            CustodyAttestationClass::CloudKmsAttestationUnavailable => {
                Self::CloudKmsAttestationUnavailable
            }
            CustodyAttestationClass::Pkcs11HsmAttestationUnavailable => {
                Self::Pkcs11HsmAttestationUnavailable
            }
            CustodyAttestationClass::ProductionAttestationUnavailable => {
                Self::ProductionAttestationUnavailable
            }
            CustodyAttestationClass::Unknown => Self::Unknown,
        }
    }
}

// ===========================================================================
// Wire forms
// ===========================================================================

/// Run 207 — wire-safe encoding of the Run 205
/// [`CustodyAttestationEvidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAttestationEvidenceWire {
    pub attestation_class: CustodyAttestationClassWire,
    pub attestation_version: u16,
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub bundle_signing_key_fingerprint: String,
    pub custody_class: AuthorityCustodyClassWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_backend_kind: Option<String>,
    pub backend_provider_signer_id: String,
    pub custody_key_id: String,
    pub suite_id: u8,
    pub lifecycle_action: LocalLifecycleAction,
    pub candidate_digest: String,
    pub authority_domain_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_proof_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_digest: Option<String>,
    pub attestation_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub attestation_commitment: String,
}

impl CustodyAttestationEvidenceWire {
    /// Convert into the internal Run 205 [`CustodyAttestationEvidence`].
    /// Fails closed when any mandatory string field is empty.
    pub fn to_evidence(
        &self,
    ) -> Result<CustodyAttestationEvidence, CustodyAttestationWireParseError> {
        let evidence = CustodyAttestationEvidence {
            attestation_class: self.attestation_class.to_class(),
            attestation_version: self.attestation_version,
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: self.bundle_signing_key_fingerprint.clone(),
            custody_class: self.custody_class.to_class(),
            custody_backend_kind: self.custody_backend_kind.clone(),
            backend_provider_signer_id: self.backend_provider_signer_id.clone(),
            custody_key_id: self.custody_key_id.clone(),
            suite_id: self.suite_id,
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            governance_proof_digest: self.governance_proof_digest.clone(),
            request_digest: self.request_digest.clone(),
            response_digest: self.response_digest.clone(),
            transcript_digest: self.transcript_digest.clone(),
            attestation_nonce: self.attestation_nonce.clone(),
            issued_at_unix: self.issued_at_unix,
            freshness_unix: self.freshness_unix,
            expires_at_unix: self.expires_at_unix,
            attestation_commitment: self.attestation_commitment.clone(),
        };
        if !evidence.is_well_formed() {
            return Err(CustodyAttestationWireParseError::EmptyRequiredField {
                part: "evidence",
            });
        }
        Ok(evidence)
    }

    /// Source/test helper: build a wire form from an in-process Run 205
    /// [`CustodyAttestationEvidence`].
    pub fn from_evidence(e: &CustodyAttestationEvidence) -> Self {
        Self {
            attestation_class: CustodyAttestationClassWire::from_class(e.attestation_class),
            attestation_version: e.attestation_version,
            environment: e.environment,
            chain_id: e.chain_id.clone(),
            genesis_hash: e.genesis_hash.clone(),
            authority_root_fingerprint: e.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: e.bundle_signing_key_fingerprint.clone(),
            custody_class: AuthorityCustodyClassWire::from_class(e.custody_class),
            custody_backend_kind: e.custody_backend_kind.clone(),
            backend_provider_signer_id: e.backend_provider_signer_id.clone(),
            custody_key_id: e.custody_key_id.clone(),
            suite_id: e.suite_id,
            lifecycle_action: e.lifecycle_action,
            candidate_digest: e.candidate_digest.clone(),
            authority_domain_sequence: e.authority_domain_sequence,
            governance_proof_digest: e.governance_proof_digest.clone(),
            request_digest: e.request_digest.clone(),
            response_digest: e.response_digest.clone(),
            transcript_digest: e.transcript_digest.clone(),
            attestation_nonce: e.attestation_nonce.clone(),
            issued_at_unix: e.issued_at_unix,
            freshness_unix: e.freshness_unix,
            expires_at_unix: e.expires_at_unix,
            attestation_commitment: e.attestation_commitment.clone(),
        }
    }
}

/// Run 207 — wire-safe encoding of the Run 205
/// [`CustodyAttestationInput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAttestationInputWire {
    pub expected_environment: TrustBundleEnvironment,
    pub expected_chain_id: String,
    pub expected_genesis_hash: String,
    pub expected_authority_root_fingerprint: String,
    pub expected_bundle_signing_key_fingerprint: String,
    pub expected_custody_class: AuthorityCustodyClassWire,
    pub expected_backend_provider_signer_id: String,
    pub expected_custody_key_id: String,
    pub expected_suite_id: u8,
    pub expected_lifecycle_action: LocalLifecycleAction,
    pub expected_candidate_digest: String,
    pub expected_authority_domain_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_governance_proof_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_response_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_transcript_digest: Option<String>,
    pub expected_attestation_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_window_since_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_window_until_unix: Option<u64>,
    pub now_unix: u64,
}

impl CustodyAttestationInputWire {
    /// Convert into the internal Run 205 [`CustodyAttestationInput`].
    /// Fails closed when any mandatory string field is empty.
    pub fn to_input(&self) -> Result<CustodyAttestationInput, CustodyAttestationWireParseError> {
        if self.expected_chain_id.is_empty()
            || self.expected_genesis_hash.is_empty()
            || self.expected_authority_root_fingerprint.is_empty()
            || self.expected_bundle_signing_key_fingerprint.is_empty()
            || self.expected_backend_provider_signer_id.is_empty()
            || self.expected_custody_key_id.is_empty()
            || self.expected_candidate_digest.is_empty()
            || self.expected_attestation_nonce.is_empty()
        {
            return Err(CustodyAttestationWireParseError::EmptyRequiredField { part: "input" });
        }
        Ok(CustodyAttestationInput {
            expected_environment: self.expected_environment,
            expected_chain_id: self.expected_chain_id.clone(),
            expected_genesis_hash: self.expected_genesis_hash.clone(),
            expected_authority_root_fingerprint: self.expected_authority_root_fingerprint.clone(),
            expected_bundle_signing_key_fingerprint: self
                .expected_bundle_signing_key_fingerprint
                .clone(),
            expected_custody_class: self.expected_custody_class.to_class(),
            expected_backend_provider_signer_id: self.expected_backend_provider_signer_id.clone(),
            expected_custody_key_id: self.expected_custody_key_id.clone(),
            expected_suite_id: self.expected_suite_id,
            expected_lifecycle_action: self.expected_lifecycle_action,
            expected_candidate_digest: self.expected_candidate_digest.clone(),
            expected_authority_domain_sequence: self.expected_authority_domain_sequence,
            expected_governance_proof_digest: self.expected_governance_proof_digest.clone(),
            expected_request_digest: self.expected_request_digest.clone(),
            expected_response_digest: self.expected_response_digest.clone(),
            expected_transcript_digest: self.expected_transcript_digest.clone(),
            expected_attestation_nonce: self.expected_attestation_nonce.clone(),
            replay_window_since_unix: self.replay_window_since_unix,
            replay_window_until_unix: self.replay_window_until_unix,
            now_unix: self.now_unix,
        })
    }

    /// Source/test helper: build a wire form from an in-process Run 205
    /// [`CustodyAttestationInput`].
    pub fn from_input(i: &CustodyAttestationInput) -> Self {
        Self {
            expected_environment: i.expected_environment,
            expected_chain_id: i.expected_chain_id.clone(),
            expected_genesis_hash: i.expected_genesis_hash.clone(),
            expected_authority_root_fingerprint: i.expected_authority_root_fingerprint.clone(),
            expected_bundle_signing_key_fingerprint: i
                .expected_bundle_signing_key_fingerprint
                .clone(),
            expected_custody_class: AuthorityCustodyClassWire::from_class(i.expected_custody_class),
            expected_backend_provider_signer_id: i.expected_backend_provider_signer_id.clone(),
            expected_custody_key_id: i.expected_custody_key_id.clone(),
            expected_suite_id: i.expected_suite_id,
            expected_lifecycle_action: i.expected_lifecycle_action,
            expected_candidate_digest: i.expected_candidate_digest.clone(),
            expected_authority_domain_sequence: i.expected_authority_domain_sequence,
            expected_governance_proof_digest: i.expected_governance_proof_digest.clone(),
            expected_request_digest: i.expected_request_digest.clone(),
            expected_response_digest: i.expected_response_digest.clone(),
            expected_transcript_digest: i.expected_transcript_digest.clone(),
            expected_attestation_nonce: i.expected_attestation_nonce.clone(),
            replay_window_since_unix: i.replay_window_since_unix,
            replay_window_until_unix: i.replay_window_until_unix,
            now_unix: i.now_unix,
        }
    }
}

/// Run 207 — combined additive wire-form custody attestation carried as
/// an optional sibling on the v2 ratification sidecar JSON.
///
/// Bundles the [`CustodyAttestationEvidenceWire`] and the
/// [`CustodyAttestationInputWire`] behind a single `schema_version`. Old
/// sidecars (Runs 167–206) that do not carry this sibling continue to
/// parse and validate exactly as before — the sibling is extracted from
/// the surrounding `serde_json::Value` and is absent when missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAttestationPayloadWire {
    pub schema_version: u32,
    pub evidence: CustodyAttestationEvidenceWire,
    pub input: CustodyAttestationInputWire,
}

impl CustodyAttestationPayloadWire {
    /// Convert the Run 207 combined wire form into the internal Run 205
    /// [`CustodyAttestationParts`].
    ///
    /// Fails closed when:
    ///
    /// * the `schema_version` is not the one Run 207 supports
    ///   ([`CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION`]);
    /// * any required string field of the evidence / input is empty.
    ///
    /// The conversion does not interpret the placeholder attestation
    /// commitment — all trust-domain / lifecycle / custody / sequence /
    /// candidate-digest / suite / freshness / replay checks are deferred
    /// to the Run 205 verifier.
    pub fn to_parts(&self) -> Result<CustodyAttestationParts, CustodyAttestationWireParseError> {
        if self.schema_version != CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION {
            return Err(CustodyAttestationWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION,
            });
        }
        let evidence = self.evidence.to_evidence()?;
        let input = self.input.to_input()?;
        Ok(CustodyAttestationParts { evidence, input })
    }

    /// Source/test helper: build a Run 207 combined wire form from
    /// in-process Run 205 parts.
    pub fn from_parts(evidence: &CustodyAttestationEvidence, input: &CustodyAttestationInput) -> Self {
        Self {
            schema_version: CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION,
            evidence: CustodyAttestationEvidenceWire::from_evidence(evidence),
            input: CustodyAttestationInputWire::from_input(input),
        }
    }
}

/// Run 207 — the internal Run 205 custody-attestation parts produced by
/// converting a well-formed [`CustodyAttestationPayloadWire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyAttestationParts {
    pub evidence: CustodyAttestationEvidence,
    pub input: CustodyAttestationInput,
}

// ===========================================================================
// Typed wire-form parse error
// ===========================================================================

/// Run 207 — typed wire-form parse error emitted by
/// [`CustodyAttestationPayloadWire::to_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationWireParseError {
    /// The wire form's `schema_version` is not the one Run 207 supports.
    UnknownSchemaVersion { got: u32, expected: u32 },
    /// A required string field of the named part (`evidence` / `input`)
    /// was empty.
    EmptyRequiredField { part: &'static str },
}

impl std::fmt::Display for CustodyAttestationWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-207] unsupported custody_attestation schema_version={} (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField { part } => write!(
                f,
                "[run-207] custody_attestation {} has an empty required field. Fail closed.",
                part
            ),
        }
    }
}

impl std::error::Error for CustodyAttestationWireParseError {}

// ===========================================================================
// Typed payload-level parse error
// ===========================================================================

/// Run 207 — typed parse error emitted at the payload/sibling boundary
/// when a `custody_attestation` sibling is present but cannot be
/// converted into typed Run 205 parts.
///
/// Distinct from [`CustodyAttestationWireParseError`] so that JSON-shape
/// failures (payload-level) are kept separate from wire-form structural
/// failures (Run 207 schema-level). Both map to a single
/// [`CustodyAttestationPayloadCarryingDecisionOutcome::MalformedCustodyAttestationPayload`]
/// variant at the call-site routing helpers and never to a partially
/// parsed attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationPayloadParseError {
    /// JSON decoding of the optional `custody_attestation` sibling field
    /// failed.
    Json { error: String },
    /// The sibling decoded as a [`CustodyAttestationPayloadWire`] but the
    /// wire form failed structural validation (unknown schema_version,
    /// empty required field).
    Wire(CustodyAttestationWireParseError),
}

impl std::fmt::Display for CustodyAttestationPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-207] failed to JSON-decode optional `{}` sibling: {}. Fail closed.",
                CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, error
            ),
            Self::Wire(e) => write!(f, "[run-207] {}", e),
        }
    }
}

impl std::error::Error for CustodyAttestationPayloadParseError {}

impl From<CustodyAttestationWireParseError> for CustodyAttestationPayloadParseError {
    fn from(e: CustodyAttestationWireParseError) -> Self {
        Self::Wire(e)
    }
}

// ===========================================================================
// Typed load status
// ===========================================================================

/// Run 207 — typed load status of the optional
/// [`CustodyAttestationPayloadWire`] sibling on the v2 ratification
/// sidecar JSON / `0x05` peer-candidate envelope.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationLoadStatus {
    /// The carrier carried no `custody_attestation` sibling field.
    /// Backwards-compatible with all pre-Run-207 v2 sidecars and live
    /// envelopes — a no-attestation payload remains accepted under the
    /// default [`CustodyAttestationPolicy::Disabled`] policy.
    Absent,
    /// The carrier carried a well-formed wire attestation which was
    /// structurally converted into the typed Run 205 parts. The parts
    /// have NOT yet been validated against trust-domain / lifecycle /
    /// custody / replay / freshness bindings — validation is performed by
    /// the Run 207 per-surface routing helpers which delegate to the
    /// Run 205 verifier.
    Available(CustodyAttestationParts),
    /// The carrier carried a `custody_attestation` sibling field that
    /// failed to decode at the JSON layer or failed wire structural
    /// validation. Always fails closed at the Run 207 per-surface
    /// routing helpers.
    Malformed(CustodyAttestationPayloadParseError),
}

impl CustodyAttestationLoadStatus {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Borrow the typed parts when the carrier was well-formed. `None`
    /// for `Absent` and `Malformed`.
    pub fn as_parts(&self) -> Option<&CustodyAttestationParts> {
        match self {
            Self::Available(p) => Some(p),
            Self::Absent | Self::Malformed(_) => None,
        }
    }

    /// Return the typed parse error when the carrier was malformed.
    pub fn malformed_error(&self) -> Option<&CustodyAttestationPayloadParseError> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::Absent | Self::Available(_) => None,
        }
    }
}

// ===========================================================================
// Sibling parsing
// ===========================================================================

/// Run 207 — pure parse helper that extracts the optional
/// `custody_attestation` sibling from a generic JSON value and returns a
/// typed [`CustodyAttestationLoadStatus`].
///
/// Behaviour:
///
/// * `value` has no `custody_attestation` field, or the field is `null`:
///   returns [`CustodyAttestationLoadStatus::Absent`].
/// * `value` has a non-null `custody_attestation` field that fails to
///   decode as [`CustodyAttestationPayloadWire`]: returns
///   [`CustodyAttestationLoadStatus::Malformed`] carrying a
///   [`CustodyAttestationPayloadParseError::Json`].
/// * `value` has a well-formed wire object but
///   [`CustodyAttestationPayloadWire::to_parts`] rejects it (unknown
///   schema version, empty required field): returns
///   [`CustodyAttestationLoadStatus::Malformed`] carrying the wire parse
///   error.
/// * Otherwise: returns [`CustodyAttestationLoadStatus::Available`] with
///   the typed Run 205 parts.
///
/// Pure — does not mutate `value` and performs no I/O.
pub fn parse_optional_custody_attestation_sibling_from_json_value(
    value: &Value,
) -> CustodyAttestationLoadStatus {
    let sibling = value.get(CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD);
    match sibling {
        None => CustodyAttestationLoadStatus::Absent,
        Some(Value::Null) => CustodyAttestationLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<CustodyAttestationPayloadWire>(raw.clone()) {
            Ok(wire) => match wire.to_parts() {
                Ok(parts) => CustodyAttestationLoadStatus::Available(parts),
                Err(e) => CustodyAttestationLoadStatus::Malformed(
                    CustodyAttestationPayloadParseError::Wire(e),
                ),
            },
            Err(e) => CustodyAttestationLoadStatus::Malformed(
                CustodyAttestationPayloadParseError::Json {
                    error: e.to_string(),
                },
            ),
        },
    }
}

// ===========================================================================
// Combined v2 sidecar loader
// ===========================================================================

/// Run 207 — typed result of loading a v2 ratification sidecar together
/// with the Run 207 [`CustodyAttestationPayloadWire`] sibling.
///
/// Strictly additive over the prior combined sidecars: pre-Run-207
/// sidecars yield [`CustodyAttestationLoadStatus::Absent`] in the new
/// field.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecarWithCustodyAttestation {
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    pub custody_attestation: CustodyAttestationLoadStatus,
}

/// Run 207 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse the Run 207 `custody_attestation` sibling.
///
/// The optional sibling field is **strictly additive**. A v2 sidecar
/// without it continues to parse as before and yields
/// [`CustodyAttestationLoadStatus::Absent`]. A sibling that fails to
/// deserialise into its wire form, or that fails wire-form structural
/// validation, yields [`CustodyAttestationLoadStatus::Malformed`]. The v2
/// ratification itself is still returned so the caller can fall through
/// the policy/gate pipeline.
///
/// No file write, no marker write, no sequence write, no live trust swap,
/// no session eviction, no Run 070 call.
pub fn load_v2_ratification_sidecar_with_custody_attestation_from_path(
    path: &Path,
) -> Result<LoadedV2RatificationSidecarWithCustodyAttestation, VersionedRatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, path)
}

/// Run 207 — bytes-form variant of
/// [`load_v2_ratification_sidecar_with_custody_attestation_from_path`].
///
/// Used by validation-only / live-inbound surfaces that already hold the
/// JSON envelope in memory. The `path_for_diagnostics` argument is only
/// used to populate typed [`VersionedRatificationInputError`] variants —
/// it does NOT trigger any file access on this code path.
pub fn load_v2_ratification_sidecar_with_custody_attestation_from_bytes(
    bytes: &[u8],
    path_for_diagnostics: &Path,
) -> Result<LoadedV2RatificationSidecarWithCustodyAttestation, VersionedRatificationInputError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path_for_diagnostics.to_path_buf(),
            error: e.to_string(),
        })?;

    let version_value = value.get("schema_version").or_else(|| value.get("version"));
    let version_int = match version_value.and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return Err(VersionedRatificationInputError::UnknownSchemaVersion {
                path: path_for_diagnostics.to_path_buf(),
                got: version_value.cloned(),
            });
        }
    };
    if version_int != 2 {
        return Err(VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: version_int,
            error: format!(
                "Run 207 custody-attestation carrier requires v2 sidecar (got schema_version={})",
                version_int
            ),
        });
    }

    // Extract the optional sibling BEFORE re-parsing into the typed
    // ratification, so the sibling cannot poison the v2 parse and so it
    // produces its own typed load status independently.
    let custody_attestation = parse_optional_custody_attestation_sibling_from_json_value(&value);

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecarWithCustodyAttestation {
        ratification,
        custody_attestation,
    })
}

// ===========================================================================
// Wire-encoding helper for the additive sibling
// ===========================================================================

/// Run 207 — additive optional sibling shape used to produce a v2
/// ratification sidecar JSON document that carries a
/// [`CustodyAttestationPayloadWire`] alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`].
///
/// Source/test helper. Production paths continue to write the
/// `BundleSigningRatificationV2` directly when no custody-attestation
/// material is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RatificationSidecarWithCustodyAttestationWire {
    #[serde(flatten)]
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_attestation: Option<CustodyAttestationPayloadWire>,
}

// ===========================================================================
// Call-site context
// ===========================================================================

/// Run 207 — typed bundle of the natural production call-site inputs
/// required to drive a Run 205 lifecycle + governance + custody +
/// attestation preflight at any of the seven production v2
/// marker-decision surfaces.
///
/// Every field is borrowed; the struct is purely a typed argument bundle
/// and never mutates any input. Constructing it is free of I/O.
#[derive(Debug)]
pub struct CustodyAttestationCallsiteContext<'a> {
    /// In-process Run 188 custody attestation already resolved by the
    /// calling surface (e.g. via the Run 190 custody carrier). The
    /// Run 205 composition validates this under `custody_policy` before
    /// consulting the attestation verifier.
    pub custody_attestation: &'a AuthorityCustodyAttestation,
    /// Persisted v2 record when the call site has one in hand.
    pub persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    /// Candidate v2 record being preflighted by the call site.
    pub candidate: &'a PersistentAuthorityStateRecordV2,
    /// Active trust domain at the call site.
    pub trust_domain: &'a AuthorityTrustDomain,
    /// Expected governance authority class binding for the Run 188
    /// validator.
    pub expected_governance_authority_class: GovernanceAuthorityClass,
    /// Expected lifecycle action binding.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate digest binding.
    pub expected_candidate_digest: &'a str,
    /// Expected next authority-domain sequence binding.
    pub expected_authority_domain_sequence: u64,
    /// Optional expected custody key id binding.
    pub expected_custody_key_id: Option<&'a str>,
    /// Active Run 188 [`AuthorityCustodyPolicy`].
    pub custody_policy: AuthorityCustodyPolicy,
    /// Active Run 205 [`CustodyAttestationPolicy`]. Default in production
    /// is [`CustodyAttestationPolicy::Disabled`].
    pub attestation_policy: CustodyAttestationPolicy,
    /// Wall-clock seconds-since-epoch.
    pub now_unix: u64,
}

impl<'a> CustodyAttestationCallsiteContext<'a> {
    /// Run 207 — pure surface-level MainNet refusal helper. Returns
    /// `true` iff the candidate, the trust domain, or any carried
    /// attestation part binds MainNet. Used by the peer-driven drain
    /// routing helper before the verifier is invoked, mirroring the
    /// Run 152 MainNet peer-driven-apply refusal.
    pub fn binds_mainnet(&self, parts: Option<&CustodyAttestationParts>) -> bool {
        self.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || self.candidate.environment == TrustBundleEnvironment::Mainnet
            || parts
                .map(|p| {
                    p.evidence.environment == TrustBundleEnvironment::Mainnet
                        || p.input.expected_environment == TrustBundleEnvironment::Mainnet
                })
                .unwrap_or(false)
    }
}

// ===========================================================================
// Routing into Run 205 validation
// ===========================================================================

/// Run 207 — typed outcome of routing a Run 207
/// [`CustodyAttestationLoadStatus`] through any of the seven production
/// v2 marker-decision surfaces.
///
/// Adds typed variants in front of the Run 205
/// [`CustodyMetadataAttestationOutcome`]:
///
/// * [`Self::MalformedCustodyAttestationPayload`] — the carrier sibling
///   was present but malformed at the JSON or wire-structural level.
///   Always fail-closed regardless of policy. The Run 205 verifier is
///   NOT invoked.
/// * [`Self::CustodyAttestationRequiredButAbsent`] — the active
///   attestation policy requires material (every non-`Disabled` policy)
///   and the carrier sibling is absent. Always fail-closed.
/// * [`Self::NoCustodyAttestationSupplied`] — the carrier sibling is
///   absent and the active attestation policy is
///   [`CustodyAttestationPolicy::Disabled`]. Legacy no-attestation
///   payload compatibility variant; the calling surface continues with
///   its pre-Run-207 path. The Run 205 verifier is NOT invoked.
/// * [`Self::MainNetPeerDrivenApplyRefused`] — the peer-driven drain
///   surface refuses MainNet unconditionally regardless of attestation
///   contents.
/// * [`Self::Callsite`] — wraps the Run 205
///   [`CustodyMetadataAttestationOutcome`] for every parsed, present
///   carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyAttestationPayloadCarryingDecisionOutcome {
    /// The carrier sibling was present but malformed. Fail closed before
    /// any Run 205 validation, before any sequence/marker write, before
    /// any live trust swap, before any session eviction, before any Run
    /// 070 call.
    MalformedCustodyAttestationPayload(CustodyAttestationPayloadParseError),
    /// The active attestation policy requires material and the carrier
    /// sibling is absent. Fail closed.
    CustodyAttestationRequiredButAbsent { policy: CustodyAttestationPolicy },
    /// The carrier sibling is absent and the active attestation policy is
    /// `Disabled`. Legacy no-attestation payload compatibility.
    NoCustodyAttestationSupplied,
    /// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
    /// refusal regardless of attestation contents. Surfaced only by the
    /// peer-driven drain routing helper.
    MainNetPeerDrivenApplyRefused,
    /// The carrier sibling parsed and the Run 205 composition was
    /// invoked. Carries the typed Run 205 combined lifecycle +
    /// governance + custody + attestation outcome.
    Callsite(CustodyMetadataAttestationOutcome),
}

impl CustodyAttestationPayloadCarryingDecisionOutcome {
    pub fn is_accept(&self) -> bool {
        match self {
            Self::Callsite(o) => o.is_accept(),
            _ => false,
        }
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !self.is_bypassed()
    }

    /// `true` iff the policy was `Disabled` and the carrier was absent —
    /// the legacy no-attestation-payload bypass variant.
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::NoCustodyAttestationSupplied)
    }

    pub fn is_malformed_payload(&self) -> bool {
        matches!(self, Self::MalformedCustodyAttestationPayload(_))
    }

    pub fn is_required_but_absent(&self) -> bool {
        matches!(self, Self::CustodyAttestationRequiredButAbsent { .. })
    }

    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Borrow the inner Run 205 outcome, if any.
    pub fn callsite_outcome(&self) -> Option<&CustodyMetadataAttestationOutcome> {
        match self {
            Self::Callsite(o) => Some(o),
            _ => None,
        }
    }
}

/// Internal — short-circuit a malformed-carrier load status into the
/// Run 207 fail-closed outcome. `Absent` and `Available` return `None`,
/// in which case the caller continues per-surface.
fn malformed_payload_shortcircuit(
    loaded: &CustodyAttestationLoadStatus,
) -> Option<CustodyAttestationPayloadCarryingDecisionOutcome> {
    match loaded {
        CustodyAttestationLoadStatus::Malformed(e) => Some(
            CustodyAttestationPayloadCarryingDecisionOutcome::MalformedCustodyAttestationPayload(
                e.clone(),
            ),
        ),
        CustodyAttestationLoadStatus::Absent | CustodyAttestationLoadStatus::Available(_) => None,
    }
}

/// Internal — handle the absent-carrier case under the active attestation
/// policy. Returns `None` only when the carrier is `Available`.
fn absent_or_available_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> Option<CustodyAttestationPayloadCarryingDecisionOutcome> {
    match loaded {
        CustodyAttestationLoadStatus::Absent => match ctx.attestation_policy {
            CustodyAttestationPolicy::Disabled => {
                Some(CustodyAttestationPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied)
            }
            other => Some(
                CustodyAttestationPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent {
                    policy: other,
                },
            ),
        },
        CustodyAttestationLoadStatus::Available(_) => None,
        // Already short-circuited by [`malformed_payload_shortcircuit`].
        CustodyAttestationLoadStatus::Malformed(_) => None,
    }
}

/// Internal — invoke the Run 205 lifecycle + governance + custody +
/// attestation composition with the call-site context inputs.
fn run_205_validate(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    parts: &CustodyAttestationParts,
    is_peer_driven_apply_preflight: bool,
) -> CustodyMetadataAttestationOutcome {
    validate_custody_metadata_and_attestation(
        ctx.custody_attestation,
        ctx.candidate,
        ctx.persisted,
        ctx.trust_domain,
        ctx.expected_governance_authority_class,
        ctx.expected_lifecycle_action,
        ctx.expected_candidate_digest,
        ctx.expected_authority_domain_sequence,
        ctx.expected_custody_key_id,
        ctx.custody_policy,
        &parts.evidence,
        &parts.input,
        ctx.attestation_policy,
        ctx.now_unix,
        is_peer_driven_apply_preflight,
    )
}

/// Internal — generic per-surface routing entry shared by every
/// non-`peer_driven_drain` surface.
fn route_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
    is_peer_driven_apply_preflight: bool,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    if let Some(short) = malformed_payload_shortcircuit(loaded) {
        return short;
    }
    if let Some(short) = absent_or_available_decision(ctx, loaded) {
        return short;
    }
    let parts = match loaded {
        CustodyAttestationLoadStatus::Available(p) => p,
        // Unreachable: short-circuited above.
        _ => unreachable!("malformed_payload_shortcircuit / absent_or_available_decision handled"),
    };
    CustodyAttestationPayloadCarryingDecisionOutcome::Callsite(run_205_validate(
        ctx,
        parts,
        is_peer_driven_apply_preflight,
    ))
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// `--p2p-trust-bundle-reload-check` validation-only call-site.
/// Validation-only mutation contract: the caller MUST drop the returned
/// outcome and MUST NOT persist a marker, advance the bundle-signing
/// sequence, swap live trust state, evict sessions, or invoke Run 070.
pub fn route_loaded_custody_attestation_to_reload_check_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// `--p2p-trust-bundle-reload-apply-*` mutating-preflight call-site. A
/// malformed carrier short-circuits before the verifier is invoked,
/// before any sequence/marker write, and before any Run 070 call.
pub fn route_loaded_custody_attestation_to_reload_apply_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// startup `--p2p-trust-bundle` mutating-preflight call-site.
pub fn route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// SIGHUP live trust-bundle reload mutating-preflight call-site.
pub fn route_loaded_custody_attestation_to_sighup_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// local `--p2p-trust-bundle-peer-candidate-check` validation-only
/// call-site.
pub fn route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// live inbound `0x05` peer-candidate validation-only call-site. An
/// invalid live `0x05` custody-attestation candidate (malformed payload,
/// absent under non-`Disabled` policy, or rejected by the Run 205
/// verifier) is **not propagated, staged, or applied** — the rejection
/// short-circuits at this routing helper before any staging path is
/// reached.
pub fn route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 207 — route a parsed [`CustodyAttestationLoadStatus`] through the
/// Run 150 peer-driven apply drain coordinator preflight call-site.
///
/// **Surface-level MainNet refusal.** Even if the active
/// [`CustodyAttestationPolicy`] is `FixtureAttestationAllowed` and a
/// fully-valid fixture custody attestation is supplied, this entry
/// refuses MainNet peer-driven apply unconditionally and returns
/// [`CustodyAttestationPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
/// before the verifier is invoked, mirroring the Run 152 MainNet refusal
/// at the calling surface. Non-MainNet candidates fall through to the
/// shared composition with the peer-driven-apply preflight flag set so
/// the Run 205 composition layers its own MainNet refusal.
pub fn route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome {
    if ctx.binds_mainnet(loaded.as_parts()) {
        return CustodyAttestationPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused;
    }
    route_callsite_decision(ctx, loaded, true)
}

// ===========================================================================
// Convenience constructor + reachability / fail-closed helpers
// ===========================================================================

/// Run 207 — convenience constructor mirroring the Run 196
/// `callsite_context_for_remote_signer` helper. Builds a
/// [`CustodyAttestationCallsiteContext`] from the natural production
/// call-site inputs the preflight already has in hand.
#[allow(clippy::too_many_arguments)]
pub fn callsite_context_for_custody_attestation<'a>(
    custody_attestation: &'a AuthorityCustodyAttestation,
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    trust_domain: &'a AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &'a str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&'a str>,
    custody_policy: AuthorityCustodyPolicy,
    attestation_policy: CustodyAttestationPolicy,
    now_unix: u64,
) -> CustodyAttestationCallsiteContext<'a> {
    CustodyAttestationCallsiteContext {
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        attestation_policy,
        now_unix,
    }
}

/// Run 207 — explicit fail-closed helper mirroring the Run 196 / Run 205
/// helpers. Returns `true` iff the trust-domain environment is MainNet.
/// Pure data — never reads attestation material.
pub fn mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 207 — grep-verifiable reachability helper. Routes the carried
/// custody-attestation parts directly into the Run 205
/// [`verify_custody_attestation`] verifier (without the Run 188 custody
/// composition). Returns `None` when the carrier is not `Available`.
pub fn verify_loaded_custody_attestation(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
) -> Option<CustodyAttestationOutcome> {
    loaded.as_parts().map(|parts| {
        verify_custody_attestation(
            &parts.evidence,
            &parts.input,
            ctx.trust_domain,
            ctx.attestation_policy,
        )
    })
}

/// Run 207 — grep-verifiable reachability helper. Routes the carried
/// custody-attestation parts through the Run 205
/// [`validate_lifecycle_custody_and_attestation`] full lifecycle +
/// governance + custody + attestation composition. Returns `None` when
/// the carrier is not `Available`.
pub fn validate_loaded_lifecycle_custody_and_attestation(
    ctx: &CustodyAttestationCallsiteContext<'_>,
    loaded: &CustodyAttestationLoadStatus,
    is_peer_driven_apply_preflight: bool,
) -> Option<CustodyMetadataAttestationOutcome> {
    loaded.as_parts().map(|parts| {
        validate_lifecycle_custody_and_attestation(
            ctx.custody_attestation,
            ctx.candidate,
            ctx.persisted,
            ctx.trust_domain,
            ctx.expected_governance_authority_class,
            ctx.expected_lifecycle_action,
            ctx.expected_candidate_digest,
            ctx.expected_authority_domain_sequence,
            ctx.expected_custody_key_id,
            ctx.custody_policy,
            &parts.evidence,
            &parts.input,
            ctx.attestation_policy,
            ctx.now_unix,
            is_peer_driven_apply_preflight,
        )
    })
}