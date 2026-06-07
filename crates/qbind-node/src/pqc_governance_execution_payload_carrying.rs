//! Run 213 — source/test governance-execution payload carrying and
//! production-context preflight wiring.
//!
//! ## Strict scope (Run 213)
//!
//! * **Source/test only.** Run 213 does **not** capture release-binary
//!   evidence; release-binary governance-execution payload/carrying
//!   evidence is deferred to **Run 214**.
//! * **No real governance execution engine, no real on-chain governance
//!   proof verifier, no validator-set rotation.** The Run 211
//!   [`crate::pqc_governance_execution_policy`] production / on-chain /
//!   MainNet governance execution evaluators remain callable but fail
//!   closed as unavailable.
//! * **No MainNet governance enablement and no MainNet peer-driven apply
//!   enablement.** The Run 147/148/152 MainNet refusal at the
//!   peer-driven apply surface remains intact even with a fully-valid
//!   DevNet/TestNet fixture governance execution decision carried through
//!   this Run 213 payload layer.
//! * **No real KMS/HSM backend, no real RemoteSigner backend, no
//!   production signing-key custody.**
//! * **No marker / sequence-file / authority-marker / trust-bundle core
//!   schema change.** The carrier is a strictly additive, optional
//!   sibling on the existing v2 ratification sidecar JSON alongside the
//!   Run 167 `governance_authority_proof`, Run 184
//!   `onchain_governance_proof`, Run 190 `authority_custody_attestation`,
//!   Run 196 `remote_signer_attestation`, and Run 207
//!   `custody_attestation` siblings: legacy no-governance-execution
//!   payloads continue to parse and to be accepted under the default
//!   [`GovernanceExecutionPolicy::Disabled`] policy bit-for-bit.
//!
//! Run 213 does **not** weaken any prior run (Runs 070, 130–212) and does
//! **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 213 the Run 211 typed [`GovernanceExecutionInput`] and
//! [`GovernanceExecutionDecision`] could only reach the Run 211 evaluator
//! via in-process source/test construction: no production payload/context
//! ever delivered governance-execution material, and the Run 211
//! [`evaluate_governance_execution_policy`] /
//! [`evaluate_governance_execution_with_peer_driven_guard`] evaluators
//! were never reached from a production call site.
//!
//! Run 213 closes that gap at the source/test level by adding:
//!
//! 1. An **additive optional sibling field** —
//!    [`GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD`] — on the same v2
//!    ratification sidecar JSON document already used by the Run 167 /
//!    184 / 190 / 196 / 207 siblings.
//! 2. A wire/context representation —
//!    [`GovernanceExecutionPayloadWire`] (combining
//!    [`GovernanceExecutionInputWire`] and
//!    [`GovernanceExecutionDecisionWire`]) — with an explicit
//!    `schema_version` plus string-tagged
//!    [`GovernanceExecutionClassWire`] / [`GovernanceExecutionActionWire`].
//!    The wire form converts into the internal Run 211 types via
//!    [`GovernanceExecutionPayloadWire::to_parts`]; an unknown
//!    `schema_version` or an empty required field fails closed.
//! 3. A typed [`GovernanceExecutionLoadStatus`] (`Absent` / `Available` /
//!    `Malformed`) parallel to the Run 207
//!    [`crate::pqc_custody_attestation_payload_carrying::CustodyAttestationLoadStatus`].
//! 4. Typed [`GovernanceExecutionWireParseError`] /
//!    [`GovernanceExecutionPayloadParseError`] separating wire-form
//!    structural failures from JSON-shape failures.
//! 5. A pure
//!    [`parse_optional_governance_execution_sibling_from_json_value`]
//!    helper extracting the optional sibling from a generic
//!    `serde_json::Value` envelope.
//! 6. A combined v2 sidecar loader
//!    [`load_v2_ratification_sidecar_with_governance_execution_from_path`]
//!    (and bytes variant) returning the typed
//!    [`qbind_ledger::BundleSigningRatificationV2`] together with the
//!    Run 213 [`GovernanceExecutionLoadStatus`].
//! 7. A typed [`GovernanceExecutionCallsiteContext`] — the natural
//!    production call-site inputs already available at every Run 211
//!    governance-execution decision (the caller-derived
//!    [`GovernanceExecutionExpectations`], the trust domain, and the
//!    active [`GovernanceExecutionPolicy`]).
//! 8. Seven typed per-surface routing helpers
//!    ([`route_loaded_governance_execution_to_*_callsite_decision`])
//!    binding a parsed [`GovernanceExecutionLoadStatus`] to the seven
//!    production v2 marker-decision surfaces (reload-check / reload-apply
//!    / startup `--p2p-trust-bundle` / SIGHUP / local
//!    peer-candidate-check / live inbound `0x05` / peer-driven drain)
//!    with:
//!      * a typed
//!        [`GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload`]
//!        variant placed *in front of* the Run 211 boundary so a
//!        malformed carrier fails closed BEFORE the evaluator is invoked,
//!        BEFORE any sequence/marker write, BEFORE any live trust swap,
//!        BEFORE any session eviction, and BEFORE any Run 070 call;
//!      * a typed
//!        [`GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent`]
//!        variant when the active policy requires material and the
//!        carrier is absent;
//!      * a typed
//!        [`GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied`]
//!        bypass variant when the active policy is `Disabled` and the
//!        carrier is absent — the legacy no-governance-execution payload
//!        compatibility variant;
//!      * a typed
//!        [`GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
//!        variant on the peer-driven drain surface that fires *before*
//!        the evaluator regardless of governance-execution contents,
//!        mirroring the Run 147 / 148 / 152 MainNet refusal;
//!      * an inner Run 211 [`GovernanceExecutionOutcome`] for every
//!        parsed, present carrier.
//!
//! ## Pure / non-mutating
//!
//! The loaders perform read-only file I/O. The routing helpers perform no
//! I/O. No marker write, no sequence write, no live trust swap, no
//! session eviction, no Run 070 call.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_execution_policy::{
    evaluate_governance_execution_policy, evaluate_governance_execution_with_peer_driven_guard,
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionComposedOutcome,
    GovernanceExecutionDecision, GovernanceExecutionExpectations, GovernanceExecutionInput,
    GovernanceExecutionOutcome, GovernanceExecutionPolicy, GovernanceQuorumThreshold,
};
use crate::pqc_governance_proof_wire::GovernanceAuthorityClassWire;
use crate::pqc_ratification_input::VersionedRatificationInputError;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Sibling field name + schema version
// ===========================================================================

/// JSON sibling field name carrying the Run 213 optional
/// [`GovernanceExecutionPayloadWire`] on the v2 ratification sidecar
/// envelope.
///
/// The field is strictly additive: legacy sidecars without this sibling
/// parse exactly as before and yield
/// [`GovernanceExecutionLoadStatus::Absent`].
pub const GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: &str = "governance_execution";

/// Run 213 — wire schema version for the additive optional
/// [`GovernanceExecutionPayloadWire`] sibling. Versioning is additive: a
/// future run extending the wire shape MUST bump this constant. Run 213
/// rejects unknown versions with
/// [`GovernanceExecutionWireParseError::UnknownSchemaVersion`].
pub const GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION: u32 = 1;

// ===========================================================================
// Wire-tagged governance execution class
// ===========================================================================

/// Run 213 — wire-tagged form of the Run 211
/// [`GovernanceExecutionClass`].
///
/// The Run 211 [`GovernanceExecutionClass`] does not derive `Serialize` /
/// `Deserialize` (it is an internal symbol), so Run 213 mirrors it as a
/// string-tagged wire enum and converts in
/// [`GovernanceExecutionInputWire::to_input`]. Unknown tag values map to
/// [`GovernanceExecutionClass::Unknown`] which the Run 211 evaluator
/// already rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceExecutionClassWire {
    Disabled,
    FixtureGovernance,
    EmergencyCouncilFixture,
    OnChainGovernanceUnavailable,
    ProductionGovernanceUnavailable,
    MainnetGovernanceUnavailable,
    Unknown,
}

impl GovernanceExecutionClassWire {
    pub const fn to_class(self) -> GovernanceExecutionClass {
        match self {
            Self::Disabled => GovernanceExecutionClass::Disabled,
            Self::FixtureGovernance => GovernanceExecutionClass::FixtureGovernance,
            Self::EmergencyCouncilFixture => GovernanceExecutionClass::EmergencyCouncilFixture,
            Self::OnChainGovernanceUnavailable => {
                GovernanceExecutionClass::OnChainGovernanceUnavailable
            }
            Self::ProductionGovernanceUnavailable => {
                GovernanceExecutionClass::ProductionGovernanceUnavailable
            }
            Self::MainnetGovernanceUnavailable => {
                GovernanceExecutionClass::MainnetGovernanceUnavailable
            }
            Self::Unknown => GovernanceExecutionClass::Unknown,
        }
    }

    pub const fn from_class(c: GovernanceExecutionClass) -> Self {
        match c {
            GovernanceExecutionClass::Disabled => Self::Disabled,
            GovernanceExecutionClass::FixtureGovernance => Self::FixtureGovernance,
            GovernanceExecutionClass::EmergencyCouncilFixture => Self::EmergencyCouncilFixture,
            GovernanceExecutionClass::OnChainGovernanceUnavailable => {
                Self::OnChainGovernanceUnavailable
            }
            GovernanceExecutionClass::ProductionGovernanceUnavailable => {
                Self::ProductionGovernanceUnavailable
            }
            GovernanceExecutionClass::MainnetGovernanceUnavailable => {
                Self::MainnetGovernanceUnavailable
            }
            GovernanceExecutionClass::Unknown => Self::Unknown,
        }
    }
}

// ===========================================================================
// Wire-tagged governance action
// ===========================================================================

/// Run 213 — wire-tagged form of the Run 211 [`GovernanceAction`].
///
/// Mirrors every Run 211 governance action, including the unsupported
/// policy-change and validator-set-rotation request placeholders, so a
/// carried unsupported action reaches the Run 211 evaluator and is
/// rejected there (rather than being silently dropped at the wire layer).
/// Unknown tag values map to [`GovernanceAction::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceExecutionActionWire {
    AuthoritySigningKeyInitialActivation,
    Rotate,
    Retire,
    Revoke,
    EmergencyRevoke,
    PolicyChangeRequest,
    CustodyPolicyChangeRequest,
    RemoteSignerPolicyChangeRequest,
    CustodyAttestationPolicyChangeRequest,
    ValidatorSetRotationRequest,
    Unknown,
}

impl GovernanceExecutionActionWire {
    pub const fn to_action(self) -> GovernanceAction {
        match self {
            Self::AuthoritySigningKeyInitialActivation => {
                GovernanceAction::AuthoritySigningKeyInitialActivation
            }
            Self::Rotate => GovernanceAction::Rotate,
            Self::Retire => GovernanceAction::Retire,
            Self::Revoke => GovernanceAction::Revoke,
            Self::EmergencyRevoke => GovernanceAction::EmergencyRevoke,
            Self::PolicyChangeRequest => GovernanceAction::PolicyChangeRequest,
            Self::CustodyPolicyChangeRequest => GovernanceAction::CustodyPolicyChangeRequest,
            Self::RemoteSignerPolicyChangeRequest => {
                GovernanceAction::RemoteSignerPolicyChangeRequest
            }
            Self::CustodyAttestationPolicyChangeRequest => {
                GovernanceAction::CustodyAttestationPolicyChangeRequest
            }
            Self::ValidatorSetRotationRequest => GovernanceAction::ValidatorSetRotationRequest,
            Self::Unknown => GovernanceAction::Unknown,
        }
    }

    pub const fn from_action(a: GovernanceAction) -> Self {
        match a {
            GovernanceAction::AuthoritySigningKeyInitialActivation => {
                Self::AuthoritySigningKeyInitialActivation
            }
            GovernanceAction::Rotate => Self::Rotate,
            GovernanceAction::Retire => Self::Retire,
            GovernanceAction::Revoke => Self::Revoke,
            GovernanceAction::EmergencyRevoke => Self::EmergencyRevoke,
            GovernanceAction::PolicyChangeRequest => Self::PolicyChangeRequest,
            GovernanceAction::CustodyPolicyChangeRequest => Self::CustodyPolicyChangeRequest,
            GovernanceAction::RemoteSignerPolicyChangeRequest => {
                Self::RemoteSignerPolicyChangeRequest
            }
            GovernanceAction::CustodyAttestationPolicyChangeRequest => {
                Self::CustodyAttestationPolicyChangeRequest
            }
            GovernanceAction::ValidatorSetRotationRequest => Self::ValidatorSetRotationRequest,
            GovernanceAction::Unknown => Self::Unknown,
        }
    }
}

// ===========================================================================
// Wire-tagged quorum / threshold metadata
// ===========================================================================

/// Run 213 — wire-safe encoding of the Run 211
/// [`GovernanceQuorumThreshold`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GovernanceQuorumThresholdWire {
    pub approvals: u32,
    pub participants: u32,
    pub required_threshold: u32,
}

impl GovernanceQuorumThresholdWire {
    pub const fn to_threshold(self) -> GovernanceQuorumThreshold {
        GovernanceQuorumThreshold::new(self.approvals, self.participants, self.required_threshold)
    }

    pub const fn from_threshold(q: GovernanceQuorumThreshold) -> Self {
        Self {
            approvals: q.approvals,
            participants: q.participants,
            required_threshold: q.required_threshold,
        }
    }
}

// ===========================================================================
// Wire forms
// ===========================================================================

/// Run 213 — wire-safe encoding of the Run 211
/// [`GovernanceExecutionInput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExecutionInputWire {
    pub execution_version: u16,
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub governance_class: GovernanceExecutionClassWire,
    pub proposal_id: String,
    pub decision_id: String,
    pub authority_root_fingerprint: String,
    pub current_signing_key_fingerprint: String,
    pub candidate_signing_key_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_signing_key_fingerprint: Option<String>,
    pub governance_action: GovernanceExecutionActionWire,
    pub lifecycle_action: LocalLifecycleAction,
    pub candidate_digest: String,
    pub authority_domain_sequence: u64,
    pub governance_proof_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_chain_proof_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_attestation_digest: Option<String>,
    pub suite_id: u8,
    pub effective_epoch: u64,
    pub expiry_epoch: u64,
    pub replay_nonce: String,
    pub quorum: GovernanceQuorumThresholdWire,
    pub emergency_flag: bool,
}

impl GovernanceExecutionInputWire {
    /// Convert into the internal Run 211 [`GovernanceExecutionInput`].
    /// Fails closed when any mandatory string field is empty.
    pub fn to_input(&self) -> Result<GovernanceExecutionInput, GovernanceExecutionWireParseError> {
        let input = GovernanceExecutionInput {
            execution_version: self.execution_version,
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            governance_class: self.governance_class.to_class(),
            proposal_id: self.proposal_id.clone(),
            decision_id: self.decision_id.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            current_signing_key_fingerprint: self.current_signing_key_fingerprint.clone(),
            candidate_signing_key_fingerprint: self.candidate_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: self.revoked_signing_key_fingerprint.clone(),
            governance_action: self.governance_action.to_action(),
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            governance_proof_digest: self.governance_proof_digest.clone(),
            on_chain_proof_digest: self.on_chain_proof_digest.clone(),
            custody_attestation_digest: self.custody_attestation_digest.clone(),
            suite_id: self.suite_id,
            effective_epoch: self.effective_epoch,
            expiry_epoch: self.expiry_epoch,
            replay_nonce: self.replay_nonce.clone(),
            quorum: self.quorum.to_threshold(),
            emergency_flag: self.emergency_flag,
        };
        if !input.is_well_formed() {
            return Err(GovernanceExecutionWireParseError::EmptyRequiredField { part: "input" });
        }
        Ok(input)
    }

    /// Source/test helper: build a wire form from an in-process Run 211
    /// [`GovernanceExecutionInput`].
    pub fn from_input(i: &GovernanceExecutionInput) -> Self {
        Self {
            execution_version: i.execution_version,
            environment: i.environment,
            chain_id: i.chain_id.clone(),
            genesis_hash: i.genesis_hash.clone(),
            governance_class: GovernanceExecutionClassWire::from_class(i.governance_class),
            proposal_id: i.proposal_id.clone(),
            decision_id: i.decision_id.clone(),
            authority_root_fingerprint: i.authority_root_fingerprint.clone(),
            current_signing_key_fingerprint: i.current_signing_key_fingerprint.clone(),
            candidate_signing_key_fingerprint: i.candidate_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: i.revoked_signing_key_fingerprint.clone(),
            governance_action: GovernanceExecutionActionWire::from_action(i.governance_action),
            lifecycle_action: i.lifecycle_action,
            candidate_digest: i.candidate_digest.clone(),
            authority_domain_sequence: i.authority_domain_sequence,
            governance_proof_digest: i.governance_proof_digest.clone(),
            on_chain_proof_digest: i.on_chain_proof_digest.clone(),
            custody_attestation_digest: i.custody_attestation_digest.clone(),
            suite_id: i.suite_id,
            effective_epoch: i.effective_epoch,
            expiry_epoch: i.expiry_epoch,
            replay_nonce: i.replay_nonce.clone(),
            quorum: GovernanceQuorumThresholdWire::from_threshold(i.quorum),
            emergency_flag: i.emergency_flag,
        }
    }
}

/// Run 213 — wire-safe encoding of the Run 211
/// [`GovernanceExecutionDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExecutionDecisionWire {
    pub execution_version: u16,
    pub proposal_id: String,
    pub decision_id: String,
    pub approved: bool,
    pub authorized_governance_action: GovernanceExecutionActionWire,
    pub authorized_lifecycle_action: LocalLifecycleAction,
    pub authorized_authority_root_fingerprint: String,
    pub authorized_candidate_digest: String,
    pub authorized_sequence: u64,
    pub effective_epoch: u64,
    pub expiry_epoch: u64,
    pub decision_commitment: String,
    pub issuer_authority_class: GovernanceAuthorityClassWire,
    pub emergency_flag: bool,
    pub replay_nonce: String,
}

impl GovernanceExecutionDecisionWire {
    /// Convert into the internal Run 211 [`GovernanceExecutionDecision`].
    /// Fails closed when any mandatory string field is empty.
    pub fn to_decision(
        &self,
    ) -> Result<GovernanceExecutionDecision, GovernanceExecutionWireParseError> {
        let decision = GovernanceExecutionDecision {
            execution_version: self.execution_version,
            proposal_id: self.proposal_id.clone(),
            decision_id: self.decision_id.clone(),
            approved: self.approved,
            authorized_governance_action: self.authorized_governance_action.to_action(),
            authorized_lifecycle_action: self.authorized_lifecycle_action,
            authorized_authority_root_fingerprint: self
                .authorized_authority_root_fingerprint
                .clone(),
            authorized_candidate_digest: self.authorized_candidate_digest.clone(),
            authorized_sequence: self.authorized_sequence,
            effective_epoch: self.effective_epoch,
            expiry_epoch: self.expiry_epoch,
            decision_commitment: self.decision_commitment.clone(),
            issuer_authority_class: self.issuer_authority_class.to_class(),
            emergency_flag: self.emergency_flag,
            replay_nonce: self.replay_nonce.clone(),
        };
        if !decision.is_well_formed() {
            return Err(GovernanceExecutionWireParseError::EmptyRequiredField { part: "decision" });
        }
        Ok(decision)
    }

    /// Source/test helper: build a wire form from an in-process Run 211
    /// [`GovernanceExecutionDecision`].
    pub fn from_decision(d: &GovernanceExecutionDecision) -> Self {
        Self {
            execution_version: d.execution_version,
            proposal_id: d.proposal_id.clone(),
            decision_id: d.decision_id.clone(),
            approved: d.approved,
            authorized_governance_action: GovernanceExecutionActionWire::from_action(
                d.authorized_governance_action,
            ),
            authorized_lifecycle_action: d.authorized_lifecycle_action,
            authorized_authority_root_fingerprint: d.authorized_authority_root_fingerprint.clone(),
            authorized_candidate_digest: d.authorized_candidate_digest.clone(),
            authorized_sequence: d.authorized_sequence,
            effective_epoch: d.effective_epoch,
            expiry_epoch: d.expiry_epoch,
            decision_commitment: d.decision_commitment.clone(),
            issuer_authority_class: GovernanceAuthorityClassWire::from_class(
                d.issuer_authority_class,
            ),
            emergency_flag: d.emergency_flag,
            replay_nonce: d.replay_nonce.clone(),
        }
    }
}

/// Run 213 — combined additive wire-form governance-execution material
/// carried as an optional sibling on the v2 ratification sidecar JSON.
///
/// Bundles the [`GovernanceExecutionInputWire`] and the
/// [`GovernanceExecutionDecisionWire`] behind a single `schema_version`.
/// Old sidecars (Runs 167–212) that do not carry this sibling continue to
/// parse and validate exactly as before — the sibling is extracted from
/// the surrounding `serde_json::Value` and is absent when missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExecutionPayloadWire {
    pub schema_version: u32,
    pub input: GovernanceExecutionInputWire,
    pub decision: GovernanceExecutionDecisionWire,
}

impl GovernanceExecutionPayloadWire {
    /// Convert the Run 213 combined wire form into the internal Run 211
    /// parts.
    ///
    /// Fails closed when:
    ///
    /// * the `schema_version` is not the one Run 213 supports
    ///   ([`GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION`]);
    /// * any required string field of the input / decision is empty.
    ///
    /// The conversion does not interpret the placeholder decision
    /// commitment — all trust-domain / lifecycle / governance / sequence
    /// / candidate-digest / suite / window / quorum / replay checks are
    /// deferred to the Run 211 evaluator.
    pub fn to_parts(&self) -> Result<GovernanceExecutionParts, GovernanceExecutionWireParseError> {
        if self.schema_version != GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION {
            return Err(GovernanceExecutionWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
            });
        }
        let input = self.input.to_input()?;
        let decision = self.decision.to_decision()?;
        Ok(GovernanceExecutionParts { input, decision })
    }

    /// Source/test helper: build a Run 213 combined wire form from
    /// in-process Run 211 parts.
    pub fn from_parts(
        input: &GovernanceExecutionInput,
        decision: &GovernanceExecutionDecision,
    ) -> Self {
        Self {
            schema_version: GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
            input: GovernanceExecutionInputWire::from_input(input),
            decision: GovernanceExecutionDecisionWire::from_decision(decision),
        }
    }
}

/// Run 213 — the internal Run 211 governance-execution parts produced by
/// converting a well-formed [`GovernanceExecutionPayloadWire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionParts {
    pub input: GovernanceExecutionInput,
    pub decision: GovernanceExecutionDecision,
}

impl GovernanceExecutionParts {
    /// Run 213 — deterministic Run 211 input digest of the carried input.
    /// Preserved bit-for-bit through wire conversion.
    pub fn input_digest(&self) -> String {
        self.input.input_digest()
    }

    /// Run 213 — deterministic Run 211 decision digest of the carried
    /// decision. Preserved bit-for-bit through wire conversion.
    pub fn decision_digest(&self) -> String {
        self.decision.decision_digest()
    }
}

// ===========================================================================
// Typed wire-form parse error
// ===========================================================================

/// Run 213 — typed wire-form parse error emitted by
/// [`GovernanceExecutionPayloadWire::to_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionWireParseError {
    /// The wire form's `schema_version` is not the one Run 213 supports.
    UnknownSchemaVersion { got: u32, expected: u32 },
    /// A required string field of the named part (`input` / `decision`)
    /// was empty.
    EmptyRequiredField { part: &'static str },
}

impl std::fmt::Display for GovernanceExecutionWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-213] unsupported governance_execution schema_version={} (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField { part } => write!(
                f,
                "[run-213] governance_execution {} has an empty required field. Fail closed.",
                part
            ),
        }
    }
}

impl std::error::Error for GovernanceExecutionWireParseError {}

// ===========================================================================
// Typed payload-level parse error
// ===========================================================================

/// Run 213 — typed parse error emitted at the payload/sibling boundary
/// when a `governance_execution` sibling is present but cannot be
/// converted into typed Run 211 parts.
///
/// Distinct from [`GovernanceExecutionWireParseError`] so that JSON-shape
/// failures (payload-level) are kept separate from wire-form structural
/// failures (Run 213 schema-level). Both map to a single
/// [`GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload`]
/// variant at the call-site routing helpers and never to a partially
/// parsed governance execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionPayloadParseError {
    /// JSON decoding of the optional `governance_execution` sibling field
    /// failed.
    Json { error: String },
    /// The sibling decoded as a [`GovernanceExecutionPayloadWire`] but the
    /// wire form failed structural validation (unknown schema_version,
    /// empty required field).
    Wire(GovernanceExecutionWireParseError),
}

impl std::fmt::Display for GovernanceExecutionPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-213] failed to JSON-decode optional `{}` sibling: {}. Fail closed.",
                GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD, error
            ),
            Self::Wire(e) => write!(f, "[run-213] {}", e),
        }
    }
}

impl std::error::Error for GovernanceExecutionPayloadParseError {}

impl From<GovernanceExecutionWireParseError> for GovernanceExecutionPayloadParseError {
    fn from(e: GovernanceExecutionWireParseError) -> Self {
        Self::Wire(e)
    }
}

// ===========================================================================
// Typed load status
// ===========================================================================

/// Run 213 — typed load status of the optional
/// [`GovernanceExecutionPayloadWire`] sibling on the v2 ratification
/// sidecar JSON / `0x05` peer-candidate envelope.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionLoadStatus {
    /// The carrier carried no `governance_execution` sibling field.
    /// Backwards-compatible with all pre-Run-213 v2 sidecars and live
    /// envelopes — a no-governance-execution payload remains accepted
    /// under the default [`GovernanceExecutionPolicy::Disabled`] policy.
    Absent,
    /// The carrier carried a well-formed wire payload which was
    /// structurally converted into the typed Run 211 parts. The parts
    /// have NOT yet been validated against trust-domain / lifecycle /
    /// governance / window / quorum / replay bindings — validation is
    /// performed by the Run 213 per-surface routing helpers which
    /// delegate to the Run 211 evaluator.
    Available(GovernanceExecutionParts),
    /// The carrier carried a `governance_execution` sibling field that
    /// failed to decode at the JSON layer or failed wire structural
    /// validation. Always fails closed at the Run 213 per-surface routing
    /// helpers.
    Malformed(GovernanceExecutionPayloadParseError),
}

impl GovernanceExecutionLoadStatus {
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
    pub fn as_parts(&self) -> Option<&GovernanceExecutionParts> {
        match self {
            Self::Available(p) => Some(p),
            Self::Absent | Self::Malformed(_) => None,
        }
    }

    /// Return the typed parse error when the carrier was malformed.
    pub fn malformed_error(&self) -> Option<&GovernanceExecutionPayloadParseError> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::Absent | Self::Available(_) => None,
        }
    }
}

// ===========================================================================
// Sibling parsing
// ===========================================================================

/// Run 213 — pure parse helper that extracts the optional
/// `governance_execution` sibling from a generic JSON value and returns a
/// typed [`GovernanceExecutionLoadStatus`].
///
/// Behaviour:
///
/// * `value` has no `governance_execution` field, or the field is `null`:
///   returns [`GovernanceExecutionLoadStatus::Absent`].
/// * `value` has a non-null `governance_execution` field that fails to
///   decode as [`GovernanceExecutionPayloadWire`]: returns
///   [`GovernanceExecutionLoadStatus::Malformed`] carrying a
///   [`GovernanceExecutionPayloadParseError::Json`].
/// * `value` has a well-formed wire object but
///   [`GovernanceExecutionPayloadWire::to_parts`] rejects it (unknown
///   schema version, empty required field): returns
///   [`GovernanceExecutionLoadStatus::Malformed`] carrying the wire parse
///   error.
/// * Otherwise: returns [`GovernanceExecutionLoadStatus::Available`] with
///   the typed Run 211 parts.
///
/// Pure — does not mutate `value` and performs no I/O.
pub fn parse_optional_governance_execution_sibling_from_json_value(
    value: &Value,
) -> GovernanceExecutionLoadStatus {
    let sibling = value.get(GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD);
    match sibling {
        None => GovernanceExecutionLoadStatus::Absent,
        Some(Value::Null) => GovernanceExecutionLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<GovernanceExecutionPayloadWire>(raw.clone()) {
            Ok(wire) => match wire.to_parts() {
                Ok(parts) => GovernanceExecutionLoadStatus::Available(parts),
                Err(e) => GovernanceExecutionLoadStatus::Malformed(
                    GovernanceExecutionPayloadParseError::Wire(e),
                ),
            },
            Err(e) => GovernanceExecutionLoadStatus::Malformed(
                GovernanceExecutionPayloadParseError::Json {
                    error: e.to_string(),
                },
            ),
        },
    }
}

// ===========================================================================
// Combined v2 sidecar loader
// ===========================================================================

/// Run 213 — typed result of loading a v2 ratification sidecar together
/// with the Run 213 [`GovernanceExecutionPayloadWire`] sibling.
///
/// Strictly additive over the prior combined sidecars: pre-Run-213
/// sidecars yield [`GovernanceExecutionLoadStatus::Absent`] in the new
/// field.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecarWithGovernanceExecution {
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    pub governance_execution: GovernanceExecutionLoadStatus,
}

/// Run 213 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse the Run 213 `governance_execution` sibling.
///
/// The optional sibling field is **strictly additive**. A v2 sidecar
/// without it continues to parse as before and yields
/// [`GovernanceExecutionLoadStatus::Absent`]. A sibling that fails to
/// deserialise into its wire form, or that fails wire-form structural
/// validation, yields [`GovernanceExecutionLoadStatus::Malformed`]. The
/// v2 ratification itself is still returned so the caller can fall
/// through the policy/gate pipeline.
///
/// No file write, no marker write, no sequence write, no live trust swap,
/// no session eviction, no Run 070 call.
pub fn load_v2_ratification_sidecar_with_governance_execution_from_path(
    path: &Path,
) -> Result<LoadedV2RatificationSidecarWithGovernanceExecution, VersionedRatificationInputError> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    load_v2_ratification_sidecar_with_governance_execution_from_bytes(&bytes, path)
}

/// Run 213 — bytes-form variant of
/// [`load_v2_ratification_sidecar_with_governance_execution_from_path`].
///
/// Used by validation-only / live-inbound surfaces that already hold the
/// JSON envelope in memory. The `path_for_diagnostics` argument is only
/// used to populate typed [`VersionedRatificationInputError`] variants —
/// it does NOT trigger any file access on this code path.
pub fn load_v2_ratification_sidecar_with_governance_execution_from_bytes(
    bytes: &[u8],
    path_for_diagnostics: &Path,
) -> Result<LoadedV2RatificationSidecarWithGovernanceExecution, VersionedRatificationInputError> {
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
                "Run 213 governance-execution carrier requires v2 sidecar (got schema_version={})",
                version_int
            ),
        });
    }

    // Extract the optional sibling BEFORE re-parsing into the typed
    // ratification, so the sibling cannot poison the v2 parse and so it
    // produces its own typed load status independently.
    let governance_execution = parse_optional_governance_execution_sibling_from_json_value(&value);

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecarWithGovernanceExecution {
        ratification,
        governance_execution,
    })
}

// ===========================================================================
// Wire-encoding helper for the additive sibling
// ===========================================================================

/// Run 213 — additive optional sibling shape used to produce a v2
/// ratification sidecar JSON document that carries a
/// [`GovernanceExecutionPayloadWire`] alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`].
///
/// Source/test helper. Production paths continue to write the
/// `BundleSigningRatificationV2` directly when no governance-execution
/// material is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RatificationSidecarWithGovernanceExecutionWire {
    #[serde(flatten)]
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_execution: Option<GovernanceExecutionPayloadWire>,
}

// ===========================================================================
// Call-site context
// ===========================================================================

/// Run 213 — typed bundle of the natural production call-site inputs
/// required to drive a Run 211 governance-execution preflight at any of
/// the seven production v2 marker-decision surfaces.
///
/// Every field is borrowed; the struct is purely a typed argument bundle
/// and never mutates any input. Constructing it is free of I/O. The
/// [`GovernanceExecutionExpectations`] are derived by the calling surface
/// from the persisted candidate metadata and the per-attempt anti-replay
/// material; the [`GovernanceExecutionPolicy`] defaults to `Disabled` in
/// production.
#[derive(Debug)]
pub struct GovernanceExecutionCallsiteContext<'a> {
    /// Active trust domain at the call site.
    pub trust_domain: &'a AuthorityTrustDomain,
    /// Caller-derived Run 211 expectations binding the persisted
    /// candidate metadata + per-attempt anti-replay material.
    pub expectations: &'a GovernanceExecutionExpectations,
    /// Active Run 211 [`GovernanceExecutionPolicy`]. Default in
    /// production is [`GovernanceExecutionPolicy::Disabled`].
    pub policy: GovernanceExecutionPolicy,
}

impl<'a> GovernanceExecutionCallsiteContext<'a> {
    /// Run 213 — pure surface-level MainNet refusal helper. Returns
    /// `true` iff the trust domain, the expectations, or any carried
    /// part binds MainNet. Used by the peer-driven drain routing helper
    /// before the evaluator is invoked, mirroring the Run 152 MainNet
    /// peer-driven-apply refusal.
    pub fn binds_mainnet(&self, parts: Option<&GovernanceExecutionParts>) -> bool {
        self.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || self.expectations.expected_environment == TrustBundleEnvironment::Mainnet
            || parts
                .map(|p| p.input.environment == TrustBundleEnvironment::Mainnet)
                .unwrap_or(false)
    }
}

// ===========================================================================
// Routing into Run 211 evaluation
// ===========================================================================

/// Run 213 — typed outcome of routing a Run 213
/// [`GovernanceExecutionLoadStatus`] through any of the seven production
/// v2 marker-decision surfaces.
///
/// Adds typed variants in front of the Run 211
/// [`GovernanceExecutionOutcome`]:
///
/// * [`Self::MalformedGovernanceExecutionPayload`] — the carrier sibling
///   was present but malformed at the JSON or wire-structural level.
///   Always fail-closed regardless of policy. The Run 211 evaluator is
///   NOT invoked.
/// * [`Self::GovernanceExecutionRequiredButAbsent`] — the active policy
///   requires material (every non-`Disabled` policy) and the carrier
///   sibling is absent. Always fail-closed.
/// * [`Self::NoGovernanceExecutionSupplied`] — the carrier sibling is
///   absent and the active policy is
///   [`GovernanceExecutionPolicy::Disabled`]. Legacy
///   no-governance-execution payload compatibility variant; the calling
///   surface continues with its pre-Run-213 path. The Run 211 evaluator
///   is NOT invoked.
/// * [`Self::MainNetPeerDrivenApplyRefused`] — the peer-driven drain
///   surface refuses MainNet unconditionally regardless of
///   governance-execution contents.
/// * [`Self::Callsite`] — wraps the Run 211 [`GovernanceExecutionOutcome`]
///   for every parsed, present carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionPayloadCarryingDecisionOutcome {
    /// The carrier sibling was present but malformed. Fail closed before
    /// any Run 211 evaluation, before any sequence/marker write, before
    /// any live trust swap, before any session eviction, before any Run
    /// 070 call.
    MalformedGovernanceExecutionPayload(GovernanceExecutionPayloadParseError),
    /// The active policy requires material and the carrier sibling is
    /// absent. Fail closed.
    GovernanceExecutionRequiredButAbsent { policy: GovernanceExecutionPolicy },
    /// The carrier sibling is absent and the active policy is `Disabled`.
    /// Legacy no-governance-execution payload compatibility.
    NoGovernanceExecutionSupplied,
    /// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
    /// refusal regardless of governance-execution contents. Surfaced only
    /// by the peer-driven drain routing helper.
    MainNetPeerDrivenApplyRefused,
    /// The carrier sibling parsed and the Run 211 evaluator was invoked.
    /// Carries the typed Run 211 governance-execution outcome.
    Callsite(GovernanceExecutionOutcome),
}

impl GovernanceExecutionPayloadCarryingDecisionOutcome {
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
    /// the legacy no-governance-execution-payload bypass variant.
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::NoGovernanceExecutionSupplied)
    }

    pub fn is_malformed_payload(&self) -> bool {
        matches!(self, Self::MalformedGovernanceExecutionPayload(_))
    }

    pub fn is_required_but_absent(&self) -> bool {
        matches!(self, Self::GovernanceExecutionRequiredButAbsent { .. })
    }

    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Borrow the inner Run 211 outcome, if any.
    pub fn callsite_outcome(&self) -> Option<&GovernanceExecutionOutcome> {
        match self {
            Self::Callsite(o) => Some(o),
            _ => None,
        }
    }
}

/// Internal — short-circuit a malformed-carrier load status into the
/// Run 213 fail-closed outcome. `Absent` and `Available` return `None`,
/// in which case the caller continues per-surface.
fn malformed_payload_shortcircuit(
    loaded: &GovernanceExecutionLoadStatus,
) -> Option<GovernanceExecutionPayloadCarryingDecisionOutcome> {
    match loaded {
        GovernanceExecutionLoadStatus::Malformed(e) => Some(
            GovernanceExecutionPayloadCarryingDecisionOutcome::MalformedGovernanceExecutionPayload(
                e.clone(),
            ),
        ),
        GovernanceExecutionLoadStatus::Absent | GovernanceExecutionLoadStatus::Available(_) => None,
    }
}

/// Internal — handle the absent-carrier case under the active policy.
/// Returns `None` only when the carrier is `Available`.
fn absent_or_available_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> Option<GovernanceExecutionPayloadCarryingDecisionOutcome> {
    match loaded {
        GovernanceExecutionLoadStatus::Absent => match ctx.policy {
            GovernanceExecutionPolicy::Disabled => Some(
                GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied,
            ),
            other => Some(
                GovernanceExecutionPayloadCarryingDecisionOutcome::GovernanceExecutionRequiredButAbsent {
                    policy: other,
                },
            ),
        },
        GovernanceExecutionLoadStatus::Available(_) => None,
        // Already short-circuited by [`malformed_payload_shortcircuit`].
        GovernanceExecutionLoadStatus::Malformed(_) => None,
    }
}

/// Internal — invoke the Run 211 governance-execution evaluator with the
/// call-site context inputs.
fn run_211_evaluate(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    parts: &GovernanceExecutionParts,
) -> GovernanceExecutionOutcome {
    evaluate_governance_execution_policy(
        &parts.input,
        &parts.decision,
        ctx.expectations,
        ctx.trust_domain,
        ctx.policy,
    )
}

/// Internal — generic per-surface routing entry shared by every
/// non-`peer_driven_drain` surface.
fn route_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    if let Some(short) = malformed_payload_shortcircuit(loaded) {
        return short;
    }
    if let Some(short) = absent_or_available_decision(ctx, loaded) {
        return short;
    }
    let parts = match loaded {
        GovernanceExecutionLoadStatus::Available(p) => p,
        // Unreachable: short-circuited above.
        _ => unreachable!("malformed_payload_shortcircuit / absent_or_available_decision handled"),
    };
    GovernanceExecutionPayloadCarryingDecisionOutcome::Callsite(run_211_evaluate(ctx, parts))
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// `--p2p-trust-bundle-reload-check` validation-only call-site.
/// Validation-only mutation contract: the caller MUST drop the returned
/// outcome and MUST NOT persist a marker, advance the bundle-signing
/// sequence, swap live trust state, evict sessions, or invoke Run 070.
pub fn route_loaded_governance_execution_to_reload_check_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// `--p2p-trust-bundle-reload-apply-*` mutating-preflight call-site. A
/// malformed carrier short-circuits before the evaluator is invoked,
/// before any sequence/marker write, and before any Run 070 call.
pub fn route_loaded_governance_execution_to_reload_apply_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// startup `--p2p-trust-bundle` mutating-preflight call-site.
pub fn route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// SIGHUP live trust-bundle reload mutating-preflight call-site.
pub fn route_loaded_governance_execution_to_sighup_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// local `--p2p-trust-bundle-peer-candidate-check` validation-only
/// call-site.
pub fn route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// live inbound `0x05` peer-candidate validation-only call-site. An
/// invalid live `0x05` governance-execution candidate (malformed payload,
/// absent under non-`Disabled` policy, or rejected by the Run 211
/// evaluator) is **not propagated, staged, or applied** — the rejection
/// short-circuits at this routing helper before any staging path is
/// reached.
pub fn route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 213 — route a parsed [`GovernanceExecutionLoadStatus`] through the
/// Run 150 peer-driven apply drain coordinator preflight call-site.
///
/// **Surface-level MainNet refusal.** Even if the active
/// [`GovernanceExecutionPolicy`] is `FixtureGovernanceAllowed` and a
/// fully-valid fixture governance decision is supplied, this entry
/// refuses MainNet peer-driven apply unconditionally and returns
/// [`GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
/// before the evaluator is invoked, mirroring the Run 152 MainNet refusal
/// at the calling surface.
pub fn route_loaded_governance_execution_to_peer_driven_drain_callsite_decision(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    if ctx.binds_mainnet(loaded.as_parts()) {
        return GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused;
    }
    route_callsite_decision(ctx, loaded)
}

// ===========================================================================
// Convenience constructor + reachability / fail-closed helpers
// ===========================================================================

/// Run 213 — convenience constructor mirroring the Run 207
/// `callsite_context_for_custody_attestation` helper. Builds a
/// [`GovernanceExecutionCallsiteContext`] from the natural production
/// call-site inputs the preflight already has in hand.
pub fn callsite_context_for_governance_execution<'a>(
    trust_domain: &'a AuthorityTrustDomain,
    expectations: &'a GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
) -> GovernanceExecutionCallsiteContext<'a> {
    GovernanceExecutionCallsiteContext {
        trust_domain,
        expectations,
        policy,
    }
}

/// Run 213 — explicit fail-closed helper mirroring the Run 207 / Run 211
/// helpers. Returns `true` iff the trust-domain environment is MainNet.
/// Pure data — never reads governance-execution material.
pub fn mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 213 — grep-verifiable reachability helper. Routes the carried
/// governance-execution parts directly into the Run 211
/// [`evaluate_governance_execution_policy`] evaluator. Returns `None`
/// when the carrier is not `Available`.
pub fn evaluate_loaded_governance_execution(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
) -> Option<GovernanceExecutionOutcome> {
    loaded.as_parts().map(|parts| {
        evaluate_governance_execution_policy(
            &parts.input,
            &parts.decision,
            ctx.expectations,
            ctx.trust_domain,
            ctx.policy,
        )
    })
}

/// Run 213 — grep-verifiable reachability helper. Routes the carried
/// governance-execution parts through the Run 211
/// [`evaluate_governance_execution_with_peer_driven_guard`] composition,
/// preserving the MainNet peer-driven-apply refusal. Returns `None` when
/// the carrier is not `Available`.
pub fn evaluate_loaded_governance_execution_with_peer_driven_guard(
    ctx: &GovernanceExecutionCallsiteContext<'_>,
    loaded: &GovernanceExecutionLoadStatus,
    is_peer_driven_apply_preflight: bool,
) -> Option<GovernanceExecutionComposedOutcome> {
    loaded.as_parts().map(|parts| {
        evaluate_governance_execution_with_peer_driven_guard(
            &parts.input,
            &parts.decision,
            ctx.expectations,
            ctx.trust_domain,
            ctx.policy,
            is_peer_driven_apply_preflight,
        )
    })
}
