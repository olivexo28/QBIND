//! Run 222 — source/test production governance execution evaluator
//! interface boundary.
//!
//! Source/test only. Run 222 does **not** implement a real governance
//! execution engine, a real on-chain governance proof verifier, MainNet
//! governance enablement, MainNet peer-driven apply enablement, or
//! validator-set rotation. Nor does it implement a real KMS/HSM backend,
//! a real RemoteSigner backend, or production signing-key custody.
//!
//! Run 211 (`pqc_governance_execution_policy`) added the typed
//! governance-execution policy boundary (input / decision / expectations /
//! evaluator-policy / outcome). Run 213 added the payload carrying /
//! production-context wiring, Run 215 the hidden policy selector, Run 217
//! the runtime arming carrier, and Run 220 the long-running runtime
//! consumption. But there was **no typed production *evaluator* interface**
//! modelling how a *future* governance engine supplies decisions from a
//! decision source, validates decision provenance, tracks replay, checks
//! proposal/decision state, and returns fail-closed production outcomes.
//! Run 222 closes that gap at the source/test level by adding:
//!
//! * A typed [`EvaluatorSourceKind`] (`Disabled`, `FixtureDecisionSource`,
//!   `EmergencyCouncilFixtureSource`, `OnChainDecisionSourceUnavailable`,
//!   `ProductionDecisionSourceUnavailable`,
//!   `MainnetDecisionSourceUnavailable`, `Unknown`) and a typed
//!   [`EvaluatorPolicy`] (`Disabled` default,
//!   `FixtureDecisionSourceAllowed`,
//!   `EmergencyCouncilFixtureSourceAllowed`,
//!   `ProductionDecisionSourceRequired`, `MainnetDecisionSourceRequired`).
//! * A typed [`DecisionSourceIdentity`] binding the decision source id,
//!   governance class, issuer/authority class, environment, chain id,
//!   genesis hash, authority-root fingerprint, governance / on-chain /
//!   custody-attestation proof digests, evaluator version, and the
//!   freshness / replay window.
//! * A typed [`EvaluatorRequest`] binding the governance-execution input
//!   digest, proposal / decision id, lifecycle action, candidate digest,
//!   authority-domain sequence, the enactment window, the replay nonce,
//!   the emergency flag, and the decision-source-identity digest.
//! * A typed [`EvaluatorResponse`] binding the request digest, decision
//!   digest, approved/rejected decision, authorized lifecycle action,
//!   authorized candidate digest, authorized sequence, the enactment
//!   window, the replay nonce, the evaluator/source id, the response
//!   freshness / expiry, and a placeholder response commitment.
//! * Deterministic, domain-separated digest helpers
//!   ([`DecisionSourceIdentity::source_identity_digest`],
//!   [`EvaluatorRequest::request_digest`],
//!   [`EvaluatorResponse::response_digest`], and
//!   [`evaluator_transcript_digest`]).
//! * A pure / mockable [`ProductionGovernanceExecutionEvaluator`] trait
//!   with [`ProductionGovernanceExecutionEvaluator::evaluate_governance_decision_source`]
//!   and [`ProductionGovernanceExecutionEvaluator::verify_governance_evaluator_response`]
//!   methods, a DevNet/TestNet source/test-only
//!   [`FixtureGovernanceExecutionEvaluatorInterface`], an explicit
//!   non-production
//!   [`EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface`], and
//!   production / on-chain / MainNet evaluators that are callable but fail
//!   closed as unavailable.
//! * A typed [`EvaluatorOutcome`] distinguishing every accept/reject case
//!   the task enumerates, plus a [`EvaluatorComposedOutcome`] preserving
//!   the MainNet peer-driven-apply refusal even when a fixture evaluator
//!   approves.
//!
//! Run 222 composes with the Run 211 governance execution input/decision
//! types and the Run 220 runtime consumption (as a *future* production
//! evaluator target) **without changing runtime behaviour**. Production
//! and MainNet evaluators remain unavailable/fail-closed. Fixture
//! evaluators are DevNet/TestNet source/test only. The emergency fixture
//! evaluator is explicit and non-production.
//!
//! Release-binary evaluator-interface evidence is **deferred to Run 223**.
//! Validator-set rotation remains unsupported, full C4 remains open, and
//! C5 remains open.
//!
//! The module is pure: every public function and trait method performs no
//! network or file I/O, writes no marker, writes no sequence, mutates no
//! live trust, evicts no sessions, and never invokes Run 070 apply.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / sentinels / versioning
// ===========================================================================

/// Run 222 — decision-source-identity digest domain tag.
pub const EVALUATOR_SOURCE_IDENTITY_DOMAIN_TAG: &str =
    "QBIND:run222-governance-execution-evaluator-source-identity:v1";

/// Run 222 — evaluator-request digest domain tag.
pub const EVALUATOR_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run222-governance-execution-evaluator-request:v1";

/// Run 222 — evaluator-response digest domain tag.
pub const EVALUATOR_RESPONSE_DOMAIN_TAG: &str =
    "QBIND:run222-governance-execution-evaluator-response:v1";

/// Run 222 — evaluator-transcript digest domain tag.
pub const EVALUATOR_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run222-governance-execution-evaluator-transcript:v1";

/// Run 222 — explicit invalid response-commitment sentinel for
/// source/test rejection vectors. A response carrying this commitment is
/// rejected as [`EvaluatorOutcome::InvalidResponseCommitment`].
pub const EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL: &str =
    "INVALID-GOVERNANCE-EXECUTION-EVALUATOR-RESPONSE-COMMITMENT";

/// Run 222 — the only evaluator interface version this boundary supports.
/// Any other version is rejected as
/// [`EvaluatorOutcome::UnsupportedEvaluatorVersion`].
pub const EVALUATOR_SUPPORTED_VERSION: u16 = 1;

// ===========================================================================
// Evaluator source kind
// ===========================================================================

/// Run 222 — typed governance-decision-source kind.
///
/// `Disabled` is the inert default. `FixtureDecisionSource` and
/// `EmergencyCouncilFixtureSource` are DevNet/TestNet source/test-only
/// kinds. `OnChainDecisionSourceUnavailable`,
/// `ProductionDecisionSourceUnavailable`, and
/// `MainnetDecisionSourceUnavailable` are production-class sources that are
/// callable but fail closed as unavailable because Run 222 wires no real
/// governance execution engine or on-chain proof verifier. `Unknown` is
/// always fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EvaluatorSourceKind {
    /// Inert default. No decision source is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture decision source.
    FixtureDecisionSource,
    /// DevNet/TestNet source/test emergency-council fixture decision source.
    EmergencyCouncilFixtureSource,
    /// On-chain decision source. Callable, fails closed.
    OnChainDecisionSourceUnavailable,
    /// Generic production decision source. Callable, fails closed.
    ProductionDecisionSourceUnavailable,
    /// MainNet production decision source. Callable, fails closed.
    MainnetDecisionSourceUnavailable,
    /// Unknown / unsupported decision source. Always fail-closed.
    Unknown,
}

impl EvaluatorSourceKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureDecisionSource => "fixture-decision-source",
            Self::EmergencyCouncilFixtureSource => "emergency-council-fixture-source",
            Self::OnChainDecisionSourceUnavailable => "on-chain-decision-source-unavailable",
            Self::ProductionDecisionSourceUnavailable => "production-decision-source-unavailable",
            Self::MainnetDecisionSourceUnavailable => "mainnet-decision-source-unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this kind is a DevNet/TestNet source/test
    /// fixture decision source.
    pub const fn is_fixture(self) -> bool {
        matches!(
            self,
            Self::FixtureDecisionSource | Self::EmergencyCouncilFixtureSource
        )
    }

    /// Returns `true` iff this kind is a production-class source that Run
    /// 222 fails closed as unavailable.
    pub const fn is_production_unavailable(self) -> bool {
        matches!(
            self,
            Self::OnChainDecisionSourceUnavailable
                | Self::ProductionDecisionSourceUnavailable
                | Self::MainnetDecisionSourceUnavailable
        )
    }
}

// ===========================================================================
// Evaluator policy
// ===========================================================================

/// Run 222 — typed production-governance evaluator policy.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// decision source regardless of contents, preserving the Run 050–221
/// conservative defaults. `FixtureDecisionSourceAllowed` and
/// `EmergencyCouncilFixtureSourceAllowed` are DevNet/TestNet source/test-
/// only policies. `ProductionDecisionSourceRequired` and
/// `MainnetDecisionSourceRequired` REQUIRE a real governance execution
/// engine — and Run 222 has none, so they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EvaluatorPolicy {
    /// Default. Refuses every decision source.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture decision-source policy.
    FixtureDecisionSourceAllowed,
    /// DevNet/TestNet source/test emergency-council fixture policy.
    EmergencyCouncilFixtureSourceAllowed,
    /// Generic production decision source required. Run 222 fails closed
    /// because no real engine exists.
    ProductionDecisionSourceRequired,
    /// MainNet production decision source required. Run 222 fails closed
    /// for every source — fixture material is rejected as non-production
    /// and every production source is rejected as unavailable.
    MainnetDecisionSourceRequired,
}

impl EvaluatorPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureDecisionSourceAllowed => "fixture-decision-source-allowed",
            Self::EmergencyCouncilFixtureSourceAllowed => {
                "emergency-council-fixture-source-allowed"
            }
            Self::ProductionDecisionSourceRequired => "production-decision-source-required",
            Self::MainnetDecisionSourceRequired => "mainnet-decision-source-required",
        }
    }

    /// Returns `true` iff this policy requires a real production
    /// governance execution engine (and therefore Run 222 fails closed).
    pub const fn requires_production_source(self) -> bool {
        matches!(
            self,
            Self::ProductionDecisionSourceRequired | Self::MainnetDecisionSourceRequired
        )
    }

    /// Returns the fixture source kind this policy accepts, or `None` for
    /// the disabled / production-required policies.
    pub const fn allowed_fixture_source(self) -> Option<EvaluatorSourceKind> {
        match self {
            Self::FixtureDecisionSourceAllowed => Some(EvaluatorSourceKind::FixtureDecisionSource),
            Self::EmergencyCouncilFixtureSourceAllowed => {
                Some(EvaluatorSourceKind::EmergencyCouncilFixtureSource)
            }
            _ => None,
        }
    }
}

// ===========================================================================
// Decision source identity
// ===========================================================================

/// Run 222 — typed governance decision-source identity.
///
/// Pure data binding the decision-source id, the governance class, the
/// issuer / authority class, the trust-domain environment / chain id /
/// genesis hash / authority-root fingerprint, the governance / on-chain /
/// custody-attestation proof digests, the evaluator version, and the
/// freshness / replay window. A future production governance engine would
/// validate decision provenance against this identity; Run 222 binds it
/// only as typed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSourceIdentity {
    /// Evaluator interface version.
    pub evaluator_version: u16,
    /// Decision-source kind.
    pub source_kind: EvaluatorSourceKind,
    /// Decision-source id.
    pub source_id: String,
    /// Declared governance class (Run 211).
    pub governance_class: GovernanceExecutionClass,
    /// Issuer / authority class (Run 163).
    pub issuer_authority_class: GovernanceAuthorityClass,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Bound trust-domain authority-root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound governance proof digest.
    pub governance_proof_digest: String,
    /// Bound on-chain governance proof digest, where applicable.
    pub on_chain_proof_digest: Option<String>,
    /// Bound custody attestation digest, where applicable.
    pub custody_attestation_digest: Option<String>,
    /// Freshness / replay window (in epochs). Must be positive.
    pub freshness_replay_window: u64,
}

impl DecisionSourceIdentity {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.source_id.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.governance_proof_digest.is_empty()
            && self.freshness_replay_window > 0
    }

    /// Deterministic SHA3-256 hex digest over every identity field. The
    /// digest is domain-separated so it can never collide with any other
    /// QBIND canonical digest.
    pub fn source_identity_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(EVALUATOR_SOURCE_IDENTITY_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"evaluator_version", &self.evaluator_version.to_le_bytes());
        field(b"source_kind", self.source_kind.tag().as_bytes());
        field(b"source_id", self.source_id.as_bytes());
        field(b"governance_class", self.governance_class.tag().as_bytes());
        field(
            b"issuer_authority_class",
            self.issuer_authority_class.tag().as_bytes(),
        );
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(
            b"governance_proof_digest",
            self.governance_proof_digest.as_bytes(),
        );
        field(
            b"on_chain_proof_digest",
            self.on_chain_proof_digest.as_deref().unwrap_or("").as_bytes(),
        );
        field(
            b"on_chain_present",
            &[self.on_chain_proof_digest.is_some() as u8],
        );
        field(
            b"custody_attestation_digest",
            self.custody_attestation_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"custody_present",
            &[self.custody_attestation_digest.is_some() as u8],
        );
        field(
            b"freshness_replay_window",
            &self.freshness_replay_window.to_le_bytes(),
        );
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Evaluator request
// ===========================================================================

/// Run 222 — typed governance evaluator request.
///
/// Pure data binding the Run 211 governance-execution input digest, the
/// proposal / decision id, the requested governance / lifecycle action,
/// the candidate digest, the authority-domain sequence, the enactment
/// window (`effective_epoch` / `expiry_epoch`), the replay nonce, the
/// emergency flag, and the decision-source-identity digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorRequest {
    /// Evaluator interface version.
    pub evaluator_version: u16,
    /// Run 211 governance-execution input digest.
    pub governance_execution_input_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Requested governance action (Run 211).
    pub governance_action: GovernanceAction,
    /// Requested lifecycle action (Run 159).
    pub lifecycle_action: LocalLifecycleAction,
    /// Candidate digest (next persistent authority record digest).
    pub candidate_digest: String,
    /// Authority-domain sequence (next sequence number).
    pub authority_domain_sequence: u64,
    /// Effective / activation epoch (inclusive lower bound).
    pub effective_epoch: u64,
    /// Expiry epoch (exclusive upper bound).
    pub expiry_epoch: u64,
    /// Per-execution anti-replay nonce. Must be non-empty.
    pub replay_nonce: String,
    /// Quorum / threshold metadata (Run 211).
    pub quorum: GovernanceQuorumThreshold,
    /// Emergency flag.
    pub emergency_flag: bool,
    /// Decision-source-identity digest binding this request to its source.
    pub decision_source_identity_digest: String,
}

impl EvaluatorRequest {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.governance_execution_input_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.replay_nonce.is_empty()
            && !self.decision_source_identity_digest.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every request field.
    pub fn request_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(EVALUATOR_REQUEST_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"evaluator_version", &self.evaluator_version.to_le_bytes());
        field(
            b"governance_execution_input_digest",
            self.governance_execution_input_digest.as_bytes(),
        );
        field(b"proposal_id", self.proposal_id.as_bytes());
        field(b"decision_id", self.decision_id.as_bytes());
        field(b"governance_action", self.governance_action.tag().as_bytes());
        field(b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        field(b"candidate_digest", self.candidate_digest.as_bytes());
        field(
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        field(b"effective_epoch", &self.effective_epoch.to_le_bytes());
        field(b"expiry_epoch", &self.expiry_epoch.to_le_bytes());
        field(b"replay_nonce", self.replay_nonce.as_bytes());
        field(b"quorum_approvals", &self.quorum.approvals.to_le_bytes());
        field(b"quorum_participants", &self.quorum.participants.to_le_bytes());
        field(
            b"quorum_required_threshold",
            &self.quorum.required_threshold.to_le_bytes(),
        );
        field(b"emergency_flag", &[self.emergency_flag as u8]);
        field(
            b"decision_source_identity_digest",
            self.decision_source_identity_digest.as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Evaluator response
// ===========================================================================

/// Run 222 — typed governance evaluator response.
///
/// Pure data binding the request digest, the Run 211 decision digest, the
/// approved/rejected decision, the authorized governance / lifecycle
/// action, the authorized candidate digest, the authorized
/// authority-domain sequence, the enactment window, the replay nonce, the
/// evaluator / source id, the response freshness / expiry, and a
/// placeholder response commitment.
///
/// `response_commitment` is the placeholder a future production governance
/// engine will replace with a real evaluator signature / proof. Run 222
/// only enforces presence, non-emptiness, and the explicit invalid
/// sentinel; it does not interpret the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorResponse {
    /// Evaluator interface version.
    pub evaluator_version: u16,
    /// Request digest this response answers.
    pub request_digest: String,
    /// Run 211 decision digest.
    pub decision_digest: String,
    /// Whether the evaluator approved (`true`) or rejected (`false`).
    pub approved: bool,
    /// Authorized governance action (Run 211).
    pub authorized_governance_action: GovernanceAction,
    /// Authorized lifecycle action (Run 159).
    pub authorized_lifecycle_action: LocalLifecycleAction,
    /// Authorized candidate digest.
    pub authorized_candidate_digest: String,
    /// Authorized authority-domain sequence.
    pub authorized_authority_domain_sequence: u64,
    /// Effective / activation epoch (inclusive lower bound).
    pub effective_epoch: u64,
    /// Expiry epoch (exclusive upper bound).
    pub expiry_epoch: u64,
    /// Per-execution anti-replay nonce. Must be non-empty.
    pub replay_nonce: String,
    /// Evaluator / source id.
    pub evaluator_source_id: String,
    /// Response freshness lower bound (inclusive).
    pub response_effective_epoch: u64,
    /// Response expiry upper bound (exclusive).
    pub response_expiry_epoch: u64,
    /// Emergency flag.
    pub emergency_flag: bool,
    /// Placeholder response commitment. Must be non-empty and must not be
    /// the explicit invalid sentinel.
    pub response_commitment: String,
}

impl EvaluatorResponse {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.request_digest.is_empty()
            && !self.decision_digest.is_empty()
            && !self.authorized_candidate_digest.is_empty()
            && !self.replay_nonce.is_empty()
            && !self.evaluator_source_id.is_empty()
            && !self.response_commitment.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every response field.
    pub fn response_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(EVALUATOR_RESPONSE_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"evaluator_version", &self.evaluator_version.to_le_bytes());
        field(b"request_digest", self.request_digest.as_bytes());
        field(b"decision_digest", self.decision_digest.as_bytes());
        field(b"approved", &[self.approved as u8]);
        field(
            b"authorized_governance_action",
            self.authorized_governance_action.tag().as_bytes(),
        );
        field(
            b"authorized_lifecycle_action",
            self.authorized_lifecycle_action.tag().as_bytes(),
        );
        field(
            b"authorized_candidate_digest",
            self.authorized_candidate_digest.as_bytes(),
        );
        field(
            b"authorized_authority_domain_sequence",
            &self.authorized_authority_domain_sequence.to_le_bytes(),
        );
        field(b"effective_epoch", &self.effective_epoch.to_le_bytes());
        field(b"expiry_epoch", &self.expiry_epoch.to_le_bytes());
        field(b"replay_nonce", self.replay_nonce.as_bytes());
        field(b"evaluator_source_id", self.evaluator_source_id.as_bytes());
        field(
            b"response_effective_epoch",
            &self.response_effective_epoch.to_le_bytes(),
        );
        field(
            b"response_expiry_epoch",
            &self.response_expiry_epoch.to_le_bytes(),
        );
        field(b"emergency_flag", &[self.emergency_flag as u8]);
        field(b"response_commitment", self.response_commitment.as_bytes());
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Transcript digest
// ===========================================================================

/// Run 222 — deterministic, domain-separated evaluator transcript digest.
/// Binds the source-identity digest, the request digest, and the response
/// digest into a single commitment the calling surface can log and a
/// future production engine can sign over.
pub fn evaluator_transcript_digest(
    source_identity_digest: &str,
    request_digest: &str,
    response_digest: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(EVALUATOR_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"source_identity_digest", source_identity_digest.as_bytes());
    field(b"request_digest", request_digest.as_bytes());
    field(b"response_digest", response_digest.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Evaluator expectations
// ===========================================================================

/// Run 222 — caller-supplied verifier expectations for the evaluator
/// interface.
///
/// Pure data, typically derived from the persisted candidate metadata and
/// the per-attempt anti-replay material the calling surface generated for
/// this governance evaluation round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorExpectations {
    pub expected_evaluator_version: u16,
    pub expected_environment: TrustBundleEnvironment,
    pub expected_chain_id: String,
    pub expected_genesis_hash: String,
    pub expected_authority_root_fingerprint: String,
    pub expected_proposal_id: String,
    pub expected_decision_id: String,
    pub expected_governance_action: GovernanceAction,
    pub expected_lifecycle_action: LocalLifecycleAction,
    pub expected_candidate_digest: String,
    pub expected_authority_domain_sequence: u64,
    pub expected_governance_proof_digest: String,
    pub expected_on_chain_proof_digest: Option<String>,
    pub expected_custody_attestation_digest: Option<String>,
    pub expected_effective_epoch: u64,
    pub expected_expiry_epoch: u64,
    pub expected_replay_nonce: String,
    pub expected_governance_execution_input_digest: String,
    /// Current logical epoch used for freshness / enactment-window checks.
    pub now_epoch: u64,
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 222 — typed outcome of the production governance evaluator
/// interface boundary.
///
/// Reject variants are precise so each can be distinguished from any other
/// in tests and operator log lines. Acceptance is **always** of a fixture
/// (or emergency-council fixture) decision source under the matching
/// explicit fixture policy on a DevNet/TestNet trust domain — production /
/// on-chain / MainNet decision sources are refused as unavailable
/// regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluatorOutcome {
    /// DevNet/TestNet fixture decision source accepted under the explicit
    /// `FixtureDecisionSourceAllowed` policy. Acceptance is evidence-only.
    FixtureDecisionSourceAccepted {
        source_id: String,
        proposal_id: String,
        decision_id: String,
        lifecycle_action: LocalLifecycleAction,
        environment: TrustBundleEnvironment,
    },
    /// DevNet/TestNet emergency-council fixture decision source accepted
    /// under the explicit `EmergencyCouncilFixtureSourceAllowed` policy.
    EmergencyFixtureAccepted {
        source_id: String,
        proposal_id: String,
        decision_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The evaluator response verified and authorized the lifecycle action.
    EvaluatorResponseAuthorized {
        lifecycle_action: LocalLifecycleAction,
        candidate_digest: String,
        authority_domain_sequence: u64,
    },
    /// The active policy is `Disabled`. Every source fails closed.
    EvaluatorDisabled,
    /// Production decision source unavailable. Run 222 has no real engine.
    ProductionDecisionSourceUnavailable,
    /// On-chain decision source unavailable. Run 222 has no real on-chain
    /// proof verifier.
    OnChainDecisionSourceUnavailable,
    /// MainNet decision source unavailable.
    MainnetDecisionSourceUnavailable,
    /// Fixture decision source rejected because the active policy requires
    /// a production / MainNet decision source.
    FixtureRejectedUnderProductionPolicy { policy_tag: &'static str },
    /// Emergency fixture decision source rejected because the active
    /// policy requires a production / MainNet decision source.
    EmergencyFixtureRejectedUnderProductionPolicy { policy_tag: &'static str },
    /// The decision-source kind does not match the fixture kind the active
    /// fixture policy allows.
    SourceKindPolicyMismatch {
        policy_tag: &'static str,
        source_tag: &'static str,
    },
    /// Unknown / unsupported decision source.
    UnknownSourceRejected { source_tag: &'static str },
    /// Fixture decision source rejected because the trust domain is
    /// MainNet. Fixture sources are DevNet/TestNet source/test only.
    FixtureRejectedForMainNet,
    /// Trust-domain environment does not match.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        attested: TrustBundleEnvironment,
    },
    /// Trust-domain chain id does not match.
    WrongChain { expected: String, attested: String },
    /// Trust-domain genesis hash does not match.
    WrongGenesis { expected: String, attested: String },
    /// Authority root fingerprint does not match.
    WrongAuthorityRoot { expected: String, attested: String },
    /// Governance proof digest does not match.
    WrongGovernanceProofDigest { expected: String, attested: String },
    /// On-chain governance proof digest does not match.
    WrongOnChainProofDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Custody attestation digest does not match.
    WrongCustodyAttestationDigest {
        expected: Option<String>,
        attested: Option<String>,
    },
    /// Proposal id does not match.
    WrongProposalId { expected: String, attested: String },
    /// Decision id does not match.
    WrongDecisionId { expected: String, attested: String },
    /// Lifecycle action does not match.
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        attested: LocalLifecycleAction,
    },
    /// Candidate digest does not match.
    WrongCandidateDigest { expected: String, attested: String },
    /// Authority-domain sequence does not match.
    WrongAuthorityDomainSequence { expected: u64, attested: u64 },
    /// Effective / activation epoch does not match.
    WrongEffectiveEpoch { expected: u64, attested: u64 },
    /// The enactment / freshness window has elapsed (or is not yet
    /// effective).
    ExpiredDecision { now_epoch: u64 },
    /// The replay nonce did not match the expected fresh nonce (stale or
    /// replayed decision).
    StaleOrReplayedDecision,
    /// The quorum threshold is insufficient.
    QuorumThresholdInsufficient { approvals: u32, required: u32 },
    /// An emergency action is not authorized under the active policy /
    /// request / response.
    EmergencyActionNotAuthorized,
    /// Validator-set rotation is unsupported in Run 222.
    ValidatorSetRotationUnsupported,
    /// A policy-change action is unsupported in Run 222.
    PolicyChangeActionUnsupported,
    /// The decision-source identity is structurally malformed.
    MalformedSourceIdentity { reason: String },
    /// The evaluator request is structurally malformed.
    MalformedEvaluatorRequest { reason: String },
    /// The evaluator response is structurally malformed.
    MalformedEvaluatorResponse { reason: String },
    /// The evaluator interface version is unsupported.
    UnsupportedEvaluatorVersion { version: u16 },
    /// The response commitment is invalid (empty or the explicit invalid
    /// sentinel).
    InvalidResponseCommitment,
    /// The evaluator response explicitly rejected the decision
    /// (`approved == false`).
    EvaluatorResponseRejected,
    /// The composed governance execution decision (Run 211 material) is
    /// invalid even though the evaluator response verified.
    GovernanceExecutionDecisionInvalid { reason: String },
    /// The evaluator response is invalid even though the composed
    /// governance execution decision (Run 211 material) is valid.
    EvaluatorResponseInvalid { reason: String },
    /// A local operator key cannot satisfy a production evaluator policy.
    LocalOperatorCannotSatisfyEvaluatorPolicy,
    /// Peer majority / gossip count cannot satisfy a production evaluator
    /// policy.
    PeerMajorityCannotSatisfyEvaluatorPolicy,
}

impl EvaluatorOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FixtureDecisionSourceAccepted { .. }
                | Self::EmergencyFixtureAccepted { .. }
                | Self::EvaluatorResponseAuthorized { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production / on-chain / MainNet decision source" rejection.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionDecisionSourceUnavailable
                | Self::OnChainDecisionSourceUnavailable
                | Self::MainnetDecisionSourceUnavailable
        )
    }
}

// ===========================================================================
// Evaluator trait + implementations
// ===========================================================================

/// Run 222 — pure production governance execution evaluator interface.
///
/// Implementations perform no I/O, write no marker, write no sequence,
/// mutate no live trust, evict no sessions, and never invoke Run 070. A
/// production / on-chain / MainNet implementation fails closed by
/// returning the matching unavailable [`EvaluatorOutcome`] until a real
/// governance engine lands.
pub trait ProductionGovernanceExecutionEvaluator {
    /// The decision-source kind this implementation presents.
    fn source_kind(&self) -> EvaluatorSourceKind;

    /// Evaluate `identity` and `request` against `expectations` for
    /// `trust_domain` under `policy`. No I/O is performed.
    fn evaluate_governance_decision_source(
        &self,
        identity: &DecisionSourceIdentity,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
        trust_domain: &AuthorityTrustDomain,
        policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome;

    /// Verify `response` against `request` and `expectations`. No I/O is
    /// performed.
    fn verify_governance_evaluator_response(
        &self,
        response: &EvaluatorResponse,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome;
}

/// Run 222 — DevNet/TestNet fixture governance evaluator interface.
///
/// **Source/test only.** Delegates to the pure
/// [`evaluate_governance_decision_source`] and
/// [`verify_governance_evaluator_response`] functions. It is NOT a real
/// governance engine; it exists only so DevNet/TestNet source/test vectors
/// can exercise the accepted path, and the underlying evaluator refuses
/// fixture sources on a MainNet trust domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixtureGovernanceExecutionEvaluatorInterface;

impl ProductionGovernanceExecutionEvaluator for FixtureGovernanceExecutionEvaluatorInterface {
    fn source_kind(&self) -> EvaluatorSourceKind {
        EvaluatorSourceKind::FixtureDecisionSource
    }

    fn evaluate_governance_decision_source(
        &self,
        identity: &DecisionSourceIdentity,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
        trust_domain: &AuthorityTrustDomain,
        policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome {
        evaluate_governance_decision_source(identity, request, expectations, trust_domain, policy)
    }

    fn verify_governance_evaluator_response(
        &self,
        response: &EvaluatorResponse,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome {
        verify_governance_evaluator_response(response, request, expectations)
    }
}

/// Run 222 — DevNet/TestNet emergency-council fixture governance evaluator
/// interface.
///
/// **Source/test only and explicitly non-production.** Delegates to the
/// same pure functions; it differs from the plain fixture evaluator only
/// in the kind it presents. Acceptance still requires the explicit
/// `EmergencyCouncilFixtureSourceAllowed` policy and an emergency action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface;

impl ProductionGovernanceExecutionEvaluator
    for EmergencyCouncilFixtureGovernanceExecutionEvaluatorInterface
{
    fn source_kind(&self) -> EvaluatorSourceKind {
        EvaluatorSourceKind::EmergencyCouncilFixtureSource
    }

    fn evaluate_governance_decision_source(
        &self,
        identity: &DecisionSourceIdentity,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
        trust_domain: &AuthorityTrustDomain,
        policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome {
        evaluate_governance_decision_source(identity, request, expectations, trust_domain, policy)
    }

    fn verify_governance_evaluator_response(
        &self,
        response: &EvaluatorResponse,
        request: &EvaluatorRequest,
        expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome {
        verify_governance_evaluator_response(response, request, expectations)
    }
}

/// Run 222 — production governance evaluator interface placeholder.
/// Callable but fails closed with
/// [`EvaluatorOutcome::ProductionDecisionSourceUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProductionDecisionSourceEvaluatorInterface;

impl ProductionGovernanceExecutionEvaluator for ProductionDecisionSourceEvaluatorInterface {
    fn source_kind(&self) -> EvaluatorSourceKind {
        EvaluatorSourceKind::ProductionDecisionSourceUnavailable
    }

    fn evaluate_governance_decision_source(
        &self,
        _identity: &DecisionSourceIdentity,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::ProductionDecisionSourceUnavailable
    }

    fn verify_governance_evaluator_response(
        &self,
        _response: &EvaluatorResponse,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::ProductionDecisionSourceUnavailable
    }
}

/// Run 222 — on-chain governance evaluator interface placeholder.
/// Callable but fails closed with
/// [`EvaluatorOutcome::OnChainDecisionSourceUnavailable`]. Run 222 wires
/// no real on-chain governance proof verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OnChainDecisionSourceEvaluatorInterface;

impl ProductionGovernanceExecutionEvaluator for OnChainDecisionSourceEvaluatorInterface {
    fn source_kind(&self) -> EvaluatorSourceKind {
        EvaluatorSourceKind::OnChainDecisionSourceUnavailable
    }

    fn evaluate_governance_decision_source(
        &self,
        _identity: &DecisionSourceIdentity,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::OnChainDecisionSourceUnavailable
    }

    fn verify_governance_evaluator_response(
        &self,
        _response: &EvaluatorResponse,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::OnChainDecisionSourceUnavailable
    }
}

/// Run 222 — MainNet governance evaluator interface placeholder.
/// Callable but fails closed with
/// [`EvaluatorOutcome::MainnetDecisionSourceUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MainnetDecisionSourceEvaluatorInterface;

impl ProductionGovernanceExecutionEvaluator for MainnetDecisionSourceEvaluatorInterface {
    fn source_kind(&self) -> EvaluatorSourceKind {
        EvaluatorSourceKind::MainnetDecisionSourceUnavailable
    }

    fn evaluate_governance_decision_source(
        &self,
        _identity: &DecisionSourceIdentity,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: EvaluatorPolicy,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::MainnetDecisionSourceUnavailable
    }

    fn verify_governance_evaluator_response(
        &self,
        _response: &EvaluatorResponse,
        _request: &EvaluatorRequest,
        _expectations: &EvaluatorExpectations,
    ) -> EvaluatorOutcome {
        EvaluatorOutcome::MainnetDecisionSourceUnavailable
    }
}

// ===========================================================================
// Pure evaluation
// ===========================================================================

/// Classify a production-required / MainNet-required policy rejection for
/// the decision-source kind. Fixture material is rejected as
/// non-production; production/on-chain/MainNet material is rejected as
/// unavailable; unknown/disabled material is rejected as unknown.
fn classify_production_policy_rejection(
    policy: EvaluatorPolicy,
    kind: EvaluatorSourceKind,
) -> EvaluatorOutcome {
    match kind {
        EvaluatorSourceKind::FixtureDecisionSource => {
            EvaluatorOutcome::FixtureRejectedUnderProductionPolicy {
                policy_tag: policy.tag(),
            }
        }
        EvaluatorSourceKind::EmergencyCouncilFixtureSource => {
            EvaluatorOutcome::EmergencyFixtureRejectedUnderProductionPolicy {
                policy_tag: policy.tag(),
            }
        }
        EvaluatorSourceKind::ProductionDecisionSourceUnavailable => {
            if policy == EvaluatorPolicy::MainnetDecisionSourceRequired {
                EvaluatorOutcome::MainnetDecisionSourceUnavailable
            } else {
                EvaluatorOutcome::ProductionDecisionSourceUnavailable
            }
        }
        EvaluatorSourceKind::OnChainDecisionSourceUnavailable => {
            EvaluatorOutcome::OnChainDecisionSourceUnavailable
        }
        EvaluatorSourceKind::MainnetDecisionSourceUnavailable => {
            EvaluatorOutcome::MainnetDecisionSourceUnavailable
        }
        EvaluatorSourceKind::Disabled | EvaluatorSourceKind::Unknown => {
            EvaluatorOutcome::UnknownSourceRejected {
                source_tag: kind.tag(),
            }
        }
    }
}

/// Map a production-class source to its unavailable outcome.
fn production_kind_unavailable(kind: EvaluatorSourceKind) -> EvaluatorOutcome {
    match kind {
        EvaluatorSourceKind::OnChainDecisionSourceUnavailable => {
            EvaluatorOutcome::OnChainDecisionSourceUnavailable
        }
        EvaluatorSourceKind::MainnetDecisionSourceUnavailable => {
            EvaluatorOutcome::MainnetDecisionSourceUnavailable
        }
        EvaluatorSourceKind::ProductionDecisionSourceUnavailable => {
            EvaluatorOutcome::ProductionDecisionSourceUnavailable
        }
        _ => EvaluatorOutcome::UnknownSourceRejected {
            source_tag: kind.tag(),
        },
    }
}

/// Run 222 — pure typed decision-source evaluation.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no live
/// trust. Evicts no sessions. Never invokes Run 070.
///
/// The evaluation binds every decision source to the trust domain, the
/// proposal/decision identity, the authority root, the governance /
/// lifecycle action, the candidate digest, the authority-domain sequence,
/// the governance / on-chain / custody digests, the enactment / freshness
/// window, the quorum threshold, the per-execution replay nonce, the
/// emergency flag, and the decision-source-identity digest. Acceptance is
/// only ever a fixture (or emergency-council fixture) decision source under
/// the matching explicit fixture policy on a DevNet/TestNet trust domain —
/// production / on-chain / MainNet decision sources are refused as
/// unavailable regardless of contents.
pub fn evaluate_governance_decision_source(
    identity: &DecisionSourceIdentity,
    request: &EvaluatorRequest,
    expectations: &EvaluatorExpectations,
    trust_domain: &AuthorityTrustDomain,
    policy: EvaluatorPolicy,
) -> EvaluatorOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies fail
    //    closed before any binding check.
    match policy {
        EvaluatorPolicy::Disabled => {
            return EvaluatorOutcome::EvaluatorDisabled;
        }
        EvaluatorPolicy::ProductionDecisionSourceRequired
        | EvaluatorPolicy::MainnetDecisionSourceRequired => {
            return classify_production_policy_rejection(policy, identity.source_kind);
        }
        EvaluatorPolicy::FixtureDecisionSourceAllowed
        | EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed => {}
    }

    // 2. Under a fixture-allowed policy a production / on-chain / MainNet
    //    source is still unavailable, and an unknown/disabled kind is
    //    rejected.
    match identity.source_kind {
        EvaluatorSourceKind::OnChainDecisionSourceUnavailable
        | EvaluatorSourceKind::ProductionDecisionSourceUnavailable
        | EvaluatorSourceKind::MainnetDecisionSourceUnavailable => {
            return production_kind_unavailable(identity.source_kind);
        }
        EvaluatorSourceKind::Disabled | EvaluatorSourceKind::Unknown => {
            return EvaluatorOutcome::UnknownSourceRejected {
                source_tag: identity.source_kind.tag(),
            };
        }
        EvaluatorSourceKind::FixtureDecisionSource
        | EvaluatorSourceKind::EmergencyCouncilFixtureSource => {}
    }

    // 3. The fixture kind must match the fixture policy.
    let allowed_fixture = policy
        .allowed_fixture_source()
        .expect("fixture-allowed policy has an allowed fixture source");
    if identity.source_kind != allowed_fixture {
        return EvaluatorOutcome::SourceKindPolicyMismatch {
            policy_tag: policy.tag(),
            source_tag: identity.source_kind.tag(),
        };
    }

    // 4. Fixture decision sources are DevNet/TestNet source/test only —
    //    never MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return EvaluatorOutcome::FixtureRejectedForMainNet;
    }

    // 5. Unsupported actions.
    if request.governance_action == GovernanceAction::ValidatorSetRotationRequest {
        return EvaluatorOutcome::ValidatorSetRotationUnsupported;
    }
    if request.governance_action.is_policy_change_request() {
        return EvaluatorOutcome::PolicyChangeActionUnsupported;
    }
    let expected_lifecycle_from_action = match request.governance_action.to_lifecycle_action() {
        Some(action) => action,
        None => {
            return EvaluatorOutcome::MalformedEvaluatorRequest {
                reason: "unknown governance action has no lifecycle mapping".to_string(),
            };
        }
    };

    // 6. Structural well-formedness.
    if !identity.is_well_formed() {
        return EvaluatorOutcome::MalformedSourceIdentity {
            reason: "source identity missing one or more mandatory fields".to_string(),
        };
    }
    if !request.is_well_formed() {
        return EvaluatorOutcome::MalformedEvaluatorRequest {
            reason: "request missing one or more mandatory fields".to_string(),
        };
    }

    // 7. Evaluator interface version.
    if identity.evaluator_version != EVALUATOR_SUPPORTED_VERSION
        || expectations.expected_evaluator_version != EVALUATOR_SUPPORTED_VERSION
    {
        return EvaluatorOutcome::UnsupportedEvaluatorVersion {
            version: identity.evaluator_version,
        };
    }
    if request.evaluator_version != EVALUATOR_SUPPORTED_VERSION {
        return EvaluatorOutcome::UnsupportedEvaluatorVersion {
            version: request.evaluator_version,
        };
    }

    // 8. Trust-domain environment binding.
    if identity.environment != trust_domain.environment
        || expectations.expected_environment != trust_domain.environment
    {
        return EvaluatorOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: identity.environment,
        };
    }

    // 9. Trust-domain chain binding.
    if identity.chain_id != trust_domain.chain_id
        || expectations.expected_chain_id != trust_domain.chain_id
    {
        return EvaluatorOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: identity.chain_id.clone(),
        };
    }

    // 10. Trust-domain genesis binding.
    if identity.genesis_hash != trust_domain.genesis_hash
        || expectations.expected_genesis_hash != trust_domain.genesis_hash
    {
        return EvaluatorOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: identity.genesis_hash.clone(),
        };
    }

    // 11. Authority root binding (identity + expectation + trust domain).
    if identity.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || expectations.expected_authority_root_fingerprint
            != trust_domain.authority_root_fingerprint
    {
        return EvaluatorOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: identity.authority_root_fingerprint.clone(),
        };
    }

    // 12. Governance proof digest binding.
    if identity.governance_proof_digest != expectations.expected_governance_proof_digest {
        return EvaluatorOutcome::WrongGovernanceProofDigest {
            expected: expectations.expected_governance_proof_digest.clone(),
            attested: identity.governance_proof_digest.clone(),
        };
    }

    // 13. On-chain governance proof digest binding (where applicable).
    if identity.on_chain_proof_digest != expectations.expected_on_chain_proof_digest {
        return EvaluatorOutcome::WrongOnChainProofDigest {
            expected: expectations.expected_on_chain_proof_digest.clone(),
            attested: identity.on_chain_proof_digest.clone(),
        };
    }

    // 14. Custody attestation digest binding (where applicable).
    if identity.custody_attestation_digest != expectations.expected_custody_attestation_digest {
        return EvaluatorOutcome::WrongCustodyAttestationDigest {
            expected: expectations.expected_custody_attestation_digest.clone(),
            attested: identity.custody_attestation_digest.clone(),
        };
    }

    // 15. Decision-source-identity digest binding.
    if request.decision_source_identity_digest != identity.source_identity_digest() {
        return EvaluatorOutcome::MalformedEvaluatorRequest {
            reason: "request decision-source-identity digest does not bind the source identity"
                .to_string(),
        };
    }

    // 16. Governance execution input digest binding.
    if request.governance_execution_input_digest
        != expectations.expected_governance_execution_input_digest
    {
        return EvaluatorOutcome::MalformedEvaluatorRequest {
            reason: "request governance-execution input digest does not match expectation"
                .to_string(),
        };
    }

    // 17. Proposal id binding.
    if request.proposal_id != expectations.expected_proposal_id {
        return EvaluatorOutcome::WrongProposalId {
            expected: expectations.expected_proposal_id.clone(),
            attested: request.proposal_id.clone(),
        };
    }

    // 18. Decision id binding.
    if request.decision_id != expectations.expected_decision_id {
        return EvaluatorOutcome::WrongDecisionId {
            expected: expectations.expected_decision_id.clone(),
            attested: request.decision_id.clone(),
        };
    }

    // 19. Lifecycle / governance action authorization.
    if request.lifecycle_action != expected_lifecycle_from_action
        || request.lifecycle_action != expectations.expected_lifecycle_action
        || request.governance_action != expectations.expected_governance_action
    {
        return EvaluatorOutcome::WrongLifecycleAction {
            expected: expectations.expected_lifecycle_action,
            attested: request.lifecycle_action,
        };
    }

    // 20. Candidate digest binding.
    if request.candidate_digest != expectations.expected_candidate_digest {
        return EvaluatorOutcome::WrongCandidateDigest {
            expected: expectations.expected_candidate_digest.clone(),
            attested: request.candidate_digest.clone(),
        };
    }

    // 21. Authority-domain sequence binding.
    if request.authority_domain_sequence != expectations.expected_authority_domain_sequence {
        return EvaluatorOutcome::WrongAuthorityDomainSequence {
            expected: expectations.expected_authority_domain_sequence,
            attested: request.authority_domain_sequence,
        };
    }

    // 22. Effective epoch binding.
    if request.effective_epoch != expectations.expected_effective_epoch {
        return EvaluatorOutcome::WrongEffectiveEpoch {
            expected: expectations.expected_effective_epoch,
            attested: request.effective_epoch,
        };
    }

    // 23. Replay nonce binding.
    if request.replay_nonce != expectations.expected_replay_nonce {
        return EvaluatorOutcome::StaleOrReplayedDecision;
    }

    // 24. Enactment / freshness window. The request window must match the
    //     expected window and `now_epoch` must fall inside
    //     `[effective, expiry)`, with the window bounded by the source
    //     freshness/replay window.
    if request.expiry_epoch != expectations.expected_expiry_epoch
        || request.expiry_epoch <= request.effective_epoch
        || request.expiry_epoch - request.effective_epoch > identity.freshness_replay_window
        || expectations.now_epoch < request.effective_epoch
        || expectations.now_epoch >= request.expiry_epoch
    {
        return EvaluatorOutcome::ExpiredDecision {
            now_epoch: expectations.now_epoch,
        };
    }

    // 25. Quorum threshold.
    if !request.quorum.is_satisfied() {
        return EvaluatorOutcome::QuorumThresholdInsufficient {
            approvals: request.quorum.approvals,
            required: request.quorum.required_threshold,
        };
    }

    // 26. Emergency-action separation.
    let is_emergency_action = request.lifecycle_action == LocalLifecycleAction::EmergencyRevoke;
    match policy {
        EvaluatorPolicy::EmergencyCouncilFixtureSourceAllowed => {
            if !is_emergency_action || !request.emergency_flag {
                return EvaluatorOutcome::EmergencyActionNotAuthorized;
            }
        }
        EvaluatorPolicy::FixtureDecisionSourceAllowed => {
            if is_emergency_action || request.emergency_flag {
                return EvaluatorOutcome::EmergencyActionNotAuthorized;
            }
        }
        // Production / disabled policies never reach here.
        _ => unreachable!("non-fixture policy handled by the policy gate"),
    }

    // 27. Accept — fixture / emergency-council fixture only,
    //     DevNet/TestNet, evidence-only.
    if is_emergency_action {
        EvaluatorOutcome::EmergencyFixtureAccepted {
            source_id: identity.source_id.clone(),
            proposal_id: request.proposal_id.clone(),
            decision_id: request.decision_id.clone(),
            environment: trust_domain.environment,
        }
    } else {
        EvaluatorOutcome::FixtureDecisionSourceAccepted {
            source_id: identity.source_id.clone(),
            proposal_id: request.proposal_id.clone(),
            decision_id: request.decision_id.clone(),
            lifecycle_action: request.lifecycle_action,
            environment: trust_domain.environment,
        }
    }
}

/// Run 222 — pure typed evaluator-response verification.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no live
/// trust. Evicts no sessions. Never invokes Run 070.
///
/// Verifies that the response binds the request digest, that the response
/// commitment is present and not the explicit invalid sentinel, that the
/// evaluator approved, and that the authorized lifecycle action, candidate
/// digest, sequence, enactment window, and replay nonce match the request
/// and the caller expectations. The response is only authorized when the
/// authorized action, candidate digest, and sequence all match.
pub fn verify_governance_evaluator_response(
    response: &EvaluatorResponse,
    request: &EvaluatorRequest,
    expectations: &EvaluatorExpectations,
) -> EvaluatorOutcome {
    // 1. Structural well-formedness.
    if !response.is_well_formed() {
        return EvaluatorOutcome::MalformedEvaluatorResponse {
            reason: "response missing one or more mandatory fields".to_string(),
        };
    }

    // 2. Evaluator interface version.
    if response.evaluator_version != EVALUATOR_SUPPORTED_VERSION {
        return EvaluatorOutcome::UnsupportedEvaluatorVersion {
            version: response.evaluator_version,
        };
    }

    // 3. Response commitment must be present and not the invalid sentinel.
    if response.response_commitment == EVALUATOR_INVALID_RESPONSE_COMMITMENT_SENTINEL {
        return EvaluatorOutcome::InvalidResponseCommitment;
    }

    // 4. The response must bind the request digest.
    if response.request_digest != request.request_digest() {
        return EvaluatorOutcome::MalformedEvaluatorResponse {
            reason: "response request digest does not bind the request".to_string(),
        };
    }

    // 5. The evaluator must have approved.
    if !response.approved {
        return EvaluatorOutcome::EvaluatorResponseRejected;
    }

    // 6. Authorized lifecycle / governance action authorization.
    if response.authorized_lifecycle_action != request.lifecycle_action
        || response.authorized_governance_action != request.governance_action
        || response.authorized_lifecycle_action != expectations.expected_lifecycle_action
    {
        return EvaluatorOutcome::WrongLifecycleAction {
            expected: request.lifecycle_action,
            attested: response.authorized_lifecycle_action,
        };
    }

    // 7. Authorized candidate digest binding.
    if response.authorized_candidate_digest != request.candidate_digest
        || response.authorized_candidate_digest != expectations.expected_candidate_digest
    {
        return EvaluatorOutcome::WrongCandidateDigest {
            expected: request.candidate_digest.clone(),
            attested: response.authorized_candidate_digest.clone(),
        };
    }

    // 8. Authorized authority-domain sequence binding.
    if response.authorized_authority_domain_sequence != request.authority_domain_sequence
        || response.authorized_authority_domain_sequence
            != expectations.expected_authority_domain_sequence
    {
        return EvaluatorOutcome::WrongAuthorityDomainSequence {
            expected: request.authority_domain_sequence,
            attested: response.authorized_authority_domain_sequence,
        };
    }

    // 9. Effective epoch binding.
    if response.effective_epoch != request.effective_epoch {
        return EvaluatorOutcome::WrongEffectiveEpoch {
            expected: request.effective_epoch,
            attested: response.effective_epoch,
        };
    }

    // 10. Replay nonce binding.
    if response.replay_nonce != request.replay_nonce
        || response.replay_nonce != expectations.expected_replay_nonce
    {
        return EvaluatorOutcome::StaleOrReplayedDecision;
    }

    // 11. Emergency flag must agree with the request.
    if response.emergency_flag != request.emergency_flag {
        return EvaluatorOutcome::EmergencyActionNotAuthorized;
    }

    // 12. Response freshness / expiry window must match the request
    //     enactment window and `now_epoch` must fall inside it.
    if response.expiry_epoch != request.expiry_epoch
        || response.response_expiry_epoch <= response.response_effective_epoch
        || expectations.now_epoch < response.response_effective_epoch
        || expectations.now_epoch >= response.response_expiry_epoch
    {
        return EvaluatorOutcome::ExpiredDecision {
            now_epoch: expectations.now_epoch,
        };
    }

    // 13. Authorized — the response binds and authorizes the action.
    EvaluatorOutcome::EvaluatorResponseAuthorized {
        lifecycle_action: response.authorized_lifecycle_action,
        candidate_digest: response.authorized_candidate_digest.clone(),
        authority_domain_sequence: response.authorized_authority_domain_sequence,
    }
}

// ===========================================================================
// Composition helpers
// ===========================================================================

/// Run 222 — typed combined outcome for an evaluator-interface preflight
/// that also enforces the MainNet peer-driven-apply refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluatorComposedOutcome {
    /// The evaluator accepted the decision source and verified the
    /// response.
    Accepted(EvaluatorOutcome),
    /// The evaluator rejected the decision source or the response.
    Rejected(EvaluatorOutcome),
    /// MainNet trust domain — peer-driven apply remains the Run 147 / 148
    /// / 152 FATAL refusal regardless of any fixture evaluator approval.
    MainNetPeerDrivenApplyRefused,
}

impl EvaluatorComposedOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 222 — pure composition helper.
///
/// Refuses MainNet peer-driven apply preflights up front (regardless of
/// any fixture evaluator approval), evaluates the decision source, then
/// verifies the evaluator response. The first reject short-circuits.
/// Performs no I/O, writes no marker, writes no sequence, mutates no live
/// trust, evicts no sessions, never invokes Run 070.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_governance_evaluator_with_peer_driven_guard(
    identity: &DecisionSourceIdentity,
    request: &EvaluatorRequest,
    response: &EvaluatorResponse,
    expectations: &EvaluatorExpectations,
    trust_domain: &AuthorityTrustDomain,
    policy: EvaluatorPolicy,
    is_peer_driven_apply_preflight: bool,
) -> EvaluatorComposedOutcome {
    // MainNet peer-driven apply remains refused regardless of any fixture
    // evaluator success.
    if is_peer_driven_apply_preflight && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return EvaluatorComposedOutcome::MainNetPeerDrivenApplyRefused;
    }

    let source_outcome =
        evaluate_governance_decision_source(identity, request, expectations, trust_domain, policy);
    if source_outcome.is_reject() {
        return EvaluatorComposedOutcome::Rejected(source_outcome);
    }

    let response_outcome = verify_governance_evaluator_response(response, request, expectations);
    if response_outcome.is_reject() {
        return EvaluatorComposedOutcome::Rejected(response_outcome);
    }

    EvaluatorComposedOutcome::Accepted(response_outcome)
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 222 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes, at
/// the typed Run 222 evaluator boundary, the rule that MainNet peer-driven
/// apply remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// evaluator response — even a fixture evaluator response that the policy
/// approves. Pure data; never reads response material.
pub fn mainnet_peer_driven_apply_remains_refused_under_evaluator(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 222 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a production
/// evaluator policy. Run 222 always returns `true`: a production evaluator
/// decision is an authorized governance-council decision and is never
/// satisfiable by a local operator key. Grep-verifiable named symbol for
/// an operator-log line.
pub fn local_operator_cannot_satisfy_evaluator_policy() -> bool {
    true
}

/// Run 222 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// production evaluator policy. Run 222 always returns `true`: a production
/// evaluator decision is an authorized governance decision and is never
/// satisfiable by counting peers. Grep-verifiable named symbol for an
/// operator-log line.
pub fn peer_majority_cannot_satisfy_evaluator_policy() -> bool {
    true
}

/// Run 222 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported. Run 222
/// always returns `true`: no validator-set rotation exists. Grep-verifiable
/// named symbol for an operator-log line.
pub fn validator_set_rotation_remains_unsupported_under_evaluator() -> bool {
    true
}