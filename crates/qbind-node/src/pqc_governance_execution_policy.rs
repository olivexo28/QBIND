//! Run 211 — source/test governance execution policy boundary.
//!
//! Source/test only. Run 211 does **not** implement a real governance
//! execution engine, a real on-chain governance proof verifier, MainNet
//! governance enablement, MainNet peer-driven apply enablement, or
//! validator-set rotation. Nor does it implement a real KMS/HSM backend,
//! a real RemoteSigner backend, or production signing-key custody.
//!
//! Before Run 211 governance proof material could be *carried* and
//! *checked* (Runs 163/165/167/169/171, 178/180/182/184/186), and
//! custody / RemoteSigner / KMS-HSM / custody-attestation state could be
//! bound (Runs 188–210), but there was **no typed execution-policy
//! model** describing how an *approved governance decision* authorizes an
//! authority lifecycle action: no typed governance proposal/decision, no
//! enactment window, no quorum/threshold policy, no replay protection, no
//! emergency-mode separation, and no action-to-lifecycle authorization.
//! Run 211 closes that gap at the source/test level by adding:
//!
//! * A typed [`GovernanceExecutionClass`] (`Disabled`,
//!   `FixtureGovernance`, `EmergencyCouncilFixture`,
//!   `OnChainGovernanceUnavailable`, `ProductionGovernanceUnavailable`,
//!   `MainnetGovernanceUnavailable`, `Unknown`) and a typed
//!   [`GovernanceExecutionPolicy`] (`Disabled` default,
//!   `FixtureGovernanceAllowed`, `EmergencyCouncilFixtureAllowed`,
//!   `ProductionGovernanceRequired`, `MainnetGovernanceRequired`).
//! * A typed [`GovernanceAction`] covering authority signing-key initial
//!   activation, rotate, retire, revoke, emergency revoke, the four
//!   policy-change request placeholders, the validator-set rotation
//!   request placeholder, and an unknown action.
//! * A typed [`GovernanceExecutionInput`] (the requested execution claim),
//!   a typed [`GovernanceExecutionDecision`] (the governance authorization),
//!   and a typed [`GovernanceExecutionExpectations`] (the trust-domain
//!   expectations the calling surface derived from persisted state).
//! * Deterministic, domain-separated digest helpers
//!   ([`GovernanceExecutionInput::input_digest`],
//!   [`GovernanceExecutionDecision::decision_digest`],
//!   [`governance_execution_transcript_digest`], and the optional
//!   [`governance_execution_policy_digest`]).
//! * A pure / mockable [`GovernanceExecutionEvaluator`] trait with an
//!   [`GovernanceExecutionEvaluator::evaluate_governance_execution_policy`]
//!   method, a DevNet/TestNet source/test-only
//!   [`FixtureGovernanceExecutionEvaluator`], and
//!   production / on-chain / MainNet evaluators that are callable but
//!   fail closed as unavailable.
//! * A pure typed [`evaluate_governance_execution_policy`] and a typed
//!   [`GovernanceExecutionOutcome`] distinguishing every accept/reject
//!   case the task enumerates.
//! * Composition helpers preserving the MainNet peer-driven-apply
//!   refusal even when a fixture governance decision approves.
//!
//! Run 211 binds the Run 163/178/205 governance / on-chain / custody
//! material only as opaque digests and changes none of those boundaries.
//! Production and MainNet governance execution remain
//! unavailable/fail-closed. Fixture governance execution is
//! DevNet/TestNet source/test only.
//!
//! Release-binary governance execution policy-boundary evidence is
//! **deferred to Run 212**. validator-set rotation remains unsupported,
//! full C4 remains open, and C5 remains open.
//!
//! The module is pure: every public function and trait method performs
//! no network or file I/O, writes no marker, writes no sequence, mutates
//! no live trust, evicts no sessions, and never invokes Run 070 apply.

use crate::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / sentinels / versioning
// ===========================================================================

/// Run 211 — governance-execution-input digest domain tag.
pub const GOVERNANCE_EXECUTION_INPUT_DOMAIN_TAG: &str =
    "QBIND:run211-governance-execution-input:v1";

/// Run 211 — governance-execution-decision digest domain tag.
pub const GOVERNANCE_EXECUTION_DECISION_DOMAIN_TAG: &str =
    "QBIND:run211-governance-execution-decision:v1";

/// Run 211 — governance-execution-transcript digest domain tag.
pub const GOVERNANCE_EXECUTION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run211-governance-execution-transcript:v1";

/// Run 211 — governance-execution-policy digest domain tag.
pub const GOVERNANCE_EXECUTION_POLICY_DOMAIN_TAG: &str =
    "QBIND:run211-governance-execution-policy:v1";

/// Run 211 — explicit invalid decision-commitment sentinel for
/// source/test rejection vectors. A decision carrying this commitment is
/// rejected as [`GovernanceExecutionOutcome::MalformedExecutionDecision`].
pub const GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL: &str =
    "INVALID-GOVERNANCE-EXECUTION-DECISION-COMMITMENT";

/// Run 211 — the only governance-execution schema version this boundary
/// supports. Any other version is rejected as
/// [`GovernanceExecutionOutcome::UnsupportedGovernanceExecutionVersion`].
pub const GOVERNANCE_EXECUTION_SUPPORTED_VERSION: u16 = 1;

// ===========================================================================
// Governance execution class
// ===========================================================================

/// Run 211 — typed governance execution class.
///
/// `Disabled` is the inert default. `FixtureGovernance` and
/// `EmergencyCouncilFixture` are DevNet/TestNet source/test-only classes.
/// `OnChainGovernanceUnavailable`, `ProductionGovernanceUnavailable`, and
/// `MainnetGovernanceUnavailable` are production-class executions that are
/// callable but fail closed as unavailable because Run 211 wires no real
/// governance execution engine or on-chain proof verifier. `Unknown` is
/// always fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GovernanceExecutionClass {
    /// Inert default. No governance execution is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture governance execution.
    FixtureGovernance,
    /// DevNet/TestNet source/test emergency-council fixture governance.
    EmergencyCouncilFixture,
    /// On-chain governance execution. Callable, fails closed.
    OnChainGovernanceUnavailable,
    /// Generic production governance execution. Callable, fails closed.
    ProductionGovernanceUnavailable,
    /// MainNet production governance execution. Callable, fails closed.
    MainnetGovernanceUnavailable,
    /// Unknown / unsupported governance class. Always fail-closed.
    Unknown,
}

impl GovernanceExecutionClass {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureGovernance => "fixture-governance",
            Self::EmergencyCouncilFixture => "emergency-council-fixture",
            Self::OnChainGovernanceUnavailable => "on-chain-governance-unavailable",
            Self::ProductionGovernanceUnavailable => "production-governance-unavailable",
            Self::MainnetGovernanceUnavailable => "mainnet-governance-unavailable",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this class is a DevNet/TestNet source/test
    /// fixture governance class.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureGovernance | Self::EmergencyCouncilFixture)
    }

    /// Returns `true` iff this class is a production-class execution that
    /// Run 211 fails closed as unavailable.
    pub const fn is_production_unavailable(self) -> bool {
        matches!(
            self,
            Self::OnChainGovernanceUnavailable
                | Self::ProductionGovernanceUnavailable
                | Self::MainnetGovernanceUnavailable
        )
    }
}

// ===========================================================================
// Governance execution policy
// ===========================================================================

/// Run 211 — typed governance execution policy.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// governance execution regardless of contents, preserving the Run
/// 050–210 conservative defaults. `FixtureGovernanceAllowed` and
/// `EmergencyCouncilFixtureAllowed` are DevNet/TestNet source/test-only
/// policies. `ProductionGovernanceRequired` and `MainnetGovernanceRequired`
/// REQUIRE a real governance execution engine — and Run 211 has none, so
/// they fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GovernanceExecutionPolicy {
    /// Default. Refuses every governance execution.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture governance policy.
    FixtureGovernanceAllowed,
    /// DevNet/TestNet source/test emergency-council fixture policy.
    EmergencyCouncilFixtureAllowed,
    /// Generic production governance required. Run 211 fails closed
    /// because no real engine exists.
    ProductionGovernanceRequired,
    /// MainNet production governance required. Run 211 fails closed for
    /// every execution — fixture material is rejected as non-production
    /// and every production execution is rejected as unavailable.
    MainnetGovernanceRequired,
}

impl GovernanceExecutionPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureGovernanceAllowed => "fixture-governance-allowed",
            Self::EmergencyCouncilFixtureAllowed => "emergency-council-fixture-allowed",
            Self::ProductionGovernanceRequired => "production-governance-required",
            Self::MainnetGovernanceRequired => "mainnet-governance-required",
        }
    }

    /// Returns `true` iff this policy requires a real production
    /// governance execution engine (and therefore Run 211 fails closed).
    pub const fn requires_production_governance(self) -> bool {
        matches!(
            self,
            Self::ProductionGovernanceRequired | Self::MainnetGovernanceRequired
        )
    }

    /// Returns the fixture governance class this policy accepts, or
    /// `None` for the disabled / production-required policies.
    pub const fn allowed_fixture_class(self) -> Option<GovernanceExecutionClass> {
        match self {
            Self::FixtureGovernanceAllowed => Some(GovernanceExecutionClass::FixtureGovernance),
            Self::EmergencyCouncilFixtureAllowed => {
                Some(GovernanceExecutionClass::EmergencyCouncilFixture)
            }
            _ => None,
        }
    }
}

// ===========================================================================
// Governance action
// ===========================================================================

/// Run 211 — typed governance action.
///
/// The first five variants map 1:1 to a Run 159 [`LocalLifecycleAction`].
/// The four `*PolicyChangeRequest` variants and the
/// `ValidatorSetRotationRequest` placeholder are **unsupported** in Run
/// 211: they have no lifecycle mapping and are rejected as unsupported.
/// `Unknown` is always fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GovernanceAction {
    /// Authority signing-key initial activation. Maps to
    /// [`LocalLifecycleAction::ActivateInitial`].
    AuthoritySigningKeyInitialActivation,
    /// Authority signing-key rotate. Maps to
    /// [`LocalLifecycleAction::Rotate`].
    Rotate,
    /// Authority signing-key retire. Maps to
    /// [`LocalLifecycleAction::Retire`].
    Retire,
    /// Authority signing-key revoke. Maps to
    /// [`LocalLifecycleAction::Revoke`].
    Revoke,
    /// Authority signing-key emergency revoke. Maps to
    /// [`LocalLifecycleAction::EmergencyRevoke`].
    EmergencyRevoke,
    /// Policy-change request placeholder. Unsupported in Run 211.
    PolicyChangeRequest,
    /// Custody-policy-change request placeholder. Unsupported in Run 211.
    CustodyPolicyChangeRequest,
    /// RemoteSigner-policy-change request placeholder. Unsupported.
    RemoteSignerPolicyChangeRequest,
    /// Custody-attestation-policy-change request placeholder. Unsupported.
    CustodyAttestationPolicyChangeRequest,
    /// Validator-set rotation request placeholder. Unsupported in Run 211.
    ValidatorSetRotationRequest,
    /// Unknown / unsupported governance action. Always fail-closed.
    #[default]
    Unknown,
}

impl GovernanceAction {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuthoritySigningKeyInitialActivation => {
                "authority-signing-key-initial-activation"
            }
            Self::Rotate => "rotate",
            Self::Retire => "retire",
            Self::Revoke => "revoke",
            Self::EmergencyRevoke => "emergency-revoke",
            Self::PolicyChangeRequest => "policy-change-request",
            Self::CustodyPolicyChangeRequest => "custody-policy-change-request",
            Self::RemoteSignerPolicyChangeRequest => "remote-signer-policy-change-request",
            Self::CustodyAttestationPolicyChangeRequest => {
                "custody-attestation-policy-change-request"
            }
            Self::ValidatorSetRotationRequest => "validator-set-rotation-request",
            Self::Unknown => "unknown",
        }
    }

    /// Maps a lifecycle-bearing governance action to its Run 159
    /// [`LocalLifecycleAction`]. Returns `None` for the policy-change,
    /// validator-set-rotation, and unknown placeholders, which Run 211
    /// does not support.
    pub const fn to_lifecycle_action(self) -> Option<LocalLifecycleAction> {
        match self {
            Self::AuthoritySigningKeyInitialActivation => {
                Some(LocalLifecycleAction::ActivateInitial)
            }
            Self::Rotate => Some(LocalLifecycleAction::Rotate),
            Self::Retire => Some(LocalLifecycleAction::Retire),
            Self::Revoke => Some(LocalLifecycleAction::Revoke),
            Self::EmergencyRevoke => Some(LocalLifecycleAction::EmergencyRevoke),
            _ => None,
        }
    }

    /// Returns `true` iff this is one of the four policy-change request
    /// placeholders, which Run 211 rejects as unsupported.
    pub const fn is_policy_change_request(self) -> bool {
        matches!(
            self,
            Self::PolicyChangeRequest
                | Self::CustodyPolicyChangeRequest
                | Self::RemoteSignerPolicyChangeRequest
                | Self::CustodyAttestationPolicyChangeRequest
        )
    }
}

// ===========================================================================
// Quorum / threshold metadata
// ===========================================================================

/// Run 211 — typed quorum / threshold metadata bound into the governance
/// execution input.
///
/// `approvals` is the number of governance approvals presented;
/// `participants` is the size of the governance set; `required_threshold`
/// is the minimum number of approvals required for quorum. The quorum is
/// satisfied only when a positive threshold is met without exceeding the
/// participant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernanceQuorumThreshold {
    pub approvals: u32,
    pub participants: u32,
    pub required_threshold: u32,
}

impl GovernanceQuorumThreshold {
    pub const fn new(approvals: u32, participants: u32, required_threshold: u32) -> Self {
        Self {
            approvals,
            participants,
            required_threshold,
        }
    }

    /// Returns `true` iff the quorum threshold is satisfied.
    pub const fn is_satisfied(&self) -> bool {
        self.required_threshold > 0
            && self.required_threshold <= self.participants
            && self.approvals >= self.required_threshold
            && self.approvals <= self.participants
    }
}

// ===========================================================================
// Governance execution input
// ===========================================================================

/// Run 211 — typed governance execution input (the requested execution
/// claim).
///
/// Pure data binding the trust domain, the governance class, the
/// proposal/decision identity, the authority root and signing-key
/// fingerprints, the governance/lifecycle action, the candidate digest
/// and authority-domain sequence, the bound governance / on-chain /
/// custody-attestation proof digests, the enactment window
/// (`effective_epoch` / `expiry_epoch`), the replay nonce, the quorum
/// metadata, and the emergency flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionInput {
    /// Governance-execution schema version.
    pub execution_version: u16,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Declared governance class.
    pub governance_class: GovernanceExecutionClass,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Current signing-key fingerprint.
    pub current_signing_key_fingerprint: String,
    /// Candidate signing-key fingerprint.
    pub candidate_signing_key_fingerprint: String,
    /// Revoked signing-key fingerprint, where applicable.
    pub revoked_signing_key_fingerprint: Option<String>,
    /// Requested governance action.
    pub governance_action: GovernanceAction,
    /// Requested lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Candidate digest (next persistent authority record digest).
    pub candidate_digest: String,
    /// Authority-domain sequence (next sequence number).
    pub authority_domain_sequence: u64,
    /// Bound governance proof digest.
    pub governance_proof_digest: String,
    /// Bound on-chain governance proof digest, where applicable.
    pub on_chain_proof_digest: Option<String>,
    /// Bound custody attestation digest, where applicable.
    pub custody_attestation_digest: Option<String>,
    /// Suite id (only the Run 159 PQC signing suite is accepted).
    pub suite_id: u8,
    /// Effective / activation epoch (inclusive lower bound).
    pub effective_epoch: u64,
    /// Expiry epoch (exclusive upper bound).
    pub expiry_epoch: u64,
    /// Per-execution anti-replay nonce. Must be non-empty.
    pub replay_nonce: String,
    /// Quorum / threshold metadata.
    pub quorum: GovernanceQuorumThreshold,
    /// Emergency flag.
    pub emergency_flag: bool,
}

impl GovernanceExecutionInput {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.current_signing_key_fingerprint.is_empty()
            && !self.candidate_signing_key_fingerprint.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.governance_proof_digest.is_empty()
            && !self.replay_nonce.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every input field. The
    /// digest is domain-separated so it can never collide with any other
    /// QBIND canonical digest.
    pub fn input_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(GOVERNANCE_EXECUTION_INPUT_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"execution_version", &self.execution_version.to_le_bytes());
        field(b"environment", &self.environment.metric_code().to_le_bytes());
        field(b"chain_id", self.chain_id.as_bytes());
        field(b"genesis_hash", self.genesis_hash.as_bytes());
        field(b"governance_class", self.governance_class.tag().as_bytes());
        field(b"proposal_id", self.proposal_id.as_bytes());
        field(b"decision_id", self.decision_id.as_bytes());
        field(
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        field(
            b"current_signing_key_fingerprint",
            self.current_signing_key_fingerprint.as_bytes(),
        );
        field(
            b"candidate_signing_key_fingerprint",
            self.candidate_signing_key_fingerprint.as_bytes(),
        );
        field(
            b"revoked_signing_key_fingerprint",
            self.revoked_signing_key_fingerprint
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        field(
            b"revoked_present",
            &[self.revoked_signing_key_fingerprint.is_some() as u8],
        );
        field(b"governance_action", self.governance_action.tag().as_bytes());
        field(b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        field(b"candidate_digest", self.candidate_digest.as_bytes());
        field(
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
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
        field(b"suite_id", &[self.suite_id]);
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
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Governance execution decision
// ===========================================================================

/// Run 211 — typed governance execution decision (the governance
/// authorization).
///
/// Pure data binding the proposal/decision identity, the approved/rejected
/// decision, the authorized governance and lifecycle action, the
/// authorized authority root, candidate digest and sequence, the
/// enactment window, the issuer / authority class, the emergency flag, the
/// replay nonce, and a placeholder decision commitment.
///
/// `decision_commitment` is the placeholder a future production
/// governance engine will replace with a real decision signature / proof.
/// Run 211 only enforces presence, non-emptiness, and the explicit
/// invalid sentinel; it does not interpret the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionDecision {
    /// Governance-execution schema version.
    pub execution_version: u16,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Whether governance approved (`true`) or rejected (`false`).
    pub approved: bool,
    /// Authorized governance action.
    pub authorized_governance_action: GovernanceAction,
    /// Authorized lifecycle action.
    pub authorized_lifecycle_action: LocalLifecycleAction,
    /// Authorized authority root fingerprint.
    pub authorized_authority_root_fingerprint: String,
    /// Authorized candidate digest.
    pub authorized_candidate_digest: String,
    /// Authorized authority-domain sequence.
    pub authorized_sequence: u64,
    /// Effective / activation epoch (inclusive lower bound).
    pub effective_epoch: u64,
    /// Expiry epoch (exclusive upper bound).
    pub expiry_epoch: u64,
    /// Placeholder decision commitment. Must be non-empty and must not be
    /// the explicit invalid sentinel.
    pub decision_commitment: String,
    /// Issuer / authority class.
    pub issuer_authority_class: GovernanceAuthorityClass,
    /// Emergency flag.
    pub emergency_flag: bool,
    /// Per-execution anti-replay nonce. Must be non-empty.
    pub replay_nonce: String,
}

impl GovernanceExecutionDecision {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.authorized_authority_root_fingerprint.is_empty()
            && !self.authorized_candidate_digest.is_empty()
            && !self.decision_commitment.is_empty()
            && !self.replay_nonce.is_empty()
    }

    /// Deterministic SHA3-256 hex digest over every decision field.
    pub fn decision_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(GOVERNANCE_EXECUTION_DECISION_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"execution_version", &self.execution_version.to_le_bytes());
        field(b"proposal_id", self.proposal_id.as_bytes());
        field(b"decision_id", self.decision_id.as_bytes());
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
            b"authorized_authority_root_fingerprint",
            self.authorized_authority_root_fingerprint.as_bytes(),
        );
        field(
            b"authorized_candidate_digest",
            self.authorized_candidate_digest.as_bytes(),
        );
        field(b"authorized_sequence", &self.authorized_sequence.to_le_bytes());
        field(b"effective_epoch", &self.effective_epoch.to_le_bytes());
        field(b"expiry_epoch", &self.expiry_epoch.to_le_bytes());
        field(b"decision_commitment", self.decision_commitment.as_bytes());
        field(
            b"issuer_authority_class",
            self.issuer_authority_class.tag().as_bytes(),
        );
        field(b"emergency_flag", &[self.emergency_flag as u8]);
        field(b"replay_nonce", self.replay_nonce.as_bytes());
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Governance execution expectations
// ===========================================================================

/// Run 211 — caller-supplied verifier expectations for
/// [`evaluate_governance_execution_policy`].
///
/// Pure data, typically derived from the persisted candidate metadata and
/// the per-attempt anti-replay material the calling surface generated for
/// this governance execution round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceExecutionExpectations {
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
    pub expected_suite_id: u8,
    pub expected_effective_epoch: u64,
    pub expected_replay_nonce: String,
    /// Current logical epoch used for enactment-window checks.
    pub now_epoch: u64,
}

// ===========================================================================
// Transcript / policy digests
// ===========================================================================

/// Run 211 — deterministic, domain-separated governance execution
/// transcript digest. Binds the input digest and the decision digest into
/// a single commitment the calling surface can log and a future
/// production engine can sign over.
pub fn governance_execution_transcript_digest(input_digest: &str, decision_digest: &str) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(GOVERNANCE_EXECUTION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"input_digest", input_digest.as_bytes());
    field(b"decision_digest", decision_digest.as_bytes());
    hex::encode(h.finalize())
}

/// Run 211 — optional deterministic, domain-separated governance policy
/// digest. Binds the active policy and governance class so a calling
/// surface can log "which policy + class governed this decision" without
/// leaking the full input/decision.
pub fn governance_execution_policy_digest(
    policy: GovernanceExecutionPolicy,
    class: GovernanceExecutionClass,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(GOVERNANCE_EXECUTION_POLICY_DOMAIN_TAG.as_bytes());
    let mut field = |label: &[u8], value: &[u8]| {
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    field(b"policy", policy.tag().as_bytes());
    field(b"class", class.tag().as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome
// ===========================================================================

/// Run 211 — typed outcome of the governance execution policy boundary.
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines. Acceptance is **always** of a
/// fixture (or emergency-council fixture) governance decision under the
/// matching explicit fixture policy on a DevNet/TestNet trust domain —
/// production / on-chain / MainNet governance executions are refused as
/// unavailable regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionOutcome {
    /// DevNet/TestNet fixture governance accepted under the explicit
    /// `FixtureGovernanceAllowed` policy. Acceptance is evidence-only.
    FixtureGovernanceAccepted {
        proposal_id: String,
        decision_id: String,
        lifecycle_action: LocalLifecycleAction,
        environment: TrustBundleEnvironment,
    },
    /// DevNet/TestNet emergency-council fixture governance accepted under
    /// the explicit `EmergencyCouncilFixtureAllowed` policy.
    EmergencyCouncilFixtureAccepted {
        proposal_id: String,
        decision_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy is `Disabled`. Every execution fails closed.
    GovernanceExecutionDisabled,
    /// Fixture governance rejected because the active policy is
    /// `ProductionGovernanceRequired`.
    FixtureRejectedProductionRequired,
    /// Fixture governance rejected because the active policy is
    /// `MainnetGovernanceRequired`.
    FixtureRejectedMainnetRequired,
    /// Emergency fixture governance rejected because the active policy is
    /// `ProductionGovernanceRequired`.
    EmergencyFixtureRejectedProductionRequired,
    /// Emergency fixture governance rejected because the active policy is
    /// `MainnetGovernanceRequired`.
    EmergencyFixtureRejectedMainnetRequired,
    /// Production governance unavailable. Run 211 has no real engine.
    ProductionGovernanceUnavailable,
    /// On-chain governance unavailable. Run 211 has no real on-chain
    /// proof verifier.
    OnChainGovernanceUnavailable,
    /// MainNet governance unavailable.
    MainNetGovernanceUnavailable,
    /// The execution governance class does not match the fixture class
    /// the active fixture policy allows.
    GovernanceClassPolicyMismatch {
        policy_tag: &'static str,
        class_tag: &'static str,
    },
    /// Unknown / unsupported governance class.
    UnknownGovernanceClassRejected { class_tag: &'static str },
    /// Fixture governance rejected because the trust domain is MainNet.
    /// Fixture governance is DevNet/TestNet source/test only.
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
    /// Lifecycle action does not match (input/decision/expectation
    /// mismatch).
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        attested: LocalLifecycleAction,
    },
    /// Candidate digest does not match.
    WrongCandidateDigest { expected: String, attested: String },
    /// Authority-domain sequence does not match.
    WrongAuthorityDomainSequence { expected: u64, attested: u64 },
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
    /// Effective / activation epoch does not match.
    WrongEffectiveEpoch { expected: u64, attested: u64 },
    /// The enactment window has elapsed (or is not yet effective).
    ExpiredDecision { now_epoch: u64 },
    /// The replay nonce did not match the expected fresh nonce (stale or
    /// replayed decision).
    StaleOrReplayedDecision,
    /// The quorum threshold is insufficient.
    QuorumThresholdInsufficient { approvals: u32, required: u32 },
    /// An emergency action is not authorized under the active policy /
    /// decision.
    EmergencyActionNotAuthorized,
    /// Validator-set rotation is unsupported in Run 211.
    ValidatorSetRotationUnsupported,
    /// A policy-change action is unsupported in Run 211.
    PolicyChangeActionUnsupported,
    /// Governance rejected the decision (`approved == false`).
    GovernanceDecisionRejected,
    /// The execution input is structurally malformed.
    MalformedExecutionInput { reason: String },
    /// The execution decision is structurally malformed.
    MalformedExecutionDecision { reason: String },
    /// The governance-execution schema version is unsupported.
    UnsupportedGovernanceExecutionVersion { version: u16 },
    /// A local operator key cannot satisfy a production governance
    /// execution policy.
    LocalOperatorCannotSatisfyGovernanceExecution,
    /// Peer majority / gossip count cannot satisfy a production
    /// governance execution policy.
    PeerMajorityCannotSatisfyGovernanceExecution,
}

impl GovernanceExecutionOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::FixtureGovernanceAccepted { .. } | Self::EmergencyCouncilFixtureAccepted { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production / on-chain / MainNet governance execution" rejection.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionGovernanceUnavailable
                | Self::OnChainGovernanceUnavailable
                | Self::MainNetGovernanceUnavailable
        )
    }
}

// ===========================================================================
// Evaluator trait + implementations
// ===========================================================================

/// Run 211 — pure governance execution evaluator boundary.
///
/// Implementations perform no I/O, write no marker, write no sequence,
/// mutate no live trust, evict no sessions, and never invoke Run 070. A
/// production / on-chain / MainNet implementation fails closed by
/// returning the matching unavailable [`GovernanceExecutionOutcome`]
/// until a real engine lands.
pub trait GovernanceExecutionEvaluator {
    /// The governance class this implementation presents.
    fn class(&self) -> GovernanceExecutionClass;

    /// Evaluate `input` against `decision` and `expectations` for
    /// `trust_domain` under `policy`. No I/O is performed.
    fn evaluate_governance_execution_policy(
        &self,
        input: &GovernanceExecutionInput,
        decision: &GovernanceExecutionDecision,
        expectations: &GovernanceExecutionExpectations,
        trust_domain: &AuthorityTrustDomain,
        policy: GovernanceExecutionPolicy,
    ) -> GovernanceExecutionOutcome;
}

/// Run 211 — DevNet/TestNet fixture governance execution evaluator.
///
/// **Source/test only.** Delegates to the pure
/// [`evaluate_governance_execution_policy`] function. It is NOT a real
/// governance engine; it exists only so DevNet/TestNet source/test
/// vectors can exercise the accepted path, and the underlying evaluator
/// refuses fixture governance on a MainNet trust domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FixtureGovernanceExecutionEvaluator;

impl GovernanceExecutionEvaluator for FixtureGovernanceExecutionEvaluator {
    fn class(&self) -> GovernanceExecutionClass {
        GovernanceExecutionClass::FixtureGovernance
    }

    fn evaluate_governance_execution_policy(
        &self,
        input: &GovernanceExecutionInput,
        decision: &GovernanceExecutionDecision,
        expectations: &GovernanceExecutionExpectations,
        trust_domain: &AuthorityTrustDomain,
        policy: GovernanceExecutionPolicy,
    ) -> GovernanceExecutionOutcome {
        evaluate_governance_execution_policy(input, decision, expectations, trust_domain, policy)
    }
}

/// Run 211 — production governance execution evaluator placeholder.
/// Callable but fails closed with
/// [`GovernanceExecutionOutcome::ProductionGovernanceUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProductionGovernanceExecutionEvaluator;

impl GovernanceExecutionEvaluator for ProductionGovernanceExecutionEvaluator {
    fn class(&self) -> GovernanceExecutionClass {
        GovernanceExecutionClass::ProductionGovernanceUnavailable
    }

    fn evaluate_governance_execution_policy(
        &self,
        _input: &GovernanceExecutionInput,
        _decision: &GovernanceExecutionDecision,
        _expectations: &GovernanceExecutionExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: GovernanceExecutionPolicy,
    ) -> GovernanceExecutionOutcome {
        GovernanceExecutionOutcome::ProductionGovernanceUnavailable
    }
}

/// Run 211 — on-chain governance execution evaluator placeholder.
/// Callable but fails closed with
/// [`GovernanceExecutionOutcome::OnChainGovernanceUnavailable`]. Run 211
/// wires no real on-chain governance proof verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OnChainGovernanceExecutionEvaluator;

impl GovernanceExecutionEvaluator for OnChainGovernanceExecutionEvaluator {
    fn class(&self) -> GovernanceExecutionClass {
        GovernanceExecutionClass::OnChainGovernanceUnavailable
    }

    fn evaluate_governance_execution_policy(
        &self,
        _input: &GovernanceExecutionInput,
        _decision: &GovernanceExecutionDecision,
        _expectations: &GovernanceExecutionExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: GovernanceExecutionPolicy,
    ) -> GovernanceExecutionOutcome {
        GovernanceExecutionOutcome::OnChainGovernanceUnavailable
    }
}

/// Run 211 — MainNet governance execution evaluator placeholder.
/// Callable but fails closed with
/// [`GovernanceExecutionOutcome::MainNetGovernanceUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MainnetGovernanceExecutionEvaluator;

impl GovernanceExecutionEvaluator for MainnetGovernanceExecutionEvaluator {
    fn class(&self) -> GovernanceExecutionClass {
        GovernanceExecutionClass::MainnetGovernanceUnavailable
    }

    fn evaluate_governance_execution_policy(
        &self,
        _input: &GovernanceExecutionInput,
        _decision: &GovernanceExecutionDecision,
        _expectations: &GovernanceExecutionExpectations,
        _trust_domain: &AuthorityTrustDomain,
        _policy: GovernanceExecutionPolicy,
    ) -> GovernanceExecutionOutcome {
        GovernanceExecutionOutcome::MainNetGovernanceUnavailable
    }
}

// ===========================================================================
// Evaluator
// ===========================================================================

/// Classify a production-required / MainNet-required policy rejection for
/// the execution governance class. Fixture material is rejected as
/// non-production; production/on-chain/MainNet material is rejected as
/// unavailable; unknown/disabled material is rejected as unknown.
fn classify_production_policy_rejection(
    policy: GovernanceExecutionPolicy,
    class: GovernanceExecutionClass,
) -> GovernanceExecutionOutcome {
    let mainnet = policy == GovernanceExecutionPolicy::MainnetGovernanceRequired;
    match class {
        GovernanceExecutionClass::FixtureGovernance => {
            if mainnet {
                GovernanceExecutionOutcome::FixtureRejectedMainnetRequired
            } else {
                GovernanceExecutionOutcome::FixtureRejectedProductionRequired
            }
        }
        GovernanceExecutionClass::EmergencyCouncilFixture => {
            if mainnet {
                GovernanceExecutionOutcome::EmergencyFixtureRejectedMainnetRequired
            } else {
                GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired
            }
        }
        GovernanceExecutionClass::ProductionGovernanceUnavailable => {
            if mainnet {
                GovernanceExecutionOutcome::MainNetGovernanceUnavailable
            } else {
                GovernanceExecutionOutcome::ProductionGovernanceUnavailable
            }
        }
        GovernanceExecutionClass::OnChainGovernanceUnavailable => {
            GovernanceExecutionOutcome::OnChainGovernanceUnavailable
        }
        GovernanceExecutionClass::MainnetGovernanceUnavailable => {
            GovernanceExecutionOutcome::MainNetGovernanceUnavailable
        }
        GovernanceExecutionClass::Disabled | GovernanceExecutionClass::Unknown => {
            GovernanceExecutionOutcome::UnknownGovernanceClassRejected {
                class_tag: class.tag(),
            }
        }
    }
}

/// Map a production-class execution to its unavailable outcome.
fn production_class_unavailable(class: GovernanceExecutionClass) -> GovernanceExecutionOutcome {
    match class {
        GovernanceExecutionClass::OnChainGovernanceUnavailable => {
            GovernanceExecutionOutcome::OnChainGovernanceUnavailable
        }
        GovernanceExecutionClass::MainnetGovernanceUnavailable => {
            GovernanceExecutionOutcome::MainNetGovernanceUnavailable
        }
        GovernanceExecutionClass::ProductionGovernanceUnavailable => {
            GovernanceExecutionOutcome::ProductionGovernanceUnavailable
        }
        _ => GovernanceExecutionOutcome::UnknownGovernanceClassRejected {
            class_tag: class.tag(),
        },
    }
}

/// Run 211 — pure typed governance execution policy evaluator.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no live
/// trust. Evicts no sessions. Never invokes Run 070.
///
/// The evaluator binds every decision to the trust domain, the
/// proposal/decision identity, the authority root, the
/// governance/lifecycle action, the candidate digest, the
/// authority-domain sequence, the governance / on-chain / custody
/// digests, the enactment window, the quorum threshold, the per-execution
/// replay nonce, and the emergency flag. Acceptance is only ever a
/// fixture (or emergency-council fixture) governance decision under the
/// matching explicit fixture policy on a DevNet/TestNet trust domain —
/// production / on-chain / MainNet governance paths are refused as
/// unavailable regardless of contents.
pub fn evaluate_governance_execution_policy(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
    expectations: &GovernanceExecutionExpectations,
    trust_domain: &AuthorityTrustDomain,
    policy: GovernanceExecutionPolicy,
) -> GovernanceExecutionOutcome {
    // 1. Policy gate. `Disabled` and the production-required policies fail
    //    closed before any binding check.
    match policy {
        GovernanceExecutionPolicy::Disabled => {
            return GovernanceExecutionOutcome::GovernanceExecutionDisabled;
        }
        GovernanceExecutionPolicy::ProductionGovernanceRequired
        | GovernanceExecutionPolicy::MainnetGovernanceRequired => {
            return classify_production_policy_rejection(policy, input.governance_class);
        }
        GovernanceExecutionPolicy::FixtureGovernanceAllowed
        | GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed => {}
    }

    // 2. Under a fixture-allowed policy a production / on-chain / MainNet
    //    execution is still unavailable, and an unknown/disabled class is
    //    rejected.
    match input.governance_class {
        GovernanceExecutionClass::OnChainGovernanceUnavailable
        | GovernanceExecutionClass::ProductionGovernanceUnavailable
        | GovernanceExecutionClass::MainnetGovernanceUnavailable => {
            return production_class_unavailable(input.governance_class);
        }
        GovernanceExecutionClass::Disabled | GovernanceExecutionClass::Unknown => {
            return GovernanceExecutionOutcome::UnknownGovernanceClassRejected {
                class_tag: input.governance_class.tag(),
            };
        }
        GovernanceExecutionClass::FixtureGovernance
        | GovernanceExecutionClass::EmergencyCouncilFixture => {}
    }

    // 3. The fixture class must match the fixture policy.
    let allowed_fixture = policy
        .allowed_fixture_class()
        .expect("fixture-allowed policy has an allowed fixture class");
    if input.governance_class != allowed_fixture {
        return GovernanceExecutionOutcome::GovernanceClassPolicyMismatch {
            policy_tag: policy.tag(),
            class_tag: input.governance_class.tag(),
        };
    }

    // 4. Fixture governance is DevNet/TestNet source/test only — never
    //    MainNet, regardless of any otherwise-valid binding.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return GovernanceExecutionOutcome::FixtureRejectedForMainNet;
    }

    // 5. Unsupported governance actions.
    if input.governance_action == GovernanceAction::ValidatorSetRotationRequest {
        return GovernanceExecutionOutcome::ValidatorSetRotationUnsupported;
    }
    if input.governance_action.is_policy_change_request() {
        return GovernanceExecutionOutcome::PolicyChangeActionUnsupported;
    }
    let expected_lifecycle_from_action = match input.governance_action.to_lifecycle_action() {
        Some(action) => action,
        None => {
            return GovernanceExecutionOutcome::MalformedExecutionInput {
                reason: "unknown governance action has no lifecycle mapping".to_string(),
            };
        }
    };

    // 6. Structural well-formedness.
    if !input.is_well_formed() {
        return GovernanceExecutionOutcome::MalformedExecutionInput {
            reason: "input missing one or more mandatory fields".to_string(),
        };
    }
    if !decision.is_well_formed() {
        return GovernanceExecutionOutcome::MalformedExecutionDecision {
            reason: "decision missing one or more mandatory fields".to_string(),
        };
    }
    if decision.decision_commitment == GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL {
        return GovernanceExecutionOutcome::MalformedExecutionDecision {
            reason: "decision commitment is the explicit invalid sentinel".to_string(),
        };
    }

    // 7. Schema version.
    if input.execution_version != GOVERNANCE_EXECUTION_SUPPORTED_VERSION {
        return GovernanceExecutionOutcome::UnsupportedGovernanceExecutionVersion {
            version: input.execution_version,
        };
    }
    if decision.execution_version != GOVERNANCE_EXECUTION_SUPPORTED_VERSION {
        return GovernanceExecutionOutcome::UnsupportedGovernanceExecutionVersion {
            version: decision.execution_version,
        };
    }

    // 8. Suite binding (must be the Run 159 PQC suite and match expected).
    if input.suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || expectations.expected_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44
        || input.suite_id != expectations.expected_suite_id
    {
        return GovernanceExecutionOutcome::MalformedExecutionInput {
            reason: "suite id is not the Run 159 PQC signing suite".to_string(),
        };
    }

    // 9. Trust-domain environment binding.
    if input.environment != trust_domain.environment
        || expectations.expected_environment != trust_domain.environment
    {
        return GovernanceExecutionOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: input.environment,
        };
    }

    // 10. Trust-domain chain binding.
    if input.chain_id != trust_domain.chain_id
        || expectations.expected_chain_id != trust_domain.chain_id
    {
        return GovernanceExecutionOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: input.chain_id.clone(),
        };
    }

    // 11. Trust-domain genesis binding.
    if input.genesis_hash != trust_domain.genesis_hash
        || expectations.expected_genesis_hash != trust_domain.genesis_hash
    {
        return GovernanceExecutionOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: input.genesis_hash.clone(),
        };
    }

    // 12. Authority root binding (input + decision + expectation +
    //     trust domain).
    if input.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || decision.authorized_authority_root_fingerprint
            != trust_domain.authority_root_fingerprint
        || expectations.expected_authority_root_fingerprint
            != trust_domain.authority_root_fingerprint
    {
        return GovernanceExecutionOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: input.authority_root_fingerprint.clone(),
        };
    }

    // 13. Governance must have approved the decision.
    if !decision.approved {
        return GovernanceExecutionOutcome::GovernanceDecisionRejected;
    }

    // 14. Proposal id binding.
    if input.proposal_id != expectations.expected_proposal_id
        || decision.proposal_id != expectations.expected_proposal_id
    {
        return GovernanceExecutionOutcome::WrongProposalId {
            expected: expectations.expected_proposal_id.clone(),
            attested: input.proposal_id.clone(),
        };
    }

    // 15. Decision id binding.
    if input.decision_id != expectations.expected_decision_id
        || decision.decision_id != expectations.expected_decision_id
    {
        return GovernanceExecutionOutcome::WrongDecisionId {
            expected: expectations.expected_decision_id.clone(),
            attested: input.decision_id.clone(),
        };
    }

    // 16. Lifecycle / governance action authorization. The input
    //     governance action must map to the input lifecycle action, the
    //     expected lifecycle action must match, the decision must
    //     authorize the same lifecycle action, and the decision must
    //     authorize the same governance action.
    if input.lifecycle_action != expected_lifecycle_from_action
        || input.lifecycle_action != expectations.expected_lifecycle_action
        || decision.authorized_lifecycle_action != input.lifecycle_action
        || decision.authorized_governance_action != input.governance_action
        || input.governance_action != expectations.expected_governance_action
    {
        return GovernanceExecutionOutcome::WrongLifecycleAction {
            expected: expectations.expected_lifecycle_action,
            attested: input.lifecycle_action,
        };
    }

    // 17. Emergency-action separation.
    let is_emergency_action = input.lifecycle_action == LocalLifecycleAction::EmergencyRevoke;
    match policy {
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed => {
            if !is_emergency_action || !input.emergency_flag || !decision.emergency_flag {
                return GovernanceExecutionOutcome::EmergencyActionNotAuthorized;
            }
        }
        GovernanceExecutionPolicy::FixtureGovernanceAllowed => {
            if is_emergency_action || input.emergency_flag || decision.emergency_flag {
                return GovernanceExecutionOutcome::EmergencyActionNotAuthorized;
            }
        }
        // Production / disabled policies never reach here.
        _ => unreachable!("non-fixture policy handled by the policy gate"),
    }

    // 18. Candidate digest binding.
    if input.candidate_digest != expectations.expected_candidate_digest
        || decision.authorized_candidate_digest != expectations.expected_candidate_digest
    {
        return GovernanceExecutionOutcome::WrongCandidateDigest {
            expected: expectations.expected_candidate_digest.clone(),
            attested: input.candidate_digest.clone(),
        };
    }

    // 19. Authority-domain sequence binding.
    if input.authority_domain_sequence != expectations.expected_authority_domain_sequence
        || decision.authorized_sequence != expectations.expected_authority_domain_sequence
    {
        return GovernanceExecutionOutcome::WrongAuthorityDomainSequence {
            expected: expectations.expected_authority_domain_sequence,
            attested: input.authority_domain_sequence,
        };
    }

    // 20. Governance proof digest binding.
    if input.governance_proof_digest != expectations.expected_governance_proof_digest {
        return GovernanceExecutionOutcome::WrongGovernanceProofDigest {
            expected: expectations.expected_governance_proof_digest.clone(),
            attested: input.governance_proof_digest.clone(),
        };
    }

    // 21. On-chain governance proof digest binding (where applicable).
    if input.on_chain_proof_digest != expectations.expected_on_chain_proof_digest {
        return GovernanceExecutionOutcome::WrongOnChainProofDigest {
            expected: expectations.expected_on_chain_proof_digest.clone(),
            attested: input.on_chain_proof_digest.clone(),
        };
    }

    // 22. Custody attestation digest binding (where applicable).
    if input.custody_attestation_digest != expectations.expected_custody_attestation_digest {
        return GovernanceExecutionOutcome::WrongCustodyAttestationDigest {
            expected: expectations.expected_custody_attestation_digest.clone(),
            attested: input.custody_attestation_digest.clone(),
        };
    }

    // 23. Effective epoch binding.
    if input.effective_epoch != expectations.expected_effective_epoch
        || decision.effective_epoch != expectations.expected_effective_epoch
    {
        return GovernanceExecutionOutcome::WrongEffectiveEpoch {
            expected: expectations.expected_effective_epoch,
            attested: input.effective_epoch,
        };
    }

    // 24. Replay nonce binding.
    if input.replay_nonce != expectations.expected_replay_nonce
        || decision.replay_nonce != expectations.expected_replay_nonce
    {
        return GovernanceExecutionOutcome::StaleOrReplayedDecision;
    }

    // 25. Enactment window. The decision window must match the input
    //     window and `now_epoch` must fall inside `[effective, expiry)`.
    if input.expiry_epoch != decision.expiry_epoch
        || decision.expiry_epoch <= decision.effective_epoch
        || expectations.now_epoch < decision.effective_epoch
        || expectations.now_epoch >= decision.expiry_epoch
    {
        return GovernanceExecutionOutcome::ExpiredDecision {
            now_epoch: expectations.now_epoch,
        };
    }

    // 26. Quorum threshold.
    if !input.quorum.is_satisfied() {
        return GovernanceExecutionOutcome::QuorumThresholdInsufficient {
            approvals: input.quorum.approvals,
            required: input.quorum.required_threshold,
        };
    }

    // 27. Accept — fixture / emergency-council fixture only,
    //     DevNet/TestNet, evidence-only.
    if is_emergency_action {
        GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted {
            proposal_id: input.proposal_id.clone(),
            decision_id: input.decision_id.clone(),
            environment: trust_domain.environment,
        }
    } else {
        GovernanceExecutionOutcome::FixtureGovernanceAccepted {
            proposal_id: input.proposal_id.clone(),
            decision_id: input.decision_id.clone(),
            lifecycle_action: input.lifecycle_action,
            environment: trust_domain.environment,
        }
    }
}

// ===========================================================================
// Composition helpers
// ===========================================================================

/// Run 211 — typed combined decision for a governance execution preflight
/// that also enforces the MainNet peer-driven-apply refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceExecutionComposedOutcome {
    /// The governance execution policy accepted the decision.
    Accepted(GovernanceExecutionOutcome),
    /// The governance execution policy rejected the decision.
    Rejected(GovernanceExecutionOutcome),
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of any fixture governance
    /// approval.
    MainNetPeerDrivenApplyRefused,
}

impl GovernanceExecutionComposedOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 211 — pure composition helper.
///
/// Refuses MainNet peer-driven apply preflights up front (regardless of
/// any fixture governance approval), then calls the pure
/// [`evaluate_governance_execution_policy`] evaluator and wraps its typed
/// outcome. Performs no I/O, writes no marker, writes no sequence,
/// mutates no live trust, evicts no sessions, never invokes Run 070.
pub fn evaluate_governance_execution_with_peer_driven_guard(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
    expectations: &GovernanceExecutionExpectations,
    trust_domain: &AuthorityTrustDomain,
    policy: GovernanceExecutionPolicy,
    is_peer_driven_apply_preflight: bool,
) -> GovernanceExecutionComposedOutcome {
    // MainNet peer-driven apply remains refused regardless of any fixture
    // governance success.
    if is_peer_driven_apply_preflight && trust_domain.environment == TrustBundleEnvironment::Mainnet
    {
        return GovernanceExecutionComposedOutcome::MainNetPeerDrivenApplyRefused;
    }

    let outcome =
        evaluate_governance_execution_policy(input, decision, expectations, trust_domain, policy);

    if outcome.is_accept() {
        GovernanceExecutionComposedOutcome::Accepted(outcome)
    } else {
        GovernanceExecutionComposedOutcome::Rejected(outcome)
    }
}

// ===========================================================================
// Explicit fail-closed helpers
// ===========================================================================

/// Run 211 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. Encodes,
/// at the typed Run 211 boundary, the rule that MainNet peer-driven apply
/// remains the Run 147 / 148 / 152 FATAL refusal regardless of any
/// governance execution decision — even a fixture governance decision
/// that the policy approves. Pure data; never reads decision material.
pub fn mainnet_peer_driven_apply_remains_refused_under_governance_execution(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 211 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy a production
/// governance execution policy. Run 211 always returns `true`: a
/// production governance execution is an authorized governance-council
/// decision and is never satisfiable by a local operator key.
/// Grep-verifiable named symbol for an operator-log line.
pub fn local_operator_cannot_satisfy_governance_execution() -> bool {
    true
}

/// Run 211 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy a
/// production governance execution policy. Run 211 always returns `true`:
/// a production governance execution is an authorized governance decision
/// and is never satisfiable by counting peers. Grep-verifiable named
/// symbol for an operator-log line.
pub fn peer_majority_cannot_satisfy_governance_execution() -> bool {
    true
}

/// Run 211 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported. Run 211
/// always returns `true`: no validator-set rotation exists. Grep-verifiable
/// named symbol for an operator-log line.
pub fn validator_set_rotation_remains_unsupported() -> bool {
    true
}
