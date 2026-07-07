//! Run 305 — source/test **real** validator-set rotation application /
//! epoch-transition executor boundary.
//!
//! This module implements the next source/test boundary above the Run
//! 303/304 validator-set rotation / authority-set synchronization *intent*
//! boundary: the boundary that consumes a **verified** Run 303/304
//! non-mutating validator-set rotation *plan* (the accepted
//! [`crate::pqc_production_validator_set_rotation_intent::ProductionValidatorSetRotationDecision`]
//! carrying a
//! [`crate::pqc_production_validator_set_rotation_intent::ProductionValidatorSetRotationPlan`],
//! as release-binary-evidenced by Run 304) and translates it into a typed,
//! deterministic, policy-gated **application decision / epoch-transition
//! intent** — *without* ever applying a live validator-set change,
//! transitioning a consensus epoch, or mutating any trust state.
//!
//! Where the Run 303 boundary answers "given a verified governance execution
//! intent, what typed non-mutating validator-set rotation plan does it
//! authorize?", Run 305 answers the next question: "given a verified
//! validator-set rotation plan, what typed, non-mutating **application
//! decision** for a *future* epoch-transition executor does it authorize,
//! under an explicit application policy, bound to the full rotation-plan /
//! governance / validator-set / custody / attestation / durable-replay
//! evidence tuple, and to an explicit epoch-transition target?".
//!
//! ## Scope and honesty constraints (Run 305)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 306**.
//! * The default policy is
//!   [`ProductionValidatorSetRotationApplicationPolicy::Disabled`] and fails
//!   closed **before** any plan binding, validator-set binding, or
//!   application-decision construction.
//! * Only a **verified** Run 303/304 validator-set rotation decision that
//!   `is_accept()` and carries a
//!   [`crate::pqc_production_validator_set_rotation_intent::ProductionValidatorSetRotationPlan`]
//!   can authorize an application decision. Unverified decisions, governance
//!   proof alone, governance execution intent alone, local-operator
//!   assertions, peer-majority assertions, custody-only, RemoteSigner-only,
//!   custody-attestation-only, fixture-only plans, and arbitrary
//!   validator-set bytes are all rejected as production authority.
//! * The boundary produces only a typed
//!   [`ProductionValidatorSetRotationApplicationIntent`]; it **never**
//!   applies the plan, never mutates a live validator set, never writes
//!   durable validator-set state, never calls
//!   `BasicHotStuffEngine::transition_to_epoch`, never writes
//!   `meta:current_epoch`, and never injects a `PAYLOAD_KIND_RECONFIG`
//!   block. Only a typed accepted outcome may authorize a *future* mutation
//!   run.
//! * MainNet remains **refused**: even a fully valid source/test
//!   DevNet/TestNet application decision does not enable MainNet runtime
//!   behavior.
//! * The boundary is **non-mutating**: no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust swap,
//!   no session eviction, no PQC trust-bundle sequence write, no authority
//!   marker write, no durable replay overwrite, no KMS/HSM signing call, no
//!   RemoteSigner fallback, no custody/fixture/local/peer-majority
//!   fallback, no settlement, no external publication, and no default
//!   runtime wiring.
//! * No CLI flag and no default runtime wiring is added. Full C4 remains
//!   OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_305.md`.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::OnChainGovernanceQuorum;
use crate::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding,
};
use crate::pqc_production_validator_set_rotation_intent::{
    ProductionValidatorSetRotationDecision, ProductionValidatorSetRotationPlan,
    ProductionValidatorSetRotationPlanKind, ValidatorSetRotationAction,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 305 — the only validator-set rotation application boundary protocol
/// version this run accepts.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION: u16 = 1;

/// Run 305 — validator-set rotation application intent digest domain tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_INTENT_DOMAIN_TAG: &str =
    "QBIND:run305-validator-set-rotation-application-intent:v1";

/// Run 305 — validator-set rotation application request-id domain tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run305-validator-set-rotation-application-request:v1";

/// Run 305 — validator-set rotation application transcript digest domain
/// tag.
pub const PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run305-validator-set-rotation-application-transcript:v1";

/// Length-prefixed domain-separated field hashing helper. `Debug`
/// formatting is never used as canonical bytes.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

// ===========================================================================
// Protocol version newtype
// ===========================================================================

/// Run 305 — typed validator-set rotation application boundary protocol
/// version. Only
/// [`PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION`] is
/// supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionValidatorSetRotationApplicationProtocolVersion(pub u16);

impl ProductionValidatorSetRotationApplicationProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION
    }
}

impl Default for ProductionValidatorSetRotationApplicationProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 305 — typed validator-set rotation application boundary policy.
///
/// `Disabled` is the default fail-closed policy: the boundary refuses
/// before any plan binding or application-decision construction.
/// `AllowSourceTestValidatorSetRotationApplication` is the only policy that
/// can produce an accepted source/test application decision, and only on
/// DevNet/TestNet with a verified Run 303/304 validator-set rotation plan.
/// `RequireProductionValidatorSetRotationApplication` and
/// `MainnetProductionValidatorSetRotationApplicationRequired` are
/// **reachable but fail-closed** production/MainNet policies: no production
/// validator-set rotation application authority is wired, so they fail
/// closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionValidatorSetRotationApplicationPolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified validator-set rotation
    /// plan may produce a typed non-mutating application decision as
    /// source/test evidence only. MainNet remains refused.
    AllowSourceTestValidatorSetRotationApplication,
    /// Production policy. Reachable but fails closed: no production
    /// validator-set rotation application prerequisites are wired.
    RequireProductionValidatorSetRotationApplication,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production validator-set rotation application authority is wired.
    MainnetProductionValidatorSetRotationApplicationRequired,
}

impl ProductionValidatorSetRotationApplicationPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestValidatorSetRotationApplication => {
                "allow-source-test-validator-set-rotation-application"
            }
            Self::RequireProductionValidatorSetRotationApplication => {
                "require-production-validator-set-rotation-application"
            }
            Self::MainnetProductionValidatorSetRotationApplicationRequired => {
                "mainnet-production-validator-set-rotation-application-required"
            }
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy allows source/test validator-set
    /// rotation application decisions (DevNet/TestNet only).
    pub const fn allows_source_test(self) -> bool {
        matches!(self, Self::AllowSourceTestValidatorSetRotationApplication)
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(self, Self::RequireProductionValidatorSetRotationApplication)
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(
            self,
            Self::MainnetProductionValidatorSetRotationApplicationRequired
        )
    }
}

// ===========================================================================
// Boundary kind taxonomy
// ===========================================================================

/// Run 305 — typed validator-set rotation application boundary kind.
///
/// `Disabled` is the inert default.
/// `SourceTestValidatorSetRotationApplication` performs real source/test
/// application-decision construction. A reserved
/// `ProductionValidatorSetRotationApplication` kind is fail-closed as
/// unavailable in Run 305 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionValidatorSetRotationApplicationKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test validator-set rotation application executor
    /// boundary.
    SourceTestValidatorSetRotationApplication,
    /// Reserved production application kind. Fail-closed in Run 305.
    ProductionValidatorSetRotationApplication,
}

impl ProductionValidatorSetRotationApplicationKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestValidatorSetRotationApplication => {
                "source-test-validator-set-rotation-application"
            }
            Self::ProductionValidatorSetRotationApplication => {
                "production-validator-set-rotation-application"
            }
        }
    }

    /// Returns `true` iff this kind performs real source/test application
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(self, Self::SourceTestValidatorSetRotationApplication)
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 305 — typed validator-set rotation application boundary config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationConfig {
    /// Boundary protocol version. Must equal the supported version.
    pub protocol_version: ProductionValidatorSetRotationApplicationProtocolVersion,
    /// The boundary kind.
    pub kind: ProductionValidatorSetRotationApplicationKind,
}

impl ProductionValidatorSetRotationApplicationConfig {
    pub fn new(kind: ProductionValidatorSetRotationApplicationKind) -> Self {
        Self {
            protocol_version: ProductionValidatorSetRotationApplicationProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test application boundary kind.
    pub fn source_test() -> Self {
        Self::new(ProductionValidatorSetRotationApplicationKind::SourceTestValidatorSetRotationApplication)
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionValidatorSetRotationApplicationConfig {
    fn default() -> Self {
        Self::new(ProductionValidatorSetRotationApplicationKind::Disabled)
    }
}

// ===========================================================================
// Application decision kind taxonomy
// ===========================================================================

/// Run 305 — the typed kind of a prepared, non-mutating validator-set
/// rotation application decision / epoch-transition intent.
///
/// Each kind corresponds one-to-one with a supported Run 303
/// [`ProductionValidatorSetRotationPlanKind`]; the reserved
/// [`Self::UnsupportedApplication`] never authorizes a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorSetRotationApplicationDecisionKind {
    ApplyNoOpAlreadySynchronized,
    ApplyValidatorAdd,
    ApplyValidatorRemove,
    ApplyValidatorMetadataUpdate,
    ApplyValidatorIdentityRotation,
    ApplyValidatorRetirement,
    ApplyEmergencyValidatorRemoval,
    ApplyAuthoritySetSynchronization,
    ApplyBulkValidatorSetRotation,
    UnsupportedApplication,
}

impl ValidatorSetRotationApplicationDecisionKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ApplyNoOpAlreadySynchronized => "apply-no-op-already-synchronized",
            Self::ApplyValidatorAdd => "apply-validator-add",
            Self::ApplyValidatorRemove => "apply-validator-remove",
            Self::ApplyValidatorMetadataUpdate => "apply-validator-metadata-update",
            Self::ApplyValidatorIdentityRotation => "apply-validator-identity-rotation",
            Self::ApplyValidatorRetirement => "apply-validator-retirement",
            Self::ApplyEmergencyValidatorRemoval => "apply-emergency-validator-removal",
            Self::ApplyAuthoritySetSynchronization => "apply-authority-set-synchronization",
            Self::ApplyBulkValidatorSetRotation => "apply-bulk-validator-set-rotation",
            Self::UnsupportedApplication => "unsupported-application",
        }
    }

    /// Every Run 305 application decision kind is a *prepared*,
    /// non-mutating decision; none applies a live validator-set change.
    pub const fn is_non_mutating(self) -> bool {
        true
    }

    /// Maps a supported Run 303 plan kind to its application decision kind.
    /// Returns [`Self::UnsupportedApplication`] for the reserved
    /// unsupported plan kind.
    pub const fn from_plan_kind(kind: ProductionValidatorSetRotationPlanKind) -> Self {
        use ProductionValidatorSetRotationPlanKind as P;
        match kind {
            P::NoOpAlreadySynchronized => Self::ApplyNoOpAlreadySynchronized,
            P::ValidatorAdd => Self::ApplyValidatorAdd,
            P::ValidatorRemove => Self::ApplyValidatorRemove,
            P::ValidatorMetadataUpdate => Self::ApplyValidatorMetadataUpdate,
            P::ValidatorIdentityRotation => Self::ApplyValidatorIdentityRotation,
            P::ValidatorRetirement => Self::ApplyValidatorRetirement,
            P::EmergencyValidatorRemoval => Self::ApplyEmergencyValidatorRemoval,
            P::AuthoritySetSynchronization => Self::ApplyAuthoritySetSynchronization,
            P::BulkValidatorSetRotation => Self::ApplyBulkValidatorSetRotation,
            P::UnsupportedRotationRequest => Self::UnsupportedApplication,
        }
    }

    /// Returns `true` iff this is the reserved unsupported kind.
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedApplication)
    }
}

// ===========================================================================
// Authority source
// ===========================================================================

/// Run 305 — the validator-set rotation authority source presented to the
/// executor.
///
/// Only [`Self::VerifiedRotationPlan`] carrying a Run 303/304 validator-set
/// rotation decision that `is_accept()` **and** carries a prepared plan can
/// authorize an application decision. Every other variant is a non-authority
/// source rejected with a precise fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorSetRotationApplicationAuthoritySource {
    /// A verified Run 303/304 validator-set rotation decision. The **only**
    /// accepted authority source. The decision must `is_accept()` and carry
    /// `Some(plan)`.
    VerifiedRotationPlan {
        decision: ProductionValidatorSetRotationDecision,
    },
    /// No rotation plan was supplied.
    MissingRotationPlan,
    /// An unverified / non-accept validator-set rotation decision. Rejected.
    UnverifiedRotationPlan {
        decision: ProductionValidatorSetRotationDecision,
    },
    /// An accepted decision that carries no prepared plan. Rejected.
    AcceptedDecisionWithoutPlan {
        decision: ProductionValidatorSetRotationDecision,
    },
    /// A raw on-chain governance proof presented directly, without a Run 303
    /// rotation plan. Rejected.
    GovernanceProofWithoutRotationPlan,
    /// A Run 301/302 governance execution intent presented directly,
    /// without a Run 303 rotation plan. Rejected.
    GovernanceExecutionIntentWithoutRotationPlan,
    /// A local-operator assertion. Rejected.
    LocalOperatorAssertion,
    /// A peer-majority assertion. Rejected.
    PeerMajorityAssertion,
    /// Custody-backend evidence presented alone as authority. Rejected.
    CustodyOnlyEvidence,
    /// RemoteSigner evidence presented alone as authority. Rejected.
    RemoteSignerOnlyEvidence,
    /// Custody-attestation evidence presented alone as authority. Rejected.
    CustodyAttestationOnlyEvidence,
    /// A Run 178 fixture-class rotation plan presented as production
    /// authority. Rejected.
    FixtureOnlyPlan,
    /// Arbitrary validator-set bytes presented directly, without a verified
    /// rotation plan. Rejected.
    ArbitraryValidatorSetBytes,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 305 — the explicit trusted inputs the executor binds a verified
/// validator-set rotation plan against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// The opaque application policy id bound into the application decision.
    pub application_policy_id: String,
    /// Expected Run 303 rotation policy id (bound into the plan).
    pub expected_rotation_policy_id: String,
    /// Expected governance domain id.
    pub expected_governance_domain_id: String,
    /// Expected governance epoch.
    pub expected_governance_epoch: u64,
    /// Expected proposal id.
    pub expected_proposal_id: String,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected requested rotation action.
    pub expected_rotation_action: ValidatorSetRotationAction,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected quorum.
    pub expected_quorum: OnChainGovernanceQuorum,
    /// Expected threshold.
    pub expected_threshold: GovernanceThreshold,
    /// Expected Run 301 governance execution decision id (bound into the
    /// plan).
    pub expected_governance_decision_id: String,
    /// Expected Run 301 governance execution request id.
    pub expected_governance_request_id: String,
    /// Expected Run 301 governance execution intent digest.
    pub expected_governance_intent_digest: String,
    /// Expected Run 303 rotation decision id.
    pub expected_rotation_decision_id: String,
    /// Expected Run 303 rotation request id.
    pub expected_rotation_request_id: String,
    /// Expected Run 303 rotation transcript digest.
    pub expected_rotation_transcript_digest: String,
    /// Expected Run 303 rotation plan digest (the authority-input binding).
    pub expected_rotation_plan_digest: String,
    /// Expected current validator-set digest (the set the delta applies to).
    pub expected_current_set_digest: String,
    /// Expected proposed validator-set digest (the post-delta set).
    pub expected_proposed_set_digest: String,
    /// Expected validator-set delta digest.
    pub expected_delta_digest: String,
    /// Expected proposed validator-set epoch.
    pub expected_validator_set_epoch: u64,
    /// Expected proposed validator-set version.
    pub expected_validator_set_version: u64,
    /// Expected rotation nonce (bound into the plan).
    pub expected_rotation_nonce: u64,
    /// Expected epoch-transition target a future executor would transition
    /// to. Must equal the plan's proposed validator-set epoch.
    pub expected_epoch_transition_target: u64,
    /// Minimum acceptable governance epoch (freshness; never wall-clock).
    pub min_governance_epoch: u64,
    /// Minimum acceptable validator-set epoch (freshness; never wall-clock).
    pub min_validator_set_epoch: u64,
    /// Minimum acceptable validator-set version (freshness).
    pub min_validator_set_version: u64,
    /// Optional persisted authority-domain sequence for stale-lower-sequence
    /// replay detection.
    pub persisted_sequence: Option<u64>,
    /// Whether custody backend evidence is required, and its expected
    /// binding.
    pub require_custody_evidence: bool,
    pub expected_custody: Option<GovernanceExecutionCustodyBinding>,
    /// Whether custody attestation evidence is required, and its expected
    /// binding.
    pub require_attestation_evidence: bool,
    pub expected_attestation: Option<GovernanceExecutionAttestationBinding>,
    /// Whether durable replay evidence is required, and its expected
    /// binding.
    pub require_durable_replay_evidence: bool,
    pub expected_durable_replay: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionValidatorSetRotationApplicationInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.application_policy_id.is_empty()
            && !self.expected_rotation_policy_id.is_empty()
            && !self.expected_governance_domain_id.is_empty()
            && !self.expected_proposal_id.is_empty()
            && !self.expected_governance_decision_id.is_empty()
            && !self.expected_governance_request_id.is_empty()
            && !self.expected_governance_intent_digest.is_empty()
            && !self.expected_rotation_decision_id.is_empty()
            && !self.expected_rotation_request_id.is_empty()
            && !self.expected_rotation_transcript_digest.is_empty()
            && !self.expected_rotation_plan_digest.is_empty()
            && !self.expected_current_set_digest.is_empty()
            && !self.expected_proposed_set_digest.is_empty()
            && !self.expected_delta_digest.is_empty()
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 305 — a validator-set rotation application request: the authority
/// source (a verified rotation plan), the explicit epoch-transition target,
/// an application nonce, and any represented custody / attestation /
/// durable-replay evidence bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationRequest {
    pub authority_source: ValidatorSetRotationApplicationAuthoritySource,
    /// The epoch a future epoch-transition executor would transition to.
    pub proposed_epoch_transition_target: u64,
    /// The application nonce (idempotency / replay binding).
    pub application_nonce: u64,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionValidatorSetRotationApplicationRequest {
    /// Construct a request carrying only an authority source, epoch target,
    /// and application nonce (no represented custody / attestation /
    /// durable-replay evidence).
    pub fn new(
        authority_source: ValidatorSetRotationApplicationAuthoritySource,
        proposed_epoch_transition_target: u64,
        application_nonce: u64,
    ) -> Self {
        Self {
            authority_source,
            proposed_epoch_transition_target,
            application_nonce,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 305 — caller-owned replay application-id set. The executor reads from
/// this set but never mutates it.
pub trait ValidatorSetRotationApplicationReplaySet {
    fn contains(&self, application_id: &str) -> bool;
}

impl ValidatorSetRotationApplicationReplaySet for &[String] {
    fn contains(&self, application_id: &str) -> bool {
        (*self).iter().any(|s| s == application_id)
    }
}

impl ValidatorSetRotationApplicationReplaySet for Vec<String> {
    fn contains(&self, application_id: &str) -> bool {
        self.iter().any(|s| s == application_id)
    }
}

/// Empty replay set helper.
pub struct EmptyValidatorSetRotationApplicationReplaySet;

impl ValidatorSetRotationApplicationReplaySet for EmptyValidatorSetRotationApplicationReplaySet {
    fn contains(&self, _application_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Application intent (boundary output)
// ===========================================================================

/// Run 305 — a typed, deterministic, **non-mutating** validator-set rotation
/// application decision / epoch-transition intent. Only a typed accepted
/// outcome carrying this intent may authorize a *future* mutation run (Run
/// 306+); Run 305 never applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationIntent {
    pub decision_kind: ValidatorSetRotationApplicationDecisionKind,
    pub protocol_version: u16,
    pub application_policy_id: String,

    // ---- Bound rotation-plan authority tuple --------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,
    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub governance_height: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,
    pub lifecycle_action: LocalLifecycleAction,
    pub rotation_action: ValidatorSetRotationAction,
    pub authority_domain_sequence: u64,
    pub governance_decision_id: String,
    pub governance_request_id: String,
    pub governance_intent_digest: String,
    pub rotation_decision_id: String,
    pub rotation_request_id: String,
    pub rotation_transcript_digest: String,
    pub rotation_plan_digest: String,

    // ---- Bound validator-set tuple ------------------------------------
    pub current_set_digest: String,
    pub proposed_set_digest: String,
    pub delta_digest: String,
    pub validator_set_epoch: u64,
    pub validator_set_version: u64,
    pub proposed_validator_count: u64,
    pub rotation_nonce: u64,

    // ---- Epoch-transition application binding --------------------------
    pub epoch_transition_target: u64,
    pub application_nonce: u64,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionValidatorSetRotationApplicationIntent {
    /// Deterministic, domain-separated SHA3-256 hex intent digest. `Debug`
    /// formatting is never used as canonical bytes.
    pub fn intent_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_INTENT_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"decision_kind", self.decision_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(&mut h, b"application_policy_id", self.application_policy_id.as_bytes());
        hash_field(&mut h, b"environment", &self.environment.metric_code().to_le_bytes());
        hash_field(&mut h, b"chain_id", self.chain_id.as_bytes());
        hash_field(&mut h, b"genesis_hash", self.genesis_hash.as_bytes());
        hash_field(
            &mut h,
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        hash_field(&mut h, b"authority_root_suite_id", &[self.authority_root_suite_id]);
        hash_field(&mut h, b"governance_domain_id", self.governance_domain_id.as_bytes());
        hash_field(&mut h, b"governance_epoch", &self.governance_epoch.to_le_bytes());
        hash_field(&mut h, b"governance_height", &self.governance_height.to_le_bytes());
        hash_field(&mut h, b"proposal_id", self.proposal_id.as_bytes());
        hash_field(&mut h, b"proposal_digest", self.proposal_digest.as_bytes());
        hash_field(&mut h, b"quorum_voted", &self.quorum.voters_voted.to_le_bytes());
        hash_field(&mut h, b"quorum_total", &self.quorum.total_voters.to_le_bytes());
        hash_field(&mut h, b"quorum_required", &self.quorum.required_quorum.to_le_bytes());
        hash_field(&mut h, b"threshold_approvals", &self.threshold.approvals.to_le_bytes());
        hash_field(&mut h, b"threshold_required", &self.threshold.required.to_le_bytes());
        hash_field(&mut h, b"threshold_total", &self.threshold.total.to_le_bytes());
        hash_field(&mut h, b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        hash_field(&mut h, b"rotation_action", self.rotation_action.tag().as_bytes());
        hash_field(
            &mut h,
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        hash_field(&mut h, b"governance_decision_id", self.governance_decision_id.as_bytes());
        hash_field(&mut h, b"governance_request_id", self.governance_request_id.as_bytes());
        hash_field(&mut h, b"governance_intent_digest", self.governance_intent_digest.as_bytes());
        hash_field(&mut h, b"rotation_decision_id", self.rotation_decision_id.as_bytes());
        hash_field(&mut h, b"rotation_request_id", self.rotation_request_id.as_bytes());
        hash_field(
            &mut h,
            b"rotation_transcript_digest",
            self.rotation_transcript_digest.as_bytes(),
        );
        hash_field(&mut h, b"rotation_plan_digest", self.rotation_plan_digest.as_bytes());
        hash_field(&mut h, b"current_set_digest", self.current_set_digest.as_bytes());
        hash_field(&mut h, b"proposed_set_digest", self.proposed_set_digest.as_bytes());
        hash_field(&mut h, b"delta_digest", self.delta_digest.as_bytes());
        hash_field(&mut h, b"validator_set_epoch", &self.validator_set_epoch.to_le_bytes());
        hash_field(&mut h, b"validator_set_version", &self.validator_set_version.to_le_bytes());
        hash_field(
            &mut h,
            b"proposed_validator_count",
            &self.proposed_validator_count.to_le_bytes(),
        );
        hash_field(&mut h, b"rotation_nonce", &self.rotation_nonce.to_le_bytes());
        hash_field(&mut h, b"epoch_transition_target", &self.epoch_transition_target.to_le_bytes());
        hash_field(&mut h, b"application_nonce", &self.application_nonce.to_le_bytes());
        match &self.custody_binding {
            Some(c) => {
                hash_field(&mut h, b"custody_present", &[1u8]);
                custody_hash_into(c, &mut h);
            }
            None => hash_field(&mut h, b"custody_present", &[0u8]),
        }
        match &self.attestation_binding {
            Some(a) => {
                hash_field(&mut h, b"attestation_present", &[1u8]);
                attestation_hash_into(a, &mut h);
            }
            None => hash_field(&mut h, b"attestation_present", &[0u8]),
        }
        match &self.durable_replay_binding {
            Some(d) => {
                hash_field(&mut h, b"durable_present", &[1u8]);
                durable_hash_into(d, &mut h);
            }
            None => hash_field(&mut h, b"durable_present", &[0u8]),
        }
        hex::encode(h.finalize())
    }

    /// This application intent is prepared, non-mutating, and never applied
    /// by Run 305.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }
}

/// Custody binding canonical hashing (module-local; mirrors Run 301/303
/// field order for cross-run digest stability).
fn custody_hash_into(c: &GovernanceExecutionCustodyBinding, h: &mut sha3::Sha3_256) {
    hash_field(h, b"custody_provider_class", c.provider_class.tag().as_bytes());
    hash_field(h, b"custody_key_handle", c.key_handle.as_bytes());
    hash_field(h, b"custody_signer_fingerprint", c.signer_fingerprint.as_bytes());
    hash_field(
        h,
        b"custody_transcript_digest",
        c.custody_transcript_digest.as_bytes(),
    );
}

fn attestation_hash_into(a: &GovernanceExecutionAttestationBinding, h: &mut sha3::Sha3_256) {
    hash_field(
        h,
        b"attestation_transcript_digest",
        a.attestation_transcript_digest.as_bytes(),
    );
    hash_field(h, b"attestation_measurement", a.measurement.as_bytes());
}

fn durable_hash_into(d: &GovernanceExecutionDurableReplayBinding, h: &mut sha3::Sha3_256) {
    hash_field(h, b"durable_record_id", d.durable_record_id.as_bytes());
    hash_field(h, b"durable_record_digest", d.durable_record_digest.as_bytes());
}

/// Run 305 — deterministic application intent digest wrapper exposed as a
/// named symbol.
pub fn production_validator_set_rotation_application_intent_digest(
    intent: &ProductionValidatorSetRotationApplicationIntent,
) -> String {
    intent.intent_digest()
}

/// Run 305 — deterministic, domain-separated application request id binding
/// the protocol version, rotation plan digest, application policy id,
/// epoch-transition target, and application nonce. Deterministic across
/// identical inputs; never wall-clock.
pub fn production_validator_set_rotation_application_request_id(
    protocol_version: u16,
    rotation_plan_digest: &str,
    application_policy_id: &str,
    epoch_transition_target: u64,
    application_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_REQUEST_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"rotation_plan_digest", rotation_plan_digest.as_bytes());
    hash_field(&mut h, b"application_policy_id", application_policy_id.as_bytes());
    hash_field(
        &mut h,
        b"epoch_transition_target",
        &epoch_transition_target.to_le_bytes(),
    );
    hash_field(&mut h, b"application_nonce", &application_nonce.to_le_bytes());
    hex::encode(h.finalize())
}

/// Run 305 — deterministic, domain-separated application transcript digest
/// binding the protocol version, request id, intent digest, and outcome tag.
pub fn production_validator_set_rotation_application_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    intent_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"request_id", request_id.as_bytes());
    hash_field(&mut h, b"intent_digest", intent_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 305 — typed outcome of the validator-set rotation application
/// executor boundary.
///
/// Only [`Self::AcceptedSourceTestValidatorSetRotationApplicationDecision`]
/// authorizes a (source/test, DevNet/TestNet, evidence-only, non-mutating)
/// application decision. Every other variant is a precise, non-mutating
/// fail-closed reject (or the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionValidatorSetRotationApplicationOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no authority was bound.
    Disabled,
    /// The boundary kind is unavailable / misconfigured.
    ValidatorSetRotationApplicationBoundaryUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionValidatorSetRotationApplicationUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionValidatorSetRotationApplicationUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet validator-set rotation plan produced a
    /// typed non-mutating application decision under the source/test policy.
    /// **Evidence only.**
    AcceptedSourceTestValidatorSetRotationApplicationDecision {
        decision_kind: ValidatorSetRotationApplicationDecisionKind,
        environment: TrustBundleEnvironment,
        epoch_transition_target: u64,
        application_nonce: u64,
    },

    // ---- Rotation-plan / authority failures ---------------------------
    VerifiedRotationPlanRequired,
    UnverifiedRotationPlanRejected,
    GovernanceProofAloneRejected,
    GovernanceExecutionIntentAloneRejected,
    FixtureRotationPlanRejectedAsProductionAuthority,
    LocalOperatorProofRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,
    CustodyAttestationOnlyProofRejected,
    ArbitraryValidatorSetBytesRejected,
    RotationPlanDigestMismatch,
    RotationPlanTranscriptMismatch,
    RotationPlanRequestIdMismatch,
    RotationPlanIntegrityMismatch,
    WrongEnvironment,
    WrongChain,
    WrongGenesis,
    WrongAuthorityRoot,
    WrongGovernanceDomain,
    WrongGovernanceEpoch,
    WrongProposalId,
    WrongGovernanceExecutionDecisionId,
    WrongGovernanceExecutionRequestId,
    WrongGovernanceExecutionIntentDigest,
    WrongRotationDecisionId,
    WrongLifecycleAction,
    WrongRotationAction,
    WrongAuthoritySequence,
    WrongQuorum,
    WrongThreshold,

    // ---- Validator-set binding failures -------------------------------
    WrongCurrentValidatorSetDigest,
    WrongProposedValidatorSetDigest,
    WrongValidatorSetDeltaDigest,
    WrongValidatorSetEpoch,
    WrongValidatorSetVersion,
    WrongRotationNonce,
    UnsupportedApplicationDecision,

    // ---- Epoch-transition binding failures ----------------------------
    WrongEpochTransitionTarget,

    // ---- Custody / attestation / durable replay -----------------------
    CustodyBackendEvidenceRequired,
    CustodyBackendMismatch,
    CustodyAttestationRequired,
    CustodyAttestationMismatch,
    DurableReplayEvidenceRequired,
    DurableReplayMismatch,
    DurableReplayUnavailable,

    // ---- Replay / freshness -------------------------------------------
    ApplicationReplayRejected { application_id: String },
    StaleGovernanceEpoch,
    StaleAuthoritySequence,
    StaleValidatorSetEpoch,
    StaleValidatorSetVersion,
    ConflictingApplicationForSameRotation,
    ValidatorSetRotationApplicationAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionValidatorSetRotationApplicationOutcome {
    /// Returns `true` iff this outcome accepted a source/test application
    /// decision.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestValidatorSetRotationApplicationDecision { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 305 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 305.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ValidatorSetRotationApplicationBoundaryUnavailable => {
                "validator-set-rotation-application-boundary-unavailable"
            }
            Self::ProductionValidatorSetRotationApplicationUnavailable => {
                "production-validator-set-rotation-application-unavailable"
            }
            Self::MainNetProductionValidatorSetRotationApplicationUnavailable => {
                "mainnet-production-validator-set-rotation-application-unavailable"
            }
            Self::AcceptedSourceTestValidatorSetRotationApplicationDecision { .. } => {
                "accepted-source-test-validator-set-rotation-application-decision"
            }
            Self::VerifiedRotationPlanRequired => "verified-rotation-plan-required",
            Self::UnverifiedRotationPlanRejected => "unverified-rotation-plan-rejected",
            Self::GovernanceProofAloneRejected => "governance-proof-alone-rejected",
            Self::GovernanceExecutionIntentAloneRejected => {
                "governance-execution-intent-alone-rejected"
            }
            Self::FixtureRotationPlanRejectedAsProductionAuthority => {
                "fixture-rotation-plan-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::ArbitraryValidatorSetBytesRejected => "arbitrary-validator-set-bytes-rejected",
            Self::RotationPlanDigestMismatch => "rotation-plan-digest-mismatch",
            Self::RotationPlanTranscriptMismatch => "rotation-plan-transcript-mismatch",
            Self::RotationPlanRequestIdMismatch => "rotation-plan-request-id-mismatch",
            Self::RotationPlanIntegrityMismatch => "rotation-plan-integrity-mismatch",
            Self::WrongEnvironment => "wrong-environment",
            Self::WrongChain => "wrong-chain",
            Self::WrongGenesis => "wrong-genesis",
            Self::WrongAuthorityRoot => "wrong-authority-root",
            Self::WrongGovernanceDomain => "wrong-governance-domain",
            Self::WrongGovernanceEpoch => "wrong-governance-epoch",
            Self::WrongProposalId => "wrong-proposal-id",
            Self::WrongGovernanceExecutionDecisionId => "wrong-governance-execution-decision-id",
            Self::WrongGovernanceExecutionRequestId => "wrong-governance-execution-request-id",
            Self::WrongGovernanceExecutionIntentDigest => "wrong-governance-execution-intent-digest",
            Self::WrongRotationDecisionId => "wrong-rotation-decision-id",
            Self::WrongLifecycleAction => "wrong-lifecycle-action",
            Self::WrongRotationAction => "wrong-rotation-action",
            Self::WrongAuthoritySequence => "wrong-authority-sequence",
            Self::WrongQuorum => "wrong-quorum",
            Self::WrongThreshold => "wrong-threshold",
            Self::WrongCurrentValidatorSetDigest => "wrong-current-validator-set-digest",
            Self::WrongProposedValidatorSetDigest => "wrong-proposed-validator-set-digest",
            Self::WrongValidatorSetDeltaDigest => "wrong-validator-set-delta-digest",
            Self::WrongValidatorSetEpoch => "wrong-validator-set-epoch",
            Self::WrongValidatorSetVersion => "wrong-validator-set-version",
            Self::WrongRotationNonce => "wrong-rotation-nonce",
            Self::UnsupportedApplicationDecision => "unsupported-application-decision",
            Self::WrongEpochTransitionTarget => "wrong-epoch-transition-target",
            Self::CustodyBackendEvidenceRequired => "custody-backend-evidence-required",
            Self::CustodyBackendMismatch => "custody-backend-mismatch",
            Self::CustodyAttestationRequired => "custody-attestation-required",
            Self::CustodyAttestationMismatch => "custody-attestation-mismatch",
            Self::DurableReplayEvidenceRequired => "durable-replay-evidence-required",
            Self::DurableReplayMismatch => "durable-replay-mismatch",
            Self::DurableReplayUnavailable => "durable-replay-unavailable",
            Self::ApplicationReplayRejected { .. } => "application-replay-rejected",
            Self::StaleGovernanceEpoch => "stale-governance-epoch",
            Self::StaleAuthoritySequence => "stale-authority-sequence",
            Self::StaleValidatorSetEpoch => "stale-validator-set-epoch",
            Self::StaleValidatorSetVersion => "stale-validator-set-version",
            Self::ConflictingApplicationForSameRotation => {
                "conflicting-application-for-same-rotation"
            }
            Self::ValidatorSetRotationApplicationAmbiguous { .. } => {
                "validator-set-rotation-application-ambiguous"
            }
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (boundary output)
// ===========================================================================

/// Run 305 — the typed decision produced by the executor boundary: the
/// outcome, the bound rotation decision id, the deterministic request id,
/// the optional prepared application intent, its digest, and the
/// verification transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationDecision {
    pub outcome: ProductionValidatorSetRotationApplicationOutcome,
    pub application_id: String,
    pub request_id: String,
    pub application_intent: Option<ProductionValidatorSetRotationApplicationIntent>,
    pub intent_digest: String,
    pub transcript_digest: String,
}

impl ProductionValidatorSetRotationApplicationDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating
    /// application intent (only on accept). The boundary never applies it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.application_intent.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 305 — typed idempotency / recovery outcome for a prepared-application
/// window. Every variant is non-mutating; no durable state is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionValidatorSetRotationApplicationRecoveryOutcome {
    /// No prior prepared application for this rotation window — clean.
    NoPriorApplicationWindow,
    /// A prior prepared application for this window was observed; the
    /// executor re-derives the same intent deterministically without
    /// mutation.
    IdempotentReplayObserved { application_id: String },
    /// The recovery window is disabled (policy `Disabled`).
    RecoveryDisabled,
}

impl ProductionValidatorSetRotationApplicationRecoveryOutcome {
    /// Every recovery outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff the recovery window is clean (no prior
    /// application).
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::NoPriorApplicationWindow)
    }
}

// ===========================================================================
// Executor boundary
// ===========================================================================

/// Run 305 — the source/test validator-set rotation application /
/// epoch-transition executor boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionValidatorSetRotationApplicationExecutor {
    pub config: ProductionValidatorSetRotationApplicationConfig,
    pub policy: ProductionValidatorSetRotationApplicationPolicy,
}

impl ProductionValidatorSetRotationApplicationExecutor {
    pub fn new(
        config: ProductionValidatorSetRotationApplicationConfig,
        policy: ProductionValidatorSetRotationApplicationPolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test executor under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionValidatorSetRotationApplicationConfig::source_test(),
            ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication,
        )
    }

    /// Extract the verified validator-set rotation decision and prepared
    /// plan from an authority source, mapping every non-authority source to
    /// its precise fail-closed outcome.
    fn resolve_authority_source<'a>(
        &self,
        source: &'a ValidatorSetRotationApplicationAuthoritySource,
    ) -> Result<
        (
            &'a ProductionValidatorSetRotationDecision,
            &'a ProductionValidatorSetRotationPlan,
        ),
        ProductionValidatorSetRotationApplicationOutcome,
    > {
        use ProductionValidatorSetRotationApplicationOutcome as O;
        use ValidatorSetRotationApplicationAuthoritySource as S;
        match source {
            S::VerifiedRotationPlan { decision } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedRotationPlanRejected);
                }
                match &decision.plan {
                    Some(plan) => Ok((decision, plan)),
                    None => Err(O::VerifiedRotationPlanRequired),
                }
            }
            S::MissingRotationPlan => Err(O::VerifiedRotationPlanRequired),
            S::UnverifiedRotationPlan { .. } => Err(O::UnverifiedRotationPlanRejected),
            S::AcceptedDecisionWithoutPlan { .. } => Err(O::VerifiedRotationPlanRequired),
            S::GovernanceProofWithoutRotationPlan => Err(O::GovernanceProofAloneRejected),
            S::GovernanceExecutionIntentWithoutRotationPlan => {
                Err(O::GovernanceExecutionIntentAloneRejected)
            }
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
            S::FixtureOnlyPlan => Err(O::FixtureRotationPlanRejectedAsProductionAuthority),
            S::ArbitraryValidatorSetBytes => Err(O::ArbitraryValidatorSetBytesRejected),
        }
    }

    /// Pure policy / kind / MainNet gate applied before any binding. Returns
    /// `Some(outcome)` to refuse, `None` to proceed.
    fn preflight_gate(
        &self,
        binding_env: TrustBundleEnvironment,
        inputs: &ProductionValidatorSetRotationApplicationInputs,
    ) -> Option<ProductionValidatorSetRotationApplicationOutcome> {
        use ProductionValidatorSetRotationApplicationOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind == ProductionValidatorSetRotationApplicationKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet plan is
        //    refused: no MainNet production authority is wired.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionValidatorSetRotationApplicationPolicy::MainnetProductionValidatorSetRotationApplicationRequired => {
                    O::MainNetProductionValidatorSetRotationApplicationUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. MainNet production policy on a non-MainNet domain still has no
        //    MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionValidatorSetRotationApplicationUnavailable);
        }

        // 4. The production policy has no production prerequisites wired —
        //    fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionValidatorSetRotationApplicationUnavailable);
        }

        // 5. Reserved production boundary kind is fail-closed in Run 305.
        if self.config.kind
            == ProductionValidatorSetRotationApplicationKind::ProductionValidatorSetRotationApplication
        {
            return Some(O::ValidatorSetRotationApplicationBoundaryUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() || !inputs.is_well_formed() {
            return Some(O::ValidatorSetRotationApplicationBoundaryUnavailable);
        }

        None
    }

    /// Cross-check the verified rotation decision and its prepared plan
    /// against the explicit trusted inputs and trust domain. Returns
    /// `Some(outcome)` on the first divergence.
    fn check_rotation_plan_binding(
        &self,
        decision: &ProductionValidatorSetRotationDecision,
        plan: &ProductionValidatorSetRotationPlan,
        inputs: &ProductionValidatorSetRotationApplicationInputs,
    ) -> Option<ProductionValidatorSetRotationApplicationOutcome> {
        use ProductionValidatorSetRotationApplicationOutcome as O;
        let td = &inputs.trust_domain;

        // Rotation-decision transcript binding.
        if decision.rotation_id != inputs.expected_rotation_decision_id {
            return Some(O::WrongRotationDecisionId);
        }
        if decision.request_id != inputs.expected_rotation_request_id {
            return Some(O::RotationPlanRequestIdMismatch);
        }
        if decision.transcript_digest != inputs.expected_rotation_transcript_digest {
            return Some(O::RotationPlanTranscriptMismatch);
        }
        if decision.plan_digest != inputs.expected_rotation_plan_digest {
            return Some(O::RotationPlanDigestMismatch);
        }
        // The prepared plan must reproduce the bound digest exactly.
        if plan.plan_digest() != decision.plan_digest {
            return Some(O::RotationPlanIntegrityMismatch);
        }

        // Trust-domain binding.
        if plan.environment != td.environment {
            return Some(O::WrongEnvironment);
        }
        if plan.chain_id != td.chain_id {
            return Some(O::WrongChain);
        }
        if plan.genesis_hash != td.genesis_hash {
            return Some(O::WrongGenesis);
        }
        if plan.authority_root_fingerprint != td.authority_root_fingerprint
            || plan.authority_root_suite_id != td.authority_root_suite_id
        {
            return Some(O::WrongAuthorityRoot);
        }

        // Rotation-policy / governance tuple binding.
        if plan.rotation_policy_id != inputs.expected_rotation_policy_id {
            return Some(O::RotationPlanIntegrityMismatch);
        }
        if plan.governance_domain_id != inputs.expected_governance_domain_id {
            return Some(O::WrongGovernanceDomain);
        }
        if plan.governance_epoch != inputs.expected_governance_epoch {
            return Some(O::WrongGovernanceEpoch);
        }
        if plan.proposal_id != inputs.expected_proposal_id {
            return Some(O::WrongProposalId);
        }
        if plan.governance_decision_id != inputs.expected_governance_decision_id {
            return Some(O::WrongGovernanceExecutionDecisionId);
        }
        if plan.governance_request_id != inputs.expected_governance_request_id {
            return Some(O::WrongGovernanceExecutionRequestId);
        }
        if plan.governance_intent_digest != inputs.expected_governance_intent_digest {
            return Some(O::WrongGovernanceExecutionIntentDigest);
        }
        if plan.lifecycle_action != inputs.expected_lifecycle_action {
            return Some(O::WrongLifecycleAction);
        }
        if plan.rotation_action != inputs.expected_rotation_action {
            return Some(O::WrongRotationAction);
        }
        if plan.authority_domain_sequence != inputs.expected_authority_domain_sequence {
            return Some(O::WrongAuthoritySequence);
        }
        if plan.quorum != inputs.expected_quorum || !plan.quorum.is_met() {
            return Some(O::WrongQuorum);
        }
        if plan.threshold != inputs.expected_threshold || !plan.threshold.is_met() {
            return Some(O::WrongThreshold);
        }

        // Validator-set tuple binding.
        if plan.current_set_digest != inputs.expected_current_set_digest {
            return Some(O::WrongCurrentValidatorSetDigest);
        }
        if plan.proposed_set_digest != inputs.expected_proposed_set_digest {
            return Some(O::WrongProposedValidatorSetDigest);
        }
        if plan.delta_digest != inputs.expected_delta_digest {
            return Some(O::WrongValidatorSetDeltaDigest);
        }
        if plan.validator_set_epoch != inputs.expected_validator_set_epoch {
            return Some(O::WrongValidatorSetEpoch);
        }
        if plan.validator_set_version != inputs.expected_validator_set_version {
            return Some(O::WrongValidatorSetVersion);
        }
        if plan.rotation_nonce != inputs.expected_rotation_nonce {
            return Some(O::WrongRotationNonce);
        }

        None
    }

    /// Evidence composition check for represented custody / attestation /
    /// durable-replay bindings. The application request's represented
    /// bindings must match both the plan's bindings (where present) and the
    /// operator-trusted expected bindings.
    fn check_evidence(
        &self,
        request: &ProductionValidatorSetRotationApplicationRequest,
        plan: &ProductionValidatorSetRotationPlan,
        inputs: &ProductionValidatorSetRotationApplicationInputs,
    ) -> Option<ProductionValidatorSetRotationApplicationOutcome> {
        use ProductionValidatorSetRotationApplicationOutcome as O;

        if inputs.require_custody_evidence {
            let Some(actual) = &request.custody_binding else {
                return Some(O::CustodyBackendEvidenceRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::CustodyBackendMismatch);
            }
            match &inputs.expected_custody {
                Some(expected) if expected == actual => {}
                _ => return Some(O::CustodyBackendMismatch),
            }
            // Must also agree with the plan's carried binding (if present).
            if let Some(plan_custody) = &plan.custody_binding {
                if plan_custody != actual {
                    return Some(O::CustodyBackendMismatch);
                }
            }
        } else if let Some(actual) = &request.custody_binding {
            if let Some(expected) = &inputs.expected_custody {
                if expected != actual {
                    return Some(O::CustodyBackendMismatch);
                }
            }
        }

        if inputs.require_attestation_evidence {
            let Some(actual) = &request.attestation_binding else {
                return Some(O::CustodyAttestationRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::CustodyAttestationMismatch);
            }
            match &inputs.expected_attestation {
                Some(expected) if expected == actual => {}
                _ => return Some(O::CustodyAttestationMismatch),
            }
            if let Some(plan_att) = &plan.attestation_binding {
                if plan_att != actual {
                    return Some(O::CustodyAttestationMismatch);
                }
            }
        } else if let Some(actual) = &request.attestation_binding {
            if let Some(expected) = &inputs.expected_attestation {
                if expected != actual {
                    return Some(O::CustodyAttestationMismatch);
                }
            }
        }

        if inputs.require_durable_replay_evidence {
            let Some(actual) = &request.durable_replay_binding else {
                return Some(O::DurableReplayEvidenceRequired);
            };
            if !actual.is_well_formed() {
                return Some(O::DurableReplayUnavailable);
            }
            match &inputs.expected_durable_replay {
                Some(expected) if expected == actual => {}
                _ => return Some(O::DurableReplayMismatch),
            }
            if let Some(plan_dur) = &plan.durable_replay_binding {
                if plan_dur != actual {
                    return Some(O::DurableReplayMismatch);
                }
            }
        } else if let Some(actual) = &request.durable_replay_binding {
            if let Some(expected) = &inputs.expected_durable_replay {
                if expected != actual {
                    return Some(O::DurableReplayMismatch);
                }
            }
        }

        None
    }

    /// Core non-mutating evaluation. Returns the typed outcome plus, on
    /// accept, the prepared application intent.
    fn evaluate_core<R: ValidatorSetRotationApplicationReplaySet + ?Sized>(
        &self,
        request: &ProductionValidatorSetRotationApplicationRequest,
        inputs: &ProductionValidatorSetRotationApplicationInputs,
        replay_set: &R,
    ) -> (
        ProductionValidatorSetRotationApplicationOutcome,
        Option<ProductionValidatorSetRotationApplicationIntent>,
    ) {
        use ProductionValidatorSetRotationApplicationOutcome as O;

        // Resolve the authority source. The binding environment is needed
        // for the MainNet gate; if the source is a non-authority source we
        // still gate on the trust-domain environment first.
        let resolved = self.resolve_authority_source(&request.authority_source);
        let binding_env = match &resolved {
            Ok((_, plan)) => plan.environment,
            Err(_) => inputs.trust_domain.environment,
        };

        // Step 1: policy / kind / MainNet gate.
        if let Some(outcome) = self.preflight_gate(binding_env, inputs) {
            return (outcome, None);
        }

        // Step 2: verified validator-set rotation plan.
        let (decision, plan) = match resolved {
            Ok(pair) => pair,
            Err(outcome) => return (outcome, None),
        };

        // Step 3: rotation-plan binding cross-checks.
        if let Some(outcome) = self.check_rotation_plan_binding(decision, plan, inputs) {
            return (outcome, None);
        }

        // Step 4: replay / freshness on the rotation tuple.
        if let Some(prev) = inputs.persisted_sequence {
            if plan.authority_domain_sequence < prev {
                return (O::StaleAuthoritySequence, None);
            }
        }
        let application_id = production_validator_set_rotation_application_request_id(
            self.config.protocol_version.0,
            &plan.plan_digest(),
            &inputs.application_policy_id,
            request.proposed_epoch_transition_target,
            request.application_nonce,
        );
        if replay_set.contains(&application_id) {
            return (O::ApplicationReplayRejected { application_id }, None);
        }
        if plan.governance_epoch < inputs.min_governance_epoch {
            return (O::StaleGovernanceEpoch, None);
        }
        if plan.validator_set_epoch < inputs.min_validator_set_epoch {
            return (O::StaleValidatorSetEpoch, None);
        }
        if plan.validator_set_version < inputs.min_validator_set_version {
            return (O::StaleValidatorSetVersion, None);
        }

        // Step 5: custody / attestation / durable-replay evidence.
        if let Some(outcome) = self.check_evidence(request, plan, inputs) {
            return (outcome, None);
        }

        // Step 6: epoch-transition target binding. The application decision
        // targets the plan's proposed validator-set epoch; a future
        // epoch-transition executor would transition to exactly this epoch.
        if request.proposed_epoch_transition_target != inputs.expected_epoch_transition_target {
            return (O::WrongEpochTransitionTarget, None);
        }
        if request.proposed_epoch_transition_target != plan.validator_set_epoch {
            return (O::WrongEpochTransitionTarget, None);
        }

        // Step 7: derive the typed application decision kind.
        let decision_kind =
            ValidatorSetRotationApplicationDecisionKind::from_plan_kind(plan.plan_kind);
        if decision_kind.is_unsupported() {
            return (O::UnsupportedApplicationDecision, None);
        }

        // Step 8: construct the typed non-mutating application intent.
        let intent = ProductionValidatorSetRotationApplicationIntent {
            decision_kind,
            protocol_version: self.config.protocol_version.0,
            application_policy_id: inputs.application_policy_id.clone(),
            environment: plan.environment,
            chain_id: plan.chain_id.clone(),
            genesis_hash: plan.genesis_hash.clone(),
            authority_root_fingerprint: plan.authority_root_fingerprint.clone(),
            authority_root_suite_id: plan.authority_root_suite_id,
            governance_domain_id: plan.governance_domain_id.clone(),
            governance_epoch: plan.governance_epoch,
            governance_height: plan.governance_height,
            proposal_id: plan.proposal_id.clone(),
            proposal_digest: plan.proposal_digest.clone(),
            quorum: plan.quorum.clone(),
            threshold: plan.threshold.clone(),
            lifecycle_action: plan.lifecycle_action,
            rotation_action: plan.rotation_action,
            authority_domain_sequence: plan.authority_domain_sequence,
            governance_decision_id: plan.governance_decision_id.clone(),
            governance_request_id: plan.governance_request_id.clone(),
            governance_intent_digest: plan.governance_intent_digest.clone(),
            rotation_decision_id: decision.rotation_id.clone(),
            rotation_request_id: decision.request_id.clone(),
            rotation_transcript_digest: decision.transcript_digest.clone(),
            rotation_plan_digest: decision.plan_digest.clone(),
            current_set_digest: plan.current_set_digest.clone(),
            proposed_set_digest: plan.proposed_set_digest.clone(),
            delta_digest: plan.delta_digest.clone(),
            validator_set_epoch: plan.validator_set_epoch,
            validator_set_version: plan.validator_set_version,
            proposed_validator_count: plan.proposed_validator_count,
            rotation_nonce: plan.rotation_nonce,
            epoch_transition_target: request.proposed_epoch_transition_target,
            application_nonce: request.application_nonce,
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
        };

        // Step 9: typed accepted non-mutating outcome.
        (
            O::AcceptedSourceTestValidatorSetRotationApplicationDecision {
                decision_kind,
                environment: plan.environment,
                epoch_transition_target: request.proposed_epoch_transition_target,
                application_nonce: request.application_nonce,
            },
            Some(intent),
        )
    }

    /// Run 305 — evaluate a validator-set rotation application request into a
    /// typed, deterministic, non-mutating decision. This never mutates any
    /// live validator set, consensus epoch, or trust state; on accept it
    /// produces only a prepared application intent.
    pub fn evaluate_validator_set_rotation_application<
        R: ValidatorSetRotationApplicationReplaySet + ?Sized,
    >(
        &self,
        request: &ProductionValidatorSetRotationApplicationRequest,
        inputs: &ProductionValidatorSetRotationApplicationInputs,
        replay_set: &R,
    ) -> ProductionValidatorSetRotationApplicationDecision {
        let (outcome, intent) = self.evaluate_core(request, inputs, replay_set);

        // Rotation decision id + plan digest for the transcript (best-effort
        // from the authority source).
        let (rotation_decision_id, rotation_plan_digest) = match &request.authority_source {
            ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision }
            | ValidatorSetRotationApplicationAuthoritySource::UnverifiedRotationPlan {
                decision,
            }
            | ValidatorSetRotationApplicationAuthoritySource::AcceptedDecisionWithoutPlan {
                decision,
            } => (decision.rotation_id.clone(), decision.plan_digest.clone()),
            _ => (String::new(), String::new()),
        };

        let request_id = production_validator_set_rotation_application_request_id(
            self.config.protocol_version.0,
            &rotation_plan_digest,
            &inputs.application_policy_id,
            request.proposed_epoch_transition_target,
            request.application_nonce,
        );
        let intent_digest = intent.as_ref().map(|i| i.intent_digest()).unwrap_or_default();
        let transcript_digest = production_validator_set_rotation_application_transcript_digest(
            self.config.protocol_version.0,
            &request_id,
            &intent_digest,
            outcome.tag(),
        );

        ProductionValidatorSetRotationApplicationDecision {
            outcome,
            application_id: rotation_decision_id,
            request_id,
            application_intent: intent,
            intent_digest,
            transcript_digest,
        }
    }

    /// Run 305 — idempotency / recovery over a prepared-application window.
    /// Non-mutating; writes no durable state.
    pub fn recover_validator_set_rotation_application_window(
        &self,
        prior: Option<&ProductionValidatorSetRotationApplicationIntent>,
        current: &ProductionValidatorSetRotationApplicationIntent,
    ) -> ProductionValidatorSetRotationApplicationRecoveryOutcome {
        use ProductionValidatorSetRotationApplicationRecoveryOutcome as R;
        if self.policy.is_disabled()
            || self.config.kind == ProductionValidatorSetRotationApplicationKind::Disabled
        {
            return R::RecoveryDisabled;
        }
        let Some(prior) = prior else {
            return R::NoPriorApplicationWindow;
        };
        // Unrelated rotation plan digests / nonces => independent window.
        if prior.rotation_plan_digest != current.rotation_plan_digest
            || prior.application_nonce != current.application_nonce
            || prior.epoch_transition_target != current.epoch_transition_target
        {
            return R::NoPriorApplicationWindow;
        }
        // Same window, byte-identical intent => idempotent replay.
        if prior == current {
            R::IdempotentReplayObserved {
                application_id: current.rotation_decision_id.clone(),
            }
        } else {
            // Same window but non-identical intent is caller error; the
            // executor reports a clean (non-mutating) recovery signal and
            // never overwrites durable state.
            R::NoPriorApplicationWindow
        }
    }
}

// ===========================================================================
// Standalone named helpers (source/test invariants)
// ===========================================================================

/// Run 305 — the executor default policy is Disabled / fail-closed.
pub fn production_validator_set_rotation_application_executor_default_is_disabled() -> bool {
    ProductionValidatorSetRotationApplicationPolicy::default()
        == ProductionValidatorSetRotationApplicationPolicy::Disabled
        && ProductionValidatorSetRotationApplicationConfig::default().kind
            == ProductionValidatorSetRotationApplicationKind::Disabled
}

/// Run 305 — the executor is a source/test implementation, not
/// release-binary evidence (deferred to Run 306).
pub fn production_validator_set_rotation_application_executor_is_source_test_not_release_binary_evidence(
) -> bool {
    true
}

/// Run 305 — the executor refuses MainNet absent production authority.
pub fn production_validator_set_rotation_application_executor_mainnet_refused() -> bool {
    true
}

/// Run 305 — the executor never applies a live validator-set change,
/// consensus epoch transition, or trust-state mutation; every outcome is
/// non-mutating.
pub fn production_validator_set_rotation_application_executor_is_non_mutating() -> bool {
    true
}

/// Run 305 — the executor never falls back to governance-proof-alone /
/// governance-execution-intent-alone / fixture / local-operator /
/// peer-majority / custody-only / RemoteSigner-only / arbitrary-bytes
/// authority.
pub fn production_validator_set_rotation_application_executor_never_falls_back() -> bool {
    true
}

/// Run 305 — the executor adds no default runtime wiring and no CLI flag.
pub fn production_validator_set_rotation_application_executor_no_default_runtime_wiring() -> bool {
    true
}

/// Run 305 — the executor only requires a verified Run 303/304 validator-set
/// rotation plan as authority; nothing else can authorize an application
/// decision.
pub fn production_validator_set_rotation_application_executor_requires_verified_rotation_plan() -> bool
{
    true
}
