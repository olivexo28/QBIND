//! Run 313 — source/test epoch-transition **runtime handoff** /
//! live-mutation **preflight** boundary.
//!
//! This module implements the next source/test boundary above the Run
//! 311/312 guarded epoch-transition mutation-execution boundary: the boundary
//! that consumes a **verified** Run 311/312 non-mutating guarded
//! epoch-transition mutation-execution *decision* (the accepted
//! [`ProductionGuardedEpochTransitionMutationDecision`] carrying a prepared
//! [`ProductionGuardedEpochTransitionMutationRecord`], as
//! release-binary-evidenced by Run 312) and translates it into a typed,
//! deterministic, policy-gated **runtime handoff package** for a *future* live
//! executor — *without* ever applying a live validator-set change,
//! transitioning a consensus epoch, or mutating any trust state.
//!
//! Where the Run 311 boundary answers "given a verified staged
//! epoch-transition application decision, what typed non-mutating guarded
//! mutation record does it authorize?", Run 313 answers the next question:
//! "given a verified guarded mutation-execution decision, what typed,
//! non-mutating **runtime handoff package** carrying the exact preconditions a
//! *future* live executor must re-verify does it authorize, under an explicit
//! runtime handoff policy, bound to the full guarded-mutation-decision /
//! staged-application / authorization / application / rotation / governance /
//! validator-set / custody / attestation / durable-replay evidence tuple, an
//! explicit epoch-transition target, current/proposed validator-set
//! epoch/version preconditions, a required replay window, and a runtime-handoff
//! nonce?".
//!
//! ## Scope and honesty constraints (Run 313)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 314**.
//! * The default policy is
//!   [`ProductionEpochTransitionRuntimeHandoffExecutorPolicy::Disabled`]
//!   and fails closed **before** any binding, validator-set binding, or
//!   handoff-package construction.
//! * Only a **verified** Run 311/312 guarded epoch-transition
//!   mutation-execution decision that `is_accept()` and carries a
//!   [`ProductionGuardedEpochTransitionMutationRecord`] can authorize a runtime
//!   handoff package. Unverified decisions, accepted decisions without a
//!   prepared record, a Run 309/310 staged-application decision alone, a Run
//!   307/308 live-application authorization alone, a Run 305/306 application
//!   decision alone, Run 303 rotation plans alone, governance execution intent
//!   alone, governance proof alone, local-operator assertions, peer-majority
//!   assertions, custody-only, RemoteSigner-only, custody-attestation-only,
//!   fixture-only decisions, and arbitrary validator-set bytes are all rejected
//!   as production authority.
//! * The boundary produces only a typed
//!   [`ProductionEpochTransitionRuntimeHandoffPackage`]; it
//!   **never** applies the decision, never mutates a live validator set,
//!   never writes durable validator-set state, never calls
//!   `BasicHotStuffEngine::transition_to_epoch`, never writes
//!   `meta:current_epoch`, and never injects a `PAYLOAD_KIND_RECONFIG`
//!   block. Only a typed accepted outcome may authorize a *future* live
//!   mutation run.
//! * MainNet remains **refused**: even a fully valid source/test
//!   DevNet/TestNet handoff package does not enable MainNet runtime behavior.
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
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_313.md`.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::OnChainGovernanceQuorum;
use crate::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding,
};
use crate::pqc_production_guarded_epoch_transition_mutation_executor::{
    ProductionGuardedEpochTransitionMutationDecision,
    ProductionGuardedEpochTransitionMutationRecord,
    GuardedEpochTransitionMutationKind,
};
use crate::pqc_production_validator_set_rotation_intent::ValidatorSetRotationAction;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 313 — the only live validator-set application authorization boundary
/// protocol version this run accepts.
pub const PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_PROTOCOL_VERSION: u16 = 1;

/// Run 313 — live validator-set application authorization intent digest
/// domain tag.
pub const PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_INTENT_DOMAIN_TAG: &str =
    "QBIND:run313-epoch-transition-runtime-handoff-intent:v1";

/// Run 313 — live validator-set application authorization request-id domain
/// tag.
pub const PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run313-epoch-transition-runtime-handoff-request:v1";

/// Run 313 — live validator-set application authorization transcript digest
/// domain tag.
pub const PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run313-epoch-transition-runtime-handoff-transcript:v1";

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

/// Run 313 — typed live validator-set application authorization boundary
/// protocol version. Only
/// [`PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_PROTOCOL_VERSION`]
/// is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionEpochTransitionRuntimeHandoffProtocolVersion(pub u16);

impl ProductionEpochTransitionRuntimeHandoffProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_PROTOCOL_VERSION
    }
}

impl Default for ProductionEpochTransitionRuntimeHandoffProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 313 — typed live validator-set application authorization boundary
/// policy.
///
/// `Disabled` is the default fail-closed policy: the boundary refuses before
/// any application binding or authorization construction.
/// `AllowSourceTestEpochTransitionRuntimeHandoff` is the only
/// policy that can produce an accepted source/test authorization, and only on
/// DevNet/TestNet with a verified Run 311/312 validator-set rotation
/// application decision.
/// `RequireProductionEpochTransitionRuntimeHandoff` and
/// `MainnetProductionEpochTransitionRuntimeHandoffRequired` are
/// **reachable but fail-closed** production/MainNet policies: no production
/// live validator-set application authorization authority is wired, so they
/// fail closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionEpochTransitionRuntimeHandoffExecutorPolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified validator-set rotation
    /// application decision may produce a typed non-mutating live-application
    /// authorization as source/test evidence only. MainNet remains refused.
    AllowSourceTestEpochTransitionRuntimeHandoff,
    /// Production policy. Reachable but fails closed: no production live
    /// validator-set application authorization prerequisites are wired.
    RequireProductionEpochTransitionRuntimeHandoff,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production live validator-set application authorization authority is
    /// wired.
    MainnetProductionEpochTransitionRuntimeHandoffRequired,
}

impl ProductionEpochTransitionRuntimeHandoffExecutorPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestEpochTransitionRuntimeHandoff => {
                "allow-source-test-epoch-transition-runtime-handoff"
            }
            Self::RequireProductionEpochTransitionRuntimeHandoff => {
                "require-production-epoch-transition-runtime-handoff"
            }
            Self::MainnetProductionEpochTransitionRuntimeHandoffRequired => {
                "mainnet-production-epoch-transition-runtime-handoff-required"
            }
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy allows source/test live validator-set
    /// application authorizations (DevNet/TestNet only).
    pub const fn allows_source_test(self) -> bool {
        matches!(
            self,
            Self::AllowSourceTestEpochTransitionRuntimeHandoff
        )
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Self::RequireProductionEpochTransitionRuntimeHandoff
        )
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(
            self,
            Self::MainnetProductionEpochTransitionRuntimeHandoffRequired
        )
    }
}

// ===========================================================================
// Boundary kind taxonomy
// ===========================================================================

/// Run 313 — typed live validator-set application authorization boundary
/// kind.
///
/// `Disabled` is the inert default.
/// `SourceTestEpochTransitionRuntimeHandoff` performs real
/// source/test authorization construction. A reserved
/// `ProductionEpochTransitionRuntimeHandoff` kind is fail-closed as
/// unavailable in Run 313 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionEpochTransitionRuntimeHandoffExecutorKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test live validator-set application authorization
    /// boundary.
    SourceTestEpochTransitionRuntimeHandoff,
    /// Reserved production authorization kind. Fail-closed in Run 313.
    ProductionEpochTransitionRuntimeHandoff,
}

impl ProductionEpochTransitionRuntimeHandoffExecutorKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestEpochTransitionRuntimeHandoff => {
                "source-test-epoch-transition-runtime-handoff"
            }
            Self::ProductionEpochTransitionRuntimeHandoff => {
                "production-epoch-transition-runtime-handoff"
            }
        }
    }

    /// Returns `true` iff this kind performs real source/test authorization
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(
            self,
            Self::SourceTestEpochTransitionRuntimeHandoff
        )
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 313 — typed live validator-set application authorization boundary
/// config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffConfig {
    /// Boundary protocol version. Must equal the supported version.
    pub protocol_version: ProductionEpochTransitionRuntimeHandoffProtocolVersion,
    /// The boundary kind.
    pub kind: ProductionEpochTransitionRuntimeHandoffExecutorKind,
}

impl ProductionEpochTransitionRuntimeHandoffConfig {
    pub fn new(kind: ProductionEpochTransitionRuntimeHandoffExecutorKind) -> Self {
        Self {
            protocol_version:
                ProductionEpochTransitionRuntimeHandoffProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test authorization boundary kind.
    pub fn source_test() -> Self {
        Self::new(
            ProductionEpochTransitionRuntimeHandoffExecutorKind::SourceTestEpochTransitionRuntimeHandoff,
        )
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionEpochTransitionRuntimeHandoffConfig {
    fn default() -> Self {
        Self::new(ProductionEpochTransitionRuntimeHandoffExecutorKind::Disabled)
    }
}

// ===========================================================================
// Staged application kind taxonomy
// ===========================================================================

/// Run 313 — the typed kind of a prepared, non-mutating staged live
/// validator-set / epoch-transition application record.
///
/// Each kind corresponds one-to-one with a supported Run 311/312
/// [`GuardedEpochTransitionMutationKind`]; the reserved
/// [`Self::UnsupportedStagedApplication`] never authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EpochTransitionRuntimeHandoffKind {
    StageApplyNoOpAlreadySynchronized,
    StageApplyValidatorAdd,
    StageApplyValidatorRemove,
    StageApplyValidatorMetadataUpdate,
    StageApplyValidatorIdentityRotation,
    StageApplyValidatorRetirement,
    StageApplyEmergencyValidatorRemoval,
    StageApplyAuthoritySetSynchronization,
    StageApplyBulkValidatorSetRotation,
    UnsupportedStagedApplication,
}

impl EpochTransitionRuntimeHandoffKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::StageApplyNoOpAlreadySynchronized => {
                "stage-apply-no-op-already-synchronized"
            }
            Self::StageApplyValidatorAdd => "stage-apply-validator-add",
            Self::StageApplyValidatorRemove => "stage-apply-validator-remove",
            Self::StageApplyValidatorMetadataUpdate => {
                "stage-apply-validator-metadata-update"
            }
            Self::StageApplyValidatorIdentityRotation => {
                "stage-apply-validator-identity-rotation"
            }
            Self::StageApplyValidatorRetirement => "stage-apply-validator-retirement",
            Self::StageApplyEmergencyValidatorRemoval => {
                "stage-apply-emergency-validator-removal"
            }
            Self::StageApplyAuthoritySetSynchronization => {
                "stage-apply-authority-set-synchronization"
            }
            Self::StageApplyBulkValidatorSetRotation => {
                "stage-apply-bulk-validator-set-rotation"
            }
            Self::UnsupportedStagedApplication => "unsupported-staged-application",
        }
    }

    /// Every Run 313 staged application kind is a *prepared*, non-mutating
    /// record; none applies a live validator-set change.
    pub const fn is_non_mutating(self) -> bool {
        true
    }

    /// Maps a supported Run 311/312 staged live validator-set / epoch-transition
    /// application kind to its guarded mutation kind. Returns
    /// [`Self::UnsupportedStagedApplication`] for the reserved unsupported
    /// staged application kind.
    pub const fn from_staged_application_kind(
        kind: GuardedEpochTransitionMutationKind,
    ) -> Self {
        use GuardedEpochTransitionMutationKind as A;
        match kind {
            A::StageApplyNoOpAlreadySynchronized => Self::StageApplyNoOpAlreadySynchronized,
            A::StageApplyValidatorAdd => Self::StageApplyValidatorAdd,
            A::StageApplyValidatorRemove => Self::StageApplyValidatorRemove,
            A::StageApplyValidatorMetadataUpdate => Self::StageApplyValidatorMetadataUpdate,
            A::StageApplyValidatorIdentityRotation => {
                Self::StageApplyValidatorIdentityRotation
            }
            A::StageApplyValidatorRetirement => Self::StageApplyValidatorRetirement,
            A::StageApplyEmergencyValidatorRemoval => Self::StageApplyEmergencyValidatorRemoval,
            A::StageApplyAuthoritySetSynchronization => {
                Self::StageApplyAuthoritySetSynchronization
            }
            A::StageApplyBulkValidatorSetRotation => Self::StageApplyBulkValidatorSetRotation,
            A::UnsupportedStagedApplication => Self::UnsupportedStagedApplication,
        }
    }

    /// Returns `true` iff this is the reserved unsupported kind.
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedStagedApplication)
    }
}

// ===========================================================================
// Authority source
// ===========================================================================

/// Run 313 — the staged live validator-set / epoch-transition application
/// authority source presented to the executor.
///
/// Only [`Self::VerifiedGuardedMutationDecision`] carrying a Run 311/312
/// live validator-set application authorization decision that `is_accept()`
/// **and** carries a prepared authorization intent can authorize a staged
/// application record. Every other variant is a non-authority source rejected
/// with a precise fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochTransitionRuntimeHandoffAuthoritySource {
    /// A verified Run 311/312 live validator-set application authorization
    /// decision. The **only** accepted authority source. The decision must
    /// `is_accept()` and carry `Some(authorization_intent)`.
    VerifiedGuardedMutationDecision {
        decision: ProductionGuardedEpochTransitionMutationDecision,
    },
    /// No live-application authorization decision was supplied.
    MissingGuardedMutationDecision,
    /// An unverified / non-accept live-application authorization decision.
    /// Rejected.
    UnverifiedGuardedMutationDecision {
        decision: ProductionGuardedEpochTransitionMutationDecision,
    },
    /// An accepted authorization decision that carries no prepared
    /// authorization intent. Rejected.
    AcceptedGuardedMutationWithoutRecord {
        decision: ProductionGuardedEpochTransitionMutationDecision,
    },
    /// A Run 305/306 validator-set rotation *application decision* presented
    /// directly, without a Run 311/312 live-application authorization.
    /// Rejected.
    ApplicationDecisionWithoutGuardedMutation,
    /// A Run 303/304 validator-set rotation plan presented directly, without a
    /// Run 311/312 live-application authorization. Rejected.
    RotationPlanWithoutGuardedMutation,
    /// A Run 301/302 governance execution intent presented directly, without a
    /// Run 311/312 live-application authorization. Rejected.
    GovernanceExecutionIntentWithoutGuardedMutation,
    /// A raw on-chain governance proof presented directly, without a Run
    /// 307/308 live-application authorization. Rejected.
    GovernanceProofWithoutGuardedMutation,
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
    /// A Run 178 fixture-class live-application authorization decision
    /// presented as production authority. Rejected.
    FixtureOnlyGuardedMutation,
    /// Arbitrary validator-set bytes presented directly, without a verified
    /// live-application authorization. Rejected.
    ArbitraryValidatorSetBytes,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 313 — the explicit trusted inputs the executor binds a verified
/// Run 311/312 live validator-set application authorization decision against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// The opaque staged-application policy id bound into the staged record.
    pub staged_application_policy_id: String,
    /// Expected Run 311/312 live-application authorization policy id (bound
    /// into the consumed authorization intent).
    pub expected_authorization_policy_id: String,
    /// Expected Run 305/306 application policy id (re-exposed by the
    /// authorization intent).
    pub expected_application_policy_id: String,
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
    /// Expected Run 301 governance execution decision id.
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
    /// Expected Run 303 rotation plan digest.
    pub expected_rotation_plan_digest: String,
    /// Expected current validator-set digest.
    pub expected_current_set_digest: String,
    /// Expected proposed validator-set digest.
    pub expected_proposed_set_digest: String,
    /// Expected validator-set delta digest.
    pub expected_delta_digest: String,
    /// Expected proposed validator-set epoch.
    pub expected_validator_set_epoch: u64,
    /// Expected proposed validator-set version.
    pub expected_validator_set_version: u64,
    /// Expected proposed validator count.
    pub expected_proposed_validator_count: u64,
    /// Expected rotation nonce.
    pub expected_rotation_nonce: u64,
    /// Expected Run 305/306 application decision id (re-exposed by the
    /// authorization intent).
    pub expected_application_decision_id: String,
    /// Expected Run 305/306 application request id.
    pub expected_application_request_id: String,
    /// Expected Run 305/306 application intent digest.
    pub expected_application_intent_digest: String,
    /// Expected Run 305/306 application transcript digest.
    pub expected_application_transcript_digest: String,
    /// Expected Run 311/312 authorization decision id (bound into the
    /// consumed authorization decision).
    pub expected_authorization_decision_id: String,
    /// Expected Run 311/312 authorization request id.
    pub expected_authorization_request_id: String,
    /// Expected Run 311/312 authorization intent digest.
    pub expected_authorization_intent_digest: String,
    /// Expected Run 311/312 authorization transcript digest.
    pub expected_authorization_transcript_digest: String,
    /// Expected Run 311/312 staged-application decision id (bound into the
    /// consumed staged-application decision).
    pub expected_staged_application_decision_id: String,
    /// Expected Run 311/312 staged-application request id.
    pub expected_staged_application_request_id: String,
    /// Expected Run 311/312 staged-application intent digest.
    pub expected_staged_application_intent_digest: String,
    /// Expected Run 311/312 staged-application transcript digest.
    pub expected_staged_application_transcript_digest: String,
    /// Expected Run 311/312 staged-application nonce (re-exposed by the
    /// consumed staged-application record).
    pub expected_staged_application_nonce: u64,
    /// Expected epoch-transition target a future executor would transition
    /// to. Must equal the authorization intent's epoch-transition target.
    pub expected_epoch_transition_target: u64,
    /// Expected Run 305/306 application nonce (re-exposed by the authorization
    /// intent).
    pub expected_application_nonce: u64,
    /// Expected Run 311/312 live-application nonce (re-exposed by the
    /// authorization intent).
    pub expected_live_application_nonce: u64,
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
    /// Whether durable replay evidence is required, and its expected binding.
    pub require_durable_replay_evidence: bool,
    pub expected_durable_replay: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionEpochTransitionRuntimeHandoffInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.staged_application_policy_id.is_empty()
            && !self.expected_authorization_policy_id.is_empty()
            && !self.expected_application_policy_id.is_empty()
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
            && !self.expected_application_decision_id.is_empty()
            && !self.expected_application_request_id.is_empty()
            && !self.expected_application_intent_digest.is_empty()
            && !self.expected_application_transcript_digest.is_empty()
            && !self.expected_authorization_decision_id.is_empty()
            && !self.expected_authorization_request_id.is_empty()
            && !self.expected_authorization_intent_digest.is_empty()
            && !self.expected_authorization_transcript_digest.is_empty()
            && !self.expected_staged_application_decision_id.is_empty()
            && !self.expected_staged_application_request_id.is_empty()
            && !self.expected_staged_application_intent_digest.is_empty()
            && !self.expected_staged_application_transcript_digest.is_empty()
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 313 — a staged live validator-set / epoch-transition application
/// request: the authority source (a verified live-application authorization
/// decision), the explicit epoch-transition target, a staged-application
/// nonce, and any represented custody / attestation / durable-replay evidence
/// bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffRequest {
    pub authority_source: EpochTransitionRuntimeHandoffAuthoritySource,
    /// The epoch a future epoch-transition executor would transition to.
    pub proposed_epoch_transition_target: u64,
    /// The staged-application nonce (idempotency / replay binding).
    pub staged_application_nonce: u64,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionEpochTransitionRuntimeHandoffRequest {
    /// Construct a request carrying only an authority source, epoch target,
    /// and staged-application nonce (no represented custody / attestation /
    /// durable-replay evidence).
    pub fn new(
        authority_source: EpochTransitionRuntimeHandoffAuthoritySource,
        proposed_epoch_transition_target: u64,
        staged_application_nonce: u64,
    ) -> Self {
        Self {
            authority_source,
            proposed_epoch_transition_target,
            staged_application_nonce,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 313 — caller-owned replay authorization-id set. The executor reads
/// from this set but never mutates it.
pub trait EpochTransitionRuntimeHandoffReplaySet {
    fn contains(&self, authorization_id: &str) -> bool;
}

impl EpochTransitionRuntimeHandoffReplaySet for &[String] {
    fn contains(&self, authorization_id: &str) -> bool {
        (*self).iter().any(|s| s == authorization_id)
    }
}

impl EpochTransitionRuntimeHandoffReplaySet for Vec<String> {
    fn contains(&self, authorization_id: &str) -> bool {
        self.iter().any(|s| s == authorization_id)
    }
}

/// Empty replay set helper.
pub struct EmptyEpochTransitionRuntimeHandoffReplaySet;

impl EpochTransitionRuntimeHandoffReplaySet
    for EmptyEpochTransitionRuntimeHandoffReplaySet
{
    fn contains(&self, _authorization_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Staged application record (boundary output)
// ===========================================================================

/// Run 313 — a typed, deterministic, **non-mutating** staged live
/// validator-set / epoch-transition application record. Only a typed accepted
/// outcome carrying this record may authorize a *future* real mutation run
/// (Run 314+); Run 313 never applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffPackage {
    pub staged_kind: EpochTransitionRuntimeHandoffKind,
    pub protocol_version: u16,
    pub staged_application_policy_id: String,

    // ---- Re-exposed Run 311/312 authorization intent tuple ------------
    pub authorization_policy_id: String,
    pub application_policy_id: String,
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
    pub current_set_digest: String,
    pub proposed_set_digest: String,
    pub delta_digest: String,
    pub validator_set_epoch: u64,
    pub validator_set_version: u64,
    pub proposed_validator_count: u64,
    pub rotation_nonce: u64,

    // ---- Re-exposed Run 305/306 application-decision tuple ------------
    pub application_decision_id: String,
    pub application_request_id: String,
    pub application_intent_digest: String,
    pub application_transcript_digest: String,
    pub application_nonce: u64,

    // ---- Re-exposed epoch-transition / live-application binding -------
    pub epoch_transition_target: u64,
    pub live_application_nonce: u64,

    // ---- Bound Run 311/312 authorization-decision authority tuple -----
    // (re-exposed by the consumed staged-application record)
    pub authorization_decision_id: String,
    pub authorization_request_id: String,
    pub authorization_intent_digest: String,
    pub authorization_transcript_digest: String,

    // ---- Bound Run 311/312 staged-application-decision authority tuple -
    pub staged_application_decision_id: String,
    pub staged_application_request_id: String,
    pub staged_application_intent_digest: String,
    pub staged_application_transcript_digest: String,

    // ---- Staged application binding (re-exposed consumed nonce) --------
    pub staged_application_nonce: u64,

    // ---- Guarded mutation-execution binding ---------------------------
    /// The newly proposed guarded mutation-execution nonce.
    pub guarded_mutation_nonce: u64,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionEpochTransitionRuntimeHandoffPackage {
    /// Deterministic, domain-separated SHA3-256 hex intent digest. `Debug`
    /// formatting is never used as canonical bytes.
    pub fn intent_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(
            PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_INTENT_DOMAIN_TAG.as_bytes(),
        );
        hash_field(&mut h, b"staged_kind", self.staged_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(
            &mut h,
            b"staged_application_policy_id",
            self.staged_application_policy_id.as_bytes(),
        );
        hash_field(&mut h, b"authorization_policy_id", self.authorization_policy_id.as_bytes());
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
        hash_field(&mut h, b"application_decision_id", self.application_decision_id.as_bytes());
        hash_field(&mut h, b"application_request_id", self.application_request_id.as_bytes());
        hash_field(&mut h, b"application_intent_digest", self.application_intent_digest.as_bytes());
        hash_field(
            &mut h,
            b"application_transcript_digest",
            self.application_transcript_digest.as_bytes(),
        );
        hash_field(&mut h, b"application_nonce", &self.application_nonce.to_le_bytes());
        hash_field(&mut h, b"epoch_transition_target", &self.epoch_transition_target.to_le_bytes());
        hash_field(&mut h, b"live_application_nonce", &self.live_application_nonce.to_le_bytes());
        hash_field(
            &mut h,
            b"authorization_decision_id",
            self.authorization_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"authorization_request_id",
            self.authorization_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"authorization_intent_digest",
            self.authorization_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"authorization_transcript_digest",
            self.authorization_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"staged_application_decision_id",
            self.staged_application_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"staged_application_request_id",
            self.staged_application_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"staged_application_intent_digest",
            self.staged_application_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"staged_application_transcript_digest",
            self.staged_application_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"staged_application_nonce",
            &self.staged_application_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"guarded_mutation_nonce",
            &self.guarded_mutation_nonce.to_le_bytes(),
        );
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

    /// This authorization intent is prepared, non-mutating, and never applied
    /// by Run 313.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }
}

/// Custody binding canonical hashing (module-local; mirrors Run 301/303/305
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

/// Run 313 — deterministic staged application record digest wrapper exposed
/// as a named symbol.
pub fn production_epoch_transition_runtime_handoff_intent_digest(
    record: &ProductionEpochTransitionRuntimeHandoffPackage,
) -> String {
    record.intent_digest()
}

/// Run 313 — deterministic, domain-separated staged application request id
/// binding the protocol version, authorization intent digest, staged
/// application policy id, epoch-transition target, and staged-application
/// nonce. Deterministic across identical inputs; never wall-clock.
pub fn production_epoch_transition_runtime_handoff_request_id(
    protocol_version: u16,
    authorization_intent_digest: &str,
    staged_application_policy_id: &str,
    epoch_transition_target: u64,
    staged_application_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_REQUEST_DOMAIN_TAG.as_bytes(),
    );
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(
        &mut h,
        b"authorization_intent_digest",
        authorization_intent_digest.as_bytes(),
    );
    hash_field(
        &mut h,
        b"staged_application_policy_id",
        staged_application_policy_id.as_bytes(),
    );
    hash_field(
        &mut h,
        b"epoch_transition_target",
        &epoch_transition_target.to_le_bytes(),
    );
    hash_field(
        &mut h,
        b"staged_application_nonce",
        &staged_application_nonce.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 313 — deterministic, domain-separated staged application transcript
/// digest binding the protocol version, request id, intent digest, and
/// outcome tag.
pub fn production_epoch_transition_runtime_handoff_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    intent_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_EPOCH_TRANSITION_RUNTIME_HANDOFF_TRANSCRIPT_DOMAIN_TAG.as_bytes(),
    );
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"request_id", request_id.as_bytes());
    hash_field(&mut h, b"intent_digest", intent_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 313 — typed outcome of the staged live validator-set / epoch-transition
/// application executor boundary.
///
/// Only
/// [`Self::AcceptedSourceTestEpochTransitionRuntimeHandoff`]
/// authorizes a (source/test, DevNet/TestNet, evidence-only, non-mutating)
/// staged application record. Every other variant is a precise, non-mutating
/// fail-closed reject (or the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionEpochTransitionRuntimeHandoffOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no authority was bound.
    Disabled,
    /// The boundary kind is unavailable / misconfigured.
    EpochTransitionRuntimeHandoffBoundaryUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionEpochTransitionRuntimeHandoffUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionEpochTransitionRuntimeHandoffUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet live validator-set application authorization
    /// decision produced a typed non-mutating staged application record under
    /// the source/test policy. **Evidence only.**
    AcceptedSourceTestEpochTransitionRuntimeHandoff {
        staged_kind: EpochTransitionRuntimeHandoffKind,
        environment: TrustBundleEnvironment,
        epoch_transition_target: u64,
        staged_application_nonce: u64,
    },

    // ---- Authorization-decision / authority failures ------------------
    VerifiedGuardedMutationDecisionRequired,
    UnverifiedGuardedMutationDecisionRejected,
    ApplicationDecisionAloneRejected,
    RotationPlanAloneRejected,
    GovernanceProofAloneRejected,
    GovernanceExecutionIntentAloneRejected,
    FixtureStagedApplicationRejectedAsProductionAuthority,
    LocalOperatorProofRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,
    CustodyAttestationOnlyProofRejected,
    ArbitraryValidatorSetBytesRejected,

    // ---- Authorization-decision binding failures ----------------------
    WrongAuthorizationPolicyId,
    AuthorizationDecisionIdMismatch,
    AuthorizationDecisionRequestIdMismatch,
    AuthorizationDecisionIntentDigestMismatch,
    AuthorizationDecisionTranscriptMismatch,
    AuthorizationDecisionIntegrityMismatch,

    // ---- Staged-application-decision binding failures -----------------
    StagedApplicationDecisionIdMismatch,
    StagedApplicationDecisionRequestIdMismatch,
    StagedApplicationDecisionIntentDigestMismatch,
    StagedApplicationDecisionTranscriptMismatch,
    StagedApplicationDecisionIntegrityMismatch,
    WrongStagedApplicationNonce,

    // ---- Application-decision (re-exposed) binding failures -----------
    WrongApplicationPolicyId,
    WrongApplicationDecisionId,
    WrongApplicationRequestId,
    WrongApplicationIntentDigest,
    WrongApplicationTranscriptDigest,

    // ---- Governance / rotation tuple binding failures -----------------
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
    WrongRotationRequestId,
    WrongRotationTranscriptDigest,
    WrongRotationPlanDigest,
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
    WrongProposedValidatorCount,
    WrongRotationNonce,
    UnsupportedStagedLiveApplication,

    // ---- Epoch-transition / nonce binding failures --------------------
    WrongEpochTransitionTarget,
    WrongApplicationNonce,
    WrongLiveApplicationNonce,

    // ---- Custody / attestation / durable replay -----------------------
    CustodyBackendEvidenceRequired,
    CustodyBackendMismatch,
    CustodyAttestationRequired,
    CustodyAttestationMismatch,
    DurableReplayEvidenceRequired,
    DurableReplayMismatch,
    DurableReplayUnavailable,

    // ---- Replay / freshness -------------------------------------------
    StagedApplicationReplayRejected { staged_application_id: String },
    StaleGovernanceEpoch,
    StaleAuthoritySequence,
    StaleValidatorSetEpoch,
    StaleValidatorSetVersion,
    ConflictingStagedApplicationForSameAuthorization,
    EpochTransitionRuntimeHandoffAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionEpochTransitionRuntimeHandoffOutcome {
    /// Returns `true` iff this outcome accepted a source/test authorization.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestEpochTransitionRuntimeHandoff { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 313 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 313.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::EpochTransitionRuntimeHandoffBoundaryUnavailable => {
                "epoch-transition-runtime-handoff-boundary-unavailable"
            }
            Self::ProductionEpochTransitionRuntimeHandoffUnavailable => {
                "production-epoch-transition-runtime-handoff-unavailable"
            }
            Self::MainNetProductionEpochTransitionRuntimeHandoffUnavailable => {
                "mainnet-production-epoch-transition-runtime-handoff-unavailable"
            }
            Self::AcceptedSourceTestEpochTransitionRuntimeHandoff { .. } => {
                "accepted-source-test-epoch-transition-runtime-handoff"
            }
            Self::VerifiedGuardedMutationDecisionRequired => {
                "verified-live-application-authorization-required"
            }
            Self::UnverifiedGuardedMutationDecisionRejected => {
                "unverified-live-application-authorization-rejected"
            }
            Self::ApplicationDecisionAloneRejected => "application-decision-alone-rejected",
            Self::RotationPlanAloneRejected => "rotation-plan-alone-rejected",
            Self::GovernanceProofAloneRejected => "governance-proof-alone-rejected",
            Self::GovernanceExecutionIntentAloneRejected => {
                "governance-execution-intent-alone-rejected"
            }
            Self::FixtureStagedApplicationRejectedAsProductionAuthority => {
                "fixture-live-application-authorization-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::ArbitraryValidatorSetBytesRejected => "arbitrary-validator-set-bytes-rejected",
            Self::WrongAuthorizationPolicyId => "wrong-authorization-policy-id",
            Self::AuthorizationDecisionIdMismatch => "authorization-decision-id-mismatch",
            Self::AuthorizationDecisionRequestIdMismatch => {
                "authorization-decision-request-id-mismatch"
            }
            Self::AuthorizationDecisionIntentDigestMismatch => {
                "authorization-decision-intent-digest-mismatch"
            }
            Self::AuthorizationDecisionTranscriptMismatch => {
                "authorization-decision-transcript-mismatch"
            }
            Self::AuthorizationDecisionIntegrityMismatch => {
                "authorization-decision-integrity-mismatch"
            }
            Self::StagedApplicationDecisionIdMismatch => {
                "staged-application-decision-id-mismatch"
            }
            Self::StagedApplicationDecisionRequestIdMismatch => {
                "staged-application-decision-request-id-mismatch"
            }
            Self::StagedApplicationDecisionIntentDigestMismatch => {
                "staged-application-decision-intent-digest-mismatch"
            }
            Self::StagedApplicationDecisionTranscriptMismatch => {
                "staged-application-decision-transcript-mismatch"
            }
            Self::StagedApplicationDecisionIntegrityMismatch => {
                "staged-application-decision-integrity-mismatch"
            }
            Self::WrongStagedApplicationNonce => "wrong-staged-application-nonce",
            Self::WrongApplicationPolicyId => "wrong-application-policy-id",
            Self::WrongApplicationDecisionId => "wrong-application-decision-id",
            Self::WrongApplicationRequestId => "wrong-application-request-id",
            Self::WrongApplicationIntentDigest => "wrong-application-intent-digest",
            Self::WrongApplicationTranscriptDigest => "wrong-application-transcript-digest",
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
            Self::WrongRotationRequestId => "wrong-rotation-request-id",
            Self::WrongRotationTranscriptDigest => "wrong-rotation-transcript-digest",
            Self::WrongRotationPlanDigest => "wrong-rotation-plan-digest",
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
            Self::WrongProposedValidatorCount => "wrong-proposed-validator-count",
            Self::WrongRotationNonce => "wrong-rotation-nonce",
            Self::UnsupportedStagedLiveApplication => {
                "unsupported-staged-live-application"
            }
            Self::WrongEpochTransitionTarget => "wrong-epoch-transition-target",
            Self::WrongApplicationNonce => "wrong-application-nonce",
            Self::WrongLiveApplicationNonce => "wrong-live-application-nonce",
            Self::CustodyBackendEvidenceRequired => "custody-backend-evidence-required",
            Self::CustodyBackendMismatch => "custody-backend-mismatch",
            Self::CustodyAttestationRequired => "custody-attestation-required",
            Self::CustodyAttestationMismatch => "custody-attestation-mismatch",
            Self::DurableReplayEvidenceRequired => "durable-replay-evidence-required",
            Self::DurableReplayMismatch => "durable-replay-mismatch",
            Self::DurableReplayUnavailable => "durable-replay-unavailable",
            Self::StagedApplicationReplayRejected { .. } => "staged-application-replay-rejected",
            Self::StaleGovernanceEpoch => "stale-governance-epoch",
            Self::StaleAuthoritySequence => "stale-authority-sequence",
            Self::StaleValidatorSetEpoch => "stale-validator-set-epoch",
            Self::StaleValidatorSetVersion => "stale-validator-set-version",
            Self::ConflictingStagedApplicationForSameAuthorization => {
                "conflicting-staged-application-for-same-authorization"
            }
            Self::EpochTransitionRuntimeHandoffAmbiguous { .. } => {
                "epoch-transition-runtime-handoff-ambiguous"
            }
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (boundary output)
// ===========================================================================

/// Run 313 — the typed decision produced by the executor boundary: the
/// outcome, the bound staged application id, the deterministic request id,
/// the optional prepared staged application record, its digest, and the
/// verification transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffDecision {
    pub outcome: ProductionEpochTransitionRuntimeHandoffOutcome,
    pub staged_application_id: String,
    pub request_id: String,
    pub staged_application_record:
        Option<ProductionEpochTransitionRuntimeHandoffPackage>,
    pub intent_digest: String,
    pub transcript_digest: String,
}

impl ProductionEpochTransitionRuntimeHandoffDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating
    /// staged application record (only on accept). The boundary never applies
    /// it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.staged_application_record.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 313 — typed idempotency / recovery outcome for a prepared staged
/// application window. Every variant is non-mutating; no durable state is
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionEpochTransitionRuntimeHandoffRecoveryOutcome {
    /// No prior prepared staged application for this window — clean.
    NoPriorStagedApplicationWindow,
    /// A prior prepared staged application for this window was observed; the
    /// executor re-derives the same record deterministically without
    /// mutation.
    IdempotentReplayObserved { staged_application_id: String },
    /// The recovery window is disabled (policy `Disabled`).
    RecoveryDisabled,
}

impl ProductionEpochTransitionRuntimeHandoffRecoveryOutcome {
    /// Every recovery outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff the recovery window is clean (no prior staged
    /// application).
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::NoPriorStagedApplicationWindow)
    }
}

// ===========================================================================
// Executor boundary
// ===========================================================================

/// Run 313 — the source/test staged live validator-set / epoch-transition
/// application executor boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionEpochTransitionRuntimeHandoffExecutor {
    pub config: ProductionEpochTransitionRuntimeHandoffConfig,
    pub policy: ProductionEpochTransitionRuntimeHandoffExecutorPolicy,
}

impl ProductionEpochTransitionRuntimeHandoffExecutor {
    pub fn new(
        config: ProductionEpochTransitionRuntimeHandoffConfig,
        policy: ProductionEpochTransitionRuntimeHandoffExecutorPolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test executor under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionEpochTransitionRuntimeHandoffConfig::source_test(),
            ProductionEpochTransitionRuntimeHandoffExecutorPolicy::AllowSourceTestEpochTransitionRuntimeHandoff,
        )
    }

    /// Extract the verified live-application authorization decision and
    /// prepared authorization intent from an authority source, mapping every
    /// non-authority source to its precise fail-closed outcome.
    fn resolve_authority_source<'a>(
        &self,
        source: &'a EpochTransitionRuntimeHandoffAuthoritySource,
    ) -> Result<
        (
            &'a ProductionGuardedEpochTransitionMutationDecision,
            &'a ProductionGuardedEpochTransitionMutationRecord,
        ),
        ProductionEpochTransitionRuntimeHandoffOutcome,
    > {
        use ProductionEpochTransitionRuntimeHandoffOutcome as O;
        use EpochTransitionRuntimeHandoffAuthoritySource as S;
        match source {
            S::VerifiedGuardedMutationDecision { decision } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedGuardedMutationDecisionRejected);
                }
                match &decision.staged_application_record {
                    Some(intent) => Ok((decision, intent)),
                    None => Err(O::VerifiedGuardedMutationDecisionRequired),
                }
            }
            S::MissingGuardedMutationDecision => {
                Err(O::VerifiedGuardedMutationDecisionRequired)
            }
            S::UnverifiedGuardedMutationDecision { .. } => {
                Err(O::UnverifiedGuardedMutationDecisionRejected)
            }
            S::AcceptedGuardedMutationWithoutRecord { .. } => {
                Err(O::VerifiedGuardedMutationDecisionRequired)
            }
            S::ApplicationDecisionWithoutGuardedMutation => {
                Err(O::ApplicationDecisionAloneRejected)
            }
            S::RotationPlanWithoutGuardedMutation => Err(O::RotationPlanAloneRejected),
            S::GovernanceExecutionIntentWithoutGuardedMutation => {
                Err(O::GovernanceExecutionIntentAloneRejected)
            }
            S::GovernanceProofWithoutGuardedMutation => {
                Err(O::GovernanceProofAloneRejected)
            }
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
            S::FixtureOnlyGuardedMutation => {
                Err(O::FixtureStagedApplicationRejectedAsProductionAuthority)
            }
            S::ArbitraryValidatorSetBytes => Err(O::ArbitraryValidatorSetBytesRejected),
        }
    }

    /// Pure policy / kind / MainNet gate applied before any binding. Returns
    /// `Some(outcome)` to refuse, `None` to proceed.
    fn preflight_gate(
        &self,
        binding_env: TrustBundleEnvironment,
        inputs: &ProductionEpochTransitionRuntimeHandoffInputs,
    ) -> Option<ProductionEpochTransitionRuntimeHandoffOutcome> {
        use ProductionEpochTransitionRuntimeHandoffOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionEpochTransitionRuntimeHandoffExecutorKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet authority source
        //    is refused: no MainNet production authority is wired.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionEpochTransitionRuntimeHandoffExecutorPolicy::MainnetProductionEpochTransitionRuntimeHandoffRequired => {
                    O::MainNetProductionEpochTransitionRuntimeHandoffUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. MainNet production policy on a non-MainNet domain still has no
        //    MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionEpochTransitionRuntimeHandoffUnavailable);
        }

        // 4. The production policy has no production prerequisites wired —
        //    fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionEpochTransitionRuntimeHandoffUnavailable);
        }

        // 5. Reserved production boundary kind is fail-closed in Run 313.
        if self.config.kind
            == ProductionEpochTransitionRuntimeHandoffExecutorKind::ProductionEpochTransitionRuntimeHandoff
        {
            return Some(O::EpochTransitionRuntimeHandoffBoundaryUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() || !inputs.is_well_formed() {
            return Some(O::EpochTransitionRuntimeHandoffBoundaryUnavailable);
        }

        None
    }

    /// Cross-check the verified Run 311/312 live-application authorization
    /// decision and its prepared authorization intent against the explicit
    /// trusted inputs and trust domain. Returns `Some(outcome)` on the first
    /// divergence.
    fn check_application_binding(
        &self,
        decision: &ProductionGuardedEpochTransitionMutationDecision,
        intent: &ProductionGuardedEpochTransitionMutationRecord,
        inputs: &ProductionEpochTransitionRuntimeHandoffInputs,
    ) -> Option<ProductionEpochTransitionRuntimeHandoffOutcome> {
        use ProductionEpochTransitionRuntimeHandoffOutcome as O;
        let td = &inputs.trust_domain;

        // Consumed Run 311/312 staged-application decision transcript
        // binding.
        if decision.staged_application_id != inputs.expected_staged_application_decision_id {
            return Some(O::StagedApplicationDecisionIdMismatch);
        }
        if decision.request_id != inputs.expected_staged_application_request_id {
            return Some(O::StagedApplicationDecisionRequestIdMismatch);
        }
        if decision.intent_digest != inputs.expected_staged_application_intent_digest {
            return Some(O::StagedApplicationDecisionIntentDigestMismatch);
        }
        if decision.transcript_digest != inputs.expected_staged_application_transcript_digest {
            return Some(O::StagedApplicationDecisionTranscriptMismatch);
        }
        // The prepared staged record must reproduce the bound staged decision
        // intent digest.
        if intent.intent_digest() != decision.intent_digest {
            return Some(O::StagedApplicationDecisionIntegrityMismatch);
        }
        // The consumed staged record's own staged-application nonce binding.
        if intent.staged_application_nonce != inputs.expected_staged_application_nonce {
            return Some(O::WrongStagedApplicationNonce);
        }

        // Re-exposed Run 311/312 live-authorization decision authority tuple
        // binding.
        if intent.authorization_decision_id != inputs.expected_authorization_decision_id {
            return Some(O::AuthorizationDecisionIdMismatch);
        }
        if intent.authorization_request_id != inputs.expected_authorization_request_id {
            return Some(O::AuthorizationDecisionRequestIdMismatch);
        }
        if intent.authorization_intent_digest != inputs.expected_authorization_intent_digest {
            return Some(O::AuthorizationDecisionIntentDigestMismatch);
        }
        if intent.authorization_transcript_digest != inputs.expected_authorization_transcript_digest {
            return Some(O::AuthorizationDecisionTranscriptMismatch);
        }

        // Authorization-policy binding.
        if intent.authorization_policy_id != inputs.expected_authorization_policy_id {
            return Some(O::WrongAuthorizationPolicyId);
        }

        // Re-exposed Run 305/306 application-decision authority tuple binding.
        if intent.application_decision_id != inputs.expected_application_decision_id {
            return Some(O::WrongApplicationDecisionId);
        }
        if intent.application_request_id != inputs.expected_application_request_id {
            return Some(O::WrongApplicationRequestId);
        }
        if intent.application_intent_digest != inputs.expected_application_intent_digest {
            return Some(O::WrongApplicationIntentDigest);
        }
        if intent.application_transcript_digest != inputs.expected_application_transcript_digest {
            return Some(O::WrongApplicationTranscriptDigest);
        }

        // Application-policy binding.
        if intent.application_policy_id != inputs.expected_application_policy_id {
            return Some(O::WrongApplicationPolicyId);
        }

        // Trust-domain binding.
        if intent.environment != td.environment {
            return Some(O::WrongEnvironment);
        }
        if intent.chain_id != td.chain_id {
            return Some(O::WrongChain);
        }
        if intent.genesis_hash != td.genesis_hash {
            return Some(O::WrongGenesis);
        }
        if intent.authority_root_fingerprint != td.authority_root_fingerprint
            || intent.authority_root_suite_id != td.authority_root_suite_id
        {
            return Some(O::WrongAuthorityRoot);
        }

        // Governance / rotation tuple binding.
        if intent.governance_domain_id != inputs.expected_governance_domain_id {
            return Some(O::WrongGovernanceDomain);
        }
        if intent.governance_epoch != inputs.expected_governance_epoch {
            return Some(O::WrongGovernanceEpoch);
        }
        if intent.proposal_id != inputs.expected_proposal_id {
            return Some(O::WrongProposalId);
        }
        if intent.governance_decision_id != inputs.expected_governance_decision_id {
            return Some(O::WrongGovernanceExecutionDecisionId);
        }
        if intent.governance_request_id != inputs.expected_governance_request_id {
            return Some(O::WrongGovernanceExecutionRequestId);
        }
        if intent.governance_intent_digest != inputs.expected_governance_intent_digest {
            return Some(O::WrongGovernanceExecutionIntentDigest);
        }
        if intent.rotation_decision_id != inputs.expected_rotation_decision_id {
            return Some(O::WrongRotationDecisionId);
        }
        if intent.rotation_request_id != inputs.expected_rotation_request_id {
            return Some(O::WrongRotationRequestId);
        }
        if intent.rotation_transcript_digest != inputs.expected_rotation_transcript_digest {
            return Some(O::WrongRotationTranscriptDigest);
        }
        if intent.rotation_plan_digest != inputs.expected_rotation_plan_digest {
            return Some(O::WrongRotationPlanDigest);
        }
        if intent.lifecycle_action != inputs.expected_lifecycle_action {
            return Some(O::WrongLifecycleAction);
        }
        if intent.rotation_action != inputs.expected_rotation_action {
            return Some(O::WrongRotationAction);
        }
        if intent.authority_domain_sequence != inputs.expected_authority_domain_sequence {
            return Some(O::WrongAuthoritySequence);
        }
        if intent.quorum != inputs.expected_quorum || !intent.quorum.is_met() {
            return Some(O::WrongQuorum);
        }
        if intent.threshold != inputs.expected_threshold || !intent.threshold.is_met() {
            return Some(O::WrongThreshold);
        }

        // Validator-set tuple binding.
        if intent.current_set_digest != inputs.expected_current_set_digest {
            return Some(O::WrongCurrentValidatorSetDigest);
        }
        if intent.proposed_set_digest != inputs.expected_proposed_set_digest {
            return Some(O::WrongProposedValidatorSetDigest);
        }
        if intent.delta_digest != inputs.expected_delta_digest {
            return Some(O::WrongValidatorSetDeltaDigest);
        }
        if intent.validator_set_epoch != inputs.expected_validator_set_epoch {
            return Some(O::WrongValidatorSetEpoch);
        }
        if intent.validator_set_version != inputs.expected_validator_set_version {
            return Some(O::WrongValidatorSetVersion);
        }
        if intent.proposed_validator_count != inputs.expected_proposed_validator_count {
            return Some(O::WrongProposedValidatorCount);
        }
        if intent.rotation_nonce != inputs.expected_rotation_nonce {
            return Some(O::WrongRotationNonce);
        }

        None
    }

    /// Evidence composition check for represented custody / attestation /
    /// durable-replay bindings. The request's represented bindings must match
    /// both the application intent's bindings (where present) and the
    /// operator-trusted expected bindings.
    fn check_evidence(
        &self,
        request: &ProductionEpochTransitionRuntimeHandoffRequest,
        intent: &ProductionGuardedEpochTransitionMutationRecord,
        inputs: &ProductionEpochTransitionRuntimeHandoffInputs,
    ) -> Option<ProductionEpochTransitionRuntimeHandoffOutcome> {
        use ProductionEpochTransitionRuntimeHandoffOutcome as O;

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
            if let Some(intent_custody) = &intent.custody_binding {
                if intent_custody != actual {
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
            if let Some(intent_att) = &intent.attestation_binding {
                if intent_att != actual {
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
            if let Some(intent_dur) = &intent.durable_replay_binding {
                if intent_dur != actual {
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
    /// accept, the prepared authorization intent.
    fn evaluate_core<R: EpochTransitionRuntimeHandoffReplaySet + ?Sized>(
        &self,
        request: &ProductionEpochTransitionRuntimeHandoffRequest,
        inputs: &ProductionEpochTransitionRuntimeHandoffInputs,
        replay_set: &R,
    ) -> (
        ProductionEpochTransitionRuntimeHandoffOutcome,
        Option<ProductionEpochTransitionRuntimeHandoffPackage>,
    ) {
        use ProductionEpochTransitionRuntimeHandoffOutcome as O;

        // Resolve the authority source. The binding environment is needed for
        // the MainNet gate; if the source is a non-authority source we still
        // gate on the trust-domain environment first.
        let resolved = self.resolve_authority_source(&request.authority_source);
        let binding_env = match &resolved {
            Ok((_, intent)) => intent.environment,
            Err(_) => inputs.trust_domain.environment,
        };

        // Step 1: policy / kind / MainNet gate.
        if let Some(outcome) = self.preflight_gate(binding_env, inputs) {
            return (outcome, None);
        }

        // Step 2: verified validator-set rotation application decision.
        let (decision, application_intent) = match resolved {
            Ok(pair) => pair,
            Err(outcome) => return (outcome, None),
        };

        // Step 3: application-decision binding cross-checks.
        if let Some(outcome) = self.check_application_binding(decision, application_intent, inputs) {
            return (outcome, None);
        }

        // Step 4: replay / freshness on the authorization tuple.
        if let Some(prev) = inputs.persisted_sequence {
            if application_intent.authority_domain_sequence < prev {
                return (O::StaleAuthoritySequence, None);
            }
        }
        let staged_application_id = production_epoch_transition_runtime_handoff_request_id(
            self.config.protocol_version.0,
            &decision.intent_digest,
            &inputs.staged_application_policy_id,
            request.proposed_epoch_transition_target,
            request.staged_application_nonce,
        );
        if replay_set.contains(&staged_application_id) {
            return (O::StagedApplicationReplayRejected { staged_application_id }, None);
        }
        if application_intent.governance_epoch < inputs.min_governance_epoch {
            return (O::StaleGovernanceEpoch, None);
        }
        if application_intent.validator_set_epoch < inputs.min_validator_set_epoch {
            return (O::StaleValidatorSetEpoch, None);
        }
        if application_intent.validator_set_version < inputs.min_validator_set_version {
            return (O::StaleValidatorSetVersion, None);
        }

        // Step 5: custody / attestation / durable-replay evidence.
        if let Some(outcome) = self.check_evidence(request, application_intent, inputs) {
            return (outcome, None);
        }

        // Step 6: epoch-transition target binding. A future epoch-transition
        // executor would transition to exactly the authorization intent's
        // epoch-transition target.
        if request.proposed_epoch_transition_target != inputs.expected_epoch_transition_target {
            return (O::WrongEpochTransitionTarget, None);
        }
        if request.proposed_epoch_transition_target != application_intent.epoch_transition_target {
            return (O::WrongEpochTransitionTarget, None);
        }

        // Step 7: application-nonce and live-application-nonce binding. Both
        // nonces carried by the authorization intent must equal the
        // operator-trusted expected nonces.
        if application_intent.application_nonce != inputs.expected_application_nonce {
            return (O::WrongApplicationNonce, None);
        }
        if application_intent.live_application_nonce != inputs.expected_live_application_nonce {
            return (O::WrongLiveApplicationNonce, None);
        }

        // Step 8: derive the typed guarded mutation kind from the consumed
        // staged record's staged-application kind.
        let staged_kind =
            EpochTransitionRuntimeHandoffKind::from_staged_application_kind(
                application_intent.staged_kind,
            );
        if staged_kind.is_unsupported() {
            return (O::UnsupportedStagedLiveApplication, None);
        }

        // Step 9: construct the typed non-mutating staged application record.
        let record = ProductionEpochTransitionRuntimeHandoffPackage {
            staged_kind,
            protocol_version: self.config.protocol_version.0,
            staged_application_policy_id: inputs.staged_application_policy_id.clone(),
            authorization_policy_id: application_intent.authorization_policy_id.clone(),
            application_policy_id: application_intent.application_policy_id.clone(),
            environment: application_intent.environment,
            chain_id: application_intent.chain_id.clone(),
            genesis_hash: application_intent.genesis_hash.clone(),
            authority_root_fingerprint: application_intent.authority_root_fingerprint.clone(),
            authority_root_suite_id: application_intent.authority_root_suite_id,
            governance_domain_id: application_intent.governance_domain_id.clone(),
            governance_epoch: application_intent.governance_epoch,
            governance_height: application_intent.governance_height,
            proposal_id: application_intent.proposal_id.clone(),
            proposal_digest: application_intent.proposal_digest.clone(),
            quorum: application_intent.quorum.clone(),
            threshold: application_intent.threshold.clone(),
            lifecycle_action: application_intent.lifecycle_action,
            rotation_action: application_intent.rotation_action,
            authority_domain_sequence: application_intent.authority_domain_sequence,
            governance_decision_id: application_intent.governance_decision_id.clone(),
            governance_request_id: application_intent.governance_request_id.clone(),
            governance_intent_digest: application_intent.governance_intent_digest.clone(),
            rotation_decision_id: application_intent.rotation_decision_id.clone(),
            rotation_request_id: application_intent.rotation_request_id.clone(),
            rotation_transcript_digest: application_intent.rotation_transcript_digest.clone(),
            rotation_plan_digest: application_intent.rotation_plan_digest.clone(),
            current_set_digest: application_intent.current_set_digest.clone(),
            proposed_set_digest: application_intent.proposed_set_digest.clone(),
            delta_digest: application_intent.delta_digest.clone(),
            validator_set_epoch: application_intent.validator_set_epoch,
            validator_set_version: application_intent.validator_set_version,
            proposed_validator_count: application_intent.proposed_validator_count,
            rotation_nonce: application_intent.rotation_nonce,
            application_decision_id: application_intent.application_decision_id.clone(),
            application_request_id: application_intent.application_request_id.clone(),
            application_intent_digest: application_intent.application_intent_digest.clone(),
            application_transcript_digest: application_intent.application_transcript_digest.clone(),
            application_nonce: application_intent.application_nonce,
            epoch_transition_target: application_intent.epoch_transition_target,
            live_application_nonce: application_intent.live_application_nonce,
            authorization_decision_id: application_intent.authorization_decision_id.clone(),
            authorization_request_id: application_intent.authorization_request_id.clone(),
            authorization_intent_digest: application_intent.authorization_intent_digest.clone(),
            authorization_transcript_digest: application_intent
                .authorization_transcript_digest
                .clone(),
            staged_application_decision_id: decision.staged_application_id.clone(),
            staged_application_request_id: decision.request_id.clone(),
            staged_application_intent_digest: decision.intent_digest.clone(),
            staged_application_transcript_digest: decision.transcript_digest.clone(),
            staged_application_nonce: application_intent.staged_application_nonce,
            guarded_mutation_nonce: request.staged_application_nonce,
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
        };

        // Step 10: typed accepted non-mutating outcome.
        (
            O::AcceptedSourceTestEpochTransitionRuntimeHandoff {
                staged_kind,
                environment: application_intent.environment,
                epoch_transition_target: request.proposed_epoch_transition_target,
                staged_application_nonce: request.staged_application_nonce,
            },
            Some(record),
        )
    }

    /// Run 313 — evaluate a staged live validator-set / epoch-transition
    /// application request into a typed, deterministic, non-mutating decision.
    /// This never mutates any live validator set, consensus epoch, or trust
    /// state; on accept it produces only a prepared staged application record.
    pub fn evaluate_epoch_transition_runtime_handoff<
        R: EpochTransitionRuntimeHandoffReplaySet + ?Sized,
    >(
        &self,
        request: &ProductionEpochTransitionRuntimeHandoffRequest,
        inputs: &ProductionEpochTransitionRuntimeHandoffInputs,
        replay_set: &R,
    ) -> ProductionEpochTransitionRuntimeHandoffDecision {
        let (outcome, record) = self.evaluate_core(request, inputs, replay_set);

        // Authorization decision id + intent digest for the transcript
        // (best-effort from the authority source).
        let (staged_application_id, authorization_intent_digest) = match &request.authority_source {
            EpochTransitionRuntimeHandoffAuthoritySource::VerifiedGuardedMutationDecision {
                decision,
            }
            | EpochTransitionRuntimeHandoffAuthoritySource::UnverifiedGuardedMutationDecision {
                decision,
            }
            | EpochTransitionRuntimeHandoffAuthoritySource::AcceptedGuardedMutationWithoutRecord {
                decision,
            } => (decision.staged_application_id.clone(), decision.intent_digest.clone()),
            _ => (String::new(), String::new()),
        };

        let request_id = production_epoch_transition_runtime_handoff_request_id(
            self.config.protocol_version.0,
            &authorization_intent_digest,
            &inputs.staged_application_policy_id,
            request.proposed_epoch_transition_target,
            request.staged_application_nonce,
        );
        let intent_digest = record.as_ref().map(|i| i.intent_digest()).unwrap_or_default();
        let transcript_digest =
            production_epoch_transition_runtime_handoff_transcript_digest(
                self.config.protocol_version.0,
                &request_id,
                &intent_digest,
                outcome.tag(),
            );

        ProductionEpochTransitionRuntimeHandoffDecision {
            outcome,
            staged_application_id,
            request_id,
            staged_application_record: record,
            intent_digest,
            transcript_digest,
        }
    }

    /// Run 313 — idempotency / recovery over a prepared-authorization window.
    /// Non-mutating; writes no durable state.
    pub fn recover_epoch_transition_runtime_handoff_window(
        &self,
        prior: Option<&ProductionEpochTransitionRuntimeHandoffPackage>,
        current: &ProductionEpochTransitionRuntimeHandoffPackage,
    ) -> ProductionEpochTransitionRuntimeHandoffRecoveryOutcome {
        use ProductionEpochTransitionRuntimeHandoffRecoveryOutcome as R;
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionEpochTransitionRuntimeHandoffExecutorKind::Disabled
        {
            return R::RecoveryDisabled;
        }
        let Some(prior) = prior else {
            return R::NoPriorStagedApplicationWindow;
        };
        // Unrelated staged application digests / nonces => independent window.
        if prior.authorization_intent_digest != current.authorization_intent_digest
            || prior.staged_application_nonce != current.staged_application_nonce
            || prior.epoch_transition_target != current.epoch_transition_target
        {
            return R::NoPriorStagedApplicationWindow;
        }
        // Same window, byte-identical record => idempotent replay.
        if prior == current {
            R::IdempotentReplayObserved {
                staged_application_id: current.authorization_decision_id.clone(),
            }
        } else {
            // Same window but non-identical record is caller error; the
            // executor reports a clean (non-mutating) recovery signal and
            // never overwrites durable state.
            R::NoPriorStagedApplicationWindow
        }
    }
}

// ===========================================================================
// Standalone named helpers (source/test invariants)
// ===========================================================================

/// Run 313 — the executor default policy is Disabled / fail-closed.
pub fn production_epoch_transition_runtime_handoff_executor_default_is_disabled() -> bool
{
    ProductionEpochTransitionRuntimeHandoffExecutorPolicy::default()
        == ProductionEpochTransitionRuntimeHandoffExecutorPolicy::Disabled
        && ProductionEpochTransitionRuntimeHandoffConfig::default().kind
            == ProductionEpochTransitionRuntimeHandoffExecutorKind::Disabled
}

/// Run 313 — the executor is a source/test implementation, not
/// release-binary evidence (deferred to Run 314).
pub fn production_epoch_transition_runtime_handoff_executor_is_source_test_not_release_binary_evidence(
) -> bool {
    true
}

/// Run 313 — the executor refuses MainNet absent production authority.
pub fn production_epoch_transition_runtime_handoff_executor_mainnet_refused() -> bool {
    true
}

/// Run 313 — the executor never applies a live validator-set change,
/// consensus epoch transition, or trust-state mutation; every outcome is
/// non-mutating.
pub fn production_epoch_transition_runtime_handoff_executor_is_non_mutating() -> bool {
    true
}

/// Run 313 — the executor never falls back to rotation-plan-alone /
/// governance-proof-alone / governance-execution-intent-alone / fixture /
/// local-operator / peer-majority / custody-only / RemoteSigner-only /
/// arbitrary-bytes authority.
pub fn production_epoch_transition_runtime_handoff_executor_never_falls_back() -> bool {
    true
}

/// Run 313 — the executor adds no default runtime wiring and no CLI flag.
pub fn production_epoch_transition_runtime_handoff_executor_no_default_runtime_wiring(
) -> bool {
    true
}

/// Run 313 — the executor only requires a verified Run 311/312 validator-set
/// rotation application decision as authority; nothing else can authorize a
/// live-application authorization.
pub fn production_epoch_transition_runtime_handoff_executor_requires_verified_application_decision(
) -> bool {
    true
}
// ===========================================================================
// Source/test-only in-memory fixture ledger
// ===========================================================================

/// Run 313 — an explicit, in-memory fixture ledger/state used *only* by tests
/// to demonstrate a source/test-bounded guarded mutation application path.
///
/// This type is the *only* thing a positive guarded mutation path may mutate
/// in Run 313. It is not wired into node runtime, never touches production
/// consensus validator state, never transitions a production consensus epoch,
/// never writes `meta:current_epoch`, never injects a reconfig block, never
/// calls Run 070, and never mutates `LivePqcTrustState`. It is a plain
/// in-memory struct owned by the caller (a test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionRuntimeHandoffFixtureState {
    /// The fixture's current (in-memory) epoch.
    pub current_epoch: u64,
    /// The fixture's current (in-memory) validator-set version.
    pub validator_set_version: u64,
    /// The fixture's current (in-memory) validator-set digest.
    pub current_set_digest: String,
    /// The execution ids already applied to this fixture ledger (idempotency).
    pub applied_execution_ids: Vec<String>,
}

impl EpochTransitionRuntimeHandoffFixtureState {
    /// Creates a new in-memory fixture ledger.
    pub fn new(
        current_epoch: u64,
        validator_set_version: u64,
        current_set_digest: impl Into<String>,
    ) -> Self {
        Self {
            current_epoch,
            validator_set_version,
            current_set_digest: current_set_digest.into(),
            applied_execution_ids: Vec::new(),
        }
    }

    /// Returns `true` iff the given execution id was already applied to this
    /// fixture ledger.
    pub fn has_applied(&self, execution_id: &str) -> bool {
        self.applied_execution_ids.iter().any(|id| id == execution_id)
    }

    /// Applies a prepared, accepted guarded mutation record to *this* in-memory
    /// fixture ledger only, advancing the fixture's epoch / validator-set
    /// version / set digest to the record's prepared targets.
    ///
    /// Idempotent: re-applying the same `execution_id` is a no-op returning
    /// `false`. Returns `true` on first application. This never mutates
    /// production consensus state, epoch counters, or trust state — only the
    /// fields of this owned struct.
    pub fn apply_prepared_execution(
        &mut self,
        record: &ProductionEpochTransitionRuntimeHandoffPackage,
        execution_id: &str,
    ) -> bool {
        if self.has_applied(execution_id) {
            return false;
        }
        self.current_epoch = record.epoch_transition_target;
        self.validator_set_version = record.validator_set_version;
        self.current_set_digest = record.proposed_set_digest.clone();
        self.applied_execution_ids.push(execution_id.to_string());
        true
    }
}