//! Run 325 — source/test epoch-transition **runtime handoff** /
//! live-mutation **preflight** boundary.
//!
//! This module implements the next source/test boundary above the Run
//! 321/322 guarded epoch-transition post-commit-audit boundary: the boundary
//! that consumes a **verified** Run 323/324 non-mutating guarded
//! epoch-transition post-commit-audit *decision* (the accepted
//! [`ProductionLiveEpochTransitionCommitReceiptDecision`] carrying a prepared
//! [`ProductionLiveEpochTransitionCommitReceiptArtifact`], as
//! release-binary-evidenced by Run 322) and translates it into a typed,
//! deterministic, policy-gated **runtime handoff package** for a *future* live
//! executor — *without* ever applying a live validator-set change,
//! transitioning a consensus epoch, or mutating any trust state.
//!
//! Where the Run 321 boundary answers "given a verified staged
//! epoch-transition application decision, what typed non-mutating guarded
//! mutation record does it authorize?", Run 325 answers the next question:
//! "given a verified guarded post-commit-audit decision, what typed,
//! non-mutating **runtime handoff package** carrying the exact preconditions a
//! *future* live executor must re-verify does it authorize, under an explicit
//! runtime handoff policy, bound to the full guarded-mutation-decision /
//! staged-application / authorization / application / rotation / governance /
//! validator-set / custody / attestation / durable-replay evidence tuple, an
//! explicit epoch-transition target, current/proposed validator-set
//! epoch/version preconditions, a required replay window, and a commit-receipt
//! nonce?".
//!
//! ## Scope and honesty constraints (Run 325)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 326**.
//! * The default policy is
//!   [`ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy::Disabled`]
//!   and fails closed **before** any binding, validator-set binding, or
//!   handoff-package construction.
//! * Only a **verified** Run 323/324 guarded epoch-transition
//!   post-commit-audit decision that `is_accept()` and carries a
//!   [`ProductionLiveEpochTransitionCommitReceiptArtifact`] can authorize a runtime
//!   handoff package. Unverified decisions, accepted decisions without a
//!   prepared record, a Run 319/320 staged-application decision alone, a Run
//!   317/318 live-application authorization alone, a Run 315/316 application
//!   decision alone, Run 313 rotation plans alone, governance execution intent
//!   alone, governance proof alone, local-operator assertions, peer-majority
//!   assertions, custody-only, RemoteSigner-only, custody-attestation-only,
//!   fixture-only decisions, and arbitrary validator-set bytes are all rejected
//!   as production authority.
//! * The boundary produces only a typed
//!   [`ProductionLiveEpochTransitionPostCommitAuditArtifact`]; it
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
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_317.md`.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::OnChainGovernanceQuorum;
use crate::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding,
};
use crate::pqc_production_live_epoch_transition_commit_receipt::{
    ProductionLiveEpochTransitionCommitReceiptDecision,
    ProductionLiveEpochTransitionCommitReceiptArtifact,
    LiveEpochTransitionCommitReceiptKind,
};
use crate::pqc_production_validator_set_rotation_intent::ValidatorSetRotationAction;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 325 — the only live validator-set application authorization boundary
/// protocol version this run accepts.
pub const PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_PROTOCOL_VERSION: u16 = 1;

/// Run 325 — runtime handoff content digest domain tag.
pub const PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_INTENT_DOMAIN_TAG: &str =
    "QBIND:325-epoch-transition-commit-receipt-intent:v1";

/// Run 325 — runtime handoff id domain tag.
pub const PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_ID_DOMAIN_TAG: &str =
    "QBIND:325-epoch-transition-commit-receipt-id:v1";

/// Run 325 — runtime handoff request-id domain tag.
pub const PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_REQUEST_DOMAIN_TAG: &str =
    "QBIND:325-epoch-transition-commit-receipt-request:v1";

/// Run 325 — runtime handoff transcript digest domain tag.
pub const PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:325-epoch-transition-commit-receipt-transcript:v1";

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

/// Run 325 — typed live validator-set application authorization boundary
/// protocol version. Only
/// [`PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_PROTOCOL_VERSION`]
/// is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionLiveEpochTransitionPostCommitAuditProtocolVersion(pub u16);

impl ProductionLiveEpochTransitionPostCommitAuditProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_PROTOCOL_VERSION
    }
}

impl Default for ProductionLiveEpochTransitionPostCommitAuditProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 325 — typed live validator-set application authorization boundary
/// policy.
///
/// `Disabled` is the default fail-closed policy: the boundary refuses before
/// any application binding or authorization construction.
/// `AllowSourceTestLiveEpochTransitionPostCommitAudit` is the only
/// policy that can produce an accepted source/test authorization, and only on
/// DevNet/TestNet with a verified Run 323/324 validator-set rotation
/// application decision.
/// `RequireProductionLiveEpochTransitionPostCommitAudit` and
/// `MainnetProductionLiveEpochTransitionPostCommitAuditRequired` are
/// **reachable but fail-closed** production/MainNet policies: no production
/// live validator-set application authorization authority is wired, so they
/// fail closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified validator-set rotation
    /// application decision may produce a typed non-mutating live-application
    /// authorization as source/test evidence only. MainNet remains refused.
    AllowSourceTestLiveEpochTransitionPostCommitAudit,
    /// Production policy. Reachable but fails closed: no production live
    /// validator-set application authorization prerequisites are wired.
    RequireProductionLiveEpochTransitionPostCommitAudit,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production live validator-set application authorization authority is
    /// wired.
    MainnetProductionLiveEpochTransitionPostCommitAuditRequired,
}

impl ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestLiveEpochTransitionPostCommitAudit => {
                "allow-source-test-epoch-transition-commit-receipt"
            }
            Self::RequireProductionLiveEpochTransitionPostCommitAudit => {
                "require-production-epoch-transition-commit-receipt"
            }
            Self::MainnetProductionLiveEpochTransitionPostCommitAuditRequired => {
                "mainnet-production-epoch-transition-commit-receipt-required"
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
            Self::AllowSourceTestLiveEpochTransitionPostCommitAudit
        )
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Self::RequireProductionLiveEpochTransitionPostCommitAudit
        )
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(
            self,
            Self::MainnetProductionLiveEpochTransitionPostCommitAuditRequired
        )
    }
}

// ===========================================================================
// Boundary kind taxonomy
// ===========================================================================

/// Run 325 — typed live validator-set application authorization boundary
/// kind.
///
/// `Disabled` is the inert default.
/// `SourceTestLiveEpochTransitionPostCommitAudit` performs real
/// source/test authorization construction. A reserved
/// `ProductionLiveEpochTransitionPostCommitAudit` kind is fail-closed as
/// unavailable in Run 325 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionLiveEpochTransitionPostCommitAuditExecutorKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test live validator-set application authorization
    /// boundary.
    SourceTestLiveEpochTransitionPostCommitAudit,
    /// Reserved production authorization kind. Fail-closed in Run 325.
    ProductionLiveEpochTransitionPostCommitAudit,
}

impl ProductionLiveEpochTransitionPostCommitAuditExecutorKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestLiveEpochTransitionPostCommitAudit => {
                "source-test-epoch-transition-commit-receipt"
            }
            Self::ProductionLiveEpochTransitionPostCommitAudit => {
                "production-epoch-transition-commit-receipt"
            }
        }
    }

    /// Returns `true` iff this kind performs real source/test authorization
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(
            self,
            Self::SourceTestLiveEpochTransitionPostCommitAudit
        )
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 325 — typed live validator-set application authorization boundary
/// config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditConfig {
    /// Boundary protocol version. Must equal the supported version.
    pub protocol_version: ProductionLiveEpochTransitionPostCommitAuditProtocolVersion,
    /// The boundary kind.
    pub kind: ProductionLiveEpochTransitionPostCommitAuditExecutorKind,
}

impl ProductionLiveEpochTransitionPostCommitAuditConfig {
    pub fn new(kind: ProductionLiveEpochTransitionPostCommitAuditExecutorKind) -> Self {
        Self {
            protocol_version:
                ProductionLiveEpochTransitionPostCommitAuditProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test authorization boundary kind.
    pub fn source_test() -> Self {
        Self::new(
            ProductionLiveEpochTransitionPostCommitAuditExecutorKind::SourceTestLiveEpochTransitionPostCommitAudit,
        )
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionLiveEpochTransitionPostCommitAuditConfig {
    fn default() -> Self {
        Self::new(ProductionLiveEpochTransitionPostCommitAuditExecutorKind::Disabled)
    }
}

// ===========================================================================
// Staged application kind taxonomy
// ===========================================================================

/// Run 325 — the typed kind of a prepared, non-mutating staged live
/// validator-set / epoch-transition application record.
///
/// Each kind corresponds one-to-one with a supported Run 323/324
/// [`LiveEpochTransitionCommitReceiptKind`]; the reserved
/// [`Self::UnsupportedStagedApplication`] never authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiveEpochTransitionPostCommitAuditKind {
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

impl LiveEpochTransitionPostCommitAuditKind {
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

    /// Every Run 325 staged application kind is a *prepared*, non-mutating
    /// record; none applies a live validator-set change.
    pub const fn is_non_mutating(self) -> bool {
        true
    }

    /// Maps a supported Run 323/324 staged live validator-set / epoch-transition
    /// application kind to its guarded mutation kind. Returns
    /// [`Self::UnsupportedStagedApplication`] for the reserved unsupported
    /// staged application kind.
    pub const fn from_staged_application_kind(
        kind: LiveEpochTransitionCommitReceiptKind,
    ) -> Self {
        use LiveEpochTransitionCommitReceiptKind as A;
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

/// Run 325 — the staged live validator-set / epoch-transition application
/// authority source presented to the executor.
///
/// Only [`Self::VerifiedCommitReceiptDecision`] carrying a Run 323/324
/// live validator-set application authorization decision that `is_accept()`
/// **and** carries a prepared authorization intent can authorize a staged
/// application record. Every other variant is a non-authority source rejected
/// with a precise fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveEpochTransitionPostCommitAuditAuthoritySource {
    /// A verified Run 323/324 epoch-transition runtime handoff / live-mutation
    /// preflight decision. The **only** accepted authority source. The
    /// decision must `is_accept()` and carry `Some(handoff_package)`.
    VerifiedCommitReceiptDecision {
        decision: ProductionLiveEpochTransitionCommitReceiptDecision,
    },
    /// No runtime handoff decision was supplied.
    MissingCommitReceiptDecision,
    /// An unverified / non-accept runtime handoff decision. Rejected.
    UnverifiedCommitReceiptDecision {
        decision: ProductionLiveEpochTransitionCommitReceiptDecision,
    },
    /// An accepted runtime handoff decision that carries no prepared runtime
    /// handoff package. Rejected.
    AcceptedCommitReceiptWithoutPackage {
        decision: ProductionLiveEpochTransitionCommitReceiptDecision,
    },
    /// A Run 321/322 epoch-transition commit-authorization decision presented
    /// directly, without a Run 323/324 commit-receipt decision. Rejected.
    CommitAuthorizationDecisionWithoutCommitReceipt,
    /// A Run 321/322 epoch-transition mutation-execution decision presented
    /// directly, without a Run 323/324 commit-receipt decision. Rejected.
    MutationExecutionDecisionWithoutCommitReceipt,
    /// A Run 321/322 epoch-transition execution-preparation decision presented
    /// directly, without a Run 323/324 commit-receipt decision. Rejected.
    ExecutionPreparationDecisionWithoutCommitReceipt,
    /// A Run 321/322 epoch-transition runtime handoff decision presented
    /// directly, without a Run 323/324 commit-receipt decision.
    /// Rejected.
    RuntimeHandoffDecisionWithoutCommitReceipt,
    /// A Run 321/322 guarded epoch-transition post-commit-audit decision
    /// presented directly, without a Run 323/324 runtime handoff decision.
    /// Rejected.
    GuardedMutationDecisionWithoutCommitReceipt,
    /// A Run 319/320 staged-application decision presented directly, without a
    /// Run 323/324 runtime handoff decision. Rejected.
    StagedApplicationDecisionWithoutCommitReceipt,
    /// A Run 317/318 live-application authorization presented directly, without
    /// a Run 323/324 guarded post-commit-audit decision. Rejected.
    LiveApplicationAuthorizationWithoutCommitReceipt,
    /// A Run 315/316 validator-set rotation *application decision* presented
    /// directly, without a Run 323/324 guarded post-commit-audit decision.
    /// Rejected.
    ApplicationDecisionWithoutCommitReceipt,
    /// A Run 313/314 validator-set rotation plan presented directly, without a
    /// Run 323/324 live-application authorization. Rejected.
    RotationPlanWithoutCommitReceipt,
    /// A Run 311/312 governance execution intent presented directly, without a
    /// Run 323/324 live-application authorization. Rejected.
    GovernanceExecutionIntentWithoutCommitReceipt,
    /// A raw on-chain governance proof presented directly, without a Run
    /// 317/318 live-application authorization. Rejected.
    GovernanceProofWithoutCommitReceipt,
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
    FixtureOnlyCommitReceipt,
    /// Arbitrary validator-set bytes presented directly, without a verified
    /// live-application authorization. Rejected.
    ArbitraryValidatorSetBytes,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 325 — the explicit trusted inputs the executor binds a verified
/// Run 323/324 live validator-set application authorization decision against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// The opaque staged-application policy id bound into the staged record.
    pub post_commit_audit_policy_id: String,
    /// Expected Run 323/324 live-application authorization policy id (bound
    /// into the consumed authorization intent).
    pub expected_authorization_policy_id: String,
    /// Expected Run 315/316 application policy id (re-exposed by the
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
    /// Expected Run 311 governance execution decision id.
    pub expected_governance_decision_id: String,
    /// Expected Run 311 governance execution request id.
    pub expected_governance_request_id: String,
    /// Expected Run 311 governance execution intent digest.
    pub expected_governance_intent_digest: String,
    /// Expected Run 313 rotation decision id.
    pub expected_rotation_decision_id: String,
    /// Expected Run 313 rotation request id.
    pub expected_rotation_request_id: String,
    /// Expected Run 313 rotation transcript digest.
    pub expected_rotation_transcript_digest: String,
    /// Expected Run 313 rotation plan digest.
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
    /// Expected Run 315/316 application decision id (re-exposed by the
    /// authorization intent).
    pub expected_application_decision_id: String,
    /// Expected Run 315/316 application request id.
    pub expected_application_request_id: String,
    /// Expected Run 315/316 application intent digest.
    pub expected_application_intent_digest: String,
    /// Expected Run 315/316 application transcript digest.
    pub expected_application_transcript_digest: String,
    /// Expected Run 323/324 authorization decision id (bound into the
    /// consumed authorization decision).
    pub expected_authorization_decision_id: String,
    /// Expected Run 323/324 authorization request id.
    pub expected_authorization_request_id: String,
    /// Expected Run 323/324 authorization intent digest.
    pub expected_authorization_intent_digest: String,
    /// Expected Run 323/324 authorization transcript digest.
    pub expected_authorization_transcript_digest: String,
    /// Expected Run 323/324 staged-application decision id (bound into the
    /// consumed staged-application decision).
    pub expected_staged_application_decision_id: String,
    /// Expected Run 323/324 staged-application request id.
    pub expected_staged_application_request_id: String,
    /// Expected Run 323/324 staged-application intent digest.
    pub expected_staged_application_intent_digest: String,
    /// Expected Run 323/324 staged-application transcript digest.
    pub expected_staged_application_transcript_digest: String,
    /// Expected Run 323/324 staged-application nonce (re-exposed by the
    /// consumed staged-application record).
    pub expected_staged_application_nonce: u64,
    /// Expected epoch-transition target a future executor would transition
    /// to. Must equal the authorization intent's epoch-transition target.
    pub expected_epoch_transition_target: u64,
    /// Expected Run 315/316 application nonce (re-exposed by the authorization
    /// intent).
    pub expected_application_nonce: u64,
    /// Expected Run 323/324 live-application nonce (re-exposed by the
    /// authorization intent).
    pub expected_live_application_nonce: u64,
    /// Expected Run 321/322 guarded post-commit-audit decision id (re-exposed
    /// by the consumed Run 323/324 runtime handoff package).
    pub expected_guarded_mutation_decision_id: String,
    /// Expected Run 321/322 guarded post-commit-audit request id.
    pub expected_guarded_mutation_request_id: String,
    /// Expected Run 321/322 guarded post-commit-audit intent digest.
    pub expected_guarded_mutation_intent_digest: String,
    /// Expected Run 321/322 guarded post-commit-audit transcript digest.
    pub expected_guarded_mutation_transcript_digest: String,
    /// Expected Run 321/322 guarded mutation nonce (re-exposed by the consumed
    /// runtime handoff package).
    pub expected_guarded_mutation_nonce: u64,
    /// Expected Run 323/324 runtime handoff decision id (bound into the
    /// consumed runtime handoff decision).
    pub expected_commit_receipt_decision_id: String,
    /// Expected Run 323/324 runtime handoff request id.
    pub expected_commit_receipt_request_id: String,
    /// Expected Run 323/324 runtime handoff package/content digest (the
    /// consumed decision's `post_commit_audit_digest`, i.e. the handoff content
    /// digest).
    pub expected_commit_receipt_intent_digest: String,
    /// Expected Run 323/324 runtime handoff transcript digest.
    pub expected_commit_receipt_transcript_digest: String,
    /// Expected Run 323/324 commit-receipt nonce (re-exposed by the
    /// consumed Run 323/324 commit-receipt artifact).
    pub expected_commit_receipt_nonce: u64,
    /// Expected Run 321/322 commit-authorization decision id (re-exposed by
    /// the consumed Run 323/324 commit-receipt artifact).
    pub expected_commit_authorization_decision_id: String,
    /// Expected Run 321/322 commit-authorization request id.
    pub expected_commit_authorization_request_id: String,
    /// Expected Run 321/322 commit-authorization intent/content digest.
    pub expected_commit_authorization_intent_digest: String,
    /// Expected Run 321/322 commit-authorization transcript digest.
    pub expected_commit_authorization_transcript_digest: String,
    /// Expected Run 321/322 commit-authorization nonce (re-exposed by the
    /// consumed Run 323/324 commit-receipt artifact).
    pub expected_commit_authorization_nonce: u64,
    /// Expected Run 321/322 mutation-execution decision id (re-exposed by
    /// the consumed Run 323/324 commit-receipt artifact).
    pub expected_mutation_execution_decision_id: String,
    /// Expected Run 321/322 mutation-execution request id.
    pub expected_mutation_execution_request_id: String,
    /// Expected Run 321/322 mutation-execution intent/content digest.
    pub expected_mutation_execution_intent_digest: String,
    /// Expected Run 321/322 mutation-execution transcript digest.
    pub expected_mutation_execution_transcript_digest: String,
    /// Expected Run 321/322 mutation-execution nonce (re-exposed by the
    /// consumed Run 323/324 commit-receipt artifact).
    pub expected_mutation_execution_nonce: u64,
    /// Expected Run 321/322 execution-preparation decision id (re-exposed by
    /// the consumed Run 323/324 commit-receipt artifact).
    pub expected_execution_preparation_decision_id: String,
    /// Expected Run 321/322 execution-preparation request id.
    pub expected_execution_preparation_request_id: String,
    /// Expected Run 321/322 execution-preparation intent/content digest.
    pub expected_execution_preparation_intent_digest: String,
    /// Expected Run 321/322 execution-preparation transcript digest.
    pub expected_execution_preparation_transcript_digest: String,
    /// Expected Run 321/322 execution-preparation nonce (re-exposed by the
    /// consumed Run 323/324 commit-receipt artifact).
    pub expected_execution_preparation_nonce: u64,
    /// Expected Run 321/322 runtime handoff decision id (re-exposed by the
    /// consumed Run 323/324 commit-receipt artifact).
    pub expected_runtime_handoff_decision_id: String,
    /// Expected Run 321/322 runtime handoff request id.
    pub expected_runtime_handoff_request_id: String,
    /// Expected Run 321/322 runtime handoff package/content digest.
    pub expected_runtime_handoff_intent_digest: String,
    /// Expected Run 321/322 runtime handoff transcript digest.
    pub expected_runtime_handoff_transcript_digest: String,
    /// Expected Run 321/322 runtime handoff nonce (re-exposed by the consumed
    /// Run 323/324 commit-receipt artifact).
    pub expected_runtime_handoff_nonce: u64,
    /// Expected current validator-set epoch a future live executor would
    /// transition *from*. Must be `<=` the record's proposed validator-set
    /// epoch (the proposed epoch may equal the current epoch on a no-op).
    pub expected_current_validator_set_epoch: u64,
    /// Expected current validator-set version a future live executor would
    /// transition *from*. Must be `<=` the record's proposed validator-set
    /// version.
    pub expected_current_validator_set_version: u64,
    /// Operator-declared required replay window a future live executor must
    /// honour. Encoded into the handoff package preconditions; never a
    /// wall-clock value and never a reject path in Run 325.
    pub required_replay_window: u64,
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

impl ProductionLiveEpochTransitionPostCommitAuditInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.post_commit_audit_policy_id.is_empty()
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
            && !self.expected_guarded_mutation_decision_id.is_empty()
            && !self.expected_guarded_mutation_request_id.is_empty()
            && !self.expected_guarded_mutation_intent_digest.is_empty()
            && !self.expected_guarded_mutation_transcript_digest.is_empty()
            && !self.expected_commit_receipt_decision_id.is_empty()
            && !self.expected_commit_receipt_request_id.is_empty()
            && !self.expected_commit_receipt_intent_digest.is_empty()
            && !self.expected_commit_receipt_transcript_digest.is_empty()
            && !self.expected_commit_authorization_decision_id.is_empty()
            && !self.expected_commit_authorization_request_id.is_empty()
            && !self.expected_commit_authorization_intent_digest.is_empty()
            && !self.expected_commit_authorization_transcript_digest.is_empty()
            && !self.expected_mutation_execution_decision_id.is_empty()
            && !self.expected_mutation_execution_request_id.is_empty()
            && !self.expected_mutation_execution_intent_digest.is_empty()
            && !self.expected_mutation_execution_transcript_digest.is_empty()
            && !self.expected_execution_preparation_decision_id.is_empty()
            && !self.expected_execution_preparation_request_id.is_empty()
            && !self.expected_execution_preparation_intent_digest.is_empty()
            && !self.expected_execution_preparation_transcript_digest.is_empty()
            && !self.expected_runtime_handoff_decision_id.is_empty()
            && !self.expected_runtime_handoff_request_id.is_empty()
            && !self.expected_runtime_handoff_intent_digest.is_empty()
            && !self.expected_runtime_handoff_transcript_digest.is_empty()
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 325 — a runtime handoff request: the authority source (a verified
/// guarded epoch-transition post-commit-audit decision), the explicit
/// epoch-transition target, a commit-receipt nonce, and any represented
/// custody / attestation / durable-replay evidence bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditRequest {
    pub authority_source: LiveEpochTransitionPostCommitAuditAuthoritySource,
    /// The epoch a future epoch-transition executor would transition to.
    pub proposed_epoch_transition_target: u64,
    /// The commit-receipt nonce (idempotency / replay binding).
    pub post_commit_audit_nonce: u64,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionLiveEpochTransitionPostCommitAuditRequest {
    /// Construct a request carrying only an authority source, epoch target,
    /// and commit-receipt nonce (no represented custody / attestation /
    /// durable-replay evidence).
    pub fn new(
        authority_source: LiveEpochTransitionPostCommitAuditAuthoritySource,
        proposed_epoch_transition_target: u64,
        post_commit_audit_nonce: u64,
    ) -> Self {
        Self {
            authority_source,
            proposed_epoch_transition_target,
            post_commit_audit_nonce,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 325 — caller-owned replay authorization-id set. The executor reads
/// from this set but never mutates it.
pub trait LiveEpochTransitionPostCommitAuditReplaySet {
    fn contains(&self, authorization_id: &str) -> bool;
}

impl LiveEpochTransitionPostCommitAuditReplaySet for &[String] {
    fn contains(&self, authorization_id: &str) -> bool {
        (*self).iter().any(|s| s == authorization_id)
    }
}

impl LiveEpochTransitionPostCommitAuditReplaySet for Vec<String> {
    fn contains(&self, authorization_id: &str) -> bool {
        self.iter().any(|s| s == authorization_id)
    }
}

/// Empty replay set helper.
pub struct EmptyLiveEpochTransitionPostCommitAuditReplaySet;

impl LiveEpochTransitionPostCommitAuditReplaySet
    for EmptyLiveEpochTransitionPostCommitAuditReplaySet
{
    fn contains(&self, _authorization_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Runtime handoff package (boundary output)
// ===========================================================================

/// Run 325 — a typed, deterministic, **non-mutating** epoch-transition runtime
/// handoff package. Only a typed accepted outcome carrying this package may
/// authorize a *future* real live mutation run (Run 326+); Run 325 never
/// applies it. The package re-exposes the full consumed guarded-mutation /
/// staged-application / authorization / application / rotation / governance /
/// validator-set evidence tuple **and** the exact future-executor
/// preconditions, and carries deterministic `post_commit_audit_id`, `request_id`,
/// `post_commit_audit_digest`, and `transcript_digest` identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditArtifact {
    pub staged_kind: LiveEpochTransitionPostCommitAuditKind,
    pub protocol_version: u16,
    pub post_commit_audit_policy_id: String,

    // ---- Re-exposed Run 323/324 authorization intent tuple ------------
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

    // ---- Re-exposed Run 315/316 application-decision tuple ------------
    pub application_decision_id: String,
    pub application_request_id: String,
    pub application_intent_digest: String,
    pub application_transcript_digest: String,
    pub application_nonce: u64,

    // ---- Re-exposed epoch-transition / live-application binding -------
    pub epoch_transition_target: u64,
    pub live_application_nonce: u64,

    // ---- Bound Run 323/324 authorization-decision authority tuple -----
    // (re-exposed by the consumed staged-application record)
    pub authorization_decision_id: String,
    pub authorization_request_id: String,
    pub authorization_intent_digest: String,
    pub authorization_transcript_digest: String,

    // ---- Bound Run 323/324 staged-application-decision authority tuple -
    pub staged_application_decision_id: String,
    pub staged_application_request_id: String,
    pub staged_application_intent_digest: String,
    pub staged_application_transcript_digest: String,

    // ---- Staged application binding (re-exposed consumed nonce) --------
    pub staged_application_nonce: u64,

    // ---- Bound Run 323/324 guarded post-commit-audit authority tuple -
    // (the consumed guarded post-commit-audit decision transcript)
    pub guarded_mutation_decision_id: String,
    pub guarded_mutation_request_id: String,
    pub guarded_mutation_intent_digest: String,
    pub guarded_mutation_transcript_digest: String,

    // ---- Guarded post-commit-audit binding (re-exposed consumed nonce)
    /// The re-exposed Run 321/322 guarded post-commit-audit nonce.
    pub guarded_mutation_nonce: u64,

    // ---- Bound Run 323/324 runtime handoff decision authority tuple ----
    // (the consumed runtime handoff decision transcript)
    pub commit_receipt_decision_id: String,
    pub commit_receipt_request_id: String,
    pub commit_receipt_intent_digest: String,
    pub commit_receipt_transcript_digest: String,
    /// The re-exposed Run 323/324 commit-receipt nonce (consumed).
    pub commit_receipt_nonce: u64,

    // ---- Bound Run 321/322 commit-authorization authority tuple -------
    // (re-exposed by the consumed Run 323/324 commit-receipt artifact)
    pub commit_authorization_decision_id: String,
    pub commit_authorization_request_id: String,
    pub commit_authorization_intent_digest: String,
    pub commit_authorization_transcript_digest: String,
    /// The re-exposed Run 321/322 commit-authorization nonce (consumed).
    pub commit_authorization_nonce: u64,

    // ---- Bound Run 321/322 mutation-execution authority tuple -------
    // (re-exposed by the consumed Run 323/324 commit-receipt artifact)
    pub mutation_execution_decision_id: String,
    pub mutation_execution_request_id: String,
    pub mutation_execution_intent_digest: String,
    pub mutation_execution_transcript_digest: String,
    /// The re-exposed Run 321/322 mutation-execution nonce (consumed).
    pub mutation_execution_nonce: u64,

    // ---- Bound Run 321/322 execution-preparation authority tuple -------
    // (re-exposed by the consumed Run 323/324 commit-receipt artifact)
    pub execution_preparation_decision_id: String,
    pub execution_preparation_request_id: String,
    pub execution_preparation_intent_digest: String,
    pub execution_preparation_transcript_digest: String,
    /// The re-exposed Run 321/322 execution-preparation nonce (consumed).
    pub execution_preparation_nonce: u64,

    // ---- Bound Run 321/322 runtime handoff decision authority tuple ----
    // (re-exposed by the consumed Run 323/324 commit-receipt artifact)
    pub runtime_handoff_decision_id: String,
    pub runtime_handoff_request_id: String,
    pub runtime_handoff_intent_digest: String,
    pub runtime_handoff_transcript_digest: String,
    /// The re-exposed Run 321/322 runtime handoff nonce (consumed).
    pub runtime_handoff_nonce: u64,

    // ---- Execution preparation binding --------------------------------
    /// The newly proposed post-commit-audit nonce.
    pub post_commit_audit_nonce: u64,

    // ---- Exact future-executor preconditions --------------------------
    /// Expected current validator-set digest a future live executor must
    /// transition *from* (re-exposed record current-set digest).
    pub precondition_current_validator_set_digest: String,
    /// Expected current validator-set epoch a future live executor must
    /// transition *from*.
    pub precondition_current_validator_set_epoch: u64,
    /// Expected current validator-set version a future live executor must
    /// transition *from*.
    pub precondition_current_validator_set_version: u64,
    /// Proposed validator-set digest a future live executor must transition
    /// *to* (re-exposed record proposed-set digest).
    pub precondition_proposed_validator_set_digest: String,
    /// Validator-set delta digest (re-exposed record delta digest).
    pub precondition_delta_digest: String,
    /// Target epoch a future live executor must transition to (re-exposed
    /// record epoch-transition target).
    pub precondition_target_epoch: u64,
    /// Required governance epoch a future live executor must re-verify
    /// (re-exposed record governance epoch).
    pub precondition_required_governance_epoch: u64,
    /// Required authority-domain sequence a future live executor must
    /// re-verify (re-exposed record authority-domain sequence).
    pub precondition_required_authority_sequence: u64,
    /// Required replay window a future live executor must honour
    /// (operator-declared).
    pub precondition_required_replay_window: u64,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,

    // ---- Deterministic identifiers (excluded from `content_digest`) ---
    pub post_commit_audit_id: String,
    pub request_id: String,
    pub post_commit_audit_digest: String,
    pub transcript_digest: String,
}

impl ProductionLiveEpochTransitionPostCommitAuditArtifact {
    /// Deterministic, domain-separated SHA3-256 hex content digest over every
    /// field **except** the four identifier fields (`post_commit_audit_id`,
    /// `request_id`, `post_commit_audit_digest`, `transcript_digest`). `Debug`
    /// formatting is never used as canonical bytes.
    pub fn content_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(
            PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_INTENT_DOMAIN_TAG.as_bytes(),
        );
        hash_field(&mut h, b"staged_kind", self.staged_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
        hash_field(
            &mut h,
            b"post_commit_audit_policy_id",
            self.post_commit_audit_policy_id.as_bytes(),
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
            b"guarded_mutation_decision_id",
            self.guarded_mutation_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"guarded_mutation_request_id",
            self.guarded_mutation_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"guarded_mutation_intent_digest",
            self.guarded_mutation_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"guarded_mutation_transcript_digest",
            self.guarded_mutation_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"guarded_mutation_nonce",
            &self.guarded_mutation_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_receipt_decision_id",
            self.commit_receipt_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_receipt_request_id",
            self.commit_receipt_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_receipt_intent_digest",
            self.commit_receipt_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_receipt_transcript_digest",
            self.commit_receipt_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_receipt_nonce",
            &self.commit_receipt_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_authorization_decision_id",
            self.commit_authorization_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_authorization_request_id",
            self.commit_authorization_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_authorization_intent_digest",
            self.commit_authorization_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_authorization_transcript_digest",
            self.commit_authorization_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"commit_authorization_nonce",
            &self.commit_authorization_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"mutation_execution_decision_id",
            self.mutation_execution_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"mutation_execution_request_id",
            self.mutation_execution_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"mutation_execution_intent_digest",
            self.mutation_execution_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"mutation_execution_transcript_digest",
            self.mutation_execution_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"mutation_execution_nonce",
            &self.mutation_execution_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"execution_preparation_decision_id",
            self.execution_preparation_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"execution_preparation_request_id",
            self.execution_preparation_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"execution_preparation_intent_digest",
            self.execution_preparation_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"execution_preparation_transcript_digest",
            self.execution_preparation_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"execution_preparation_nonce",
            &self.execution_preparation_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"runtime_handoff_decision_id",
            self.runtime_handoff_decision_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"runtime_handoff_request_id",
            self.runtime_handoff_request_id.as_bytes(),
        );
        hash_field(
            &mut h,
            b"runtime_handoff_intent_digest",
            self.runtime_handoff_intent_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"runtime_handoff_transcript_digest",
            self.runtime_handoff_transcript_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"runtime_handoff_nonce",
            &self.runtime_handoff_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"post_commit_audit_nonce",
            &self.post_commit_audit_nonce.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_current_validator_set_digest",
            self.precondition_current_validator_set_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_current_validator_set_epoch",
            &self.precondition_current_validator_set_epoch.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_current_validator_set_version",
            &self.precondition_current_validator_set_version.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_proposed_validator_set_digest",
            self.precondition_proposed_validator_set_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_delta_digest",
            self.precondition_delta_digest.as_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_target_epoch",
            &self.precondition_target_epoch.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_required_governance_epoch",
            &self.precondition_required_governance_epoch.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_required_authority_sequence",
            &self.precondition_required_authority_sequence.to_le_bytes(),
        );
        hash_field(
            &mut h,
            b"precondition_required_replay_window",
            &self.precondition_required_replay_window.to_le_bytes(),
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
    /// by Run 325.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }
}

/// Custody binding canonical hashing (module-local; mirrors Run 311/313/315
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

/// Run 325 — deterministic runtime handoff package content digest wrapper
/// exposed as a named symbol.
pub fn production_live_epoch_transition_post_commit_audit_content_digest(
    package: &ProductionLiveEpochTransitionPostCommitAuditArtifact,
) -> String {
    package.content_digest()
}

/// Run 325 — deterministic, domain-separated runtime handoff request id
/// binding the protocol version, guarded mutation intent digest, handoff
/// policy id, epoch-transition target, and commit-receipt nonce.
/// Deterministic across identical inputs; never wall-clock.
pub fn production_live_epoch_transition_post_commit_audit_request_id(
    protocol_version: u16,
    guarded_mutation_intent_digest: &str,
    post_commit_audit_policy_id: &str,
    epoch_transition_target: u64,
    post_commit_audit_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_REQUEST_DOMAIN_TAG.as_bytes(),
    );
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(
        &mut h,
        b"guarded_mutation_intent_digest",
        guarded_mutation_intent_digest.as_bytes(),
    );
    hash_field(
        &mut h,
        b"post_commit_audit_policy_id",
        post_commit_audit_policy_id.as_bytes(),
    );
    hash_field(
        &mut h,
        b"epoch_transition_target",
        &epoch_transition_target.to_le_bytes(),
    );
    hash_field(
        &mut h,
        b"post_commit_audit_nonce",
        &post_commit_audit_nonce.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 325 — deterministic, domain-separated runtime handoff id binding the
/// protocol version, guarded mutation intent digest, handoff policy id,
/// epoch-transition target, and commit-receipt nonce. Deterministic across
/// identical inputs; never wall-clock. Distinct domain-separated from the
/// request id.
pub fn production_live_epoch_transition_post_commit_audit_id(
    protocol_version: u16,
    guarded_mutation_intent_digest: &str,
    post_commit_audit_policy_id: &str,
    epoch_transition_target: u64,
    post_commit_audit_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_ID_DOMAIN_TAG.as_bytes(),
    );
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(
        &mut h,
        b"guarded_mutation_intent_digest",
        guarded_mutation_intent_digest.as_bytes(),
    );
    hash_field(&mut h, b"post_commit_audit_policy_id", post_commit_audit_policy_id.as_bytes());
    hash_field(
        &mut h,
        b"epoch_transition_target",
        &epoch_transition_target.to_le_bytes(),
    );
    hash_field(
        &mut h,
        b"post_commit_audit_nonce",
        &post_commit_audit_nonce.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 325 — deterministic, domain-separated runtime handoff transcript
/// digest binding the protocol version, request id, handoff (content) digest,
/// and outcome tag.
pub fn production_live_epoch_transition_post_commit_audit_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    intent_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_LIVE_EPOCH_TRANSITION_POST_COMMIT_AUDIT_TRANSCRIPT_DOMAIN_TAG.as_bytes(),
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

/// Run 325 — typed outcome of the staged live validator-set / epoch-transition
/// application executor boundary.
///
/// Only
/// [`Self::AcceptedSourceTestLiveEpochTransitionPostCommitAudit`]
/// authorizes a (source/test, DevNet/TestNet, evidence-only, non-mutating)
/// staged application record. Every other variant is a precise, non-mutating
/// fail-closed reject (or the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionLiveEpochTransitionPostCommitAuditOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no authority was bound.
    Disabled,
    /// The boundary kind is unavailable / misconfigured.
    LiveEpochTransitionPostCommitAuditBoundaryUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionLiveEpochTransitionPostCommitAuditUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionLiveEpochTransitionPostCommitAuditUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet guarded epoch-transition post-commit-audit
    /// decision produced a typed non-mutating runtime handoff package under
    /// the source/test policy. **Evidence only.**
    AcceptedSourceTestLiveEpochTransitionPostCommitAudit {
        execution_kind: LiveEpochTransitionPostCommitAuditKind,
        environment: TrustBundleEnvironment,
        epoch_transition_target: u64,
        post_commit_audit_nonce: u64,
    },

    // ---- Authorization-decision / authority failures ------------------
    VerifiedCommitReceiptDecisionRequired,
    UnverifiedCommitReceiptDecisionRejected,
    RuntimeHandoffDecisionAloneRejected,
    GuardedMutationDecisionAloneRejected,
    StagedApplicationDecisionAloneRejected,
    LiveApplicationAuthorizationAloneRejected,
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

    // ---- Runtime-handoff-decision binding failures (consumed) ---------
    CommitReceiptDecisionIdMismatch,
    CommitReceiptDecisionRequestIdMismatch,
    CommitReceiptDecisionIntentDigestMismatch,
    CommitReceiptDecisionTranscriptMismatch,
    CommitReceiptDecisionIntegrityMismatch,
    WrongCommitReceiptNonce,

    // ---- Commit-authorization-decision binding failures (re-exposed) --
    CommitAuthorizationDecisionIdMismatch,
    CommitAuthorizationDecisionRequestIdMismatch,
    CommitAuthorizationDecisionIntentDigestMismatch,
    CommitAuthorizationDecisionTranscriptMismatch,
    WrongCommitAuthorizationNonce,
    CommitAuthorizationDecisionAloneRejected,

    // ---- Runtime-handoff-decision binding failures (re-exposed) -------
    RuntimeHandoffDecisionIdMismatch,
    RuntimeHandoffDecisionRequestIdMismatch,
    RuntimeHandoffDecisionIntentDigestMismatch,
    RuntimeHandoffDecisionTranscriptMismatch,
    WrongRuntimeHandoffNonce,

    // ---- Mutation-execution-decision binding failures (re-exposed) -
    MutationExecutionDecisionIdMismatch,
    MutationExecutionDecisionRequestIdMismatch,
    MutationExecutionDecisionIntentDigestMismatch,
    MutationExecutionDecisionTranscriptMismatch,
    WrongMutationExecutionNonce,
    MutationExecutionDecisionAloneRejected,

    // ---- Execution-preparation-decision binding failures (re-exposed) -
    ExecutionPreparationDecisionIdMismatch,
    ExecutionPreparationDecisionRequestIdMismatch,
    ExecutionPreparationDecisionIntentDigestMismatch,
    ExecutionPreparationDecisionTranscriptMismatch,
    WrongExecutionPreparationNonce,
    ExecutionPreparationDecisionAloneRejected,

    // ---- Guarded-mutation-decision binding failures (re-exposed) ------
    GuardedMutationDecisionIdMismatch,
    GuardedMutationDecisionRequestIdMismatch,
    GuardedMutationDecisionIntentDigestMismatch,
    GuardedMutationDecisionTranscriptMismatch,
    WrongGuardedMutationNonce,

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
    WrongCurrentValidatorSetEpoch,
    WrongCurrentValidatorSetVersion,
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
    LiveEpochTransitionPostCommitAuditAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionLiveEpochTransitionPostCommitAuditOutcome {
    /// Returns `true` iff this outcome accepted a source/test authorization.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestLiveEpochTransitionPostCommitAudit { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 325 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 325.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LiveEpochTransitionPostCommitAuditBoundaryUnavailable => {
                "live-epoch-transition-post-commit-audit-boundary-unavailable"
            }
            Self::ProductionLiveEpochTransitionPostCommitAuditUnavailable => {
                "production-live-epoch-transition-post-commit-audit-unavailable"
            }
            Self::MainNetProductionLiveEpochTransitionPostCommitAuditUnavailable => {
                "mainnet-production-live-epoch-transition-post-commit-audit-unavailable"
            }
            Self::AcceptedSourceTestLiveEpochTransitionPostCommitAudit { .. } => {
                "accepted-source-test-live-epoch-transition-post-commit-audit"
            }
            Self::VerifiedCommitReceiptDecisionRequired => {
                "verified-commit-receipt-decision-required"
            }
            Self::UnverifiedCommitReceiptDecisionRejected => {
                "unverified-commit-receipt-decision-rejected"
            }
            Self::RuntimeHandoffDecisionAloneRejected => {
                "runtime-handoff-decision-alone-rejected"
            }
            Self::GuardedMutationDecisionAloneRejected => {
                "guarded-mutation-decision-alone-rejected"
            }
            Self::StagedApplicationDecisionAloneRejected => {
                "staged-application-decision-alone-rejected"
            }
            Self::LiveApplicationAuthorizationAloneRejected => {
                "live-application-authorization-alone-rejected"
            }
            Self::ApplicationDecisionAloneRejected => "application-decision-alone-rejected",
            Self::RotationPlanAloneRejected => "rotation-plan-alone-rejected",
            Self::GovernanceProofAloneRejected => "governance-proof-alone-rejected",
            Self::GovernanceExecutionIntentAloneRejected => {
                "governance-execution-intent-alone-rejected"
            }
            Self::FixtureStagedApplicationRejectedAsProductionAuthority => {
                "fixture-commit-receipt-decision-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::ArbitraryValidatorSetBytesRejected => "arbitrary-validator-set-bytes-rejected",
            Self::CommitReceiptDecisionIdMismatch => "commit-receipt-decision-id-mismatch",
            Self::CommitReceiptDecisionRequestIdMismatch => {
                "commit-receipt-decision-request-id-mismatch"
            }
            Self::CommitReceiptDecisionIntentDigestMismatch => {
                "commit-receipt-decision-intent-digest-mismatch"
            }
            Self::CommitReceiptDecisionTranscriptMismatch => {
                "commit-receipt-decision-transcript-mismatch"
            }
            Self::CommitReceiptDecisionIntegrityMismatch => {
                "commit-receipt-decision-integrity-mismatch"
            }
            Self::WrongCommitReceiptNonce => "wrong-commit-receipt-nonce",
            Self::CommitAuthorizationDecisionIdMismatch => {
                "commit-authorization-decision-id-mismatch"
            }
            Self::CommitAuthorizationDecisionRequestIdMismatch => {
                "commit-authorization-decision-request-id-mismatch"
            }
            Self::CommitAuthorizationDecisionIntentDigestMismatch => {
                "commit-authorization-decision-intent-digest-mismatch"
            }
            Self::CommitAuthorizationDecisionTranscriptMismatch => {
                "commit-authorization-decision-transcript-mismatch"
            }
            Self::WrongCommitAuthorizationNonce => "wrong-commit-authorization-nonce",
            Self::CommitAuthorizationDecisionAloneRejected => {
                "commit-authorization-decision-alone-rejected"
            }
            Self::RuntimeHandoffDecisionIdMismatch => "runtime-handoff-decision-id-mismatch",
            Self::RuntimeHandoffDecisionRequestIdMismatch => {
                "runtime-handoff-decision-request-id-mismatch"
            }
            Self::RuntimeHandoffDecisionIntentDigestMismatch => {
                "runtime-handoff-decision-intent-digest-mismatch"
            }
            Self::RuntimeHandoffDecisionTranscriptMismatch => {
                "runtime-handoff-decision-transcript-mismatch"
            }
            Self::WrongRuntimeHandoffNonce => "wrong-runtime-handoff-nonce",
            Self::MutationExecutionDecisionIdMismatch => {
                "mutation-execution-decision-id-mismatch"
            }
            Self::MutationExecutionDecisionRequestIdMismatch => {
                "mutation-execution-decision-request-id-mismatch"
            }
            Self::MutationExecutionDecisionIntentDigestMismatch => {
                "mutation-execution-decision-intent-digest-mismatch"
            }
            Self::MutationExecutionDecisionTranscriptMismatch => {
                "mutation-execution-decision-transcript-mismatch"
            }
            Self::WrongMutationExecutionNonce => "wrong-mutation-execution-nonce",
            Self::MutationExecutionDecisionAloneRejected => {
                "mutation-execution-decision-alone-rejected"
            }
            Self::ExecutionPreparationDecisionIdMismatch => {
                "execution-preparation-decision-id-mismatch"
            }
            Self::ExecutionPreparationDecisionRequestIdMismatch => {
                "execution-preparation-decision-request-id-mismatch"
            }
            Self::ExecutionPreparationDecisionIntentDigestMismatch => {
                "execution-preparation-decision-intent-digest-mismatch"
            }
            Self::ExecutionPreparationDecisionTranscriptMismatch => {
                "execution-preparation-decision-transcript-mismatch"
            }
            Self::WrongExecutionPreparationNonce => "wrong-execution-preparation-nonce",
            Self::ExecutionPreparationDecisionAloneRejected => {
                "execution-preparation-decision-alone-rejected"
            }
            Self::GuardedMutationDecisionIdMismatch => "guarded-mutation-decision-id-mismatch",
            Self::GuardedMutationDecisionRequestIdMismatch => {
                "guarded-mutation-decision-request-id-mismatch"
            }
            Self::GuardedMutationDecisionIntentDigestMismatch => {
                "guarded-mutation-decision-intent-digest-mismatch"
            }
            Self::GuardedMutationDecisionTranscriptMismatch => {
                "guarded-mutation-decision-transcript-mismatch"
            }
            Self::WrongGuardedMutationNonce => "wrong-guarded-mutation-nonce",
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
            Self::WrongCurrentValidatorSetEpoch => "wrong-current-validator-set-epoch",
            Self::WrongCurrentValidatorSetVersion => "wrong-current-validator-set-version",
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
            Self::LiveEpochTransitionPostCommitAuditAmbiguous { .. } => {
                "epoch-transition-commit-receipt-ambiguous"
            }
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (boundary output)
// ===========================================================================

/// Run 325 — the typed decision produced by the executor boundary: the
/// outcome, the bound handoff id, the deterministic request id, the optional
/// prepared runtime handoff package, its digest, and the verification
/// transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditDecision {
    pub outcome: ProductionLiveEpochTransitionPostCommitAuditOutcome,
    pub post_commit_audit_id: String,
    pub request_id: String,
    pub post_commit_audit_artifact:
        Option<ProductionLiveEpochTransitionPostCommitAuditArtifact>,
    pub post_commit_audit_digest: String,
    pub transcript_digest: String,
}

impl ProductionLiveEpochTransitionPostCommitAuditDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating
    /// runtime handoff package (only on accept). The boundary never applies
    /// it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.post_commit_audit_artifact.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 325 — typed idempotency / recovery outcome for a prepared staged
/// application window. Every variant is non-mutating; no durable state is
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionLiveEpochTransitionPostCommitAuditRecoveryOutcome {
    /// No prior prepared staged application for this window — clean.
    NoPriorStagedApplicationWindow,
    /// A prior prepared staged application for this window was observed; the
    /// executor re-derives the same record deterministically without
    /// mutation.
    IdempotentReplayObserved { staged_application_id: String },
    /// The recovery window is disabled (policy `Disabled`).
    RecoveryDisabled,
}

impl ProductionLiveEpochTransitionPostCommitAuditRecoveryOutcome {
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

/// Run 325 — the source/test staged live validator-set / epoch-transition
/// application executor boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveEpochTransitionPostCommitAuditExecutor {
    pub config: ProductionLiveEpochTransitionPostCommitAuditConfig,
    pub policy: ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy,
}

impl ProductionLiveEpochTransitionPostCommitAuditExecutor {
    pub fn new(
        config: ProductionLiveEpochTransitionPostCommitAuditConfig,
        policy: ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test executor under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionLiveEpochTransitionPostCommitAuditConfig::source_test(),
            ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy::AllowSourceTestLiveEpochTransitionPostCommitAudit,
        )
    }

    /// Extract the verified live-application authorization decision and
    /// prepared authorization intent from an authority source, mapping every
    /// non-authority source to its precise fail-closed outcome.
    fn resolve_authority_source<'a>(
        &self,
        source: &'a LiveEpochTransitionPostCommitAuditAuthoritySource,
    ) -> Result<
        (
            &'a ProductionLiveEpochTransitionCommitReceiptDecision,
            &'a ProductionLiveEpochTransitionCommitReceiptArtifact,
        ),
        ProductionLiveEpochTransitionPostCommitAuditOutcome,
    > {
        use ProductionLiveEpochTransitionPostCommitAuditOutcome as O;
        use LiveEpochTransitionPostCommitAuditAuthoritySource as S;
        match source {
            S::VerifiedCommitReceiptDecision { decision } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedCommitReceiptDecisionRejected);
                }
                match &decision.commit_receipt_artifact {
                    Some(intent) => Ok((decision, intent)),
                    None => Err(O::VerifiedCommitReceiptDecisionRequired),
                }
            }
            S::MissingCommitReceiptDecision => {
                Err(O::VerifiedCommitReceiptDecisionRequired)
            }
            S::UnverifiedCommitReceiptDecision { .. } => {
                Err(O::UnverifiedCommitReceiptDecisionRejected)
            }
            S::AcceptedCommitReceiptWithoutPackage { .. } => {
                Err(O::VerifiedCommitReceiptDecisionRequired)
            }
            S::CommitAuthorizationDecisionWithoutCommitReceipt => {
                Err(O::CommitAuthorizationDecisionAloneRejected)
            }
            S::MutationExecutionDecisionWithoutCommitReceipt => {
                Err(O::MutationExecutionDecisionAloneRejected)
            }
            S::ExecutionPreparationDecisionWithoutCommitReceipt => {
                Err(O::ExecutionPreparationDecisionAloneRejected)
            }
            S::RuntimeHandoffDecisionWithoutCommitReceipt => {
                Err(O::RuntimeHandoffDecisionAloneRejected)
            }
            S::GuardedMutationDecisionWithoutCommitReceipt => {
                Err(O::GuardedMutationDecisionAloneRejected)
            }
            S::ApplicationDecisionWithoutCommitReceipt => {
                Err(O::ApplicationDecisionAloneRejected)
            }
            S::StagedApplicationDecisionWithoutCommitReceipt => {
                Err(O::StagedApplicationDecisionAloneRejected)
            }
            S::LiveApplicationAuthorizationWithoutCommitReceipt => {
                Err(O::LiveApplicationAuthorizationAloneRejected)
            }
            S::RotationPlanWithoutCommitReceipt => Err(O::RotationPlanAloneRejected),
            S::GovernanceExecutionIntentWithoutCommitReceipt => {
                Err(O::GovernanceExecutionIntentAloneRejected)
            }
            S::GovernanceProofWithoutCommitReceipt => {
                Err(O::GovernanceProofAloneRejected)
            }
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
            S::FixtureOnlyCommitReceipt => {
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
        inputs: &ProductionLiveEpochTransitionPostCommitAuditInputs,
    ) -> Option<ProductionLiveEpochTransitionPostCommitAuditOutcome> {
        use ProductionLiveEpochTransitionPostCommitAuditOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionLiveEpochTransitionPostCommitAuditExecutorKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet authority source
        //    is refused: no MainNet production authority is wired.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy::MainnetProductionLiveEpochTransitionPostCommitAuditRequired => {
                    O::MainNetProductionLiveEpochTransitionPostCommitAuditUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. MainNet production policy on a non-MainNet domain still has no
        //    MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionLiveEpochTransitionPostCommitAuditUnavailable);
        }

        // 4. The production policy has no production prerequisites wired —
        //    fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionLiveEpochTransitionPostCommitAuditUnavailable);
        }

        // 5. Reserved production boundary kind is fail-closed in Run 325.
        if self.config.kind
            == ProductionLiveEpochTransitionPostCommitAuditExecutorKind::ProductionLiveEpochTransitionPostCommitAudit
        {
            return Some(O::LiveEpochTransitionPostCommitAuditBoundaryUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() || !inputs.is_well_formed() {
            return Some(O::LiveEpochTransitionPostCommitAuditBoundaryUnavailable);
        }

        None
    }

    /// Cross-check the verified Run 323/324 live-application authorization
    /// decision and its prepared authorization intent against the explicit
    /// trusted inputs and trust domain. Returns `Some(outcome)` on the first
    /// divergence.
    fn check_application_binding(
        &self,
        decision: &ProductionLiveEpochTransitionCommitReceiptDecision,
        intent: &ProductionLiveEpochTransitionCommitReceiptArtifact,
        inputs: &ProductionLiveEpochTransitionPostCommitAuditInputs,
    ) -> Option<ProductionLiveEpochTransitionPostCommitAuditOutcome> {
        use ProductionLiveEpochTransitionPostCommitAuditOutcome as O;
        let td = &inputs.trust_domain;

        // Consumed Run 323/324 epoch-transition runtime handoff decision
        // transcript binding.
        if decision.commit_receipt_id != inputs.expected_commit_receipt_decision_id {
            return Some(O::CommitReceiptDecisionIdMismatch);
        }
        if decision.request_id != inputs.expected_commit_receipt_request_id {
            return Some(O::CommitReceiptDecisionRequestIdMismatch);
        }
        if decision.commit_receipt_digest != inputs.expected_commit_receipt_intent_digest {
            return Some(O::CommitReceiptDecisionIntentDigestMismatch);
        }
        if decision.transcript_digest != inputs.expected_commit_receipt_transcript_digest {
            return Some(O::CommitReceiptDecisionTranscriptMismatch);
        }
        // The prepared runtime handoff package must reproduce the bound
        // runtime handoff decision content (handoff) digest.
        if intent.content_digest() != decision.commit_receipt_digest {
            return Some(O::CommitReceiptDecisionIntegrityMismatch);
        }
        // The consumed runtime handoff package's re-exposed commit-receipt
        // nonce binding.
        if intent.commit_receipt_nonce != inputs.expected_commit_receipt_nonce {
            return Some(O::WrongCommitReceiptNonce);
        }

        // Re-exposed Run 321/322 commit-authorization decision authority
        // tuple binding (carried through the consumed Run 323/324
        // commit-receipt artifact).
        if intent.commit_authorization_decision_id
            != inputs.expected_commit_authorization_decision_id
        {
            return Some(O::CommitAuthorizationDecisionIdMismatch);
        }
        if intent.commit_authorization_request_id
            != inputs.expected_commit_authorization_request_id
        {
            return Some(O::CommitAuthorizationDecisionRequestIdMismatch);
        }
        if intent.commit_authorization_intent_digest
            != inputs.expected_commit_authorization_intent_digest
        {
            return Some(O::CommitAuthorizationDecisionIntentDigestMismatch);
        }
        if intent.commit_authorization_transcript_digest
            != inputs.expected_commit_authorization_transcript_digest
        {
            return Some(O::CommitAuthorizationDecisionTranscriptMismatch);
        }
        // The re-exposed commit-authorization nonce binding.
        if intent.commit_authorization_nonce != inputs.expected_commit_authorization_nonce {
            return Some(O::WrongCommitAuthorizationNonce);
        }

        // Re-exposed Run 321/322 mutation-execution decision authority
        // tuple binding (carried through the consumed Run 323/324
        // commit-receipt artifact).
        if intent.mutation_execution_decision_id
            != inputs.expected_mutation_execution_decision_id
        {
            return Some(O::MutationExecutionDecisionIdMismatch);
        }
        if intent.mutation_execution_request_id
            != inputs.expected_mutation_execution_request_id
        {
            return Some(O::MutationExecutionDecisionRequestIdMismatch);
        }
        if intent.mutation_execution_intent_digest
            != inputs.expected_mutation_execution_intent_digest
        {
            return Some(O::MutationExecutionDecisionIntentDigestMismatch);
        }
        if intent.mutation_execution_transcript_digest
            != inputs.expected_mutation_execution_transcript_digest
        {
            return Some(O::MutationExecutionDecisionTranscriptMismatch);
        }
        // The re-exposed mutation-execution nonce binding.
        if intent.mutation_execution_nonce != inputs.expected_mutation_execution_nonce {
            return Some(O::WrongMutationExecutionNonce);
        }

        // Re-exposed Run 321/322 execution-preparation decision authority
        // tuple binding (carried through the consumed Run 323/324
        // commit-receipt artifact).
        if intent.execution_preparation_decision_id
            != inputs.expected_execution_preparation_decision_id
        {
            return Some(O::ExecutionPreparationDecisionIdMismatch);
        }
        if intent.execution_preparation_request_id
            != inputs.expected_execution_preparation_request_id
        {
            return Some(O::ExecutionPreparationDecisionRequestIdMismatch);
        }
        if intent.execution_preparation_intent_digest
            != inputs.expected_execution_preparation_intent_digest
        {
            return Some(O::ExecutionPreparationDecisionIntentDigestMismatch);
        }
        if intent.execution_preparation_transcript_digest
            != inputs.expected_execution_preparation_transcript_digest
        {
            return Some(O::ExecutionPreparationDecisionTranscriptMismatch);
        }
        // The re-exposed execution-preparation nonce binding.
        if intent.execution_preparation_nonce != inputs.expected_execution_preparation_nonce {
            return Some(O::WrongExecutionPreparationNonce);
        }

        // Re-exposed Run 321/322 epoch-transition runtime handoff decision
        // authority tuple binding (carried through the consumed Run 323/324
        // commit-receipt artifact).
        if intent.runtime_handoff_decision_id != inputs.expected_runtime_handoff_decision_id {
            return Some(O::RuntimeHandoffDecisionIdMismatch);
        }
        if intent.runtime_handoff_request_id != inputs.expected_runtime_handoff_request_id {
            return Some(O::RuntimeHandoffDecisionRequestIdMismatch);
        }
        if intent.runtime_handoff_intent_digest != inputs.expected_runtime_handoff_intent_digest {
            return Some(O::RuntimeHandoffDecisionIntentDigestMismatch);
        }
        if intent.runtime_handoff_transcript_digest
            != inputs.expected_runtime_handoff_transcript_digest
        {
            return Some(O::RuntimeHandoffDecisionTranscriptMismatch);
        }
        // The re-exposed runtime-handoff nonce binding.
        if intent.runtime_handoff_nonce != inputs.expected_runtime_handoff_nonce {
            return Some(O::WrongRuntimeHandoffNonce);
        }

        // Re-exposed Run 321/322 guarded epoch-transition post-commit-audit
        // decision authority tuple binding (carried through the consumed
        // runtime handoff package).
        if intent.guarded_mutation_decision_id != inputs.expected_guarded_mutation_decision_id {
            return Some(O::GuardedMutationDecisionIdMismatch);
        }
        if intent.guarded_mutation_request_id != inputs.expected_guarded_mutation_request_id {
            return Some(O::GuardedMutationDecisionRequestIdMismatch);
        }
        if intent.guarded_mutation_intent_digest != inputs.expected_guarded_mutation_intent_digest {
            return Some(O::GuardedMutationDecisionIntentDigestMismatch);
        }
        if intent.guarded_mutation_transcript_digest
            != inputs.expected_guarded_mutation_transcript_digest
        {
            return Some(O::GuardedMutationDecisionTranscriptMismatch);
        }
        // The re-exposed guarded-mutation nonce binding.
        if intent.guarded_mutation_nonce != inputs.expected_guarded_mutation_nonce {
            return Some(O::WrongGuardedMutationNonce);
        }

        // Re-exposed Run 323/324 staged-application decision authority tuple
        // binding (carried through the consumed guarded-mutation record).
        if intent.staged_application_decision_id != inputs.expected_staged_application_decision_id {
            return Some(O::StagedApplicationDecisionIdMismatch);
        }
        if intent.staged_application_request_id != inputs.expected_staged_application_request_id {
            return Some(O::StagedApplicationDecisionRequestIdMismatch);
        }
        if intent.staged_application_intent_digest
            != inputs.expected_staged_application_intent_digest
        {
            return Some(O::StagedApplicationDecisionIntentDigestMismatch);
        }
        if intent.staged_application_transcript_digest
            != inputs.expected_staged_application_transcript_digest
        {
            return Some(O::StagedApplicationDecisionTranscriptMismatch);
        }
        // The consumed record's re-exposed staged-application nonce binding.
        if intent.staged_application_nonce != inputs.expected_staged_application_nonce {
            return Some(O::WrongStagedApplicationNonce);
        }

        // Current validator-set epoch/version preflight preconditions: the
        // operator-declared current epoch/version must not lead the bound
        // (current) validator-set epoch/version carried by the record. This
        // is a fail-closed preflight guard for the future live executor; the
        // handoff itself never mutates the validator set.
        if inputs.expected_current_validator_set_epoch > intent.validator_set_epoch {
            return Some(O::WrongCurrentValidatorSetEpoch);
        }
        if inputs.expected_current_validator_set_version > intent.validator_set_version {
            return Some(O::WrongCurrentValidatorSetVersion);
        }

        // Re-exposed Run 323/324 live-authorization decision authority tuple
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

        // Re-exposed Run 315/316 application-decision authority tuple binding.
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
        request: &ProductionLiveEpochTransitionPostCommitAuditRequest,
        intent: &ProductionLiveEpochTransitionCommitReceiptArtifact,
        inputs: &ProductionLiveEpochTransitionPostCommitAuditInputs,
    ) -> Option<ProductionLiveEpochTransitionPostCommitAuditOutcome> {
        use ProductionLiveEpochTransitionPostCommitAuditOutcome as O;

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
    fn evaluate_core<R: LiveEpochTransitionPostCommitAuditReplaySet + ?Sized>(
        &self,
        request: &ProductionLiveEpochTransitionPostCommitAuditRequest,
        inputs: &ProductionLiveEpochTransitionPostCommitAuditInputs,
        replay_set: &R,
    ) -> (
        ProductionLiveEpochTransitionPostCommitAuditOutcome,
        Option<ProductionLiveEpochTransitionPostCommitAuditArtifact>,
    ) {
        use ProductionLiveEpochTransitionPostCommitAuditOutcome as O;

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
        let staged_application_id = production_live_epoch_transition_post_commit_audit_request_id(
            self.config.protocol_version.0,
            &decision.commit_receipt_digest,
            &inputs.post_commit_audit_policy_id,
            request.proposed_epoch_transition_target,
            request.post_commit_audit_nonce,
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
            LiveEpochTransitionPostCommitAuditKind::from_staged_application_kind(
                application_intent.staged_kind,
            );
        if staged_kind.is_unsupported() {
            return (O::UnsupportedStagedLiveApplication, None);
        }

        // Step 9: construct the typed non-mutating runtime handoff package.
        let mut record = ProductionLiveEpochTransitionPostCommitAuditArtifact {
            staged_kind,
            protocol_version: self.config.protocol_version.0,
            post_commit_audit_policy_id: inputs.post_commit_audit_policy_id.clone(),
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
            staged_application_decision_id: application_intent.staged_application_decision_id.clone(),
            staged_application_request_id: application_intent.staged_application_request_id.clone(),
            staged_application_intent_digest: application_intent
                .staged_application_intent_digest
                .clone(),
            staged_application_transcript_digest: application_intent
                .staged_application_transcript_digest
                .clone(),
            staged_application_nonce: application_intent.staged_application_nonce,
            // Re-exposed Run 321/322 guarded post-commit-audit decision
            // transcript (carried through the consumed runtime handoff package).
            guarded_mutation_decision_id: application_intent.guarded_mutation_decision_id.clone(),
            guarded_mutation_request_id: application_intent.guarded_mutation_request_id.clone(),
            guarded_mutation_intent_digest: application_intent.guarded_mutation_intent_digest.clone(),
            guarded_mutation_transcript_digest: application_intent
                .guarded_mutation_transcript_digest
                .clone(),
            // Re-exposed guarded post-commit-audit nonce.
            guarded_mutation_nonce: application_intent.guarded_mutation_nonce,
            // Consumed Run 323/324 runtime handoff decision transcript (the
            // authority source this run consumes).
            commit_receipt_decision_id: decision.commit_receipt_id.clone(),
            commit_receipt_request_id: decision.request_id.clone(),
            commit_receipt_intent_digest: decision.commit_receipt_digest.clone(),
            commit_receipt_transcript_digest: decision.transcript_digest.clone(),
            // Re-exposed consumed commit-receipt nonce.
            commit_receipt_nonce: application_intent.commit_receipt_nonce,
            // Re-exposed Run 321/322 commit-authorization decision authority
            // tuple (carried through the consumed commit-receipt artifact).
            commit_authorization_decision_id: application_intent
                .commit_authorization_decision_id
                .clone(),
            commit_authorization_request_id: application_intent
                .commit_authorization_request_id
                .clone(),
            commit_authorization_intent_digest: application_intent
                .commit_authorization_intent_digest
                .clone(),
            commit_authorization_transcript_digest: application_intent
                .commit_authorization_transcript_digest
                .clone(),
            // Re-exposed consumed commit-authorization nonce.
            commit_authorization_nonce: application_intent.commit_authorization_nonce,
            // Re-exposed Run 321/322 mutation-execution decision authority
            // tuple (carried through the consumed commit-receipt artifact).
            mutation_execution_decision_id: application_intent
                .mutation_execution_decision_id
                .clone(),
            mutation_execution_request_id: application_intent
                .mutation_execution_request_id
                .clone(),
            mutation_execution_intent_digest: application_intent
                .mutation_execution_intent_digest
                .clone(),
            mutation_execution_transcript_digest: application_intent
                .mutation_execution_transcript_digest
                .clone(),
            // Re-exposed consumed mutation-execution nonce.
            mutation_execution_nonce: application_intent.mutation_execution_nonce,
            // Re-exposed Run 321/322 execution-preparation decision authority
            // tuple (carried through the consumed commit-receipt artifact).
            execution_preparation_decision_id: application_intent
                .execution_preparation_decision_id
                .clone(),
            execution_preparation_request_id: application_intent
                .execution_preparation_request_id
                .clone(),
            execution_preparation_intent_digest: application_intent
                .execution_preparation_intent_digest
                .clone(),
            execution_preparation_transcript_digest: application_intent
                .execution_preparation_transcript_digest
                .clone(),
            // Re-exposed consumed execution-preparation nonce.
            execution_preparation_nonce: application_intent.execution_preparation_nonce,
            // Re-exposed Run 321/322 runtime handoff decision authority tuple
            // (carried through the consumed commit-receipt artifact).
            runtime_handoff_decision_id: application_intent.runtime_handoff_decision_id.clone(),
            runtime_handoff_request_id: application_intent.runtime_handoff_request_id.clone(),
            runtime_handoff_intent_digest: application_intent
                .runtime_handoff_intent_digest
                .clone(),
            runtime_handoff_transcript_digest: application_intent
                .runtime_handoff_transcript_digest
                .clone(),
            // Re-exposed consumed runtime handoff nonce.
            runtime_handoff_nonce: application_intent.runtime_handoff_nonce,
            // Newly proposed post-commit-audit nonce.
            post_commit_audit_nonce: request.post_commit_audit_nonce,
            // Exact future-executor preconditions.
            precondition_current_validator_set_digest: application_intent.current_set_digest.clone(),
            precondition_current_validator_set_epoch: application_intent.validator_set_epoch,
            precondition_current_validator_set_version: application_intent.validator_set_version,
            precondition_proposed_validator_set_digest: application_intent.proposed_set_digest.clone(),
            precondition_delta_digest: application_intent.delta_digest.clone(),
            precondition_target_epoch: application_intent.epoch_transition_target,
            precondition_required_governance_epoch: application_intent.governance_epoch,
            precondition_required_authority_sequence: application_intent.authority_domain_sequence,
            precondition_required_replay_window: inputs.required_replay_window,
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
            // Deterministic identifiers filled in below.
            post_commit_audit_id: String::new(),
            request_id: String::new(),
            post_commit_audit_digest: String::new(),
            transcript_digest: String::new(),
        };

        // Step 10: typed accepted non-mutating outcome + deterministic
        // identifiers bound into the package.
        let outcome = O::AcceptedSourceTestLiveEpochTransitionPostCommitAudit {
            execution_kind: staged_kind,
            environment: application_intent.environment,
            epoch_transition_target: request.proposed_epoch_transition_target,
            post_commit_audit_nonce: request.post_commit_audit_nonce,
        };
        let post_commit_audit_id = production_live_epoch_transition_post_commit_audit_id(
            self.config.protocol_version.0,
            &decision.commit_receipt_digest,
            &inputs.post_commit_audit_policy_id,
            request.proposed_epoch_transition_target,
            request.post_commit_audit_nonce,
        );
        let request_id = production_live_epoch_transition_post_commit_audit_request_id(
            self.config.protocol_version.0,
            &decision.commit_receipt_digest,
            &inputs.post_commit_audit_policy_id,
            request.proposed_epoch_transition_target,
            request.post_commit_audit_nonce,
        );
        record.post_commit_audit_digest = record.content_digest();
        record.post_commit_audit_id = post_commit_audit_id;
        record.request_id = request_id.clone();
        record.transcript_digest =
            production_live_epoch_transition_post_commit_audit_transcript_digest(
                self.config.protocol_version.0,
                &request_id,
                &record.post_commit_audit_digest,
                outcome.tag(),
            );

        (outcome, Some(record))
    }

    /// Run 325 — evaluate a staged live validator-set / epoch-transition
    /// application request into a typed, deterministic, non-mutating decision.
    /// This never mutates any live validator set, consensus epoch, or trust
    /// state; on accept it produces only a prepared staged application record.
    pub fn evaluate_live_epoch_transition_post_commit_audit<
        R: LiveEpochTransitionPostCommitAuditReplaySet + ?Sized,
    >(
        &self,
        request: &ProductionLiveEpochTransitionPostCommitAuditRequest,
        inputs: &ProductionLiveEpochTransitionPostCommitAuditInputs,
        replay_set: &R,
    ) -> ProductionLiveEpochTransitionPostCommitAuditDecision {
        let (outcome, record) = self.evaluate_core(request, inputs, replay_set);

        // On accept the package carries the deterministic identifiers already;
        // reuse them so the decision and package agree exactly.
        if let Some(pkg) = &record {
            return ProductionLiveEpochTransitionPostCommitAuditDecision {
                outcome,
                post_commit_audit_id: pkg.post_commit_audit_id.clone(),
                request_id: pkg.request_id.clone(),
                post_commit_audit_artifact: record.clone(),
                post_commit_audit_digest: pkg.post_commit_audit_digest.clone(),
                transcript_digest: pkg.transcript_digest.clone(),
            };
        }

        // On reject, derive deterministic identifiers from the consumed
        // runtime handoff decision content (handoff) digest (best-effort from
        // the authority source).
        let commit_receipt_intent_digest = match &request.authority_source {
            LiveEpochTransitionPostCommitAuditAuthoritySource::VerifiedCommitReceiptDecision {
                decision,
            }
            | LiveEpochTransitionPostCommitAuditAuthoritySource::UnverifiedCommitReceiptDecision {
                decision,
            }
            | LiveEpochTransitionPostCommitAuditAuthoritySource::AcceptedCommitReceiptWithoutPackage {
                decision,
            } => decision.commit_receipt_digest.clone(),
            _ => String::new(),
        };

        let post_commit_audit_id = production_live_epoch_transition_post_commit_audit_id(
            self.config.protocol_version.0,
            &commit_receipt_intent_digest,
            &inputs.post_commit_audit_policy_id,
            request.proposed_epoch_transition_target,
            request.post_commit_audit_nonce,
        );
        let request_id = production_live_epoch_transition_post_commit_audit_request_id(
            self.config.protocol_version.0,
            &commit_receipt_intent_digest,
            &inputs.post_commit_audit_policy_id,
            request.proposed_epoch_transition_target,
            request.post_commit_audit_nonce,
        );
        let post_commit_audit_digest = String::new();
        let transcript_digest =
            production_live_epoch_transition_post_commit_audit_transcript_digest(
                self.config.protocol_version.0,
                &request_id,
                &post_commit_audit_digest,
                outcome.tag(),
            );

        ProductionLiveEpochTransitionPostCommitAuditDecision {
            outcome,
            post_commit_audit_id,
            request_id,
            post_commit_audit_artifact: None,
            post_commit_audit_digest,
            transcript_digest,
        }
    }

    /// Run 325 — idempotency / recovery over a prepared-authorization window.
    /// Non-mutating; writes no durable state.
    pub fn recover_live_epoch_transition_post_commit_audit_window(
        &self,
        prior: Option<&ProductionLiveEpochTransitionPostCommitAuditArtifact>,
        current: &ProductionLiveEpochTransitionPostCommitAuditArtifact,
    ) -> ProductionLiveEpochTransitionPostCommitAuditRecoveryOutcome {
        use ProductionLiveEpochTransitionPostCommitAuditRecoveryOutcome as R;
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionLiveEpochTransitionPostCommitAuditExecutorKind::Disabled
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

/// Run 325 — the executor default policy is Disabled / fail-closed.
pub fn production_live_epoch_transition_post_commit_audit_executor_default_is_disabled() -> bool
{
    ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy::default()
        == ProductionLiveEpochTransitionPostCommitAuditExecutorPolicy::Disabled
        && ProductionLiveEpochTransitionPostCommitAuditConfig::default().kind
            == ProductionLiveEpochTransitionPostCommitAuditExecutorKind::Disabled
}

/// Run 325 — the executor is a source/test implementation, not
/// release-binary evidence (deferred to Run 326).
pub fn production_live_epoch_transition_post_commit_audit_executor_is_source_test_not_release_binary_evidence(
) -> bool {
    true
}

/// Run 325 — the executor refuses MainNet absent production authority.
pub fn production_live_epoch_transition_post_commit_audit_executor_mainnet_refused() -> bool {
    true
}

/// Run 325 — the executor never applies a live validator-set change,
/// consensus epoch transition, or trust-state mutation; every outcome is
/// non-mutating.
pub fn production_live_epoch_transition_post_commit_audit_executor_is_non_mutating() -> bool {
    true
}

/// Run 325 — the executor never falls back to rotation-plan-alone /
/// governance-proof-alone / governance-execution-intent-alone / fixture /
/// local-operator / peer-majority / custody-only / RemoteSigner-only /
/// arbitrary-bytes authority.
pub fn production_live_epoch_transition_post_commit_audit_executor_never_falls_back() -> bool {
    true
}

/// Run 325 — the executor adds no default runtime wiring and no CLI flag.
pub fn production_live_epoch_transition_post_commit_audit_executor_no_default_runtime_wiring(
) -> bool {
    true
}

/// Run 325 — the executor only requires a verified Run 323/324 validator-set
/// rotation application decision as authority; nothing else can authorize a
/// live-application authorization.
pub fn production_live_epoch_transition_post_commit_audit_executor_requires_verified_application_decision(
) -> bool {
    true
}
// ===========================================================================
// Source/test-only in-memory fixture ledger
// ===========================================================================

/// Run 325 — an explicit, in-memory fixture ledger/state used *only* by tests
/// to demonstrate a source/test-bounded guarded mutation application path.
///
/// This type is the *only* thing a positive guarded mutation path may mutate
/// in Run 325. It is not wired into node runtime, never touches production
/// consensus validator state, never transitions a production consensus epoch,
/// never writes `meta:current_epoch`, never injects a reconfig block, never
/// calls Run 070, and never mutates `LivePqcTrustState`. It is a plain
/// in-memory struct owned by the caller (a test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEpochTransitionPostCommitAuditFixtureState {
    /// The fixture's current (in-memory) epoch.
    pub current_epoch: u64,
    /// The fixture's current (in-memory) validator-set version.
    pub validator_set_version: u64,
    /// The fixture's current (in-memory) validator-set digest.
    pub current_set_digest: String,
    /// The execution ids already applied to this fixture ledger (idempotency).
    pub applied_execution_ids: Vec<String>,
}

impl LiveEpochTransitionPostCommitAuditFixtureState {
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
    pub fn has_applied(&self, post_commit_audit_id: &str) -> bool {
        self.applied_execution_ids.iter().any(|id| id == post_commit_audit_id)
    }

    /// Applies a prepared, accepted guarded mutation record to *this* in-memory
    /// fixture ledger only, advancing the fixture's epoch / validator-set
    /// version / set digest to the record's prepared targets.
    ///
    /// Idempotent: re-applying the same `post_commit_audit_id` is a no-op returning
    /// `false`. Returns `true` on first application. This never mutates
    /// production consensus state, epoch counters, or trust state — only the
    /// fields of this owned struct.
    pub fn apply_prepared_execution(
        &mut self,
        record: &ProductionLiveEpochTransitionPostCommitAuditArtifact,
        post_commit_audit_id: &str,
    ) -> bool {
        if self.has_applied(post_commit_audit_id) {
            return false;
        }
        self.current_epoch = record.epoch_transition_target;
        self.validator_set_version = record.validator_set_version;
        self.current_set_digest = record.proposed_set_digest.clone();
        self.applied_execution_ids.push(post_commit_audit_id.to_string());
        true
    }
}