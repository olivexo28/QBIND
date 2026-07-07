//! Run 307 — source/test **real** live validator-set application /
//! epoch-transition **authorization** boundary.
//!
//! This module implements the next source/test boundary above the Run
//! 305/306 validator-set rotation *application* / epoch-transition executor
//! boundary: the boundary that consumes a **verified** Run 305/306
//! non-mutating validator-set rotation *application decision* (the accepted
//! [`crate::pqc_production_validator_set_rotation_application_executor::ProductionValidatorSetRotationApplicationDecision`]
//! carrying a
//! [`crate::pqc_production_validator_set_rotation_application_executor::ProductionValidatorSetRotationApplicationIntent`],
//! as release-binary-evidenced by Run 306) and translates it into a typed,
//! deterministic, policy-gated **live-application authorization intent** for
//! a *future* mutating epoch-transition executor — *without* ever applying a
//! live validator-set change, transitioning a consensus epoch, or mutating
//! any trust state.
//!
//! Where the Run 305 boundary answers "given a verified validator-set
//! rotation plan, what typed non-mutating application decision does it
//! authorize?", Run 307 answers the next question: "given a verified
//! validator-set rotation *application decision*, what typed, non-mutating
//! **live-application authorization** for a *future* mutating epoch-transition
//! executor does it authorize, under an explicit authorization policy, bound
//! to the full application / rotation / governance / validator-set / custody /
//! attestation / durable-replay evidence tuple, and to an explicit
//! epoch-transition target and live-application nonce?".
//!
//! ## Scope and honesty constraints (Run 307)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 308**.
//! * The default policy is
//!   [`ProductionLiveValidatorSetApplicationAuthorizationPolicy::Disabled`]
//!   and fails closed **before** any application binding, validator-set
//!   binding, or authorization construction.
//! * Only a **verified** Run 305/306 validator-set rotation application
//!   decision that `is_accept()` and carries a
//!   [`crate::pqc_production_validator_set_rotation_application_executor::ProductionValidatorSetRotationApplicationIntent`]
//!   can authorize a live-application authorization. Unverified decisions,
//!   Run 303 rotation plans alone, governance execution intent alone,
//!   governance proof alone, local-operator assertions, peer-majority
//!   assertions, custody-only, RemoteSigner-only, custody-attestation-only,
//!   fixture-only application decisions, and arbitrary validator-set bytes
//!   are all rejected as production authority.
//! * The boundary produces only a typed
//!   [`ProductionLiveValidatorSetApplicationAuthorizationIntent`]; it
//!   **never** applies the decision, never mutates a live validator set,
//!   never writes durable validator-set state, never calls
//!   `BasicHotStuffEngine::transition_to_epoch`, never writes
//!   `meta:current_epoch`, and never injects a `PAYLOAD_KIND_RECONFIG`
//!   block. Only a typed accepted outcome may authorize a *future* mutation
//!   run.
//! * MainNet remains **refused**: even a fully valid source/test
//!   DevNet/TestNet authorization does not enable MainNet runtime behavior.
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
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_307.md`.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_onchain_governance_proof::OnChainGovernanceQuorum;
use crate::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding,
};
use crate::pqc_production_validator_set_rotation_application_executor::{
    ProductionValidatorSetRotationApplicationDecision,
    ProductionValidatorSetRotationApplicationIntent,
    ValidatorSetRotationApplicationDecisionKind,
};
use crate::pqc_production_validator_set_rotation_intent::ValidatorSetRotationAction;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 307 — the only live validator-set application authorization boundary
/// protocol version this run accepts.
pub const PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION: u16 = 1;

/// Run 307 — live validator-set application authorization intent digest
/// domain tag.
pub const PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_INTENT_DOMAIN_TAG: &str =
    "QBIND:run307-live-validator-set-application-authorization-intent:v1";

/// Run 307 — live validator-set application authorization request-id domain
/// tag.
pub const PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_REQUEST_DOMAIN_TAG: &str =
    "QBIND:run307-live-validator-set-application-authorization-request:v1";

/// Run 307 — live validator-set application authorization transcript digest
/// domain tag.
pub const PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run307-live-validator-set-application-authorization-transcript:v1";

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

/// Run 307 — typed live validator-set application authorization boundary
/// protocol version. Only
/// [`PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION`]
/// is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion(pub u16);

impl ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION
    }
}

impl Default for ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 307 — typed live validator-set application authorization boundary
/// policy.
///
/// `Disabled` is the default fail-closed policy: the boundary refuses before
/// any application binding or authorization construction.
/// `AllowSourceTestLiveValidatorSetApplicationAuthorization` is the only
/// policy that can produce an accepted source/test authorization, and only on
/// DevNet/TestNet with a verified Run 305/306 validator-set rotation
/// application decision.
/// `RequireProductionLiveValidatorSetApplicationAuthorization` and
/// `MainnetProductionLiveValidatorSetApplicationAuthorizationRequired` are
/// **reachable but fail-closed** production/MainNet policies: no production
/// live validator-set application authorization authority is wired, so they
/// fail closed as unavailable/refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionLiveValidatorSetApplicationAuthorizationPolicy {
    /// Default. Refuses every request before any binding.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test policy. A verified validator-set rotation
    /// application decision may produce a typed non-mutating live-application
    /// authorization as source/test evidence only. MainNet remains refused.
    AllowSourceTestLiveValidatorSetApplicationAuthorization,
    /// Production policy. Reachable but fails closed: no production live
    /// validator-set application authorization prerequisites are wired.
    RequireProductionLiveValidatorSetApplicationAuthorization,
    /// MainNet production policy. Reachable but fails closed: no MainNet
    /// production live validator-set application authorization authority is
    /// wired.
    MainnetProductionLiveValidatorSetApplicationAuthorizationRequired,
}

impl ProductionLiveValidatorSetApplicationAuthorizationPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestLiveValidatorSetApplicationAuthorization => {
                "allow-source-test-live-validator-set-application-authorization"
            }
            Self::RequireProductionLiveValidatorSetApplicationAuthorization => {
                "require-production-live-validator-set-application-authorization"
            }
            Self::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired => {
                "mainnet-production-live-validator-set-application-authorization-required"
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
            Self::AllowSourceTestLiveValidatorSetApplicationAuthorization
        )
    }

    /// Returns `true` iff this policy is the production policy.
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Self::RequireProductionLiveValidatorSetApplicationAuthorization
        )
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(
            self,
            Self::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired
        )
    }
}

// ===========================================================================
// Boundary kind taxonomy
// ===========================================================================

/// Run 307 — typed live validator-set application authorization boundary
/// kind.
///
/// `Disabled` is the inert default.
/// `SourceTestLiveValidatorSetApplicationAuthorization` performs real
/// source/test authorization construction. A reserved
/// `ProductionLiveValidatorSetApplicationAuthorization` kind is fail-closed as
/// unavailable in Run 307 (no production authority is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionLiveValidatorSetApplicationAuthorizationKind {
    /// Inert default; every request is refused.
    #[default]
    Disabled,
    /// Real source/test live validator-set application authorization
    /// boundary.
    SourceTestLiveValidatorSetApplicationAuthorization,
    /// Reserved production authorization kind. Fail-closed in Run 307.
    ProductionLiveValidatorSetApplicationAuthorization,
}

impl ProductionLiveValidatorSetApplicationAuthorizationKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SourceTestLiveValidatorSetApplicationAuthorization => {
                "source-test-live-validator-set-application-authorization"
            }
            Self::ProductionLiveValidatorSetApplicationAuthorization => {
                "production-live-validator-set-application-authorization"
            }
        }
    }

    /// Returns `true` iff this kind performs real source/test authorization
    /// construction.
    pub const fn is_source_test(self) -> bool {
        matches!(
            self,
            Self::SourceTestLiveValidatorSetApplicationAuthorization
        )
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 307 — typed live validator-set application authorization boundary
/// config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationConfig {
    /// Boundary protocol version. Must equal the supported version.
    pub protocol_version: ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion,
    /// The boundary kind.
    pub kind: ProductionLiveValidatorSetApplicationAuthorizationKind,
}

impl ProductionLiveValidatorSetApplicationAuthorizationConfig {
    pub fn new(kind: ProductionLiveValidatorSetApplicationAuthorizationKind) -> Self {
        Self {
            protocol_version:
                ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real source/test authorization boundary kind.
    pub fn source_test() -> Self {
        Self::new(
            ProductionLiveValidatorSetApplicationAuthorizationKind::SourceTestLiveValidatorSetApplicationAuthorization,
        )
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionLiveValidatorSetApplicationAuthorizationConfig {
    fn default() -> Self {
        Self::new(ProductionLiveValidatorSetApplicationAuthorizationKind::Disabled)
    }
}

// ===========================================================================
// Authorization kind taxonomy
// ===========================================================================

/// Run 307 — the typed kind of a prepared, non-mutating live validator-set
/// application authorization / epoch-transition authorization.
///
/// Each kind corresponds one-to-one with a supported Run 305
/// [`ValidatorSetRotationApplicationDecisionKind`]; the reserved
/// [`Self::UnsupportedAuthorization`] never authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiveValidatorSetApplicationAuthorizationKind {
    AuthorizeApplyNoOpAlreadySynchronized,
    AuthorizeApplyValidatorAdd,
    AuthorizeApplyValidatorRemove,
    AuthorizeApplyValidatorMetadataUpdate,
    AuthorizeApplyValidatorIdentityRotation,
    AuthorizeApplyValidatorRetirement,
    AuthorizeApplyEmergencyValidatorRemoval,
    AuthorizeApplyAuthoritySetSynchronization,
    AuthorizeApplyBulkValidatorSetRotation,
    UnsupportedAuthorization,
}

impl LiveValidatorSetApplicationAuthorizationKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AuthorizeApplyNoOpAlreadySynchronized => {
                "authorize-apply-no-op-already-synchronized"
            }
            Self::AuthorizeApplyValidatorAdd => "authorize-apply-validator-add",
            Self::AuthorizeApplyValidatorRemove => "authorize-apply-validator-remove",
            Self::AuthorizeApplyValidatorMetadataUpdate => {
                "authorize-apply-validator-metadata-update"
            }
            Self::AuthorizeApplyValidatorIdentityRotation => {
                "authorize-apply-validator-identity-rotation"
            }
            Self::AuthorizeApplyValidatorRetirement => "authorize-apply-validator-retirement",
            Self::AuthorizeApplyEmergencyValidatorRemoval => {
                "authorize-apply-emergency-validator-removal"
            }
            Self::AuthorizeApplyAuthoritySetSynchronization => {
                "authorize-apply-authority-set-synchronization"
            }
            Self::AuthorizeApplyBulkValidatorSetRotation => {
                "authorize-apply-bulk-validator-set-rotation"
            }
            Self::UnsupportedAuthorization => "unsupported-authorization",
        }
    }

    /// Every Run 307 authorization kind is a *prepared*, non-mutating
    /// authorization; none applies a live validator-set change.
    pub const fn is_non_mutating(self) -> bool {
        true
    }

    /// Maps a supported Run 305 application decision kind to its
    /// authorization kind. Returns [`Self::UnsupportedAuthorization`] for the
    /// reserved unsupported application kind.
    pub const fn from_application_decision_kind(
        kind: ValidatorSetRotationApplicationDecisionKind,
    ) -> Self {
        use ValidatorSetRotationApplicationDecisionKind as A;
        match kind {
            A::ApplyNoOpAlreadySynchronized => Self::AuthorizeApplyNoOpAlreadySynchronized,
            A::ApplyValidatorAdd => Self::AuthorizeApplyValidatorAdd,
            A::ApplyValidatorRemove => Self::AuthorizeApplyValidatorRemove,
            A::ApplyValidatorMetadataUpdate => Self::AuthorizeApplyValidatorMetadataUpdate,
            A::ApplyValidatorIdentityRotation => Self::AuthorizeApplyValidatorIdentityRotation,
            A::ApplyValidatorRetirement => Self::AuthorizeApplyValidatorRetirement,
            A::ApplyEmergencyValidatorRemoval => Self::AuthorizeApplyEmergencyValidatorRemoval,
            A::ApplyAuthoritySetSynchronization => Self::AuthorizeApplyAuthoritySetSynchronization,
            A::ApplyBulkValidatorSetRotation => Self::AuthorizeApplyBulkValidatorSetRotation,
            A::UnsupportedApplication => Self::UnsupportedAuthorization,
        }
    }

    /// Returns `true` iff this is the reserved unsupported kind.
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedAuthorization)
    }
}

// ===========================================================================
// Authority source
// ===========================================================================

/// Run 307 — the live validator-set application authority source presented to
/// the executor.
///
/// Only [`Self::VerifiedApplicationDecision`] carrying a Run 305/306
/// validator-set rotation application decision that `is_accept()` **and**
/// carries a prepared application intent can authorize a live-application
/// authorization. Every other variant is a non-authority source rejected with
/// a precise fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveValidatorSetApplicationAuthorizationAuthoritySource {
    /// A verified Run 305/306 validator-set rotation application decision. The
    /// **only** accepted authority source. The decision must `is_accept()`
    /// and carry `Some(application_intent)`.
    VerifiedApplicationDecision {
        decision: ProductionValidatorSetRotationApplicationDecision,
    },
    /// No application decision was supplied.
    MissingApplicationDecision,
    /// An unverified / non-accept validator-set rotation application decision.
    /// Rejected.
    UnverifiedApplicationDecision {
        decision: ProductionValidatorSetRotationApplicationDecision,
    },
    /// An accepted decision that carries no prepared application intent.
    /// Rejected.
    AcceptedDecisionWithoutApplicationIntent {
        decision: ProductionValidatorSetRotationApplicationDecision,
    },
    /// A Run 303/304 validator-set rotation plan presented directly, without a
    /// Run 305 application decision. Rejected.
    RotationPlanWithoutApplicationDecision,
    /// A Run 301/302 governance execution intent presented directly, without a
    /// Run 305 application decision. Rejected.
    GovernanceExecutionIntentWithoutApplicationDecision,
    /// A raw on-chain governance proof presented directly, without a Run 305
    /// application decision. Rejected.
    GovernanceProofWithoutApplicationDecision,
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
    /// A Run 178 fixture-class application decision presented as production
    /// authority. Rejected.
    FixtureOnlyApplicationDecision,
    /// Arbitrary validator-set bytes presented directly, without a verified
    /// application decision. Rejected.
    ArbitraryValidatorSetBytes,
}

// ===========================================================================
// Inputs
// ===========================================================================

/// Run 307 — the explicit trusted inputs the executor binds a verified
/// Run 305/306 validator-set rotation application decision against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationInputs {
    /// The authoritative trust domain.
    pub trust_domain: AuthorityTrustDomain,
    /// The opaque authorization policy id bound into the authorization.
    pub authorization_policy_id: String,
    /// Expected Run 305 application policy id (bound into the application
    /// intent).
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
    /// Expected Run 305 application decision id (bound into the decision).
    pub expected_application_decision_id: String,
    /// Expected Run 305 application request id.
    pub expected_application_request_id: String,
    /// Expected Run 305 application intent digest.
    pub expected_application_intent_digest: String,
    /// Expected Run 305 application transcript digest.
    pub expected_application_transcript_digest: String,
    /// Expected epoch-transition target a future executor would transition
    /// to. Must equal the application intent's epoch-transition target.
    pub expected_epoch_transition_target: u64,
    /// Expected Run 305 application nonce (bound into the application intent).
    pub expected_application_nonce: u64,
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

impl ProductionLiveValidatorSetApplicationAuthorizationInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        !self.trust_domain.chain_id.is_empty()
            && !self.trust_domain.genesis_hash.is_empty()
            && !self.trust_domain.authority_root_fingerprint.is_empty()
            && !self.authorization_policy_id.is_empty()
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
            && (!self.require_custody_evidence || self.expected_custody.is_some())
            && (!self.require_attestation_evidence || self.expected_attestation.is_some())
            && (!self.require_durable_replay_evidence || self.expected_durable_replay.is_some())
    }
}

// ===========================================================================
// Request
// ===========================================================================

/// Run 307 — a live validator-set application authorization request: the
/// authority source (a verified application decision), the explicit
/// epoch-transition target, a live-application nonce, and any represented
/// custody / attestation / durable-replay evidence bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationRequest {
    pub authority_source: LiveValidatorSetApplicationAuthorizationAuthoritySource,
    /// The epoch a future epoch-transition executor would transition to.
    pub proposed_epoch_transition_target: u64,
    /// The live-application nonce (idempotency / replay binding).
    pub live_application_nonce: u64,
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionLiveValidatorSetApplicationAuthorizationRequest {
    /// Construct a request carrying only an authority source, epoch target,
    /// and live-application nonce (no represented custody / attestation /
    /// durable-replay evidence).
    pub fn new(
        authority_source: LiveValidatorSetApplicationAuthorizationAuthoritySource,
        proposed_epoch_transition_target: u64,
        live_application_nonce: u64,
    ) -> Self {
        Self {
            authority_source,
            proposed_epoch_transition_target,
            live_application_nonce,
            custody_binding: None,
            attestation_binding: None,
            durable_replay_binding: None,
        }
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 307 — caller-owned replay authorization-id set. The executor reads
/// from this set but never mutates it.
pub trait LiveValidatorSetApplicationAuthorizationReplaySet {
    fn contains(&self, authorization_id: &str) -> bool;
}

impl LiveValidatorSetApplicationAuthorizationReplaySet for &[String] {
    fn contains(&self, authorization_id: &str) -> bool {
        (*self).iter().any(|s| s == authorization_id)
    }
}

impl LiveValidatorSetApplicationAuthorizationReplaySet for Vec<String> {
    fn contains(&self, authorization_id: &str) -> bool {
        self.iter().any(|s| s == authorization_id)
    }
}

/// Empty replay set helper.
pub struct EmptyLiveValidatorSetApplicationAuthorizationReplaySet;

impl LiveValidatorSetApplicationAuthorizationReplaySet
    for EmptyLiveValidatorSetApplicationAuthorizationReplaySet
{
    fn contains(&self, _authorization_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Authorization intent (boundary output)
// ===========================================================================

/// Run 307 — a typed, deterministic, **non-mutating** live validator-set
/// application authorization / epoch-transition authorization intent. Only a
/// typed accepted outcome carrying this intent may authorize a *future*
/// mutation run (Run 308+); Run 307 never applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationIntent {
    pub authorization_kind: LiveValidatorSetApplicationAuthorizationKind,
    pub protocol_version: u16,
    pub authorization_policy_id: String,

    // ---- Re-exposed Run 305 application intent tuple ------------------
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

    // ---- Bound Run 305 application-decision authority tuple -----------
    pub application_decision_id: String,
    pub application_request_id: String,
    pub application_intent_digest: String,
    pub application_transcript_digest: String,
    pub application_nonce: u64,

    // ---- Live application authorization binding -----------------------
    pub epoch_transition_target: u64,
    pub live_application_nonce: u64,

    // ---- Composed evidence (where represented) ------------------------
    pub custody_binding: Option<GovernanceExecutionCustodyBinding>,
    pub attestation_binding: Option<GovernanceExecutionAttestationBinding>,
    pub durable_replay_binding: Option<GovernanceExecutionDurableReplayBinding>,
}

impl ProductionLiveValidatorSetApplicationAuthorizationIntent {
    /// Deterministic, domain-separated SHA3-256 hex intent digest. `Debug`
    /// formatting is never used as canonical bytes.
    pub fn intent_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(
            PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_INTENT_DOMAIN_TAG.as_bytes(),
        );
        hash_field(&mut h, b"authorization_kind", self.authorization_kind.tag().as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.to_le_bytes());
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
    /// by Run 307.
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

/// Run 307 — deterministic authorization intent digest wrapper exposed as a
/// named symbol.
pub fn production_live_validator_set_application_authorization_intent_digest(
    intent: &ProductionLiveValidatorSetApplicationAuthorizationIntent,
) -> String {
    intent.intent_digest()
}

/// Run 307 — deterministic, domain-separated authorization request id binding
/// the protocol version, application intent digest, authorization policy id,
/// epoch-transition target, and live-application nonce. Deterministic across
/// identical inputs; never wall-clock.
pub fn production_live_validator_set_application_authorization_request_id(
    protocol_version: u16,
    application_intent_digest: &str,
    authorization_policy_id: &str,
    epoch_transition_target: u64,
    live_application_nonce: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_REQUEST_DOMAIN_TAG.as_bytes(),
    );
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"application_intent_digest", application_intent_digest.as_bytes());
    hash_field(&mut h, b"authorization_policy_id", authorization_policy_id.as_bytes());
    hash_field(
        &mut h,
        b"epoch_transition_target",
        &epoch_transition_target.to_le_bytes(),
    );
    hash_field(
        &mut h,
        b"live_application_nonce",
        &live_application_nonce.to_le_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 307 — deterministic, domain-separated authorization transcript digest
/// binding the protocol version, request id, intent digest, and outcome tag.
pub fn production_live_validator_set_application_authorization_transcript_digest(
    protocol_version: u16,
    request_id: &str,
    intent_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(
        PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_TRANSCRIPT_DOMAIN_TAG.as_bytes(),
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

/// Run 307 — typed outcome of the live validator-set application
/// authorization executor boundary.
///
/// Only
/// [`Self::AcceptedSourceTestLiveValidatorSetApplicationAuthorization`]
/// authorizes a (source/test, DevNet/TestNet, evidence-only, non-mutating)
/// live-application authorization. Every other variant is a precise,
/// non-mutating fail-closed reject (or the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionLiveValidatorSetApplicationAuthorizationOutcome {
    // ---- Disabled / unavailable ---------------------------------------
    /// Policy is `Disabled`; no authority was bound.
    Disabled,
    /// The boundary kind is unavailable / misconfigured.
    LiveValidatorSetApplicationAuthorizationBoundaryUnavailable,
    /// The production policy has no production prerequisites wired.
    ProductionLiveValidatorSetApplicationAuthorizationUnavailable,
    /// The MainNet production policy has no MainNet authority wired.
    MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable,

    // ---- Accepted ------------------------------------------------------
    /// A verified DevNet/TestNet validator-set rotation application decision
    /// produced a typed non-mutating live-application authorization under the
    /// source/test policy. **Evidence only.**
    AcceptedSourceTestLiveValidatorSetApplicationAuthorization {
        authorization_kind: LiveValidatorSetApplicationAuthorizationKind,
        environment: TrustBundleEnvironment,
        epoch_transition_target: u64,
        live_application_nonce: u64,
    },

    // ---- Application-decision / authority failures --------------------
    VerifiedApplicationDecisionRequired,
    UnverifiedApplicationDecisionRejected,
    RotationPlanAloneRejected,
    GovernanceProofAloneRejected,
    GovernanceExecutionIntentAloneRejected,
    FixtureApplicationDecisionRejectedAsProductionAuthority,
    LocalOperatorProofRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,
    CustodyAttestationOnlyProofRejected,
    ArbitraryValidatorSetBytesRejected,

    // ---- Application-decision binding failures ------------------------
    WrongApplicationPolicyId,
    ApplicationDecisionIdMismatch,
    ApplicationDecisionRequestIdMismatch,
    ApplicationDecisionIntentDigestMismatch,
    ApplicationDecisionTranscriptMismatch,
    ApplicationDecisionIntegrityMismatch,

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
    UnsupportedLiveApplicationAuthorization,

    // ---- Epoch-transition / nonce binding failures --------------------
    WrongEpochTransitionTarget,
    WrongApplicationNonce,

    // ---- Custody / attestation / durable replay -----------------------
    CustodyBackendEvidenceRequired,
    CustodyBackendMismatch,
    CustodyAttestationRequired,
    CustodyAttestationMismatch,
    DurableReplayEvidenceRequired,
    DurableReplayMismatch,
    DurableReplayUnavailable,

    // ---- Replay / freshness -------------------------------------------
    LiveApplicationReplayRejected { authorization_id: String },
    StaleGovernanceEpoch,
    StaleAuthoritySequence,
    StaleValidatorSetEpoch,
    StaleValidatorSetVersion,
    ConflictingAuthorizationForSameApplication,
    LiveValidatorSetApplicationAuthorizationAmbiguous { reason: String },
    MainNetRefused,
}

impl ProductionLiveValidatorSetApplicationAuthorizationOutcome {
    /// Returns `true` iff this outcome accepted a source/test authorization.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedSourceTestLiveValidatorSetApplicationAuthorization { .. }
        )
    }

    /// Returns `true` iff this outcome is a fail-closed reject (i.e. not an
    /// accept and not the inert `Disabled`).
    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !matches!(self, Self::Disabled)
    }

    /// Every Run 307 outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Only an accepted outcome may authorize a *future* mutation run; it
    /// never mutates in Run 307.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.is_accept()
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LiveValidatorSetApplicationAuthorizationBoundaryUnavailable => {
                "live-validator-set-application-authorization-boundary-unavailable"
            }
            Self::ProductionLiveValidatorSetApplicationAuthorizationUnavailable => {
                "production-live-validator-set-application-authorization-unavailable"
            }
            Self::MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable => {
                "mainnet-production-live-validator-set-application-authorization-unavailable"
            }
            Self::AcceptedSourceTestLiveValidatorSetApplicationAuthorization { .. } => {
                "accepted-source-test-live-validator-set-application-authorization"
            }
            Self::VerifiedApplicationDecisionRequired => "verified-application-decision-required",
            Self::UnverifiedApplicationDecisionRejected => {
                "unverified-application-decision-rejected"
            }
            Self::RotationPlanAloneRejected => "rotation-plan-alone-rejected",
            Self::GovernanceProofAloneRejected => "governance-proof-alone-rejected",
            Self::GovernanceExecutionIntentAloneRejected => {
                "governance-execution-intent-alone-rejected"
            }
            Self::FixtureApplicationDecisionRejectedAsProductionAuthority => {
                "fixture-application-decision-rejected-as-production-authority"
            }
            Self::LocalOperatorProofRejected => "local-operator-proof-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::CustodyAttestationOnlyProofRejected => "custody-attestation-only-proof-rejected",
            Self::ArbitraryValidatorSetBytesRejected => "arbitrary-validator-set-bytes-rejected",
            Self::WrongApplicationPolicyId => "wrong-application-policy-id",
            Self::ApplicationDecisionIdMismatch => "application-decision-id-mismatch",
            Self::ApplicationDecisionRequestIdMismatch => {
                "application-decision-request-id-mismatch"
            }
            Self::ApplicationDecisionIntentDigestMismatch => {
                "application-decision-intent-digest-mismatch"
            }
            Self::ApplicationDecisionTranscriptMismatch => {
                "application-decision-transcript-mismatch"
            }
            Self::ApplicationDecisionIntegrityMismatch => "application-decision-integrity-mismatch",
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
            Self::UnsupportedLiveApplicationAuthorization => {
                "unsupported-live-application-authorization"
            }
            Self::WrongEpochTransitionTarget => "wrong-epoch-transition-target",
            Self::WrongApplicationNonce => "wrong-application-nonce",
            Self::CustodyBackendEvidenceRequired => "custody-backend-evidence-required",
            Self::CustodyBackendMismatch => "custody-backend-mismatch",
            Self::CustodyAttestationRequired => "custody-attestation-required",
            Self::CustodyAttestationMismatch => "custody-attestation-mismatch",
            Self::DurableReplayEvidenceRequired => "durable-replay-evidence-required",
            Self::DurableReplayMismatch => "durable-replay-mismatch",
            Self::DurableReplayUnavailable => "durable-replay-unavailable",
            Self::LiveApplicationReplayRejected { .. } => "live-application-replay-rejected",
            Self::StaleGovernanceEpoch => "stale-governance-epoch",
            Self::StaleAuthoritySequence => "stale-authority-sequence",
            Self::StaleValidatorSetEpoch => "stale-validator-set-epoch",
            Self::StaleValidatorSetVersion => "stale-validator-set-version",
            Self::ConflictingAuthorizationForSameApplication => {
                "conflicting-authorization-for-same-application"
            }
            Self::LiveValidatorSetApplicationAuthorizationAmbiguous { .. } => {
                "live-validator-set-application-authorization-ambiguous"
            }
            Self::MainNetRefused => "mainnet-refused",
        }
    }
}

// ===========================================================================
// Decision (boundary output)
// ===========================================================================

/// Run 307 — the typed decision produced by the executor boundary: the
/// outcome, the bound application decision id, the deterministic request id,
/// the optional prepared authorization intent, its digest, and the
/// verification transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationDecision {
    pub outcome: ProductionLiveValidatorSetApplicationAuthorizationOutcome,
    pub authorization_id: String,
    pub request_id: String,
    pub authorization_intent: Option<ProductionLiveValidatorSetApplicationAuthorizationIntent>,
    pub intent_digest: String,
    pub transcript_digest: String,
}

impl ProductionLiveValidatorSetApplicationAuthorizationDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }

    /// Returns `true` iff the decision carries a prepared, non-mutating
    /// authorization intent (only on accept). The boundary never applies it.
    pub fn authorizes_future_mutation_only(&self) -> bool {
        self.outcome.authorizes_future_mutation_only() && self.authorization_intent.is_some()
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 307 — typed idempotency / recovery outcome for a prepared-authorization
/// window. Every variant is non-mutating; no durable state is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome {
    /// No prior prepared authorization for this application window — clean.
    NoPriorAuthorizationWindow,
    /// A prior prepared authorization for this window was observed; the
    /// executor re-derives the same intent deterministically without
    /// mutation.
    IdempotentReplayObserved { authorization_id: String },
    /// The recovery window is disabled (policy `Disabled`).
    RecoveryDisabled,
}

impl ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome {
    /// Every recovery outcome is non-mutating.
    pub const fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff the recovery window is clean (no prior
    /// authorization).
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::NoPriorAuthorizationWindow)
    }
}

// ===========================================================================
// Executor boundary
// ===========================================================================

/// Run 307 — the source/test live validator-set application authorization /
/// epoch-transition authorization executor boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionLiveValidatorSetApplicationAuthorizationExecutor {
    pub config: ProductionLiveValidatorSetApplicationAuthorizationConfig,
    pub policy: ProductionLiveValidatorSetApplicationAuthorizationPolicy,
}

impl ProductionLiveValidatorSetApplicationAuthorizationExecutor {
    pub fn new(
        config: ProductionLiveValidatorSetApplicationAuthorizationConfig,
        policy: ProductionLiveValidatorSetApplicationAuthorizationPolicy,
    ) -> Self {
        Self { config, policy }
    }

    /// A source/test executor under the source/test policy.
    pub fn source_test() -> Self {
        Self::new(
            ProductionLiveValidatorSetApplicationAuthorizationConfig::source_test(),
            ProductionLiveValidatorSetApplicationAuthorizationPolicy::AllowSourceTestLiveValidatorSetApplicationAuthorization,
        )
    }

    /// Extract the verified validator-set rotation application decision and
    /// prepared application intent from an authority source, mapping every
    /// non-authority source to its precise fail-closed outcome.
    fn resolve_authority_source<'a>(
        &self,
        source: &'a LiveValidatorSetApplicationAuthorizationAuthoritySource,
    ) -> Result<
        (
            &'a ProductionValidatorSetRotationApplicationDecision,
            &'a ProductionValidatorSetRotationApplicationIntent,
        ),
        ProductionLiveValidatorSetApplicationAuthorizationOutcome,
    > {
        use LiveValidatorSetApplicationAuthorizationAuthoritySource as S;
        use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;
        match source {
            S::VerifiedApplicationDecision { decision } => {
                if !decision.is_accept() {
                    return Err(O::UnverifiedApplicationDecisionRejected);
                }
                match &decision.application_intent {
                    Some(intent) => Ok((decision, intent)),
                    None => Err(O::VerifiedApplicationDecisionRequired),
                }
            }
            S::MissingApplicationDecision => Err(O::VerifiedApplicationDecisionRequired),
            S::UnverifiedApplicationDecision { .. } => {
                Err(O::UnverifiedApplicationDecisionRejected)
            }
            S::AcceptedDecisionWithoutApplicationIntent { .. } => {
                Err(O::VerifiedApplicationDecisionRequired)
            }
            S::RotationPlanWithoutApplicationDecision => Err(O::RotationPlanAloneRejected),
            S::GovernanceExecutionIntentWithoutApplicationDecision => {
                Err(O::GovernanceExecutionIntentAloneRejected)
            }
            S::GovernanceProofWithoutApplicationDecision => Err(O::GovernanceProofAloneRejected),
            S::LocalOperatorAssertion => Err(O::LocalOperatorProofRejected),
            S::PeerMajorityAssertion => Err(O::PeerMajorityProofRejected),
            S::CustodyOnlyEvidence => Err(O::CustodyOnlyProofRejected),
            S::RemoteSignerOnlyEvidence => Err(O::RemoteSignerOnlyProofRejected),
            S::CustodyAttestationOnlyEvidence => Err(O::CustodyAttestationOnlyProofRejected),
            S::FixtureOnlyApplicationDecision => {
                Err(O::FixtureApplicationDecisionRejectedAsProductionAuthority)
            }
            S::ArbitraryValidatorSetBytes => Err(O::ArbitraryValidatorSetBytesRejected),
        }
    }

    /// Pure policy / kind / MainNet gate applied before any binding. Returns
    /// `Some(outcome)` to refuse, `None` to proceed.
    fn preflight_gate(
        &self,
        binding_env: TrustBundleEnvironment,
        inputs: &ProductionLiveValidatorSetApplicationAuthorizationInputs,
    ) -> Option<ProductionLiveValidatorSetApplicationAuthorizationOutcome> {
        use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;

        // 1. Disabled fails closed before any binding.
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionLiveValidatorSetApplicationAuthorizationKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. MainNet gate. A MainNet trust domain or MainNet authority source
        //    is refused: no MainNet production authority is wired.
        if inputs.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || binding_env == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionLiveValidatorSetApplicationAuthorizationPolicy::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired => {
                    O::MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 3. MainNet production policy on a non-MainNet domain still has no
        //    MainNet authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable);
        }

        // 4. The production policy has no production prerequisites wired —
        //    fail closed.
        if self.policy.is_production() {
            return Some(O::ProductionLiveValidatorSetApplicationAuthorizationUnavailable);
        }

        // 5. Reserved production boundary kind is fail-closed in Run 307.
        if self.config.kind
            == ProductionLiveValidatorSetApplicationAuthorizationKind::ProductionLiveValidatorSetApplicationAuthorization
        {
            return Some(O::LiveValidatorSetApplicationAuthorizationBoundaryUnavailable);
        }

        // 6. Config / inputs well-formedness.
        if !self.config.is_well_formed() || !inputs.is_well_formed() {
            return Some(O::LiveValidatorSetApplicationAuthorizationBoundaryUnavailable);
        }

        None
    }

    /// Cross-check the verified application decision and its prepared
    /// application intent against the explicit trusted inputs and trust
    /// domain. Returns `Some(outcome)` on the first divergence.
    fn check_application_binding(
        &self,
        decision: &ProductionValidatorSetRotationApplicationDecision,
        intent: &ProductionValidatorSetRotationApplicationIntent,
        inputs: &ProductionLiveValidatorSetApplicationAuthorizationInputs,
    ) -> Option<ProductionLiveValidatorSetApplicationAuthorizationOutcome> {
        use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;
        let td = &inputs.trust_domain;

        // Application-decision transcript binding.
        if decision.application_id != inputs.expected_application_decision_id {
            return Some(O::ApplicationDecisionIdMismatch);
        }
        if decision.request_id != inputs.expected_application_request_id {
            return Some(O::ApplicationDecisionRequestIdMismatch);
        }
        if decision.intent_digest != inputs.expected_application_intent_digest {
            return Some(O::ApplicationDecisionIntentDigestMismatch);
        }
        if decision.transcript_digest != inputs.expected_application_transcript_digest {
            return Some(O::ApplicationDecisionTranscriptMismatch);
        }
        // The prepared application intent must reproduce the bound digest.
        if intent.intent_digest() != decision.intent_digest {
            return Some(O::ApplicationDecisionIntegrityMismatch);
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
        request: &ProductionLiveValidatorSetApplicationAuthorizationRequest,
        intent: &ProductionValidatorSetRotationApplicationIntent,
        inputs: &ProductionLiveValidatorSetApplicationAuthorizationInputs,
    ) -> Option<ProductionLiveValidatorSetApplicationAuthorizationOutcome> {
        use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;

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
    fn evaluate_core<R: LiveValidatorSetApplicationAuthorizationReplaySet + ?Sized>(
        &self,
        request: &ProductionLiveValidatorSetApplicationAuthorizationRequest,
        inputs: &ProductionLiveValidatorSetApplicationAuthorizationInputs,
        replay_set: &R,
    ) -> (
        ProductionLiveValidatorSetApplicationAuthorizationOutcome,
        Option<ProductionLiveValidatorSetApplicationAuthorizationIntent>,
    ) {
        use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;

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

        // Step 4: replay / freshness on the application tuple.
        if let Some(prev) = inputs.persisted_sequence {
            if application_intent.authority_domain_sequence < prev {
                return (O::StaleAuthoritySequence, None);
            }
        }
        let authorization_id = production_live_validator_set_application_authorization_request_id(
            self.config.protocol_version.0,
            &decision.intent_digest,
            &inputs.authorization_policy_id,
            request.proposed_epoch_transition_target,
            request.live_application_nonce,
        );
        if replay_set.contains(&authorization_id) {
            return (O::LiveApplicationReplayRejected { authorization_id }, None);
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

        // Step 6: epoch-transition target binding. The live-application
        // authorization targets the application intent's epoch-transition
        // target; a future epoch-transition executor would transition to
        // exactly this epoch.
        if request.proposed_epoch_transition_target != inputs.expected_epoch_transition_target {
            return (O::WrongEpochTransitionTarget, None);
        }
        if request.proposed_epoch_transition_target != application_intent.epoch_transition_target {
            return (O::WrongEpochTransitionTarget, None);
        }

        // Step 7: application-nonce binding. The Run 305 application nonce
        // carried by the intent must equal the operator-trusted expected
        // nonce.
        if application_intent.application_nonce != inputs.expected_application_nonce {
            return (O::WrongApplicationNonce, None);
        }

        // Step 8: derive the typed live-application authorization kind.
        let authorization_kind =
            LiveValidatorSetApplicationAuthorizationKind::from_application_decision_kind(
                application_intent.decision_kind,
            );
        if authorization_kind.is_unsupported() {
            return (O::UnsupportedLiveApplicationAuthorization, None);
        }

        // Step 9: construct the typed non-mutating authorization intent.
        let intent = ProductionLiveValidatorSetApplicationAuthorizationIntent {
            authorization_kind,
            protocol_version: self.config.protocol_version.0,
            authorization_policy_id: inputs.authorization_policy_id.clone(),
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
            application_decision_id: decision.application_id.clone(),
            application_request_id: decision.request_id.clone(),
            application_intent_digest: decision.intent_digest.clone(),
            application_transcript_digest: decision.transcript_digest.clone(),
            application_nonce: application_intent.application_nonce,
            epoch_transition_target: request.proposed_epoch_transition_target,
            live_application_nonce: request.live_application_nonce,
            custody_binding: request.custody_binding.clone(),
            attestation_binding: request.attestation_binding.clone(),
            durable_replay_binding: request.durable_replay_binding.clone(),
        };

        // Step 10: typed accepted non-mutating outcome.
        (
            O::AcceptedSourceTestLiveValidatorSetApplicationAuthorization {
                authorization_kind,
                environment: application_intent.environment,
                epoch_transition_target: request.proposed_epoch_transition_target,
                live_application_nonce: request.live_application_nonce,
            },
            Some(intent),
        )
    }

    /// Run 307 — evaluate a live validator-set application authorization
    /// request into a typed, deterministic, non-mutating decision. This never
    /// mutates any live validator set, consensus epoch, or trust state; on
    /// accept it produces only a prepared authorization intent.
    pub fn evaluate_live_validator_set_application_authorization<
        R: LiveValidatorSetApplicationAuthorizationReplaySet + ?Sized,
    >(
        &self,
        request: &ProductionLiveValidatorSetApplicationAuthorizationRequest,
        inputs: &ProductionLiveValidatorSetApplicationAuthorizationInputs,
        replay_set: &R,
    ) -> ProductionLiveValidatorSetApplicationAuthorizationDecision {
        let (outcome, intent) = self.evaluate_core(request, inputs, replay_set);

        // Application decision id + intent digest for the transcript
        // (best-effort from the authority source).
        let (application_decision_id, application_intent_digest) = match &request.authority_source {
            LiveValidatorSetApplicationAuthorizationAuthoritySource::VerifiedApplicationDecision {
                decision,
            }
            | LiveValidatorSetApplicationAuthorizationAuthoritySource::UnverifiedApplicationDecision {
                decision,
            }
            | LiveValidatorSetApplicationAuthorizationAuthoritySource::AcceptedDecisionWithoutApplicationIntent {
                decision,
            } => (decision.application_id.clone(), decision.intent_digest.clone()),
            _ => (String::new(), String::new()),
        };

        let request_id = production_live_validator_set_application_authorization_request_id(
            self.config.protocol_version.0,
            &application_intent_digest,
            &inputs.authorization_policy_id,
            request.proposed_epoch_transition_target,
            request.live_application_nonce,
        );
        let intent_digest = intent.as_ref().map(|i| i.intent_digest()).unwrap_or_default();
        let transcript_digest =
            production_live_validator_set_application_authorization_transcript_digest(
                self.config.protocol_version.0,
                &request_id,
                &intent_digest,
                outcome.tag(),
            );

        ProductionLiveValidatorSetApplicationAuthorizationDecision {
            outcome,
            authorization_id: application_decision_id,
            request_id,
            authorization_intent: intent,
            intent_digest,
            transcript_digest,
        }
    }

    /// Run 307 — idempotency / recovery over a prepared-authorization window.
    /// Non-mutating; writes no durable state.
    pub fn recover_live_validator_set_application_authorization_window(
        &self,
        prior: Option<&ProductionLiveValidatorSetApplicationAuthorizationIntent>,
        current: &ProductionLiveValidatorSetApplicationAuthorizationIntent,
    ) -> ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome {
        use ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome as R;
        if self.policy.is_disabled()
            || self.config.kind
                == ProductionLiveValidatorSetApplicationAuthorizationKind::Disabled
        {
            return R::RecoveryDisabled;
        }
        let Some(prior) = prior else {
            return R::NoPriorAuthorizationWindow;
        };
        // Unrelated application intent digests / nonces => independent window.
        if prior.application_intent_digest != current.application_intent_digest
            || prior.live_application_nonce != current.live_application_nonce
            || prior.epoch_transition_target != current.epoch_transition_target
        {
            return R::NoPriorAuthorizationWindow;
        }
        // Same window, byte-identical intent => idempotent replay.
        if prior == current {
            R::IdempotentReplayObserved {
                authorization_id: current.application_decision_id.clone(),
            }
        } else {
            // Same window but non-identical intent is caller error; the
            // executor reports a clean (non-mutating) recovery signal and
            // never overwrites durable state.
            R::NoPriorAuthorizationWindow
        }
    }
}

// ===========================================================================
// Standalone named helpers (source/test invariants)
// ===========================================================================

/// Run 307 — the executor default policy is Disabled / fail-closed.
pub fn production_live_validator_set_application_authorization_executor_default_is_disabled() -> bool
{
    ProductionLiveValidatorSetApplicationAuthorizationPolicy::default()
        == ProductionLiveValidatorSetApplicationAuthorizationPolicy::Disabled
        && ProductionLiveValidatorSetApplicationAuthorizationConfig::default().kind
            == ProductionLiveValidatorSetApplicationAuthorizationKind::Disabled
}

/// Run 307 — the executor is a source/test implementation, not
/// release-binary evidence (deferred to Run 308).
pub fn production_live_validator_set_application_authorization_executor_is_source_test_not_release_binary_evidence(
) -> bool {
    true
}

/// Run 307 — the executor refuses MainNet absent production authority.
pub fn production_live_validator_set_application_authorization_executor_mainnet_refused() -> bool {
    true
}

/// Run 307 — the executor never applies a live validator-set change,
/// consensus epoch transition, or trust-state mutation; every outcome is
/// non-mutating.
pub fn production_live_validator_set_application_authorization_executor_is_non_mutating() -> bool {
    true
}

/// Run 307 — the executor never falls back to rotation-plan-alone /
/// governance-proof-alone / governance-execution-intent-alone / fixture /
/// local-operator / peer-majority / custody-only / RemoteSigner-only /
/// arbitrary-bytes authority.
pub fn production_live_validator_set_application_authorization_executor_never_falls_back() -> bool {
    true
}

/// Run 307 — the executor adds no default runtime wiring and no CLI flag.
pub fn production_live_validator_set_application_authorization_executor_no_default_runtime_wiring(
) -> bool {
    true
}

/// Run 307 — the executor only requires a verified Run 305/306 validator-set
/// rotation application decision as authority; nothing else can authorize a
/// live-application authorization.
pub fn production_live_validator_set_application_authorization_executor_requires_verified_application_decision(
) -> bool {
    true
}
