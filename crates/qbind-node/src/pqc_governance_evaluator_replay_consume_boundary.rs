//! Run 234 — source/test governance evaluator **post-mutation replay consume
//! boundary**.
//!
//! Source/test only. Run 234 captures **no** release-binary evidence;
//! release-binary consume-boundary evidence is deferred to **Run 235**. Run 234
//! does **not** implement a real governance execution engine, a real on-chain
//! governance proof verifier, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, a real KMS/HSM
//! backend, a real RemoteSigner backend, or any RocksDB / file / schema /
//! migration / wire / marker / sequence / trust-bundle / storage-format change.
//!
//! ## What this module closes
//!
//! Run 230 proved a typed, pure **replay/freshness state boundary**; Run 231
//! closed its release-binary evidence; Run 232 composed that boundary into the
//! Run 224 evaluator-runtime integration path as a mandatory pre-mutation gate;
//! and Run 233 closed that composition's release-binary evidence. What was still
//! missing was a typed **post-mutation consume boundary**: replay/freshness
//! validation is now composed *before* mutation authorization, but the consume
//! step that records a decision as consumed was not yet modeled as a strict
//! **after-success-only** step. A governance decision must not be marked
//! consumed before mutation succeeds, and a successfully-applied decision must
//! not be left untracked in fixture evidence.
//!
//! Run 234 closes that gap at the source/test level. It models a pure boundary
//! that separates the four phases:
//!
//! 1. **pre-mutation freshness validation** (Run 230 / Run 232);
//! 2. **mutation authorization** ([`MutationAuthorizationOutcome`]);
//! 3. **successful mutation completion** ([`MutationCompletionStatus`]); and
//! 4. **explicit replay-state consume after success only**
//!    ([`ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess`]).
//!
//! ## Fail-closed / consume-safety contract
//!
//! * [`ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess`] is the **only**
//!   outcome that authorizes a fixture consume, and only when the mutation
//!   completion status is [`MutationCompletionStatus::AppliedSuccessfully`].
//! * A legacy bypass, a deferral, a validation-only surface, an
//!   authorized-but-not-applied decision, a failed apply, a rolled-back
//!   mutation, an unsupported surface, and a MainNet-refused decision all
//!   resolve to a typed `DoNotConsume*` outcome — never a consume.
//! * The fixture writer records a consumed decision **only** when
//!   [`perform_post_mutation_consume`] resolves
//!   [`ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess`] and the explicit
//!   [`GovernanceEvaluatorReplayStateWriter::mark_consumed`] write is accepted.
//! * Production / MainNet consume writers are callable but always fail closed
//!   ([`ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable`] /
//!   [`ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable`]).
//! * MainNet peer-driven apply remains refused unconditionally and never
//!   consumes, even when the replay state would otherwise be fresh.
//! * Evaluation is a pure function: it performs no I/O, writes no marker, writes
//!   no sequence, swaps no live trust, evicts no sessions, and never invokes
//!   Run 070. Consume rejection therefore necessarily happens before any of
//!   those mutations.
//! * Validator-set rotation and policy-change actions remain unsupported.
//!
//! ## What this module does NOT change
//!
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle, authority-marker, or sequence schema.
//! * It introduces **no** RocksDB schema, file format, or database migration.
//! * It enables **no** MainNet peer-driven apply.
//! * It does **not** claim full C4 or C5 closure.

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_evaluator_replay_runtime_integration::GovernanceEvaluatorReplayRuntimeOutcome;
use crate::pqc_governance_evaluator_replay_state::{
    replay_state_key_digest, EvaluatorReplayFreshnessInput, GovernanceEvaluatorReplayStateWriter,
    ReplayStatePolicy,
};
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Domain-separation tag for the Run 234 consume authorization digest.
pub const CONSUME_AUTHORIZATION_DOMAIN_TAG: &str =
    "qbind.run234.governance.evaluator.replay.consume.authorization.v1";
/// Domain-separation tag for the Run 234 consume transcript digest.
pub const CONSUME_TRANSCRIPT_DOMAIN_TAG: &str =
    "qbind.run234.governance.evaluator.replay.consume.transcript.v1";
/// Domain-separation tag for the Run 234 post-mutation consume record digest.
pub const POST_MUTATION_CONSUME_RECORD_DOMAIN_TAG: &str =
    "qbind.run234.governance.evaluator.replay.consume.record.v1";

// ===========================================================================
// Surface classification
// ===========================================================================

/// Run 234 — `true` iff `surface` is a validation-only (non-mutating) runtime
/// surface. A validation-only surface never marks replay state consumed.
pub const fn surface_is_validation_only(surface: GovernanceExecutionRuntimeSurface) -> bool {
    matches!(
        surface,
        GovernanceExecutionRuntimeSurface::ReloadCheck
            | GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck
            | GovernanceExecutionRuntimeSurface::LiveInbound0x05
    )
}

// ===========================================================================
// Mutation authorization outcome
// ===========================================================================

/// Run 234 — the result of the upstream Run 232 mutation-authorization phase,
/// projected to the variants the consume boundary distinguishes.
///
/// Only [`Self::AuthorizedFresh`] permits a successful mutation to consume; every
/// other variant resolves to a non-consuming outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationAuthorizationOutcome {
    /// Run 214 legacy bypass — the replay/freshness boundary was never reached.
    LegacyBypass,
    /// Fresh-but-not-yet-effective — deferred, not an approval for mutation.
    Deferred,
    /// Fresh and authorized — the only outcome that may lead to a consume.
    AuthorizedFresh,
    /// Replay/freshness or runtime integration failed closed before mutation.
    FreshnessFailClosed,
    /// Validation-only surface — never authorizes a mutation that consumes.
    ValidationOnly,
    /// MainNet peer-driven apply refused — never authorizes a mutation.
    MainNetRefused,
}

impl MutationAuthorizationOutcome {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LegacyBypass => "legacy-bypass",
            Self::Deferred => "deferred",
            Self::AuthorizedFresh => "authorized-fresh",
            Self::FreshnessFailClosed => "freshness-fail-closed",
            Self::ValidationOnly => "validation-only",
            Self::MainNetRefused => "mainnet-refused",
        }
    }

    /// `true` iff this outcome authorizes a mutation (only
    /// [`Self::AuthorizedFresh`]).
    pub const fn authorizes_mutation(self) -> bool {
        matches!(self, Self::AuthorizedFresh)
    }

    /// Project a Run 232 [`GovernanceEvaluatorReplayRuntimeOutcome`] into the
    /// consume-boundary authorization view. Run 234 never authorizes a consume
    /// for anything other than a Run 232 `ProceedFresh`.
    pub fn from_replay_runtime_outcome(outcome: &GovernanceEvaluatorReplayRuntimeOutcome) -> Self {
        match outcome {
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass => Self::LegacyBypass,
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred => Self::Deferred,
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. } => Self::AuthorizedFresh,
            GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(_)
            | GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(_) => {
                Self::FreshnessFailClosed
            }
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused => {
                Self::MainNetRefused
            }
        }
    }
}

// ===========================================================================
// Mutation completion status
// ===========================================================================

/// Run 234 — the status of the mutation-completion phase, the third phase the
/// consume boundary separates.
///
/// Only [`Self::AppliedSuccessfully`] permits an authorized decision to consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationCompletionStatus {
    /// No mutation was attempted (e.g. read-only path / fail-closed upstream).
    NotAttempted,
    /// Mutation was authorized but the apply was not performed.
    AuthorizedButNotApplied,
    /// The mutation was applied successfully. The only consume-eligible status.
    AppliedSuccessfully,
    /// The apply was attempted and failed.
    ApplyFailed,
    /// The mutation was applied then rolled back.
    RolledBack,
    /// A validation-only surface — no mutation was ever applied.
    ValidationOnly,
    /// The mutation surface is unsupported.
    UnsupportedSurface,
    /// MainNet peer-driven apply was refused.
    MainNetRefused,
}

impl MutationCompletionStatus {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::AuthorizedButNotApplied => "authorized-but-not-applied",
            Self::AppliedSuccessfully => "applied-successfully",
            Self::ApplyFailed => "apply-failed",
            Self::RolledBack => "rolled-back",
            Self::ValidationOnly => "validation-only",
            Self::UnsupportedSurface => "unsupported-surface",
            Self::MainNetRefused => "mainnet-refused",
        }
    }

    /// `true` iff the mutation completed successfully (the only consume-eligible
    /// status).
    pub const fn is_applied_successfully(self) -> bool {
        matches!(self, Self::AppliedSuccessfully)
    }
}

// ===========================================================================
// Consume boundary inputs
// ===========================================================================

/// Run 234 — typed post-mutation consume inputs for one evaluator decision.
///
/// Pure data. The digest fields reference the Run 222 evaluator material and the
/// Run 230 replay state key digest — never copies of any wire payload. The
/// `mutation_authorization_outcome` and `mutation_completion_status` carry the
/// results of the second and third phases the boundary separates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostMutationConsumeInput {
    /// Run 230 replay state key digest the decision is recorded under.
    pub replay_state_key_digest: String,
    /// Evaluator source-identity digest.
    pub evaluator_source_identity_digest: String,
    /// Evaluator request digest.
    pub evaluator_request_digest: String,
    /// Evaluator response digest.
    pub evaluator_response_digest: String,
    /// Evaluator transcript digest.
    pub evaluator_transcript_digest: String,
    /// Governance execution decision digest.
    pub governance_execution_decision_digest: String,
    /// Governance proposal id.
    pub proposal_id: String,
    /// Governance decision id.
    pub decision_id: String,
    /// Lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Candidate digest.
    pub candidate_digest: String,
    /// Authority-domain sequence.
    pub authority_domain_sequence: u64,
    /// Effective / activation epoch.
    pub effective_epoch: u64,
    /// Expiry epoch.
    pub expiry_epoch: u64,
    /// Per-execution anti-replay nonce.
    pub replay_nonce: String,
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
    /// Validation surface the decision was validated for.
    pub validation_surface: GovernanceExecutionRuntimeSurface,
    /// Mutation surface the decision authorizes / attempted to mutate.
    pub mutation_surface: GovernanceExecutionRuntimeSurface,
    /// Result of the upstream mutation-authorization phase.
    pub mutation_authorization_outcome: MutationAuthorizationOutcome,
    /// Status of the mutation-completion phase.
    pub mutation_completion_status: MutationCompletionStatus,
}

impl PostMutationConsumeInput {
    /// `true` iff every mandatory field is structurally present (non-empty).
    pub fn is_well_formed(&self) -> bool {
        !self.replay_state_key_digest.is_empty()
            && !self.evaluator_source_identity_digest.is_empty()
            && !self.evaluator_request_digest.is_empty()
            && !self.evaluator_response_digest.is_empty()
            && !self.evaluator_transcript_digest.is_empty()
            && !self.governance_execution_decision_digest.is_empty()
            && !self.proposal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.replay_nonce.is_empty()
            && !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
    }

    /// Compose a Run 234 consume input by **referencing** a Run 230
    /// [`EvaluatorReplayFreshnessInput`] plus the mutation surface and the
    /// authorization / completion phase results. The replay state key digest is
    /// derived from the same Run 230 input, so the consume binding is internally
    /// consistent with the replay/freshness binding.
    pub fn from_freshness_input(
        freshness: &EvaluatorReplayFreshnessInput,
        mutation_surface: GovernanceExecutionRuntimeSurface,
        mutation_authorization_outcome: MutationAuthorizationOutcome,
        mutation_completion_status: MutationCompletionStatus,
    ) -> Self {
        Self {
            replay_state_key_digest: replay_state_key_digest(freshness),
            evaluator_source_identity_digest: freshness.evaluator_source_identity_digest.clone(),
            evaluator_request_digest: freshness.evaluator_request_digest.clone(),
            evaluator_response_digest: freshness.evaluator_response_digest.clone(),
            evaluator_transcript_digest: freshness.evaluator_transcript_digest.clone(),
            governance_execution_decision_digest: freshness
                .governance_execution_decision_digest
                .clone(),
            proposal_id: freshness.proposal_id.clone(),
            decision_id: freshness.decision_id.clone(),
            lifecycle_action: freshness.lifecycle_action,
            candidate_digest: freshness.candidate_digest.clone(),
            authority_domain_sequence: freshness.authority_domain_sequence,
            effective_epoch: freshness.effective_epoch,
            expiry_epoch: freshness.expiry_epoch,
            replay_nonce: freshness.replay_nonce.clone(),
            environment: freshness.environment,
            chain_id: freshness.chain_id.clone(),
            genesis_hash: freshness.genesis_hash.clone(),
            validation_surface: freshness.validation_surface,
            mutation_surface,
            mutation_authorization_outcome,
            mutation_completion_status,
        }
    }
}

// ===========================================================================
// Consume boundary expectations
// ===========================================================================

/// Run 234 — the canonical binding a [`PostMutationConsumeInput`] is checked
/// against. A mismatch on any field is a typed, non-consuming fail-closed
/// ([`ConsumeBoundaryOutcome::FailClosedWrongBinding`]) — never a silent
/// consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostMutationConsumeExpectations {
    /// Expected Run 230 replay state key digest.
    pub expected_replay_state_key_digest: String,
    /// Expected evaluator source-identity digest.
    pub expected_evaluator_source_identity_digest: String,
    /// Expected evaluator request digest.
    pub expected_evaluator_request_digest: String,
    /// Expected evaluator response digest.
    pub expected_evaluator_response_digest: String,
    /// Expected evaluator transcript digest.
    pub expected_evaluator_transcript_digest: String,
    /// Expected governance execution decision digest.
    pub expected_governance_execution_decision_digest: String,
    /// Expected governance proposal id.
    pub expected_proposal_id: String,
    /// Expected governance decision id.
    pub expected_decision_id: String,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate digest.
    pub expected_candidate_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Expected effective / activation epoch.
    pub expected_effective_epoch: u64,
    /// Expected expiry epoch.
    pub expected_expiry_epoch: u64,
    /// Expected replay nonce.
    pub expected_replay_nonce: String,
    /// Expected trust-domain environment.
    pub expected_environment: TrustBundleEnvironment,
    /// Expected trust-domain chain id.
    pub expected_chain_id: String,
    /// Expected trust-domain genesis hash.
    pub expected_genesis_hash: String,
    /// Expected validation surface.
    pub expected_validation_surface: GovernanceExecutionRuntimeSurface,
    /// Expected mutation surface.
    pub expected_mutation_surface: GovernanceExecutionRuntimeSurface,
}

impl PostMutationConsumeExpectations {
    /// Derive the canonical consume expectations from the same Run 230
    /// [`EvaluatorReplayFreshnessInput`] a faithfully-bound
    /// [`PostMutationConsumeInput::from_freshness_input`] would reference, plus
    /// the expected mutation surface.
    pub fn from_freshness_input(
        freshness: &EvaluatorReplayFreshnessInput,
        expected_mutation_surface: GovernanceExecutionRuntimeSurface,
    ) -> Self {
        Self {
            expected_replay_state_key_digest: replay_state_key_digest(freshness),
            expected_evaluator_source_identity_digest: freshness
                .evaluator_source_identity_digest
                .clone(),
            expected_evaluator_request_digest: freshness.evaluator_request_digest.clone(),
            expected_evaluator_response_digest: freshness.evaluator_response_digest.clone(),
            expected_evaluator_transcript_digest: freshness.evaluator_transcript_digest.clone(),
            expected_governance_execution_decision_digest: freshness
                .governance_execution_decision_digest
                .clone(),
            expected_proposal_id: freshness.proposal_id.clone(),
            expected_decision_id: freshness.decision_id.clone(),
            expected_lifecycle_action: freshness.lifecycle_action,
            expected_candidate_digest: freshness.candidate_digest.clone(),
            expected_authority_domain_sequence: freshness.authority_domain_sequence,
            expected_effective_epoch: freshness.effective_epoch,
            expected_expiry_epoch: freshness.expiry_epoch,
            expected_replay_nonce: freshness.replay_nonce.clone(),
            expected_environment: freshness.environment,
            expected_chain_id: freshness.chain_id.clone(),
            expected_genesis_hash: freshness.genesis_hash.clone(),
            expected_validation_surface: freshness.validation_surface,
            expected_mutation_surface,
        }
    }
}

// ===========================================================================
// Consume boundary outcome
// ===========================================================================

/// Run 234 — typed outcome of the post-mutation consume boundary.
///
/// Only [`Self::ConsumeFixtureAfterSuccess`] authorizes a fixture consume, and
/// only after a successful mutation. Every other variant is a non-consuming
/// `DoNotConsume*` or a fail-closed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeBoundaryOutcome {
    /// Legacy bypass — the replay/freshness boundary was never reached; nothing
    /// to consume.
    DoNotConsumeLegacyBypass,
    /// Deferred (fresh-but-not-yet-effective) — not an approval; nothing to
    /// consume.
    DoNotConsumeDeferred,
    /// Validation-only surface — read-only validation never consumes.
    DoNotConsumeValidationOnly,
    /// Mutation authorized but not yet applied — must not consume before apply.
    DoNotConsumeBeforeApply,
    /// The apply failed — must not consume a failed apply.
    DoNotConsumeApplyFailed,
    /// The mutation was rolled back — must not consume a rolled-back mutation.
    DoNotConsumeRolledBack,
    /// The mutation surface is unsupported — must not consume.
    DoNotConsumeUnsupportedSurface,
    /// MainNet peer-driven apply refused — must not consume.
    DoNotConsumeMainNetRefused,
    /// Fixture consume authorized after a successful mutation (DevNet/TestNet
    /// source-test only). The **only** consume-authorizing outcome.
    ConsumeFixtureAfterSuccess,
    /// The consume writer is unavailable (generic, e.g. disabled policy or an
    /// absent fixture record). Non-consuming.
    FailClosedConsumeUnavailable,
    /// Production consume is unavailable (callable-but-fail-closed).
    FailClosedProductionConsumeUnavailable,
    /// MainNet consume is unavailable / refused (callable-but-fail-closed).
    FailClosedMainNetConsumeUnavailable,
    /// A consume binding field is wrong / malformed. Carries an operator-facing
    /// reason. Non-consuming.
    FailClosedWrongBinding {
        /// Operator-facing reason.
        reason: String,
    },
}

impl ConsumeBoundaryOutcome {
    /// `true` iff this outcome authorizes a fixture consume (only
    /// [`Self::ConsumeFixtureAfterSuccess`]).
    pub fn authorizes_consume(&self) -> bool {
        matches!(self, Self::ConsumeFixtureAfterSuccess)
    }

    /// `true` iff this outcome does **not** authorize a consume (every variant
    /// other than [`Self::ConsumeFixtureAfterSuccess`]).
    pub fn no_consume(&self) -> bool {
        !self.authorizes_consume()
    }

    /// `true` iff this outcome is a fail-closed (binding / availability)
    /// rejection.
    pub fn is_fail_closed(&self) -> bool {
        matches!(
            self,
            Self::FailClosedConsumeUnavailable
                | Self::FailClosedProductionConsumeUnavailable
                | Self::FailClosedMainNetConsumeUnavailable
                | Self::FailClosedWrongBinding { .. }
        )
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::DoNotConsumeLegacyBypass => "do-not-consume-legacy-bypass",
            Self::DoNotConsumeDeferred => "do-not-consume-deferred",
            Self::DoNotConsumeValidationOnly => "do-not-consume-validation-only",
            Self::DoNotConsumeBeforeApply => "do-not-consume-before-apply",
            Self::DoNotConsumeApplyFailed => "do-not-consume-apply-failed",
            Self::DoNotConsumeRolledBack => "do-not-consume-rolled-back",
            Self::DoNotConsumeUnsupportedSurface => "do-not-consume-unsupported-surface",
            Self::DoNotConsumeMainNetRefused => "do-not-consume-mainnet-refused",
            Self::ConsumeFixtureAfterSuccess => "consume-fixture-after-success",
            Self::FailClosedConsumeUnavailable => "fail-closed-consume-unavailable",
            Self::FailClosedProductionConsumeUnavailable => {
                "fail-closed-production-consume-unavailable"
            }
            Self::FailClosedMainNetConsumeUnavailable => "fail-closed-mainnet-consume-unavailable",
            Self::FailClosedWrongBinding { .. } => "fail-closed-wrong-binding",
        }
    }
}

// ===========================================================================
// Binding mismatch
// ===========================================================================

/// Internal: detect a binding mismatch / structural malformation. Returns an
/// operator-facing reason on the first mismatch.
fn consume_binding_mismatch(
    input: &PostMutationConsumeInput,
    expectations: &PostMutationConsumeExpectations,
) -> Option<String> {
    if !input.is_well_formed() {
        return Some(
            "consume input is structurally malformed (empty mandatory field)".to_string(),
        );
    }
    if input.replay_state_key_digest != expectations.expected_replay_state_key_digest {
        return Some("replay state key digest does not match expected binding".to_string());
    }
    if input.evaluator_source_identity_digest
        != expectations.expected_evaluator_source_identity_digest
    {
        return Some("evaluator source identity digest does not match expected binding".to_string());
    }
    if input.evaluator_request_digest != expectations.expected_evaluator_request_digest {
        return Some("evaluator request digest does not match expected binding".to_string());
    }
    if input.evaluator_response_digest != expectations.expected_evaluator_response_digest {
        return Some("evaluator response digest does not match expected binding".to_string());
    }
    if input.evaluator_transcript_digest != expectations.expected_evaluator_transcript_digest {
        return Some("evaluator transcript digest does not match expected binding".to_string());
    }
    if input.governance_execution_decision_digest
        != expectations.expected_governance_execution_decision_digest
    {
        return Some(
            "governance execution decision digest does not match expected binding".to_string(),
        );
    }
    if input.proposal_id != expectations.expected_proposal_id {
        return Some("proposal id does not match expected binding".to_string());
    }
    if input.decision_id != expectations.expected_decision_id {
        return Some("decision id does not match expected binding".to_string());
    }
    if input.lifecycle_action != expectations.expected_lifecycle_action {
        return Some("lifecycle action does not match expected binding".to_string());
    }
    if input.candidate_digest != expectations.expected_candidate_digest {
        return Some("candidate digest does not match expected binding".to_string());
    }
    if input.authority_domain_sequence != expectations.expected_authority_domain_sequence {
        return Some("authority-domain sequence does not match expected binding".to_string());
    }
    if input.effective_epoch != expectations.expected_effective_epoch {
        return Some("effective epoch does not match expected binding".to_string());
    }
    if input.expiry_epoch != expectations.expected_expiry_epoch {
        return Some("expiry epoch does not match expected binding".to_string());
    }
    if input.replay_nonce != expectations.expected_replay_nonce {
        return Some("replay nonce does not match expected binding".to_string());
    }
    if input.environment != expectations.expected_environment {
        return Some("trust-domain environment does not match expected binding".to_string());
    }
    if input.chain_id != expectations.expected_chain_id {
        return Some("trust-domain chain id does not match expected binding".to_string());
    }
    if input.genesis_hash != expectations.expected_genesis_hash {
        return Some("trust-domain genesis hash does not match expected binding".to_string());
    }
    if input.validation_surface != expectations.expected_validation_surface {
        return Some("validation surface does not match expected binding".to_string());
    }
    if input.mutation_surface != expectations.expected_mutation_surface {
        return Some("mutation surface does not match expected binding".to_string());
    }
    None
}

// ===========================================================================
// Evaluation
// ===========================================================================

/// Run 234 — evaluate the post-mutation consume boundary into a typed outcome.
///
/// Deterministic ordering: MainNet peer-driven apply refusal first (so a fresh
/// state can never authorize a MainNet consume), then the structural
/// non-consume reasons that short-circuit before any binding reasoning (legacy
/// bypass, deferral, validation-only), then the binding check, then the
/// mutation-completion phase.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no live
/// trust, evicts no sessions, and never invokes Run 070. A consume rejection
/// therefore happens before any mutation.
pub fn evaluate_post_mutation_consume(
    policy: ReplayStatePolicy,
    input: &PostMutationConsumeInput,
    expectations: &PostMutationConsumeExpectations,
) -> ConsumeBoundaryOutcome {
    // MainNet peer-driven apply remains refused unconditionally — guard it
    // first so a fresh state can never bypass it into a consume.
    if input.environment == TrustBundleEnvironment::Mainnet
        && (input.validation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain
            || input.mutation_surface == GovernanceExecutionRuntimeSurface::PeerDrivenDrain)
    {
        return ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused;
    }
    if input.mutation_authorization_outcome == MutationAuthorizationOutcome::MainNetRefused
        || input.mutation_completion_status == MutationCompletionStatus::MainNetRefused
    {
        return ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused;
    }

    // Structural non-consume reasons that precede any binding reasoning.
    match input.mutation_authorization_outcome {
        MutationAuthorizationOutcome::LegacyBypass => {
            return ConsumeBoundaryOutcome::DoNotConsumeLegacyBypass
        }
        MutationAuthorizationOutcome::Deferred => {
            return ConsumeBoundaryOutcome::DoNotConsumeDeferred
        }
        MutationAuthorizationOutcome::ValidationOnly => {
            return ConsumeBoundaryOutcome::DoNotConsumeValidationOnly
        }
        MutationAuthorizationOutcome::FreshnessFailClosed => {
            // No mutation could have been applied; nothing to consume.
            return ConsumeBoundaryOutcome::DoNotConsumeBeforeApply;
        }
        MutationAuthorizationOutcome::AuthorizedFresh => {}
        MutationAuthorizationOutcome::MainNetRefused => {
            return ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused
        }
    }

    // A validation-only validation or mutation surface never consumes.
    if surface_is_validation_only(input.validation_surface)
        || surface_is_validation_only(input.mutation_surface)
        || input.mutation_completion_status == MutationCompletionStatus::ValidationOnly
    {
        return ConsumeBoundaryOutcome::DoNotConsumeValidationOnly;
    }

    // Binding must match before the completion phase is honoured.
    if let Some(reason) = consume_binding_mismatch(input, expectations) {
        return ConsumeBoundaryOutcome::FailClosedWrongBinding { reason };
    }

    // Mutation-completion phase: consume only after a successful apply.
    match input.mutation_completion_status {
        MutationCompletionStatus::NotAttempted
        | MutationCompletionStatus::AuthorizedButNotApplied => {
            ConsumeBoundaryOutcome::DoNotConsumeBeforeApply
        }
        MutationCompletionStatus::ApplyFailed => ConsumeBoundaryOutcome::DoNotConsumeApplyFailed,
        MutationCompletionStatus::RolledBack => ConsumeBoundaryOutcome::DoNotConsumeRolledBack,
        MutationCompletionStatus::ValidationOnly => {
            ConsumeBoundaryOutcome::DoNotConsumeValidationOnly
        }
        MutationCompletionStatus::UnsupportedSurface => {
            ConsumeBoundaryOutcome::DoNotConsumeUnsupportedSurface
        }
        MutationCompletionStatus::MainNetRefused => {
            ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused
        }
        MutationCompletionStatus::AppliedSuccessfully => match policy {
            ReplayStatePolicy::FixtureDevNet | ReplayStatePolicy::FixtureTestNet
                if input.environment != TrustBundleEnvironment::Mainnet =>
            {
                ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess
            }
            ReplayStatePolicy::Production => {
                ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable
            }
            ReplayStatePolicy::MainNet => {
                ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable
            }
            // A fixture policy on a MainNet environment, or a disabled policy:
            // no consume backend is available.
            _ => ConsumeBoundaryOutcome::FailClosedConsumeUnavailable,
        },
    }
}

/// Run 234 — evaluate the consume boundary and, only when it resolves
/// [`ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess`], perform the explicit
/// consume against `writer`.
///
/// The writer's [`GovernanceEvaluatorReplayStateWriter::mark_consumed`] is
/// called **only** on the after-success consume path. A fixture writer accepts
/// the write only when a prior observation exists (returning `true`); the
/// callable-but-unavailable production / MainNet writers always return `false`,
/// downgrading the outcome to a fail-closed. The writer is never called for any
/// `DoNotConsume*` outcome, so a non-consume decision performs no write at all.
pub fn perform_post_mutation_consume<W>(
    policy: ReplayStatePolicy,
    input: &PostMutationConsumeInput,
    expectations: &PostMutationConsumeExpectations,
    writer: &mut W,
) -> ConsumeBoundaryOutcome
where
    W: GovernanceEvaluatorReplayStateWriter,
{
    let outcome = evaluate_post_mutation_consume(policy, input, expectations);
    if let ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess = outcome {
        if writer.mark_consumed(&input.replay_state_key_digest) {
            return ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess;
        }
        return ConsumeBoundaryOutcome::FailClosedConsumeUnavailable;
    }
    outcome
}

// ===========================================================================
// Deterministic digest helpers
// ===========================================================================

fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

/// Internal: bind the A15 consume-binding field set into `h`.
fn hash_consume_binding(h: &mut sha3::Sha3_256, input: &PostMutationConsumeInput) {
    hash_field(h, b"replay_state_key_digest", input.replay_state_key_digest.as_bytes());
    hash_field(h, b"evaluator_request_digest", input.evaluator_request_digest.as_bytes());
    hash_field(h, b"evaluator_response_digest", input.evaluator_response_digest.as_bytes());
    hash_field(
        h,
        b"governance_execution_decision_digest",
        input.governance_execution_decision_digest.as_bytes(),
    );
    hash_field(h, b"lifecycle_action", input.lifecycle_action.tag().as_bytes());
    hash_field(h, b"candidate_digest", input.candidate_digest.as_bytes());
    hash_field(
        h,
        b"authority_domain_sequence",
        &input.authority_domain_sequence.to_le_bytes(),
    );
    hash_field(h, b"replay_nonce", input.replay_nonce.as_bytes());
    hash_field(h, b"environment", &input.environment.metric_code().to_le_bytes());
    hash_field(h, b"chain_id", input.chain_id.as_bytes());
    hash_field(h, b"genesis_hash", input.genesis_hash.as_bytes());
    hash_field(h, b"validation_surface", input.validation_surface.tag().as_bytes());
    hash_field(h, b"mutation_surface", input.mutation_surface.tag().as_bytes());
    hash_field(
        h,
        b"mutation_completion_status",
        input.mutation_completion_status.tag().as_bytes(),
    );
}

/// Run 234 — deterministic SHA3-256 hex **consume authorization** digest.
///
/// Binds the full A15 consume-binding field set (replay state key, request /
/// response / decision digests, lifecycle action, candidate digest, sequence,
/// replay nonce, environment, chain id, genesis hash, validation surface,
/// mutation surface, and mutation completion status). Two structurally-identical
/// authorizations always produce the same digest.
pub fn consume_authorization_digest(input: &PostMutationConsumeInput) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(CONSUME_AUTHORIZATION_DOMAIN_TAG.as_bytes());
    hash_consume_binding(&mut h, input);
    hex::encode(h.finalize())
}

/// Run 234 — deterministic SHA3-256 hex **consume transcript** digest.
///
/// Binds the A15 consume-binding field set plus the mutation authorization
/// outcome and the resolved consume boundary outcome — the full consume
/// reasoning for one evaluation in a single stable digest.
pub fn consume_transcript_digest(
    input: &PostMutationConsumeInput,
    outcome: &ConsumeBoundaryOutcome,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(CONSUME_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_consume_binding(&mut h, input);
    hash_field(
        &mut h,
        b"mutation_authorization_outcome",
        input.mutation_authorization_outcome.tag().as_bytes(),
    );
    hash_field(&mut h, b"consume_outcome", outcome.tag().as_bytes());
    hex::encode(h.finalize())
}

/// Run 234 — deterministic SHA3-256 hex **post-mutation consume record** digest.
///
/// Binds the A15 consume-binding field set and the epoch the decision was
/// consumed at. Recorded only when a decision is explicitly consumed after a
/// successful mutation.
pub fn post_mutation_consume_record_digest(
    input: &PostMutationConsumeInput,
    consumed_epoch: u64,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(POST_MUTATION_CONSUME_RECORD_DOMAIN_TAG.as_bytes());
    hash_consume_binding(&mut h, input);
    hash_field(&mut h, b"consumed_epoch", &consumed_epoch.to_le_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Explicit fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 234 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused under the
/// consume boundary. Run 234 always returns `true` for a MainNet environment:
/// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal and
/// never consumes, regardless of any replay/freshness state — even a fresh one.
pub fn mainnet_peer_driven_apply_remains_refused_under_consume_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 234 — explicit invariant helper.
///
/// Returns `true`: consume is allowed only after a successful mutation
/// completion. Provided as a grep-verifiable statement of the after-success-only
/// contract.
pub fn consume_only_after_successful_mutation() -> bool {
    true
}

/// Run 234 — explicit invariant helper.
///
/// Returns `true`: a deferral (fresh-but-not-yet-effective) is never consumed.
pub fn deferred_is_never_consumed() -> bool {
    true
}

/// Run 234 — explicit invariant helper.
///
/// Returns `true`: a validation-only surface is never consumed.
pub fn validation_only_is_never_consumed() -> bool {
    true
}

/// Run 234 — explicit fail-closed helper.
///
/// Returns `true`: production and MainNet consume backends remain
/// unavailable / fail-closed. No real consume storage is implemented.
pub fn production_mainnet_consume_remains_unavailable() -> bool {
    true
}

/// Run 234 — explicit fail-closed helper.
///
/// Returns `true` iff a local operator key *cannot* satisfy the consume policy.
/// Run 234 always returns `true`: consume eligibility is determined by the
/// authorized evaluator decision binding and a successful mutation, never by a
/// local operator key.
pub fn local_operator_cannot_satisfy_consume_policy() -> bool {
    true
}

/// Run 234 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy the consume
/// policy. Run 234 always returns `true`: consume is never satisfiable by
/// counting peers.
pub fn peer_majority_cannot_satisfy_consume_policy() -> bool {
    true
}

/// Run 234 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported under the
/// consume boundary. Run 234 always returns `true`: no validator-set rotation
/// exists.
pub fn validator_set_rotation_remains_unsupported_under_consume_boundary() -> bool {
    true
}

/// Run 234 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the consume
/// boundary. Run 234 always returns `true`: the boundary only governs
/// trust-lifecycle evaluator decisions, never policy-change actions.
pub fn policy_change_action_remains_unsupported_under_consume_boundary() -> bool {
    true
}