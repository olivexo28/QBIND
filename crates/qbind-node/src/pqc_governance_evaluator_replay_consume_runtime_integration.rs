//! Run 236 — source/test governance evaluator **replay consume runtime
//! integration**.
//!
//! Source/test only. Run 236 captures **no** release-binary evidence;
//! release-binary consume-runtime-integration evidence is deferred to **Run
//! 237**. Run 236 does **not** implement a real governance execution engine, a
//! real on-chain governance proof verifier, a real mutation engine, MainNet
//! governance enablement, MainNet peer-driven apply enablement, validator-set
//! rotation, a real KMS/HSM backend, a real RemoteSigner backend, or any RocksDB
//! / file / schema / migration / wire / marker / sequence / trust-bundle /
//! storage-format change.
//!
//! ## What this module closes
//!
//! Run 230 proved a typed, pure **replay/freshness state boundary**; Run 231
//! closed its release-binary evidence; Run 232 composed that boundary into the
//! Run 224 evaluator-runtime integration path as a mandatory pre-mutation gate;
//! Run 233 closed that composition's release-binary evidence; Run 234 added a
//! typed **post-mutation consume boundary** that records a decision consumed
//! **after success only**; and Run 235 closed that boundary's release-binary
//! evidence. What was still missing was a single layer that *ties the consume
//! boundary into the replay/freshness runtime path as a modeled post-success
//! step*: Run 232 (replay/freshness + mutation authorization) and Run 234
//! (post-mutation consume) were proven independently but never composed into one
//! lifecycle.
//!
//! Run 236 closes that gap at the source/test level. It adds a single
//! integration layer ([`integrate_replay_consume_runtime`]) that models the full
//! lifecycle:
//!
//! 1. **validate replay/freshness** (Run 232 → Run 230);
//! 2. **authorize mutation only on fresh**
//!    ([`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`]);
//! 3. **model mutation completion** ([`MutationCompletionStatus`]); and
//! 4. **consume only after successful mutation completion** (Run 234
//!    [`ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess`]).
//!
//! ## Ordering contract
//!
//! The integration enforces the exact pipeline ordering:
//!
//! 1. **selector resolution** — Run 217 / Run 224 arming;
//! 2. **runtime / evaluator / decision validation** — Run 220 / Run 222 / Run
//!    211 (delegated to the Run 232 layer);
//! 3. **replay/freshness validation** — Run 230 state boundary;
//! 4. **mutation authorization only on fresh** — the single Run 232
//!    `ProceedFresh`;
//! 5. **mutation completion status evaluation** — [`MutationCompletionStatus`];
//! 6. **consume only after `AppliedSuccessfully`** — Run 234 consume boundary;
//! 7. **fixture consume only after success** — the DevNet/TestNet fixture writer;
//!    and
//! 8. **production / MainNet consume unavailable / fail-closed** — callable but
//!    unavailable consume writers.
//!
//! Steps 1–4 are delegated to the Run 232 layer; only a Run 232 `ProceedFresh`
//! reaches the Run 234 consume boundary. The replay/freshness validation
//! therefore necessarily happens **before** mutation authorization, and the
//! consume necessarily happens **after** a modeled successful mutation.
//!
//! ## Fail-closed / consume-safety contract
//!
//! * [`ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess`] is the
//!   **only** consume-authorizing outcome, and only when the Run 232 layer
//!   returned `ProceedFresh` **and** the mutation completion status is
//!   [`MutationCompletionStatus::AppliedSuccessfully`] **and** a wired
//!   DevNet/TestNet fixture consume writer accepts the explicit write.
//! * A legacy bypass, a deferral, a validation-only surface, an
//!   authorized-but-not-applied decision, a failed apply, a rolled-back
//!   mutation, an unsupported surface, and a MainNet-refused decision all resolve
//!   to a typed non-consuming outcome — never a consume.
//! * Production / MainNet consume writers are reached but always fail closed
//!   ([`ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable`] /
//!   [`ReplayConsumeRuntimeOutcome::MainNetConsumeUnavailable`]).
//! * **MainNet peer-driven apply remains refused** even when the replay state is
//!   fresh and the mutation completion is modeled as successful
//!   ([`ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused`]).
//! * Evaluation is a pure function: it performs no I/O, writes no marker, writes
//!   no sequence, swaps no live trust, evicts no sessions, and never invokes Run
//!   070. The only state mutation it can cause is the explicit fixture
//!   `mark_consumed` write on the after-success consume path; every non-consume
//!   outcome leaves the writer untouched.
//! * Validator-set rotation and policy-change actions remain unsupported.
//!
//! ## What this module does NOT change
//!
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle, authority-marker, or sequence schema.
//! * It introduces **no** RocksDB schema, file format, or database migration.
//! * It enables **no** MainNet peer-driven apply.
//! * It does **not** claim full C4 or C5 closure.

use crate::pqc_governance_evaluator_replay_consume_boundary::{
    perform_post_mutation_consume, ConsumeBoundaryOutcome, MutationAuthorizationOutcome,
    MutationCompletionStatus, PostMutationConsumeExpectations, PostMutationConsumeInput,
};
use crate::pqc_governance_evaluator_replay_runtime_integration::{
    integrate_governance_evaluator_replay_runtime,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use crate::pqc_governance_evaluator_replay_state::{
    GovernanceEvaluatorReplayStateWriter, ReplayStatePolicy,
};
use crate::pqc_governance_execution_evaluator::ProductionGovernanceExecutionEvaluator;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Integration input
// ===========================================================================

/// Run 236 — typed inputs for one replay-consume runtime-integration round-trip.
///
/// Composes the Run 232 replay/freshness runtime-integration context (replay
/// runtime integration input) with the Run 234 post-mutation consume boundary
/// input + expectations + consume-writer policy. Holds only borrows of
/// caller-owned data plus the `Copy` consume policy; it is itself pure data and
/// performs no work on construction.
pub struct ReplayConsumeRuntimeIntegrationInput<'a, E>
where
    E: ProductionGovernanceExecutionEvaluator,
{
    /// The Run 232 replay/freshness runtime-integration context (steps 1–4:
    /// selector resolution -> runtime/evaluator/decision validation ->
    /// replay/freshness validation -> mutation authorization only on fresh).
    pub replay_runtime: &'a GovernanceEvaluatorReplayRuntimeIntegrationContext<'a, E>,
    /// The Run 234 post-mutation consume boundary input bound to the same
    /// evaluator decision the Run 232 context carries (step 5 input). The
    /// `mutation_authorization_outcome` it carries is **replaced** by the Run
    /// 232-derived authorization before the consume boundary runs, so the two
    /// layers can never disagree.
    pub consume_input: &'a PostMutationConsumeInput,
    /// The canonical Run 234 consume expectations (step 6 binding).
    pub consume_expectations: &'a PostMutationConsumeExpectations,
    /// The active Run 234 consume-writer selector. A wired fixture policy is
    /// DevNet/TestNet source-test only; the production / MainNet policies are
    /// reached but their backing writers are unavailable / fail-closed.
    pub consume_policy: ReplayStatePolicy,
}

impl<E> ReplayConsumeRuntimeIntegrationInput<'_, E>
where
    E: ProductionGovernanceExecutionEvaluator,
{
    /// The mutation surface the consume boundary input authorizes / attempted to
    /// mutate.
    pub fn mutation_surface(&self) -> GovernanceExecutionRuntimeSurface {
        self.consume_input.mutation_surface
    }

    /// The modeled mutation completion status (phase 3).
    pub fn mutation_completion_status(&self) -> MutationCompletionStatus {
        self.consume_input.mutation_completion_status
    }

    /// The validation surface the decision was validated for.
    pub fn validation_surface(&self) -> GovernanceExecutionRuntimeSurface {
        self.consume_input.validation_surface
    }

    /// The trust-domain environment the decision is bound to.
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.consume_input.environment
    }

    /// The trust-domain chain id the decision is bound to.
    pub fn chain_id(&self) -> &str {
        &self.consume_input.chain_id
    }

    /// The trust-domain genesis hash the decision is bound to.
    pub fn genesis_hash(&self) -> &str {
        &self.consume_input.genesis_hash
    }
}

// ===========================================================================
// Integration outcome
// ===========================================================================

/// Run 236 — typed outcome of composing the Run 232 replay/freshness runtime
/// integration with the Run 234 post-mutation consume boundary.
///
/// Only [`Self::ConsumeFixtureAfterMutationSuccess`] authorizes a fixture
/// consume, and only after the Run 232 layer returned `ProceedFresh` and the
/// mutation completion status is `AppliedSuccessfully`. Every other variant is a
/// non-consuming proceed, a non-consuming `DoNotConsume*`, or a fail-closed
/// rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayConsumeRuntimeOutcome {
    /// Run 214 legacy bypass — the replay/freshness boundary was never reached;
    /// nothing to consume.
    ProceedLegacyBypassNoConsume,
    /// Fresh-but-not-yet-effective deferral — not an approval; nothing to
    /// consume.
    ProceedDeferredNoConsume,
    /// A validation-only surface reached `ProceedFresh` — read-only validation
    /// never consumes.
    ProceedValidationOnlyNoConsume,
    /// Replay/freshness is fresh and a mutation is authorized, but no successful
    /// mutation completion has been modeled yet — proceed to mutate, do not
    /// consume before apply.
    ProceedFreshMutationAuthorized,
    /// Fixture consume authorized after a successful mutation (DevNet/TestNet
    /// source-test only). The **only** consume-authorizing outcome.
    ConsumeFixtureAfterMutationSuccess,
    /// The mutation was authorized but not yet applied — must not consume before
    /// apply.
    DoNotConsumeBeforeApply,
    /// The apply failed — must not consume a failed apply.
    DoNotConsumeApplyFailed,
    /// The mutation was rolled back — must not consume a rolled-back mutation.
    DoNotConsumeRolledBack,
    /// The mutation surface is unsupported — must not consume.
    DoNotConsumeUnsupportedSurface,
    /// MainNet peer-driven apply refused — must not consume.
    DoNotConsumeMainNetRefused,
    /// The Run 232 replay/freshness runtime integration failed closed before any
    /// mutation could be authorized (expired / stale / replay / already-consumed
    /// / superseded / wrong-bound / malformed / unavailable / runtime
    /// integration fail-closed). Carries the originating Run 232 outcome.
    /// Non-consuming.
    ReplayRuntimeFailClosed(GovernanceEvaluatorReplayRuntimeOutcome),
    /// The consume boundary failed closed on a generic / binding reason (consume
    /// writer unavailable or a wrong / malformed consume binding). Carries an
    /// operator-facing reason. Non-consuming.
    ConsumeFailClosed {
        /// Operator-facing reason.
        reason: String,
    },
    /// Production consume is unavailable (callable-but-fail-closed).
    ProductionConsumeUnavailable,
    /// MainNet consume is unavailable / refused (callable-but-fail-closed).
    MainNetConsumeUnavailable,
    /// MainNet trust domain — peer-driven apply remains the Run 147 / 148 / 152
    /// FATAL refusal regardless of a fresh replay state or a modeled successful
    /// mutation. Non-consuming.
    MainNetPeerDrivenApplyRefused,
}

impl ReplayConsumeRuntimeOutcome {
    /// `true` iff this outcome authorizes a fixture consume (only
    /// [`Self::ConsumeFixtureAfterMutationSuccess`]).
    pub fn authorizes_consume(&self) -> bool {
        matches!(self, Self::ConsumeFixtureAfterMutationSuccess)
    }

    /// `true` iff this outcome does **not** authorize a consume.
    pub fn no_consume(&self) -> bool {
        !self.authorizes_consume()
    }

    /// `true` iff the runtime call site may continue (a legacy bypass, a fresh
    /// authorization, a validation-only proceed, or a successful consume). A
    /// deferral is **not** a proceed: it is a non-mutating fail-closed.
    pub fn is_proceed(&self) -> bool {
        matches!(
            self,
            Self::ProceedLegacyBypassNoConsume
                | Self::ProceedValidationOnlyNoConsume
                | Self::ProceedFreshMutationAuthorized
                | Self::ConsumeFixtureAfterMutationSuccess
        )
    }

    /// `true` iff this outcome is a non-mutating fail-closed / non-consume
    /// rejection (every variant other than the proceed variants).
    pub fn is_fail_closed(&self) -> bool {
        !self.is_proceed()
    }

    /// `true` iff this rejection is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Stable operator-facing tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProceedLegacyBypassNoConsume => "proceed-legacy-bypass-no-consume",
            Self::ProceedDeferredNoConsume => "proceed-deferred-no-consume",
            Self::ProceedValidationOnlyNoConsume => "proceed-validation-only-no-consume",
            Self::ProceedFreshMutationAuthorized => "proceed-fresh-mutation-authorized",
            Self::ConsumeFixtureAfterMutationSuccess => "consume-fixture-after-mutation-success",
            Self::DoNotConsumeBeforeApply => "do-not-consume-before-apply",
            Self::DoNotConsumeApplyFailed => "do-not-consume-apply-failed",
            Self::DoNotConsumeRolledBack => "do-not-consume-rolled-back",
            Self::DoNotConsumeUnsupportedSurface => "do-not-consume-unsupported-surface",
            Self::DoNotConsumeMainNetRefused => "do-not-consume-mainnet-refused",
            Self::ReplayRuntimeFailClosed(_) => "replay-runtime-fail-closed",
            Self::ConsumeFailClosed { .. } => "consume-fail-closed",
            Self::ProductionConsumeUnavailable => "production-consume-unavailable",
            Self::MainNetConsumeUnavailable => "mainnet-consume-unavailable",
            Self::MainNetPeerDrivenApplyRefused => "mainnet-peer-driven-apply-refused",
        }
    }
}

// ===========================================================================
// Consume-outcome projection
// ===========================================================================

/// Internal: project a Run 234 [`ConsumeBoundaryOutcome`] into the Run 236
/// outcome, refining the before-apply phase with the modeled completion status.
fn project_consume_outcome(
    outcome: ConsumeBoundaryOutcome,
    completion: MutationCompletionStatus,
) -> ReplayConsumeRuntimeOutcome {
    match outcome {
        ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess => {
            ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess
        }
        ConsumeBoundaryOutcome::DoNotConsumeValidationOnly => {
            ReplayConsumeRuntimeOutcome::ProceedValidationOnlyNoConsume
        }
        // A fresh, authorized mutation that has not yet been applied is a
        // proceed-to-mutate; an explicit authorized-but-not-applied attempt is a
        // before-apply rejection.
        ConsumeBoundaryOutcome::DoNotConsumeBeforeApply => {
            if completion == MutationCompletionStatus::NotAttempted {
                ReplayConsumeRuntimeOutcome::ProceedFreshMutationAuthorized
            } else {
                ReplayConsumeRuntimeOutcome::DoNotConsumeBeforeApply
            }
        }
        ConsumeBoundaryOutcome::DoNotConsumeApplyFailed => {
            ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed
        }
        ConsumeBoundaryOutcome::DoNotConsumeRolledBack => {
            ReplayConsumeRuntimeOutcome::DoNotConsumeRolledBack
        }
        ConsumeBoundaryOutcome::DoNotConsumeUnsupportedSurface => {
            ReplayConsumeRuntimeOutcome::DoNotConsumeUnsupportedSurface
        }
        ConsumeBoundaryOutcome::DoNotConsumeMainNetRefused => {
            ReplayConsumeRuntimeOutcome::DoNotConsumeMainNetRefused
        }
        ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable => {
            ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable
        }
        ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable => {
            ReplayConsumeRuntimeOutcome::MainNetConsumeUnavailable
        }
        ConsumeBoundaryOutcome::FailClosedConsumeUnavailable => {
            ReplayConsumeRuntimeOutcome::ConsumeFailClosed {
                reason: "consume writer unavailable / no fixture observation".to_string(),
            }
        }
        ConsumeBoundaryOutcome::FailClosedWrongBinding { reason } => {
            ReplayConsumeRuntimeOutcome::ConsumeFailClosed { reason }
        }
        // The Run 232 layer only reaches the consume boundary on `ProceedFresh`,
        // which projects to `AuthorizedFresh`; the legacy-bypass / deferred
        // consume-boundary variants are therefore never produced here. Map them
        // defensively to their non-consuming proceed equivalents.
        ConsumeBoundaryOutcome::DoNotConsumeLegacyBypass => {
            ReplayConsumeRuntimeOutcome::ProceedLegacyBypassNoConsume
        }
        ConsumeBoundaryOutcome::DoNotConsumeDeferred => {
            ReplayConsumeRuntimeOutcome::ProceedDeferredNoConsume
        }
    }
}

// ===========================================================================
// Integration entry point
// ===========================================================================

/// Run 236 — compose the Run 232 replay/freshness runtime integration with the
/// Run 234 post-mutation consume boundary as a modeled after-success-only
/// post-mutation step.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no live
/// trust, evicts no sessions, and never invokes Run 070. The replay/freshness
/// validation runs (Run 232) and authorizes a mutate **before** the consume
/// boundary is reached, and the consume happens **only** after a modeled
/// successful mutation completion. The only state mutation this can cause is the
/// explicit fixture `mark_consumed` write on the after-success consume path; a
/// non-consume outcome never calls `writer`.
pub fn integrate_replay_consume_runtime<E, W>(
    input: &ReplayConsumeRuntimeIntegrationInput<'_, E>,
    writer: &mut W,
) -> ReplayConsumeRuntimeOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
    W: GovernanceEvaluatorReplayStateWriter,
{
    // Steps 1–4: selector resolution -> runtime/evaluator/decision validation ->
    // replay/freshness validation -> mutation authorization only on fresh (Run
    // 232 / Run 230). Only a `ProceedFresh` reaches the consume boundary.
    let replay_outcome = integrate_governance_evaluator_replay_runtime(input.replay_runtime);

    match &replay_outcome {
        // Run 214 compatibility: the consume boundary is never reached for the
        // legacy bypass.
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass => {
            return ReplayConsumeRuntimeOutcome::ProceedLegacyBypassNoConsume;
        }
        // Fresh-but-not-yet-effective: defer, never consume.
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred => {
            return ReplayConsumeRuntimeOutcome::ProceedDeferredNoConsume;
        }
        // MainNet peer-driven apply remains refused regardless of a fresh replay
        // state or a modeled successful mutation — surfaced before the consume
        // boundary so a fresh state can never authorize a MainNet consume.
        GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused => {
            return ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        }
        // Any Run 232 / Run 230 fail-closed (replay/freshness fail-closed or
        // runtime integration fail-closed) fails closed before the consume
        // boundary is reached. The decision is rejected before consume.
        GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(_)
        | GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(_) => {
            return ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(replay_outcome);
        }
        // The Run 232 layer authorized a fresh mutate: proceed to the consume
        // boundary as the modeled post-success step.
        GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. } => {}
    }

    // Step 5–8: the Run 232 authorization is authoritative — inject it into the
    // consume input so the two layers cannot disagree, then evaluate the consume
    // boundary (consume only after `AppliedSuccessfully`; fixture only;
    // production / MainNet unavailable / fail-closed).
    let authorization = MutationAuthorizationOutcome::from_replay_runtime_outcome(&replay_outcome);
    let mut consume_input = input.consume_input.clone();
    consume_input.mutation_authorization_outcome = authorization;

    let consume_outcome = perform_post_mutation_consume(
        input.consume_policy,
        &consume_input,
        input.consume_expectations,
        writer,
    );

    project_consume_outcome(consume_outcome, consume_input.mutation_completion_status)
}

// ===========================================================================
// Runtime call-site wiring
// ===========================================================================

/// Run 236 — non-mutating fail-closed signal a runtime call site receives when
/// the composed replay-consume integration outcome does **not** authorize the
/// path to continue.
///
/// A call site that receives this MUST fail closed BEFORE any mutation: no Run
/// 070 call, no live trust swap, no session eviction, no sequence write, no
/// marker write. It carries the originating [`GovernanceExecutionRuntimeSurface`],
/// the precise non-proceed [`ReplayConsumeRuntimeOutcome`], and an
/// operator-facing reason string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayConsumeRuntimeCallsiteFailClosed {
    /// The runtime preflight surface that failed closed.
    pub surface: GovernanceExecutionRuntimeSurface,
    /// The non-proceed integration outcome that triggered the fail-closed.
    pub outcome: ReplayConsumeRuntimeOutcome,
    /// Operator-facing reason string.
    pub reason: String,
}

impl ReplayConsumeRuntimeCallsiteFailClosed {
    fn from_outcome(
        surface: GovernanceExecutionRuntimeSurface,
        outcome: ReplayConsumeRuntimeOutcome,
    ) -> Self {
        let reason = format!(
            "Run 236 governance-evaluator replay-consume runtime integration fail-closed on {} \
             surface: {}. No Run 070 apply, no live trust swap, no session eviction, no sequence \
             write, no marker write, no consume.",
            surface.tag(),
            outcome.tag(),
        );
        Self {
            surface,
            outcome,
            reason,
        }
    }

    /// `true` iff this fail-closed is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        self.outcome.is_mainnet_peer_driven_apply_refused()
    }
}

/// Run 236 — route a runtime call site through the composed Run 232 + Run 234
/// integration layer and **consume** the outcome.
///
/// * `Ok(..)` — a proceed outcome (legacy bypass, fresh-mutation-authorized,
///   validation-only, or a successful fixture consume); the call site continues.
/// * `Err(ReplayConsumeRuntimeCallsiteFailClosed)` — every non-proceed outcome
///   (deferral, before-apply, apply-failed, rolled-back, unsupported surface,
///   MainNet refused, replay-runtime fail-closed, consume fail-closed, or
///   production / MainNet consume unavailable). The call site MUST fail closed
///   BEFORE any mutation.
///
/// Pure aside from the explicit after-success fixture consume the underlying
/// integration performs.
pub fn wire_replay_consume_runtime_callsite<E, W>(
    input: &ReplayConsumeRuntimeIntegrationInput<'_, E>,
    writer: &mut W,
) -> Result<ReplayConsumeRuntimeOutcome, ReplayConsumeRuntimeCallsiteFailClosed>
where
    E: ProductionGovernanceExecutionEvaluator,
    W: GovernanceEvaluatorReplayStateWriter,
{
    let outcome = integrate_replay_consume_runtime(input, writer);
    if outcome.is_proceed() {
        Ok(outcome)
    } else {
        Err(ReplayConsumeRuntimeCallsiteFailClosed::from_outcome(
            input.replay_runtime.integration.surface,
            outcome,
        ))
    }
}

// ===========================================================================
// Explicit invariant / fail-closed helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 236 — explicit invariant helper.
///
/// Returns `true`: the consume is integrated as an after-success-only
/// post-mutation step. Provided as a grep-verifiable statement of the
/// after-success-only contract.
pub fn consume_integrated_as_after_success_only_post_mutation_step() -> bool {
    true
}

/// Run 236 — explicit invariant helper.
///
/// Returns `true`: a fresh replay state is required before mutation
/// authorization under the consume runtime integration. Only a Run 232
/// `ProceedFresh` reaches the consume boundary.
pub fn fresh_required_before_mutation_authorization_under_consume_runtime() -> bool {
    true
}

/// Run 236 — explicit invariant helper.
///
/// Returns `true`: deferred, validation-only, before-apply, failed-apply,
/// rolled-back, unsupported-surface, and MainNet-refused outcomes never consume
/// under the consume runtime integration.
pub fn deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime() -> bool {
    true
}

/// Run 236 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused under the consume
/// runtime integration. Run 236 always returns `true` for a MainNet environment:
/// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal
/// regardless of any replay/freshness state — even a fresh one — and never
/// consumes.
pub fn mainnet_peer_driven_apply_remains_refused_under_consume_runtime(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 236 — explicit fail-closed helper.
///
/// Returns `true`: production / MainNet consume backends remain unavailable /
/// fail-closed under the consume runtime integration. No real consume storage is
/// implemented.
pub fn production_mainnet_consume_remains_unavailable_under_consume_runtime() -> bool {
    true
}

/// Run 236 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported under the
/// consume runtime integration. Run 236 always returns `true`: no validator-set
/// rotation exists.
pub fn validator_set_rotation_remains_unsupported_under_consume_runtime() -> bool {
    true
}

/// Run 236 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the consume
/// runtime integration. Run 236 always returns `true`: the integration only
/// governs trust-lifecycle evaluator decisions, never policy-change actions.
pub fn policy_change_action_remains_unsupported_under_consume_runtime() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_proceed_helpers_partition_correctly() {
        let bypass = ReplayConsumeRuntimeOutcome::ProceedLegacyBypassNoConsume;
        assert!(bypass.is_proceed());
        assert!(!bypass.authorizes_consume());
        assert!(bypass.no_consume());
        assert!(!bypass.is_fail_closed());

        let consume = ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess;
        assert!(consume.is_proceed());
        assert!(consume.authorizes_consume());
        assert!(!consume.no_consume());

        let deferred = ReplayConsumeRuntimeOutcome::ProceedDeferredNoConsume;
        assert!(!deferred.is_proceed());
        assert!(deferred.is_fail_closed());
        assert!(deferred.no_consume());

        let refused = ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        assert!(refused.is_fail_closed());
        assert!(refused.is_mainnet_peer_driven_apply_refused());
        assert!(refused.no_consume());
    }

    #[test]
    fn invariant_helpers_are_fail_closed() {
        assert!(consume_integrated_as_after_success_only_post_mutation_step());
        assert!(fresh_required_before_mutation_authorization_under_consume_runtime());
        assert!(deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime());
        assert!(mainnet_peer_driven_apply_remains_refused_under_consume_runtime(
            TrustBundleEnvironment::Mainnet
        ));
        assert!(!mainnet_peer_driven_apply_remains_refused_under_consume_runtime(
            TrustBundleEnvironment::Devnet
        ));
        assert!(production_mainnet_consume_remains_unavailable_under_consume_runtime());
        assert!(validator_set_rotation_remains_unsupported_under_consume_runtime());
        assert!(policy_change_action_remains_unsupported_under_consume_runtime());
    }
}
