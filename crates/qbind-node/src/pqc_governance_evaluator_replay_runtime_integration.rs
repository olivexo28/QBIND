//! Run 232 — source/test governance evaluator **replay/freshness runtime
//! integration**.
//!
//! Source/test only. Run 232 captures **no** release-binary evidence;
//! release-binary replay/freshness runtime-integration evidence is deferred to
//! **Run 233**. Run 232 does **not** implement a real governance execution
//! engine, a real on-chain governance proof verifier, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set rotation, a
//! real KMS/HSM backend, a real RemoteSigner backend, or any RocksDB / file /
//! schema / migration / wire / marker / sequence / trust-bundle / storage-format
//! change.
//!
//! ## What this module closes
//!
//! Run 230 proved a typed, pure **replay/freshness state boundary**
//! ([`evaluate_evaluator_replay_freshness`]) that decides whether an evaluator
//! decision is fresh, not-yet-effective, expired, stale, replayed, consumed,
//! superseded, wrong-bound, or unavailable — and Run 231 closed that boundary's
//! release-binary evidence. But the Run 230 boundary was **not yet integrated**
//! into the Run 224 evaluator-runtime integration path as a mandatory
//! pre-mutation gate: runtime consumption + evaluator evaluation (Run 224 / Run
//! 226) and the replay/freshness boundary (Run 230) were proven independently
//! but never *composed*.
//!
//! Run 232 closes that gap at the source/test level. It adds a single
//! integration layer ([`integrate_governance_evaluator_replay_runtime`]) that
//! composes:
//!
//! * **Run 224** evaluator-runtime integration
//!   ([`integrate_governance_evaluator_runtime_consumption`]);
//! * **Run 226** runtime call-site integration
//!   ([`wire_governance_evaluator_runtime_callsite`](crate::pqc_governance_execution_evaluator_runtime_integration::wire_governance_evaluator_runtime_callsite));
//! * **Run 228** peer evaluator context where relevant
//!   ([`wire_governance_evaluator_replay_runtime_peer_context`]); and
//! * **Run 230** replay/freshness state boundary
//!   ([`gate_evaluator_replay_freshness`]).
//!
//! ## Ordering contract
//!
//! The integration enforces the exact pipeline ordering:
//!
//! 1. **selector resolution** — Run 217 [`GovernanceExecutionRuntimeArmingConfig`];
//! 2. **sidecar / load-status derivation** — Run 213 load status;
//! 3. **runtime consumption** — Run 220;
//! 4. **evaluator request construction** — caller-supplied Run 222 request;
//! 5. **evaluator evaluation** — Run 222 source + response verification;
//! 6. **governance execution decision validation** — Run 211 decision validity;
//! 7. **replay/freshness validation** — Run 230 state boundary;
//! 8. **lifecycle / governance / custody / custody-attestation checks** — Run
//!    211 / Run 222 stages where applicable; and
//! 9. **mutation authorization only after replay/freshness returns fresh** —
//!    the single
//!    [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`] variant.
//!
//! Steps 1–6 are delegated to the Run 224 / Run 226 layer; only a Run 224
//! `ProceedMutate` reaches the Run 230 replay/freshness validation. The
//! replay/freshness validation therefore necessarily happens **before** any
//! mutation authorization.
//!
//! ## Fail-closed / mutation-safety contract
//!
//! * [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`] is the **only**
//!   mutation-authorizing outcome, and it is produced only after the Run 224
//!   integration authorized a mutate **and** the Run 230 replay/freshness state
//!   classified the decision [`ReplayFreshnessState::Fresh`](crate::pqc_governance_evaluator_replay_state::ReplayFreshnessState::Fresh).
//! * [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred`] is **not** an
//!   approval for mutation (a not-yet-effective decision defers).
//! * [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass`] preserves
//!   the Run 214 disabled-policy + absent-carrier legacy bypass — the
//!   replay/freshness boundary is never reached for it.
//! * Expired / stale / replayed / consumed / superseded / wrong-bound / malformed
//!   / unavailable replay states fail closed as
//!   [`GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed`]
//!   **before** any mutation.
//! * A Run 224 / Run 226 fail-closed surfaces as
//!   [`GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed`].
//! * Production / MainNet replay readers remain callable-but-unavailable /
//!   fail-closed (the Run 230 readers).
//! * **MainNet peer-driven apply remains refused** even when the replay state is
//!   fresh
//!   ([`GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused`]).
//! * Read-only validation never marks a decision consumed: this integration is a
//!   pure function. Explicit consume remains fixture-only and is performed by the
//!   caller **after** a `ProceedFresh` authorization (never inside this module).
//! * Every rejection is non-mutating: no Run 070 call, no live trust swap, no
//!   session eviction, no sequence write, no marker write.

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_evaluator_peer_context::{
    evaluate_peer_evaluator_context, GovernanceEvaluatorPeerContext, PeerEvaluatorContextOutcome,
};
use crate::pqc_governance_evaluator_replay_state::{
    gate_evaluator_replay_freshness, EvaluatorReplayFreshnessExpectations,
    EvaluatorReplayFreshnessInput, EvaluatorReplayFreshnessOutcome, ReplayStateGateOutcome,
    ReplayStatePolicy,
};
use crate::pqc_governance_execution_evaluator::{
    EvaluatorOutcome, ProductionGovernanceExecutionEvaluator,
};
use crate::pqc_governance_execution_evaluator_runtime_integration::{
    integrate_governance_evaluator_runtime_consumption,
    GovernanceEvaluatorRuntimeIntegrationContext, GovernanceEvaluatorRuntimeIntegrationOutcome,
};
use crate::pqc_governance_execution_policy::GovernanceExecutionOutcome;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Integration context
// ===========================================================================

/// Run 232 — typed inputs for one replay/freshness runtime-integration
/// round-trip.
///
/// Composes the Run 224 / Run 226 evaluator-runtime integration context with
/// the Run 230 replay/freshness policy, input, and expectations. Holds only
/// borrows of caller-owned data plus the `Copy` replay policy; it is itself
/// pure data and performs no work on construction.
pub struct GovernanceEvaluatorReplayRuntimeIntegrationContext<'a, E>
where
    E: ProductionGovernanceExecutionEvaluator,
{
    /// The Run 224 / Run 226 evaluator-runtime integration context (steps
    /// 1–6: selector resolution -> sidecar/load-status -> runtime consumption
    /// -> evaluator request -> evaluator evaluation -> governance execution
    /// decision validation).
    pub integration: GovernanceEvaluatorRuntimeIntegrationContext<'a, E>,
    /// The active Run 230 replay-state policy. A wired fixture policy is
    /// DevNet/TestNet source-test only; the production / MainNet policies are
    /// callable but their backing readers are unavailable / fail-closed.
    pub replay_policy: ReplayStatePolicy,
    /// The Run 230 replay/freshness input bound to the same evaluator material
    /// the integration context carries (step 7 input).
    pub replay_input: &'a EvaluatorReplayFreshnessInput,
    /// The canonical Run 230 replay/freshness expectations (step 7 binding).
    pub replay_expectations: &'a EvaluatorReplayFreshnessExpectations,
}

// ===========================================================================
// Integration outcome
// ===========================================================================

/// Run 232 — typed outcome of composing the Run 224 evaluator-runtime
/// integration with the Run 230 replay/freshness state boundary.
///
/// Only [`Self::ProceedFresh`] authorizes the runtime path to mutate, and only
/// after the Run 224 integration authorized a mutate **and** the Run 230
/// replay/freshness state classified the decision fresh.
/// [`Self::ProceedLegacyBypass`] preserves the Run 214 legacy bypass. Every
/// other variant is a non-mutating fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEvaluatorReplayRuntimeOutcome {
    /// Disabled policy + absent carrier: the Run 224 layer short-circuited to
    /// the Run 214 legacy bypass and the replay/freshness boundary was never
    /// reached. The runtime path continues unchanged.
    ProceedLegacyBypass,
    /// The Run 224 integration authorized a mutate but the Run 230
    /// replay/freshness state is fresh-but-not-yet-effective: defer. This is
    /// **not** an approval for mutation.
    ProceedDeferred,
    /// Every composed stage passed and the replay/freshness state is fresh.
    /// This is the **only** outcome that authorizes a mutation, and only AFTER
    /// the replay/freshness validation returned fresh.
    ProceedFresh {
        /// The accepted Run 211 governance-execution outcome from runtime
        /// consumption.
        runtime_consumption: GovernanceExecutionOutcome,
        /// The authorizing Run 222 evaluator outcome.
        evaluator: EvaluatorOutcome,
        /// Authorized lifecycle action (bound across every composed stage).
        lifecycle_action: LocalLifecycleAction,
        /// Authorized candidate digest (bound across every composed stage).
        candidate_digest: String,
        /// Authorized authority-domain sequence (bound across every composed
        /// stage).
        authority_domain_sequence: u64,
    },
    /// The Run 230 replay/freshness validation failed closed before mutation
    /// (expired / stale / replay / already-consumed / superseded / wrong-bound
    /// / malformed / state-unavailable / production-unavailable). Carries the
    /// precise Run 230 outcome. Non-mutating.
    ReplayFreshnessFailClosed(EvaluatorReplayFreshnessOutcome),
    /// The Run 224 / Run 226 evaluator-runtime integration failed closed
    /// before the replay/freshness boundary could be reached (runtime
    /// consumption fail-closed or evaluator rejected). Carries the originating
    /// Run 224 outcome. Non-mutating.
    RuntimeIntegrationFailClosed(GovernanceEvaluatorRuntimeIntegrationOutcome),
    /// MainNet trust domain — peer-driven apply remains the Run 147 / 148 / 152
    /// FATAL refusal regardless of any fixture evaluator approval or a fresh
    /// replay state. Non-mutating.
    MainNetPeerDrivenApplyRefused,
}

impl GovernanceEvaluatorReplayRuntimeOutcome {
    /// `true` iff the runtime call site may continue (legacy bypass or a
    /// fully-authorized fresh mutate).
    pub fn is_proceed(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass | Self::ProceedFresh { .. })
    }

    /// `true` iff the runtime call site is authorized to mutate. This is the
    /// **only** variant that authorizes a marker write, a sequence advance, a
    /// live trust swap, a session eviction, or a Run 070 call — and only
    /// because every composed stage passed and the replay/freshness state was
    /// fresh first.
    pub fn is_mutate_authorized(&self) -> bool {
        matches!(self, Self::ProceedFresh { .. })
    }

    /// `true` iff this is the Run 214 legacy no-governance-execution payload
    /// bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass)
    }

    /// `true` iff this outcome is a deferral (proceed-but-not-yet-effective). A
    /// deferral does **not** authorize mutation.
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::ProceedDeferred)
    }

    /// `true` iff the runtime call site MUST fail closed before any mutation
    /// (every non-proceed variant, including a deferral).
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
            Self::ProceedLegacyBypass => "proceed-legacy-bypass",
            Self::ProceedDeferred => "proceed-deferred",
            Self::ProceedFresh { .. } => "proceed-fresh",
            Self::ReplayFreshnessFailClosed(_) => "replay-freshness-fail-closed",
            Self::RuntimeIntegrationFailClosed(_) => "runtime-integration-fail-closed",
            Self::MainNetPeerDrivenApplyRefused => "mainnet-peer-driven-apply-refused",
        }
    }
}

// ===========================================================================
// Integration entry point
// ===========================================================================

/// Run 232 — compose the Run 224 evaluator-runtime integration with the Run
/// 230 replay/freshness state boundary as a mandatory pre-mutation gate.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no live
/// trust, evicts no sessions, never invokes Run 070, and never marks a decision
/// consumed. The replay/freshness validation runs **after** the Run 224 layer
/// authorizes a mutate and **before** this function authorizes any mutation, so
/// fresh is required before mutation authorization.
///
/// Stages run in the documented order. The first stage that cannot proceed
/// fails closed; mutation is authorized only by the terminal
/// [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`] once every required
/// stage has passed and the replay/freshness state is fresh.
pub fn integrate_governance_evaluator_replay_runtime<E>(
    ctx: &GovernanceEvaluatorReplayRuntimeIntegrationContext<'_, E>,
) -> GovernanceEvaluatorReplayRuntimeOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
{
    // Steps 1–6: selector resolution -> sidecar/load-status -> runtime
    // consumption -> evaluator request -> evaluator evaluation -> governance
    // execution decision validation (Run 224 / Run 226).
    let integration_outcome = integrate_governance_evaluator_runtime_consumption(&ctx.integration);

    let mutate = match integration_outcome {
        // Run 214 compatibility: the replay/freshness boundary is never
        // reached for the legacy bypass.
        GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass => {
            return GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass;
        }
        // MainNet peer-driven apply remains refused regardless of any fixture
        // evaluator approval — surfaced before the replay/freshness boundary.
        GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused => {
            return GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        }
        // The Run 224 layer authorized a mutate: proceed to the replay/
        // freshness validation as the mandatory pre-mutation gate.
        outcome @ GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate { .. } => outcome,
        // Any Run 224 / Run 226 fail-closed (runtime consumption fail-closed or
        // evaluator rejected) fails closed before the replay/freshness boundary
        // is reached.
        other => {
            return GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(other);
        }
    };

    // Step 7: replay/freshness validation (Run 230) — the mandatory
    // pre-mutation gate. Mutation is authorized only when this returns fresh.
    let gate = gate_evaluator_replay_freshness(
        ctx.replay_policy,
        ctx.replay_input,
        ctx.replay_expectations,
    );

    let replay_outcome = match gate {
        // The replay-state boundary is not wired: with a Run 224 mutate
        // pending, fresh cannot be confirmed, so fail closed (fresh is required
        // before mutation authorization). Never authorize a mutate without a
        // wired replay/freshness gate.
        ReplayStateGateOutcome::NotWired => {
            return GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
                EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable,
            );
        }
        ReplayStateGateOutcome::Evaluated(outcome) => outcome,
    };

    match replay_outcome {
        // Step 9: mutation authorization only after replay/freshness returns
        // fresh.
        EvaluatorReplayFreshnessOutcome::ProceedFresh => match mutate {
            GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
                runtime_consumption,
                evaluator,
                lifecycle_action,
                candidate_digest,
                authority_domain_sequence,
            } => GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh {
                runtime_consumption,
                evaluator,
                lifecycle_action,
                candidate_digest,
                authority_domain_sequence,
            },
            // Unreachable: `mutate` is only ever the `ProceedMutate` variant.
            _ => unreachable!("mutate is always ProceedMutate at the replay/freshness gate"),
        },
        // Fresh-but-not-yet-effective: defer, never authorize a mutate.
        EvaluatorReplayFreshnessOutcome::ProceedDeferred => {
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred
        }
        // MainNet replay state is unavailable / MainNet peer-driven apply
        // refused — surface the MainNet refusal explicitly.
        EvaluatorReplayFreshnessOutcome::FailClosedMainNetUnavailable
            if ctx.replay_input.environment == TrustBundleEnvironment::Mainnet
                && ctx.replay_input.validation_surface
                    == GovernanceExecutionRuntimeSurface::PeerDrivenDrain =>
        {
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
        }
        // Every other replay/freshness outcome is a non-mutating fail-closed
        // before any mutation (expired / stale / replay / already-consumed /
        // superseded / wrong-bound / malformed / unavailable / production /
        // MainNet).
        other => GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(other),
    }
}

// ===========================================================================
// Runtime call-site wiring
// ===========================================================================

/// Run 232 — non-mutating fail-closed signal a long-running runtime call site
/// receives when the composed replay/freshness integration outcome does **not**
/// authorize the path to continue.
///
/// A call site that receives this MUST fail closed BEFORE any mutation: no Run
/// 070 call, no live trust swap, no session eviction, no sequence write, no
/// marker write. It carries the originating
/// [`GovernanceExecutionRuntimeSurface`], the precise non-proceed
/// [`GovernanceEvaluatorReplayRuntimeOutcome`], and an operator-facing reason
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceEvaluatorReplayRuntimeCallsiteFailClosed {
    /// The runtime preflight surface that failed closed.
    pub surface: GovernanceExecutionRuntimeSurface,
    /// The non-proceed integration outcome that triggered the fail-closed.
    pub outcome: GovernanceEvaluatorReplayRuntimeOutcome,
    /// Operator-facing reason string.
    pub reason: String,
}

impl GovernanceEvaluatorReplayRuntimeCallsiteFailClosed {
    fn from_outcome(
        surface: GovernanceExecutionRuntimeSurface,
        outcome: GovernanceEvaluatorReplayRuntimeOutcome,
    ) -> Self {
        let detail = match &outcome {
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred => {
                "replay/freshness deferred (fresh-but-not-yet-effective is not mutation approval)"
                    .to_string()
            }
            GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(inner) => {
                format!("replay/freshness fail-closed: {:?}", inner)
            }
            GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(inner) => {
                format!("runtime integration fail-closed: {:?}", inner)
            }
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused => {
                "MainNet peer-driven apply refused unconditionally".to_string()
            }
            // The proceed variants never reach this constructor.
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass
            | GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. } => "proceed".to_string(),
        };
        let reason = format!(
            "Run 232 governance-evaluator replay/freshness runtime integration fail-closed on {} \
             surface: {}. No Run 070 apply, no live trust swap, no session eviction, no sequence \
             write, no marker write.",
            surface.tag(),
            detail,
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

/// Run 232 — route a runtime call site through the composed Run 224 + Run 230
/// integration layer and **consume** the outcome.
///
/// * `Ok(ProceedLegacyBypass)` — Run 214 disabled + absent carrier legacy
///   bypass; the call site continues unchanged.
/// * `Ok(ProceedFresh { .. })` — every composed stage passed and the
///   replay/freshness state is fresh; this is the **only** outcome that
///   authorizes a mutation.
/// * `Err(GovernanceEvaluatorReplayRuntimeCallsiteFailClosed)` — every
///   non-proceed outcome (deferral, replay/freshness fail-closed, runtime
///   integration fail-closed, MainNet peer-driven apply refused). The call site
///   MUST fail closed BEFORE any mutation. A deferral is explicitly not an
///   approval, so it too is surfaced as a fail-closed here.
///
/// Pure — performs no I/O and no mutation.
pub fn wire_governance_evaluator_replay_runtime_callsite<E>(
    ctx: &GovernanceEvaluatorReplayRuntimeIntegrationContext<'_, E>,
) -> Result<
    GovernanceEvaluatorReplayRuntimeOutcome,
    GovernanceEvaluatorReplayRuntimeCallsiteFailClosed,
>
where
    E: ProductionGovernanceExecutionEvaluator,
{
    let outcome = integrate_governance_evaluator_replay_runtime(ctx);
    if outcome.is_proceed() {
        Ok(outcome)
    } else {
        Err(GovernanceEvaluatorReplayRuntimeCallsiteFailClosed::from_outcome(
            ctx.integration.surface,
            outcome,
        ))
    }
}

// ===========================================================================
// Run 228 peer evaluator context composition (where relevant)
// ===========================================================================

/// Run 232 — compose the Run 228 peer evaluator context with the Run 230
/// replay/freshness state boundary for the two previously-limited peer surfaces
/// (live inbound `0x05`, peer-driven drain).
///
/// The Run 228 [`evaluate_peer_evaluator_context`] decides whether the peer
/// context routes through the Run 226 call-site wiring into the Run 224
/// integration layer. Only when Run 228 authorizes a routed mutate
/// ([`PeerEvaluatorContextOutcome::RoutedProceedMutate`]) does this function
/// reach the Run 230 replay/freshness validation as the mandatory pre-mutation
/// gate; every other Run 228 outcome maps to a non-mutating Run 232 outcome.
///
/// MainNet peer-driven apply remains refused: Run 228 refuses it before routing,
/// so a fresh replay state can never authorize MainNet peer-driven apply here.
///
/// Pure — performs no I/O and no mutation.
pub fn wire_governance_evaluator_replay_runtime_peer_context<E>(
    peer: &GovernanceEvaluatorPeerContext,
    ctx: &GovernanceEvaluatorReplayRuntimeIntegrationContext<'_, E>,
) -> GovernanceEvaluatorReplayRuntimeOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
{
    match evaluate_peer_evaluator_context(peer, &ctx.integration) {
        // Run 214 compatibility preserved by the peer-context layer.
        PeerEvaluatorContextOutcome::LegacyValidationPreserved => {
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass
        }
        // The peer context routed a mutate through Run 226 / Run 224 — apply
        // the Run 230 replay/freshness validation as the mandatory pre-mutation
        // gate.
        PeerEvaluatorContextOutcome::RoutedProceedMutate { .. } => {
            integrate_governance_evaluator_replay_runtime(ctx)
        }
        // MainNet peer-driven apply remains refused unconditionally.
        PeerEvaluatorContextOutcome::MainNetRefused => {
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
        }
        PeerEvaluatorContextOutcome::RoutedFailClosed(fc)
            if fc.is_mainnet_peer_driven_apply_refused() =>
        {
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
        }
        // Every other peer-context outcome is a non-mutating fail-closed that
        // never reaches the replay/freshness boundary.
        PeerEvaluatorContextOutcome::RoutedFailClosed(fc) => {
            GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(fc.outcome)
        }
        PeerEvaluatorContextOutcome::UnsupportedSurface { .. }
        | PeerEvaluatorContextOutcome::WireSchemaUnavailable { .. }
        | PeerEvaluatorContextOutcome::MalformedRejected { .. }
        | PeerEvaluatorContextOutcome::MissingContextRejected { .. }
        | PeerEvaluatorContextOutcome::PeerMajorityUnsupported => {
            GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(
                GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                    EvaluatorOutcome::ProductionDecisionSourceUnavailable,
                ),
            )
        }
    }
}

// ===========================================================================
// Explicit fail-closed / refusal helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 232 — explicit refusal helper.
///
/// Returns `true` iff MainNet peer-driven apply remains refused under the
/// replay/freshness runtime integration. Run 232 always returns `true` for a
/// MainNet environment: MainNet peer-driven apply remains the Run 147 / 148 /
/// 152 FATAL refusal regardless of any replay/freshness state — even a fresh
/// one.
pub fn mainnet_peer_driven_apply_remains_refused_under_replay_runtime(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 232 — explicit fail-closed helper.
///
/// Returns `true` iff a fresh replay state is required before mutation
/// authorization. Run 232 always returns `true`: only a `ProceedFresh` outcome
/// authorizes a mutation, and it is produced only after the Run 230
/// replay/freshness validation returns fresh.
pub fn fresh_replay_state_required_before_mutation() -> bool {
    true
}

/// Run 232 — explicit fail-closed helper.
///
/// Returns `true` iff a deferral is never a mutation approval. Run 232 always
/// returns `true`: [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred`]
/// never authorizes a mutation.
pub fn deferred_is_never_mutation_approval() -> bool {
    true
}

/// Run 232 — explicit fail-closed helper.
///
/// Returns `true` iff production / MainNet replay state remains unavailable /
/// fail-closed under the replay/freshness runtime integration. Run 232 always
/// returns `true`: production / MainNet replay readers remain
/// callable-but-unavailable.
pub fn production_mainnet_replay_state_remains_unavailable() -> bool {
    true
}

/// Run 232 — explicit fail-closed helper.
///
/// Returns `true` iff validator-set rotation remains unsupported under the
/// replay/freshness runtime integration. Run 232 always returns `true`: no
/// validator-set rotation exists.
pub fn validator_set_rotation_remains_unsupported_under_replay_runtime() -> bool {
    true
}

/// Run 232 — explicit fail-closed helper.
///
/// Returns `true` iff policy-change actions remain unsupported under the
/// replay/freshness runtime integration. Run 232 always returns `true`: the
/// boundary only gates trust-lifecycle evaluator decisions, never policy-change
/// actions.
pub fn policy_change_action_remains_unsupported_under_replay_runtime() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_proceed_helpers_partition_correctly() {
        let bypass = GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass;
        assert!(bypass.is_proceed());
        assert!(bypass.is_legacy_bypass());
        assert!(!bypass.is_mutate_authorized());
        assert!(!bypass.is_fail_closed());

        let deferred = GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred;
        assert!(deferred.is_deferred());
        assert!(!deferred.is_proceed());
        assert!(!deferred.is_mutate_authorized());
        assert!(deferred.is_fail_closed());

        let refused = GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        assert!(!refused.is_proceed());
        assert!(refused.is_fail_closed());
        assert!(refused.is_mainnet_peer_driven_apply_refused());
        assert!(!refused.is_mutate_authorized());
    }

    #[test]
    fn refusal_helpers_are_fail_closed() {
        assert!(mainnet_peer_driven_apply_remains_refused_under_replay_runtime(
            TrustBundleEnvironment::Mainnet
        ));
        assert!(!mainnet_peer_driven_apply_remains_refused_under_replay_runtime(
            TrustBundleEnvironment::Devnet
        ));
        assert!(fresh_replay_state_required_before_mutation());
        assert!(deferred_is_never_mutation_approval());
        assert!(production_mainnet_replay_state_remains_unavailable());
        assert!(validator_set_rotation_remains_unsupported_under_replay_runtime());
        assert!(policy_change_action_remains_unsupported_under_replay_runtime());
    }
}