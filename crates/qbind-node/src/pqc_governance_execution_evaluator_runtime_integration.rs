//! Run 224 — source/test governance evaluator-runtime integration.
//!
//! Source/test only. Run 224 captures **no** release-binary evidence;
//! release-binary evaluator-runtime integration evidence is deferred to
//! **Run 225**. Run 224 does **not** implement a real governance execution
//! engine, a real on-chain governance proof verifier, MainNet governance
//! enablement, MainNet peer-driven apply enablement, validator-set
//! rotation, a real KMS/HSM backend, or a real RemoteSigner backend.
//!
//! ## What this module closes
//!
//! Run 220 proved that the long-running runtime paths *consume* the
//! selected governance-execution policy and the real sidecar load status
//! at the source/test level. Run 222 landed the typed *production
//! governance execution evaluator* interface boundary
//! ([`ProductionGovernanceExecutionEvaluator`]) and Run 223 proved it with
//! release-binary evidence. But the Run 222 evaluator interface was **not
//! yet integrated** as the production evaluation target inside the Run 220
//! governance-execution runtime-consumption pipeline: runtime consumption
//! and the evaluator interface were proven independently but never
//! *composed*.
//!
//! Run 224 closes that gap at the source/test level. It adds a single
//! integration layer ([`integrate_governance_evaluator_runtime_consumption`])
//! that composes:
//!
//! * **Run 220** runtime consumption
//!   ([`GovernanceExecutionRuntimeArmingConfig::consume_surface`]);
//! * **Run 222** evaluator request / response / interface
//!   ([`ProductionGovernanceExecutionEvaluator`]);
//! * **Run 211** governance execution decision validation (embedded in the
//!   Run 220 consumption via the Run 213 routing helpers); and
//! * **Run 213** governance-execution payload material
//!   ([`GovernanceExecutionLoadStatus`]).
//!
//! ## Ordering contract
//!
//! The integration preserves the exact pipeline ordering:
//!
//! 1. **selector resolution** — the armed [`GovernanceExecutionPolicy`]
//!    carried by the Run 217 [`GovernanceExecutionRuntimeArmingConfig`];
//! 2. **sidecar / load-status derivation** — the Run 213
//!    [`GovernanceExecutionLoadStatus`];
//! 3. **runtime consumption** — Run 220
//!    [`GovernanceExecutionRuntimeConsumption`];
//! 4. **evaluator request construction** — the caller-supplied Run 222
//!    [`EvaluatorRequest`];
//! 5. **evaluator evaluation** — Run 222
//!    [`ProductionGovernanceExecutionEvaluator::evaluate_governance_decision_source`]
//!    followed by
//!    [`ProductionGovernanceExecutionEvaluator::verify_governance_evaluator_response`];
//! 6. **governance execution decision validation** — the Run 211 decision
//!    validity carried out of step 3;
//! 7. **lifecycle / governance / custody / custody-attestation checks** —
//!    enforced by the Run 211 and Run 222 stages where applicable;
//! 8. **mutation only after all required checks pass** — represented by the
//!    single [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate`]
//!    variant.
//!
//! ## Fail-closed contract
//!
//! * Production / on-chain / MainNet evaluator paths remain **callable but
//!   fail closed as unavailable** — the integration reaches them and
//!   returns a non-mutating
//!   [`GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected`].
//! * The fixture evaluator remains DevNet/TestNet source/test only, and the
//!   emergency fixture evaluator remains explicit and non-production — both
//!   are refused on a MainNet trust domain by the underlying Run 222 / Run
//!   211 stages.
//! * **MainNet peer-driven apply remains refused** even when a fixture
//!   evaluator approval exists
//!   ([`GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused`]).
//! * Every rejection is **non-mutating**: the integration is a pure
//!   function that performs no I/O, writes no marker, writes no sequence,
//!   swaps no live trust, evicts no sessions, and never invokes Run 070.
//!   Only [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate`]
//!   (and the Run 214-compatibility
//!   [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass`])
//!   authorize the runtime path to continue.

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy,
    EvaluatorRequest, EvaluatorResponse, ProductionGovernanceExecutionEvaluator,
};
use crate::pqc_governance_execution_payload_carrying::{
    parse_optional_governance_execution_sibling_from_json_value, GovernanceExecutionLoadStatus,
    GovernanceExecutionPayloadCarryingDecisionOutcome,
};
use crate::pqc_governance_execution_policy::{
    GovernanceExecutionExpectations, GovernanceExecutionOutcome,
};
use crate::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeConsumption,
    GovernanceExecutionRuntimeSurface,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Integration context
// ===========================================================================

/// Run 224 — typed inputs for one evaluator-runtime integration round-trip.
///
/// Bundles the four composed layers so the integration entry point keeps a
/// single argument and the ordering contract is obvious at the call site.
/// Holds only borrows of caller-owned data plus the two `Copy` policy
/// selectors; it is itself pure data and performs no work on construction.
pub struct GovernanceEvaluatorRuntimeIntegrationContext<'a, E>
where
    E: ProductionGovernanceExecutionEvaluator,
{
    // --- Run 217 selector resolution (step 1) ---
    /// The armed runtime config carrying the resolved Run 211
    /// [`GovernanceExecutionPolicy`].
    pub arming: &'a GovernanceExecutionRuntimeArmingConfig,
    /// The named long-running runtime preflight surface to drive.
    pub surface: GovernanceExecutionRuntimeSurface,

    // --- shared trust domain ---
    /// Active trust domain.
    pub trust_domain: &'a AuthorityTrustDomain,

    // --- Run 213 payload material + Run 211 expectations (steps 2/3/6) ---
    /// Real Run 213 governance-execution sidecar load status driving
    /// runtime consumption.
    pub load_status: &'a GovernanceExecutionLoadStatus,
    /// Caller-derived Run 211 verifier expectations.
    pub governance_execution_expectations: &'a GovernanceExecutionExpectations,

    // --- Run 222 evaluator (steps 4/5) ---
    /// The production governance evaluator interface to call as the next
    /// evaluation stage. Fixture / emergency-council fixture interfaces
    /// are source/test only; production / on-chain / MainNet interfaces
    /// fail closed as unavailable.
    pub evaluator: &'a E,
    /// The decision-source identity the evaluator request binds.
    pub identity: &'a DecisionSourceIdentity,
    /// The constructed evaluator request (step 4).
    pub request: &'a EvaluatorRequest,
    /// The evaluator response to verify (step 5).
    pub response: &'a EvaluatorResponse,
    /// Caller-derived Run 222 evaluator verifier expectations.
    pub evaluator_expectations: &'a EvaluatorExpectations,
    /// Active Run 222 [`EvaluatorPolicy`].
    pub evaluator_policy: EvaluatorPolicy,

    // --- peer-driven apply guard ---
    /// `true` iff this round-trip is a peer-driven apply preflight. MainNet
    /// peer-driven apply remains refused regardless of any fixture
    /// evaluator approval.
    pub is_peer_driven_apply_preflight: bool,
}

// ===========================================================================
// Integration outcome
// ===========================================================================

/// Run 224 — typed outcome of composing Run 220 runtime consumption with
/// the Run 222 evaluator interface and the Run 211 decision validation.
///
/// Only [`Self::ProceedMutate`] authorizes the runtime path to mutate, and
/// only after **every** composed stage has passed. [`Self::ProceedLegacyBypass`]
/// preserves Run 214 no-governance-execution payload compatibility. Every
/// other variant is a non-mutating fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEvaluatorRuntimeIntegrationOutcome {
    /// Disabled policy + absent carrier: legacy no-governance-execution
    /// payload compatibility. The runtime path continues unchanged and the
    /// evaluator interface is not reached (Run 214 compatibility).
    ProceedLegacyBypass,
    /// Every composed stage passed: runtime consumption accepted the
    /// carrier (Run 220 / Run 211), the evaluator evaluated the decision
    /// source and verified the response (Run 222), and the governance
    /// execution decision validated. Mutation may proceed only AFTER this
    /// outcome is produced.
    ProceedMutate {
        /// The accepted Run 211 governance-execution outcome from runtime
        /// consumption.
        runtime_consumption: GovernanceExecutionOutcome,
        /// The authorizing Run 222 evaluator outcome.
        evaluator: EvaluatorOutcome,
        /// Authorized lifecycle action (bound across both stages).
        lifecycle_action: LocalLifecycleAction,
        /// Authorized candidate digest (bound across both stages).
        candidate_digest: String,
        /// Authorized authority-domain sequence (bound across both stages).
        authority_domain_sequence: u64,
    },
    /// Runtime consumption (Run 220) failed closed before the evaluator
    /// could authorize. Carries the rejecting Run 213 outcome. Non-mutating.
    RuntimeConsumptionFailClosed(GovernanceExecutionPayloadCarryingDecisionOutcome),
    /// The Run 222 evaluator rejected the decision source or the response
    /// (including the production / on-chain / MainNet unavailable
    /// fail-closed outcomes and the cross-stage
    /// [`EvaluatorOutcome::GovernanceExecutionDecisionInvalid`] /
    /// [`EvaluatorOutcome::EvaluatorResponseInvalid`] reconciliation
    /// rejections). Non-mutating.
    EvaluatorRejected(EvaluatorOutcome),
    /// MainNet trust domain — peer-driven apply remains the Run 147 / 148 /
    /// 152 FATAL refusal regardless of any fixture evaluator approval.
    /// Non-mutating.
    MainNetPeerDrivenApplyRefused,
}

impl GovernanceEvaluatorRuntimeIntegrationOutcome {
    /// `true` iff the runtime call site may continue (legacy bypass or a
    /// fully-authorized mutate).
    pub fn is_proceed(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass | Self::ProceedMutate { .. })
    }

    /// `true` iff the runtime call site is authorized to mutate. This is
    /// the **only** variant that authorizes a marker write, a sequence
    /// advance, a live trust swap, a session eviction, or a Run 070 call —
    /// and only because every composed stage passed first.
    pub fn is_mutate_authorized(&self) -> bool {
        matches!(self, Self::ProceedMutate { .. })
    }

    /// `true` iff this is the Run 214 legacy no-governance-execution
    /// payload bypass.
    pub fn is_legacy_bypass(&self) -> bool {
        matches!(self, Self::ProceedLegacyBypass)
    }

    /// `true` iff the runtime call site MUST fail closed before any
    /// mutation (every non-proceed variant).
    pub fn is_fail_closed(&self) -> bool {
        !self.is_proceed()
    }

    /// `true` iff this rejection is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Borrow the authorizing evaluator outcome for a [`Self::ProceedMutate`].
    pub fn evaluator_outcome(&self) -> Option<&EvaluatorOutcome> {
        match self {
            Self::ProceedMutate { evaluator, .. } => Some(evaluator),
            Self::EvaluatorRejected(o) => Some(o),
            _ => None,
        }
    }
}

// ===========================================================================
// Integration entry point
// ===========================================================================

/// Run 224 — compose Run 220 runtime consumption with the Run 222 evaluator
/// interface and the Run 211 governance execution decision validation.
///
/// Pure: performs no I/O, writes no marker, writes no sequence, swaps no
/// live trust, evicts no sessions, and never invokes Run 070. The function
/// is the source/test integration of the Run 222 evaluator interface as the
/// next evaluation stage inside the Run 220 runtime-consumption pipeline.
///
/// Stages run in the documented order. The first stage that cannot proceed
/// fails closed; mutation is authorized only by the terminal
/// [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate`] once
/// every required stage has passed.
pub fn integrate_governance_evaluator_runtime_consumption<E>(
    ctx: &GovernanceEvaluatorRuntimeIntegrationContext<'_, E>,
) -> GovernanceEvaluatorRuntimeIntegrationOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
{
    // Steps 1–3: selector resolution + sidecar/load-status derivation +
    // runtime consumption (Run 217 / Run 220 / embedded Run 213 + Run 211).
    let consumption = ctx.arming.consume_surface(
        ctx.surface,
        ctx.trust_domain,
        ctx.governance_execution_expectations,
        ctx.load_status,
    );

    // Run 214 compatibility: disabled policy + absent carrier proceeds
    // unchanged and never reaches the evaluator interface.
    if consumption.is_legacy_bypass() {
        return GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass;
    }

    // MainNet peer-driven apply remains refused regardless of any fixture
    // evaluator approval. The runtime-consumption peer-driven drain surface
    // already refuses MainNet unconditionally; surface that, and also guard
    // explicitly on the caller-declared peer-driven preflight flag.
    if matches!(
        consumption.rejecting_outcome(),
        Some(GovernanceExecutionPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused)
    ) || (ctx.is_peer_driven_apply_preflight
        && ctx.trust_domain.environment == TrustBundleEnvironment::Mainnet)
    {
        return GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused;
    }

    // The Run 211 governance execution decision validity carried out of the
    // runtime-consumption stage (step 6 input).
    let governance_execution_decision_valid =
        matches!(consumption, GovernanceExecutionRuntimeConsumption::ProceedAccepted(_));

    // Steps 4–5: evaluator request construction (caller-supplied) +
    // evaluator evaluation. The decision source is evaluated first; only a
    // non-rejecting source evaluation proceeds to response verification.
    let source_outcome = ctx.evaluator.evaluate_governance_decision_source(
        ctx.identity,
        ctx.request,
        ctx.evaluator_expectations,
        ctx.trust_domain,
        ctx.evaluator_policy,
    );
    let evaluator_outcome = if source_outcome.is_reject() {
        source_outcome
    } else {
        ctx.evaluator.verify_governance_evaluator_response(
            ctx.response,
            ctx.request,
            ctx.evaluator_expectations,
        )
    };
    let evaluator_valid = evaluator_outcome.is_accept();

    // Step 6: reconcile the evaluator (Run 222) with the governance
    // execution decision (Run 211). Mutation is authorized only when BOTH
    // are valid.
    match (governance_execution_decision_valid, evaluator_valid) {
        (true, true) => {
            // Both stages accepted. The authorized lifecycle action,
            // candidate digest, and sequence come from the verified
            // evaluator response (which Run 222 already bound to the
            // request and the caller expectations).
            let (lifecycle_action, candidate_digest, authority_domain_sequence) =
                match &evaluator_outcome {
                    EvaluatorOutcome::EvaluatorResponseAuthorized {
                        lifecycle_action,
                        candidate_digest,
                        authority_domain_sequence,
                    } => (*lifecycle_action, candidate_digest.clone(), *authority_domain_sequence),
                    // `evaluator_valid` is only `true` for an authorized
                    // response; the source-accept outcomes are superseded by
                    // the response verification above.
                    _ => {
                        return GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                            EvaluatorOutcome::EvaluatorResponseInvalid {
                                reason: "evaluator accepted without an authorized response"
                                    .to_string(),
                            },
                        );
                    }
                };
            let runtime_consumption = match consumption {
                GovernanceExecutionRuntimeConsumption::ProceedAccepted(outcome) => outcome,
                // Unreachable: `governance_execution_decision_valid` is only
                // `true` for the `ProceedAccepted` variant.
                _ => unreachable!("governance-execution decision validity implies ProceedAccepted"),
            };
            GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate {
                runtime_consumption,
                evaluator: evaluator_outcome,
                lifecycle_action,
                candidate_digest,
                authority_domain_sequence,
            }
        }
        (true, false) => {
            // The governance execution decision validated but the evaluator
            // rejected the decision source or the response — reject without
            // mutating, surfacing the precise evaluator outcome (including
            // the production / on-chain / MainNet unavailable fail-closed
            // outcomes).
            GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(evaluator_outcome)
        }
        (false, _) => {
            // The governance execution decision was invalid. A structural
            // carrier failure (malformed / required-but-absent) is always a
            // runtime-consumption fail-closed regardless of the evaluator.
            // A *present, parsed* carrier that the Run 211 evaluator
            // rejected while the Run 222 evaluator accepted is the
            // cross-stage "evaluator valid but governance execution decision
            // invalid" rejection.
            let rejecting = consumption.rejecting_outcome().cloned();
            match (rejecting, evaluator_valid) {
                (Some(GovernanceExecutionPayloadCarryingDecisionOutcome::Callsite(_)), true) => {
                    let reason = consumption
                        .fail_closed_reason()
                        .unwrap_or_else(|| "governance execution decision invalid".to_string());
                    GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                        EvaluatorOutcome::GovernanceExecutionDecisionInvalid { reason },
                    )
                }
                (Some(rejecting), _) => {
                    GovernanceEvaluatorRuntimeIntegrationOutcome::RuntimeConsumptionFailClosed(
                        rejecting,
                    )
                }
                // Unreachable: a non-accepted, non-bypass consumption is
                // always `FailClosed` with a rejecting outcome.
                (None, _) => GovernanceEvaluatorRuntimeIntegrationOutcome::EvaluatorRejected(
                    evaluator_outcome,
                ),
            }
        }
    }
}

/// Run 224 — convenience wrapper that derives the Run 213
/// [`GovernanceExecutionLoadStatus`] from an optional in-memory sidecar
/// JSON value (the Run 213 sibling parser) before composing the
/// integration. `None` (no operator sidecar supplied) is `Absent`.
///
/// Pure — performs no I/O and no mutation. This mirrors the Run 220
/// `consume_surface_from_optional_sidecar_value` ergonomics at the
/// integration layer.
#[allow(clippy::too_many_arguments)]
pub fn integrate_governance_evaluator_runtime_consumption_from_optional_sidecar_value<E>(
    arming: &GovernanceExecutionRuntimeArmingConfig,
    surface: GovernanceExecutionRuntimeSurface,
    trust_domain: &AuthorityTrustDomain,
    sidecar: Option<&serde_json::Value>,
    governance_execution_expectations: &GovernanceExecutionExpectations,
    evaluator: &E,
    identity: &DecisionSourceIdentity,
    request: &EvaluatorRequest,
    response: &EvaluatorResponse,
    evaluator_expectations: &EvaluatorExpectations,
    evaluator_policy: EvaluatorPolicy,
    is_peer_driven_apply_preflight: bool,
) -> GovernanceEvaluatorRuntimeIntegrationOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
{
    let load_status = match sidecar {
        Some(value) => parse_optional_governance_execution_sibling_from_json_value(value),
        None => GovernanceExecutionLoadStatus::Absent,
    };
    let ctx = GovernanceEvaluatorRuntimeIntegrationContext {
        arming,
        surface,
        trust_domain,
        load_status: &load_status,
        governance_execution_expectations,
        evaluator,
        identity,
        request,
        response,
        evaluator_expectations,
        evaluator_policy,
        is_peer_driven_apply_preflight,
    };
    integrate_governance_evaluator_runtime_consumption(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_governance_execution_policy::GovernanceExecutionPolicy;

    #[test]
    fn disabled_absent_proceeds_legacy_bypass_without_evaluator() {
        // A1 smoke: the integration short-circuits to the legacy bypass for
        // the disabled policy + absent carrier, never reaching the
        // evaluator interface.
        let arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        assert!(arming.is_disabled());
        assert_eq!(
            arming.governance_execution_policy(),
            GovernanceExecutionPolicy::Disabled
        );
    }

    #[test]
    fn integration_outcome_proceed_helpers_partition_correctly() {
        let bypass = GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass;
        assert!(bypass.is_proceed());
        assert!(bypass.is_legacy_bypass());
        assert!(!bypass.is_mutate_authorized());
        assert!(!bypass.is_fail_closed());

        let refused = GovernanceEvaluatorRuntimeIntegrationOutcome::MainNetPeerDrivenApplyRefused;
        assert!(!refused.is_proceed());
        assert!(refused.is_fail_closed());
        assert!(refused.is_mainnet_peer_driven_apply_refused());
        assert!(!refused.is_mutate_authorized());
    }
}