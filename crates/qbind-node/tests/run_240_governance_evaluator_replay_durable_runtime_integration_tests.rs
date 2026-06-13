//! Run 240 — source/test governance evaluator **durable replay backend runtime
//! integration** tests.
//!
//! Source/test only. Run 240 captures **no** release-binary evidence;
//! release-binary durable-runtime-integration evidence is deferred to **Run
//! 241**. These tests prove that the composed integration
//! ([`integrate_durable_replay_runtime`]) wires the Run 238 durable replay-state
//! backend into the Run 236 / 232 / 230 replay/freshness + consume runtime path
//! as the typed durable state provider: a durable read/observe happens before
//! mutation authorization, replay/freshness is validated, a mutation is
//! authorized only on fresh, a durable compare-and-mark-consumed happens only
//! after a modeled `AppliedSuccessfully` mutation, an ambiguous crash window is
//! typed and fails closed, fixture restart snapshot durability is preserved
//! through the integration, production/MainNet durable backends remain
//! unavailable/fail-closed, and MainNet peer-driven apply remains refused even
//! when the durable state reads fresh.
//!
//! Coverage: A1–A21, R1–R38, ordering (durable observe before mutation
//! authorization), consume-after-success-only, restart snapshot, crash-window
//! fail-closed, production/MainNet unavailable, non-mutation, MainNet refusal,
//! and compatibility with the Run 239 / 238 / 237 / 236 / 235 / 234 / 233 / 232
//! / 231 / 230 layers.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_240.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_runtime_integration::{
    consume_integrated_as_after_success_only_post_mutation_step,
    fresh_required_before_mutation_authorization_under_consume_runtime,
    mainnet_peer_driven_apply_remains_refused_under_consume_runtime,
};
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    compare_and_mark_consumed as durable_compare_and_mark_consumed, durable_backend_key_digest,
    mainnet_peer_driven_apply_remains_refused_under_durable_backend, CrashWindow,
    CrashWindowObservation, DurableBackendDecisionExpectations, DurableBackendDecisionInput,
    DurableBackendKind, DurableBackendOutcome, DurableConsumeOutcome, DurableMutationCompletion,
    DurableRecordState, FixtureDurableReplayBackend, GovernanceEvaluatorReplayDurableBackendReader,
};
use qbind_node::pqc_governance_evaluator_replay_durable_runtime_integration::{
    consume_only_after_successful_mutation_under_durable_runtime,
    crash_window_ambiguity_fails_closed_under_durable_runtime,
    durable_observe_happens_before_mutation_authorization, durable_runtime_rejection_is_non_mutating,
    integrate_durable_replay_runtime, local_operator_cannot_satisfy_durable_runtime_policy,
    mainnet_peer_driven_apply_remains_refused_under_durable_runtime,
    no_rocksdb_file_schema_migration_change_under_durable_runtime,
    peer_majority_cannot_satisfy_durable_runtime_policy,
    policy_change_action_remains_unsupported_under_durable_runtime,
    production_mainnet_durable_remains_unavailable_under_durable_runtime,
    recover_durable_replay_runtime_crash_window,
    restart_snapshot_is_fixture_source_test_only_under_durable_runtime,
    validator_set_rotation_remains_unsupported_under_durable_runtime,
    wire_durable_replay_runtime_callsite, DurableReplayRuntimeIntegrationInput,
    DurableReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    PreviouslySeenState, ReplayStatePolicy, SeenDecisionRecord,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 230 / 234 / 238 corpora).
// ===========================================================================

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const GOV_PROOF: &str = "governance-proof-digest-bbbbbbbbbbbbbbbb";
const NONCE: &str = "replay-nonce-cccccccccccccccccccccccccc";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SOURCE_ID: &str = "decision-source-0001";
const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const TRANSCRIPT_DIGEST: &str = "evaluator-transcript-digest-iiiiiiiiiiii";
const COMMIT: &str = "response-commitment-eeeeeeeeeeeeeeeeeeee";

const SEQUENCE: u64 = 7;
const EFFECTIVE: u64 = 100;
const EXPIRY: u64 = 200;
const CANONICAL: u64 = 150;

// ===========================================================================
// Run 222 evaluator material (epoch-parametrized)
// ===========================================================================

fn ev_identity(env: TrustBundleEnvironment) -> DecisionSourceIdentity {
    DecisionSourceIdentity {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        source_kind: EvaluatorSourceKind::FixtureDecisionSource,
        source_id: SOURCE_ID.to_string(),
        governance_class: GovernanceExecutionClass::FixtureGovernance,
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        environment: env,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        freshness_replay_window: 200,
    }
}

fn ev_request(identity: &DecisionSourceIdentity, effective: u64, expiry: u64) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: "governance-execution-input-digest-jjjj".to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        effective_epoch: effective,
        expiry_epoch: expiry,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(request: &EvaluatorRequest, effective: u64, expiry: u64) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: SEQUENCE,
        effective_epoch: effective,
        expiry_epoch: expiry,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: effective,
        response_expiry_epoch: expiry,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

// ===========================================================================
// Owned-context builder: durable input/expectations + Run 230 freshness
// input/expectations consistent with one another.
// ===========================================================================

/// Holds the caller-owned data a [`DurableReplayRuntimeIntegrationInput`]
/// borrows.
struct Ctx {
    durable_input: DurableBackendDecisionInput,
    durable_expectations: DurableBackendDecisionExpectations,
    freshness_input: EvaluatorReplayFreshnessInput,
    freshness_expectations: EvaluatorReplayFreshnessExpectations,
}

#[allow(clippy::too_many_arguments)]
fn ctx(
    env: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    effective: u64,
    expiry: u64,
    canonical: u64,
    previously_seen: PreviouslySeenState,
) -> Ctx {
    let identity = ev_identity(env);
    let request = ev_request(&identity, effective, expiry);
    let response = ev_response(&request, effective, expiry);
    let freshness_input = EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        vs,
        canonical,
        previously_seen,
    );
    let freshness_expectations = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        vs,
    );
    Ctx {
        durable_input: DurableBackendDecisionInput::from_freshness_input(&freshness_input, ms),
        durable_expectations: DurableBackendDecisionExpectations::from_freshness_input(
            &freshness_input,
            ms,
        ),
        freshness_input,
        freshness_expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        kind: DurableBackendKind,
        policy: ReplayStatePolicy,
        completion: DurableMutationCompletion,
    ) -> DurableReplayRuntimeIntegrationInput<'_> {
        DurableReplayRuntimeIntegrationInput {
            durable_kind: kind,
            durable_input: &self.durable_input,
            durable_expectations: &self.durable_expectations,
            freshness_input: &self.freshness_input,
            freshness_expectations: &self.freshness_expectations,
            replay_policy: policy,
            mutation_completion: completion,
        }
    }

    fn key(&self) -> String {
        durable_backend_key_digest(&self.durable_input)
    }
}

/// Standard fresh DevNet mutating context.
fn fresh_devnet_mutating() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    )
}

/// Standard fresh DevNet read-only validation context.
fn fresh_devnet_validation() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    )
}

fn devnet_backend() -> FixtureDurableReplayBackend {
    FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet)
}

// ===========================================================================
// A — accepted scenarios A1–A21
// ===========================================================================

#[test]
fn a1_default_disabled_legacy_bypass_no_durable_write() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::Disabled,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::ProceedLegacyBypassNoDurableWrite
    );
    assert!(backend.is_empty(), "legacy bypass performs no durable write");
}

#[test]
fn a2_first_seen_devnet_observed_fresh() {
    let c = fresh_devnet_validation();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedFreshObserved);
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedFresh
    );
}

#[test]
fn a3_first_seen_testnet_observed_fresh() {
    let c = ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Testnet);
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureTestNet,
            ReplayStatePolicy::FixtureTestNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedFreshObserved);
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedFresh
    );
}

#[test]
fn a4_known_fresh_proceeds_as_known_fresh() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    // Pass 1: observe + authorize.
    let first = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(first, DurableReplayRuntimeOutcome::ProceedMutationAuthorized);
    // Pass 2: known-fresh re-read.
    let second = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(second, DurableReplayRuntimeOutcome::ProceedKnownFresh);
}

#[test]
fn a5_deferred_observed_does_not_authorize_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        50, // canonical < effective => deferred
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedDeferredObserved);
    assert!(!outcome.authorizes_mutation());
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedDeferred
    );
}

#[test]
fn a6_fresh_observed_authorizes_mutation_after_agreement() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedMutationAuthorized);
    assert!(outcome.authorizes_mutation());
    // Durable observe happened before mutation authorization.
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedFresh
    );
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn a7_applied_successfully_consumes_in_devnet_fixture() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let consume = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert_eq!(
        consume,
        DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess
    );
    assert!(backend.is_consumed(&c.key()));
}

#[test]
fn a8_applied_successfully_consumes_in_testnet_fixture() {
    let c = ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Testnet);
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureTestNet,
            ReplayStatePolicy::FixtureTestNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let consume = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureTestNet,
            ReplayStatePolicy::FixtureTestNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert_eq!(
        consume,
        DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess
    );
    assert!(backend.is_consumed(&c.key()));
}

#[test]
fn a9_same_decision_after_durable_consume_reads_consumed_fail_closed() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    let again = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        again,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedConsumed
        )
    );
}

#[test]
fn a10_read_only_validation_observes_but_does_not_consume() {
    let c = fresh_devnet_validation();
    let mut backend = devnet_backend();
    // Even with a modeled successful mutation, a read-only validation surface
    // observes/reads but never consumes.
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedFreshObserved);
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedFresh
    );
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn a11_apply_failed_after_observe_does_not_consume() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::ApplyFailed,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::DoNotConsumeApplyFailed);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn a12_rollback_after_observe_does_not_consume() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::RolledBack,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::DoNotConsumeRolledBack);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn a13_after_mutation_before_consume_crash_window_typed_fail_closed() {
    let c = fresh_devnet_mutating();
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: true,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    };
    let outcome = recover_durable_replay_runtime_crash_window(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &obs,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::CrashWindowFailClosed(
            CrashWindow::AfterMutationBeforeConsume
        )
    );
    assert!(outcome.is_fail_closed());
}

#[test]
fn a14_after_consume_crash_window_fail_closed() {
    let c = fresh_devnet_mutating();
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: true,
        rolled_back: false,
        apply_failed: false,
        consumed: true,
    };
    let outcome = recover_durable_replay_runtime_crash_window(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &obs,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::AfterConsume)
    );
}

#[test]
fn a15_restart_snapshot_preserves_observed_state() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    // Restart: snapshot -> restore -> integration sees the observed state.
    let snapshot = backend.restart_snapshot();
    let mut restored = FixtureDurableReplayBackend::from_snapshot(snapshot);
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut restored,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedKnownFresh);
}

#[test]
fn a16_restart_snapshot_preserves_consumed_state() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    let snapshot = backend.restart_snapshot();
    let mut restored = FixtureDurableReplayBackend::from_snapshot(snapshot);
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut restored,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedConsumed
        )
    );
    assert!(restored.is_consumed(&c.key()));
}

#[test]
fn a17_production_durable_backend_unavailable() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::Production,
            ReplayStatePolicy::Production,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::ProductionDurableUnavailable
    );
    assert!(backend.is_empty());
}

#[test]
fn a18_mainnet_durable_backend_unavailable() {
    // MainNet kind on a non-peer-driven surface reaches the durable backend and
    // fails closed unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::MainNet,
            ReplayStatePolicy::MainNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::MainNetDurableUnavailable
    );
}

#[test]
fn a19_mainnet_peer_driven_apply_refused_even_if_durable_fresh() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(backend.is_empty());
}

#[test]
fn a20_run236_consume_runtime_integration_remains_compatible() {
    assert!(consume_integrated_as_after_success_only_post_mutation_step());
    assert!(fresh_required_before_mutation_authorization_under_consume_runtime());
    assert!(mainnet_peer_driven_apply_remains_refused_under_consume_runtime(
        TrustBundleEnvironment::Mainnet
    ));
}

#[test]
fn a21_run238_durable_backend_boundary_remains_compatible() {
    assert!(mainnet_peer_driven_apply_remains_refused_under_durable_backend(
        TrustBundleEnvironment::Mainnet
    ));
    // The Run 238 boundary still classifies a fresh first-seen decision.
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(outcome.is_proceed());
}

// ===========================================================================
// Ordering — durable observe before mutation authorization
// ===========================================================================

#[test]
fn ordering_durable_observe_before_mutation_authorization() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    assert!(backend.is_empty());
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::ProceedMutationAuthorized);
    // Authorization only occurs after the durable observe recorded the decision.
    assert_eq!(
        backend.read_durable_state(&c.key()),
        DurableRecordState::ObservedFresh
    );
    assert!(durable_observe_happens_before_mutation_authorization());
}

#[test]
fn ordering_consume_requires_prior_observe() {
    // A consume pass without a prior observe (durable Missing) fails closed.
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert!(matches!(
        outcome,
        DurableReplayRuntimeOutcome::ConsumeRuntimeFailClosed { .. }
    ));
    assert!(!backend.is_consumed(&c.key()));
    assert!(consume_only_after_successful_mutation_under_durable_runtime());
}

// ===========================================================================
// Callsite wiring
// ===========================================================================

#[test]
fn callsite_proceed_returns_ok() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let result = wire_durable_replay_runtime_callsite(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(result.is_ok());
}

#[test]
fn callsite_fail_closed_returns_err() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let result = wire_durable_replay_runtime_callsite(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let err = result.expect_err("MainNet peer-driven apply must fail closed");
    assert!(err.is_mainnet_peer_driven_apply_refused());
}

// ===========================================================================
// R — rejection scenarios R1–R38
// ===========================================================================

/// Tamper a single durable input field against canonical expectations and assert
/// the integration fails closed durable-malformed without recording anything.
fn assert_durable_binding_rejected(mut tamper: impl FnMut(&mut DurableBackendDecisionInput)) {
    let mut c = fresh_devnet_mutating();
    tamper(&mut c.durable_input);
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedMalformedRecord
        )
    );
    assert!(backend.is_empty());
}

#[test]
fn r1_expired_durable_state_rejected_before_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        250, // canonical >= expiry => expired
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(matches!(
        outcome,
        DurableReplayRuntimeOutcome::ReplayRuntimeFailClosed(_)
    ));
    assert!(outcome.is_fail_closed());
    assert!(backend.is_empty());
}

#[test]
fn r2_stale_durable_state_rejected_before_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EXPIRY,
        EFFECTIVE, // degenerate window => stale
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(matches!(
        outcome,
        DurableReplayRuntimeOutcome::ReplayRuntimeFailClosed(_)
    ));
    assert!(backend.is_empty());
}

fn seen_record(consumed: bool, superseded: bool) -> SeenDecisionRecord {
    SeenDecisionRecord {
        state_key_digest: "ignored-by-classifier".to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed,
        superseded,
    }
}

#[test]
fn r3_replay_detected_rejected_before_mutation() {
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::Seen(seen_record(false, false)),
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(matches!(
        outcome,
        DurableReplayRuntimeOutcome::ReplayRuntimeFailClosed(_)
    ));
    assert!(backend.is_empty());
}

#[test]
fn r4_consumed_decision_rejected_before_mutation() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedConsumed
        )
    );
}

#[test]
fn r5_superseded_decision_rejected_before_mutation() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(backend.mark_superseded(&c.key()));
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedSuperseded
        )
    );
}

#[test]
fn r6_malformed_durable_record_rejected_before_mutation() {
    assert_durable_binding_rejected(|i| i.replay_nonce = String::new());
}

#[test]
fn r7_backend_unavailable_rejected() {
    // Fixture kind keyed for a MainNet (non-peer-driven) environment is
    // unavailable.
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedBackendUnavailable
        )
    );
}

#[test]
fn r8_production_durable_backend_unavailable_rejected() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::Production,
            ReplayStatePolicy::Production,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::ProductionDurableUnavailable
    );
}

#[test]
fn r9_mainnet_durable_backend_unavailable_refused_rejected() {
    let c = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::MainNet,
            ReplayStatePolicy::MainNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::MainNetDurableUnavailable
    );
}

#[test]
fn r10_wrong_environment_rejected() {
    assert_durable_binding_rejected(|i| i.environment = TrustBundleEnvironment::Testnet);
}

#[test]
fn r11_wrong_chain_rejected() {
    assert_durable_binding_rejected(|i| i.chain_id = "wrong".to_string());
}

#[test]
fn r12_wrong_genesis_rejected() {
    assert_durable_binding_rejected(|i| i.genesis_hash = "wrong".to_string());
}

#[test]
fn r13_wrong_validation_surface_rejected() {
    assert_durable_binding_rejected(|i| {
        i.validation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn r14_wrong_mutation_surface_rejected() {
    assert_durable_binding_rejected(|i| {
        i.mutation_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
}

#[test]
fn r15_wrong_replay_state_key_digest_rejected() {
    assert_durable_binding_rejected(|i| i.replay_state_key_digest = "wrong".to_string());
}

#[test]
fn r16_wrong_source_identity_digest_rejected() {
    assert_durable_binding_rejected(|i| i.evaluator_source_identity_digest = "wrong".to_string());
}

#[test]
fn r17_wrong_request_digest_rejected() {
    assert_durable_binding_rejected(|i| i.evaluator_request_digest = "wrong".to_string());
}

#[test]
fn r18_wrong_response_digest_rejected() {
    assert_durable_binding_rejected(|i| i.evaluator_response_digest = "wrong".to_string());
}

#[test]
fn r19_wrong_transcript_digest_rejected() {
    assert_durable_binding_rejected(|i| i.evaluator_transcript_digest = "wrong".to_string());
}

#[test]
fn r20_wrong_decision_digest_rejected() {
    assert_durable_binding_rejected(|i| {
        i.governance_execution_decision_digest = "wrong".to_string()
    });
}

#[test]
fn r21_wrong_proposal_id_rejected() {
    assert_durable_binding_rejected(|i| i.proposal_id = "wrong".to_string());
}

#[test]
fn r22_wrong_decision_id_rejected() {
    assert_durable_binding_rejected(|i| i.decision_id = "wrong".to_string());
}

#[test]
fn r23_wrong_lifecycle_action_rejected() {
    assert_durable_binding_rejected(|i| i.lifecycle_action = LocalLifecycleAction::Retire);
}

#[test]
fn r24_wrong_candidate_digest_rejected() {
    assert_durable_binding_rejected(|i| i.candidate_digest = "wrong".to_string());
}

#[test]
fn r25_wrong_authority_domain_sequence_rejected() {
    assert_durable_binding_rejected(|i| i.authority_domain_sequence = 999);
}

#[test]
fn r26_wrong_replay_nonce_rejected() {
    assert_durable_binding_rejected(|i| i.replay_nonce = "wrong".to_string());
}

#[test]
fn r27_compare_and_mark_consumed_wrong_expected_state_rejected() {
    // Compose Run 238 directly: a compare-and-mark with the wrong expected state
    // is rejected without consuming.
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = durable_compare_and_mark_consumed(
        DurableBackendKind::FixtureDevNet,
        &c.durable_input,
        &c.durable_expectations,
        DurableRecordState::Consumed, // wrong expected state (actual is ObservedFresh)
        DurableMutationCompletion::AppliedSuccessfully,
        &mut backend,
    );
    assert_eq!(outcome, DurableConsumeOutcome::RejectedWrongExpectedState);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn r28_consume_before_observe_rejected() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert!(matches!(
        outcome,
        DurableReplayRuntimeOutcome::ConsumeRuntimeFailClosed { .. }
    ));
    assert!(backend.is_empty());
}

#[test]
fn r29_consume_before_successful_mutation_rejected() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AuthorizedButNotApplied,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::DoNotConsumeBeforeApply);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn r30_consume_after_failed_apply_rejected() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::ApplyFailed,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::DoNotConsumeApplyFailed);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn r31_consume_after_rollback_rejected() {
    let c = fresh_devnet_mutating();
    let mut backend = devnet_backend();
    integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::RolledBack,
        ),
        &mut backend,
    );
    assert_eq!(outcome, DurableReplayRuntimeOutcome::DoNotConsumeRolledBack);
    assert!(!backend.is_consumed(&c.key()));
}

#[test]
fn r32_ambiguous_crash_window_rejected() {
    let c = fresh_devnet_mutating();
    // Mutation attempted but neither succeeded, failed, nor rolled back: ambiguous.
    let obs = CrashWindowObservation {
        backend_kind: DurableBackendKind::FixtureDevNet,
        observed: true,
        mutation_attempted: true,
        mutation_succeeded: false,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    };
    let outcome = recover_durable_replay_runtime_crash_window(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &obs,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::UnknownCrashWindow)
    );
}

#[test]
fn r33_local_operator_cannot_satisfy_durable_runtime_policy() {
    assert!(local_operator_cannot_satisfy_durable_runtime_policy());
}

#[test]
fn r34_peer_majority_cannot_satisfy_durable_runtime_policy() {
    assert!(peer_majority_cannot_satisfy_durable_runtime_policy());
}

#[test]
fn r35_validator_set_rotation_unsupported_rejected() {
    assert!(validator_set_rotation_remains_unsupported_under_durable_runtime());
}

#[test]
fn r36_policy_change_action_unsupported_rejected() {
    assert!(policy_change_action_remains_unsupported_under_durable_runtime());
}

#[test]
fn r37_rejection_produces_no_mutation() {
    // A replay-runtime rejection leaves the durable backend untouched: no record,
    // no consume; and no Run 070 / trust swap / eviction / sequence / marker
    // write is performed by this pure layer.
    let c = ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::Seen(seen_record(false, false)),
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    assert!(outcome.is_fail_closed());
    assert!(backend.is_empty());
    assert!(durable_runtime_rejection_is_non_mutating());
    assert!(no_rocksdb_file_schema_migration_change_under_durable_runtime());
    assert!(restart_snapshot_is_fixture_source_test_only_under_durable_runtime());
    assert!(crash_window_ambiguity_fails_closed_under_durable_runtime());
    assert!(production_mainnet_durable_remains_unavailable_under_durable_runtime());
}

#[test]
fn r38_mainnet_peer_driven_apply_refused_even_when_durable_says_fresh() {
    // Seed a fresh durable record under a DevNet context, then prove a MainNet
    // peer-driven surface refuses regardless.
    let mainnet = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        EFFECTIVE,
        EXPIRY,
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );
    let mut backend = devnet_backend();
    let outcome = integrate_durable_replay_runtime(
        &mainnet.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::AppliedSuccessfully,
        ),
        &mut backend,
    );
    assert_eq!(
        outcome,
        DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused
    );
    assert!(mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(backend.is_empty());
}
