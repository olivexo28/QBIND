//! Run 247 — release-built helper for the Run 246 governance **modeled
//! end-to-end pipeline boundary**
//! (`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`).
//!
//! Where Run 246 landed the pure, typed modeled end-to-end governance pipeline at
//! the source/test level and captured **no** release-binary evidence, Run 247 is
//! that release-binary evidence. This helper drives an accepted/compatible,
//! rejection, recovery, projection, stage-ordering, non-mutation, and
//! reachability corpus through the **release-built** Run 246 symbols
//! (`run_modeled_end_to_end_pipeline`, `recover_modeled_end_to_end_pipeline_window`,
//! the `DefaultGovernanceModeledEndToEndPipelineExecutor` /
//! `GovernanceModeledEndToEndPipelineExecutor` trait boundary, the
//! `GovernanceModeledEndToEndPipelineInput` /
//! `GovernanceModeledEndToEndPipelineExpectations` /
//! `GovernanceModeledEndToEndPipelinePolicy` /
//! `GovernanceModeledEndToEndPipelineSurface` /
//! `GovernanceModeledEndToEndPipelineEnvironmentBinding` /
//! `GovernanceModeledEndToEndPipelineRuntimeBinding` /
//! `GovernanceModeledEndToEndPipelineCandidate` /
//! `GovernanceModeledEndToEndPipelineReplayBinding` /
//! `GovernanceModeledEndToEndPipelineMutationBinding` bindings, the
//! `EvaluatorCallsiteStage` / `DurableReplayObserveStage` / `MutationEngineStage`
//! / `ModeledApplierStage` / `DurableProjectionStage` /
//! `DurableConsumeDecisionStage` stage records, the
//! `GovernanceModeledEndToEndPipelineOutcome` taxonomy, the
//! `GovernanceModeledEndToEndPipelineDecision` result, the
//! `EvaluatorCallsiteAuthorization` / `DurableReplayObservation` stage
//! classifications, and the grep-verifiable invariant / fail-closed helpers),
//! proving in release mode that:
//!
//! * a disabled pipeline / evaluator-call-site policy preserves the legacy
//!   no-mutation, no-consume bypass and never invokes the applier;
//! * a DevNet/TestNet fixture evaluator + durable replay fresh + mutation-engine
//!   authorized + modeled add/retire/revoke/emergency-revoke/noop success
//!   authorizes a durable consume only after the modeled applier success;
//! * the only consume-authorizing outcome is
//!   `ModeledApplierAppliedAndDurableConsumeAuthorized`; evaluator success alone,
//!   durable replay freshness alone, and mutation-engine authorization alone are
//!   each insufficient;
//! * every evaluator/call-site rejection, replay rejection
//!   (stale/expired/consumed/superseded/backend-unavailable/deferred), binding
//!   mismatch, read-only surface, missing-root before-apply rejection, apply
//!   failure, rollback, rollback-failed, ambiguous window, unavailable
//!   production/MainNet path, validator-set rotation, and policy-change attempt is
//!   non-mutating and non-consuming;
//! * a rejection before the applier stage leaves the applier invocation count at
//!   zero and the modeled state unchanged;
//! * MainNet peer-driven apply is refused before any replay consume, modeled
//!   snapshot, or applier invocation;
//! * the crash-window recovery classification reuses the Run 244 modeled outcome
//!   semantics and fails closed on every after-apply / ambiguous / rollback-failed
//!   / unknown window.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, mutation engine, on-chain proof verifier, persistent replay
//! backend, KMS/HSM, or RemoteSigner backend. No RocksDB/file/schema/migration/
//! storage-format change. The pipeline is a pure typed ordering/composition over
//! in-memory boundaries; the fixture applier mutates only the modeled in-memory
//! `ModeledGovernanceTrustState`; it never mutates `LivePqcTrustState`, calls Run
//! 070, performs a real trust swap, evicts sessions, writes a sequence, writes a
//! marker, or performs a durable consume of its own. MainNet peer-driven apply
//! remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_end_to_end_pipeline::{
    modeled_end_to_end_pipeline_ambiguous_window_fails_closed,
    modeled_end_to_end_pipeline_applier_success_required_before_consume,
    modeled_end_to_end_pipeline_failed_apply_never_consumes,
    modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority,
    modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first,
    modeled_end_to_end_pipeline_never_calls_run_070,
    modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state,
    modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change,
    modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority,
    modeled_end_to_end_pipeline_policy_change_unsupported,
    modeled_end_to_end_pipeline_production_mainnet_unavailable,
    modeled_end_to_end_pipeline_rejection_is_non_mutating,
    modeled_end_to_end_pipeline_rollback_never_consumes,
    modeled_end_to_end_pipeline_success_required_before_durable_consume,
    modeled_end_to_end_pipeline_validator_set_rotation_unsupported,
    recover_modeled_end_to_end_pipeline_window, run_modeled_end_to_end_pipeline,
    DefaultGovernanceModeledEndToEndPipelineExecutor, DurableReplayObservation,
    EvaluatorCallsiteAuthorization, GovernanceModeledEndToEndPipelineExecutor,
    GovernanceModeledEndToEndPipelineInput, GovernanceModeledEndToEndPipelineOutcome,
    GovernanceModeledEndToEndPipelinePolicy,
};
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    FixtureModeledTrustMutationApplier, MainNetModeledTrustMutationApplier, ModeledApplierFault,
    ModeledGovernanceTrustMutation, ModeledGovernanceTrustMutationApplierKind,
    ModeledGovernanceTrustMutationEnvironmentBinding, ModeledGovernanceTrustMutationExpectations,
    ModeledGovernanceTrustMutationInput, ModeledGovernanceTrustMutationPolicy,
    ModeledGovernanceTrustMutationRuntimeBinding, ModeledGovernanceTrustMutationSurface,
    ModeledGovernanceTrustRoot, ModeledGovernanceTrustState, ModeledTrustMutationAction,
    ModeledTrustMutationOutcome, ProductionModeledTrustMutationApplier,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 246 corpus so the composed material binds to
// the same trust domain, proposal/decision identity, candidate digest).
// ===========================================================================

const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;
const ROOT: &str = "modeled-trust-root-A";

// ===========================================================================
// Owned-context builder (mirrors the Run 246 test owned-context builder).
// ===========================================================================

struct Ctx {
    mutation: ModeledGovernanceTrustMutation,
    env: ModeledGovernanceTrustMutationEnvironmentBinding,
    runtime: ModeledGovernanceTrustMutationRuntimeBinding,
    expectations: ModeledGovernanceTrustMutationExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    action: ModeledTrustMutationAction,
    root_id: &str,
) -> Ctx {
    let mutation = ModeledGovernanceTrustMutation {
        action,
        root_id: root_id.to_string(),
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
    };
    let env = ModeledGovernanceTrustMutationEnvironmentBinding {
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let runtime = ModeledGovernanceTrustMutationRuntimeBinding {
        governance_surface: ms,
        mutation_surface: ModeledGovernanceTrustMutationSurface {
            validation_surface: vs,
            mutation_surface: ms,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let expectations = ModeledGovernanceTrustMutationExpectations {
        expected_decision_digest: DECISION_DIGEST.to_string(),
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_environment: environment,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_governance_surface: ms,
        expected_validation_surface: vs,
        expected_mutation_surface: ms,
    };
    Ctx {
        mutation,
        env,
        runtime,
        expectations,
    }
}

impl Ctx {
    fn modeled_input(
        &self,
        policy: ModeledGovernanceTrustMutationPolicy,
        applier_kind: ModeledGovernanceTrustMutationApplierKind,
    ) -> ModeledGovernanceTrustMutationInput<'_> {
        ModeledGovernanceTrustMutationInput {
            applier_kind,
            policy,
            mutation: &self.mutation,
            environment_binding: &self.env,
            runtime_binding: &self.runtime,
        }
    }

    fn pipeline_input(
        &self,
        policy: GovernanceModeledEndToEndPipelinePolicy,
        evaluator: EvaluatorCallsiteAuthorization,
        replay: DurableReplayObservation,
        modeled_policy: ModeledGovernanceTrustMutationPolicy,
        applier_kind: ModeledGovernanceTrustMutationApplierKind,
    ) -> GovernanceModeledEndToEndPipelineInput<'_> {
        GovernanceModeledEndToEndPipelineInput {
            policy,
            evaluator_authorization: evaluator,
            replay_observation: replay,
            modeled_input: self.modeled_input(modeled_policy, applier_kind),
        }
    }
}

/// A DevNet mutating-surface context for the given action.
fn devnet_ctx(action: ModeledTrustMutationAction) -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        action,
        ROOT,
    )
}

fn state_with_active_root() -> ModeledGovernanceTrustState {
    ModeledGovernanceTrustState::with_roots(vec![ModeledGovernanceTrustRoot::active(ROOT)])
}

/// The canonical "everything agrees" success pipeline input parameters.
fn happy_devnet(c: &Ctx) -> GovernanceModeledEndToEndPipelineInput<'_> {
    c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        DurableReplayObservation::MutationAuthorized,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    )
}

fn devnet_applier() -> FixtureModeledTrustMutationApplier {
    FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet)
}

fn devnet_applier_fault(fault: ModeledApplierFault) -> FixtureModeledTrustMutationApplier {
    FixtureModeledTrustMutationApplier::with_fault(TrustBundleEnvironment::Devnet, fault)
}

// ===========================================================================
// Output plumbing
// ===========================================================================

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

struct Table {
    name: &'static str,
    rows: String,
    expected: String,
    actual: String,
    pass: u64,
    fail: u64,
}
impl Table {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
    }
    fn check(&mut self, id: &str, expected: &str, actual: &str) {
        let ok = expected == actual;
        self.pass += ok as u64;
        self.fail += (!ok) as u64;
        self.rows.push_str(&format!(
            "{id}\t{}\texpected={expected}\tactual={actual}\n",
            if ok { "PASS" } else { "FAIL" }
        ));
        self.expected.push_str(&format!("{id}\t{expected}\n"));
        self.actual.push_str(&format!("{id}\t{actual}\n"));
    }
    fn assert_true(&mut self, id: &str, ok: bool) {
        self.check(id, "true", if ok { "true" } else { "false" });
    }
    fn check_outcome(
        &mut self,
        id: &str,
        expected: &str,
        o: &GovernanceModeledEndToEndPipelineOutcome,
    ) {
        self.check(id, expected, o.tag());
    }
    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

/// Drive a pipeline round-trip with the canonical happy-path parameters over a
/// fresh DevNet fixture applier and an empty (or supplied) modeled state.
fn drive(
    input: &GovernanceModeledEndToEndPipelineInput<'_>,
    expectations: &ModeledGovernanceTrustMutationExpectations,
    state: &mut ModeledGovernanceTrustState,
    applier: &mut FixtureModeledTrustMutationApplier,
) -> qbind_node::pqc_governance_modeled_end_to_end_pipeline::GovernanceModeledEndToEndPipelineDecision
{
    run_modeled_end_to_end_pipeline(input, expectations, state, applier)
}

// ===========================================================================
// A — accepted / compatible scenarios exercised through the release-built Run
// 246 end-to-end pipeline symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let mut t = Table::new("accepted");

    // A1 — disabled pipeline policy preserves legacy bypass, no mutation, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::disabled(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            P::FixtureDevNet,
            K::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("A1.outcome", "proceed-legacy-bypass-no-mutation", &d.outcome);
        t.assert_true("A1.no-consume", d.outcome.no_consume());
        t.assert_true("A1.no-applier", !d.applier_invoked());
        t.assert_true("A1.attempts-zero", applier.attempts() == 0);
        t.assert_true("A1.state-empty", state.is_empty());
    }

    // A2 — disabled evaluator/call-site preserves legacy bypass, no mutation, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::LegacyBypass,
            DurableReplayObservation::MutationAuthorized,
            P::FixtureDevNet,
            K::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("A2.outcome", "proceed-legacy-bypass-no-mutation", &d.outcome);
        t.assert_true("A2.no-applier", !d.applier_invoked());
        t.assert_true("A2.attempts-zero", applier.attempts() == 0);
        t.assert_true("A2.state-empty", state.is_empty());
    }

    // A3 — DevNet fixture add-root success authorizes durable consume only after applier success.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A3.outcome",
            "modeled-applier-applied-and-durable-consume-authorized",
            &d.outcome,
        );
        t.assert_true("A3.authorizes-consume", d.authorizes_durable_consume());
        t.assert_true("A3.decision-authorized", d.durable_consume_decision.authorized);
        t.assert_true("A3.applier-invoked", d.applier_invoked());
        t.assert_true("A3.attempts-one", applier.attempts() == 1);
        t.assert_true("A3.state-active", state.contains_active(ROOT));
        t.check(
            "A3.engine-map",
            "mutation-applied-successfully",
            d.mutation_engine.as_ref().unwrap().outcome.tag(),
        );
    }

    // A4 — TestNet fixture add-root success authorizes durable consume.
    {
        let c = ctx(
            TrustBundleEnvironment::Testnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            P::FixtureTestNet,
            K::FixtureTestNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Testnet);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A4.outcome",
            "modeled-applier-applied-and-durable-consume-authorized",
            &d.outcome,
        );
        t.assert_true("A4.authorizes-consume", d.authorizes_durable_consume());
        t.assert_true("A4.state-active", state.contains_active(ROOT));
    }

    // A5..A7 — retire / revoke / emergency-revoke success authorizes consume only after success.
    for (id, action) in [
        ("A5", ModeledTrustMutationAction::RetireTrustRoot),
        ("A6", ModeledTrustMutationAction::RevokeTrustRoot),
        ("A7", ModeledTrustMutationAction::EmergencyRevokeTrustRoot),
    ] {
        let c = devnet_ctx(action);
        let input = happy_devnet(&c);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            &format!("{id}.outcome"),
            "modeled-applier-applied-and-durable-consume-authorized",
            &d.outcome,
        );
        t.assert_true(&format!("{id}.authorizes-consume"), d.authorizes_durable_consume());
        t.assert_true(&format!("{id}.applier-invoked"), d.applier_invoked());
    }

    // A8 — modeled noop success authorizes consume with no modeled state drift.
    {
        let mut c = devnet_ctx(ModeledTrustMutationAction::Noop);
        c.mutation.root_id = String::new();
        let input = happy_devnet(&c);
        let mut state = state_with_active_root();
        let before = state.len();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A8.outcome",
            "modeled-applier-applied-and-durable-consume-authorized",
            &d.outcome,
        );
        t.assert_true("A8.authorizes-consume", d.authorizes_durable_consume());
        t.assert_true("A8.no-drift", state.len() == before);
    }

    // A9 — production pipeline path reachable but unavailable, no consume, applier not invoked.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            P::Production,
            K::ProductionUnavailable,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = ProductionModeledTrustMutationApplier::default();
        let d = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("A9.outcome", "production-unavailable-no-consume", &d.outcome);
        t.assert_true("A9.no-consume", d.outcome.no_consume());
        t.assert_true("A9.no-applier", !d.applier_invoked());
    }

    // A10 — MainNet pipeline path (mutating, non-peer-driven) reachable but unavailable, no consume.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            P::MainNet,
            K::MainNetUnavailable,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = MainNetModeledTrustMutationApplier::default();
        let d = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("A10.outcome", "mainnet-unavailable-no-consume", &d.outcome);
        t.assert_true("A10.no-consume", d.outcome.no_consume());
    }

    // A11 — MainNet peer-driven apply refused before replay consume / snapshot / applier.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            P::FixtureDevNet,
            K::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A11.outcome",
            "mainnet-peer-driven-apply-refused-no-consume",
            &d.outcome,
        );
        t.assert_true(
            "A11.is-refusal",
            d.outcome.is_mainnet_peer_driven_apply_refused(),
        );
        t.assert_true("A11.no-applier", !d.applier_invoked());
        t.assert_true("A11.attempts-zero", applier.attempts() == 0);
        t.assert_true("A11.before-mutation-engine", d.mutation_engine.is_none());
        t.assert_true("A11.state-empty", state.is_empty());
    }

    // A12 — validator-set rotation unsupported, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::ValidatorSetRotationUnsupported);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A12.outcome",
            "validator-set-rotation-unsupported-no-consume",
            &d.outcome,
        );
        t.assert_true("A12.no-applier", !d.applier_invoked());
    }

    // A13 — policy-change unsupported, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::PolicyChangeUnsupported);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A13.outcome",
            "policy-change-unsupported-no-consume",
            &d.outcome,
        );
        t.assert_true("A13.no-applier", !d.applier_invoked());
    }

    // A14 — executor trait matches the free function on the happy path.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let exec = DefaultGovernanceModeledEndToEndPipelineExecutor;
        let d = exec.run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "A14.outcome",
            "modeled-applier-applied-and-durable-consume-authorized",
            &d.outcome,
        );
    }

    t.finish(out)
}

// ===========================================================================
// B — rejected / fail-closed scenarios.
// ===========================================================================

/// Helper: a binding-mismatch mutation that should reject at the mutation-engine
/// gate (before the applier) — non-mutating, no consume, applier not invoked.
fn engine_reject(t: &mut Table, id: &str, mutate: impl FnOnce(&mut Ctx)) {
    let mut c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    mutate(&mut c);
    let input = happy_devnet(&c);
    let mut state = state_with_active_root();
    let before = state.len();
    let mut applier = devnet_applier();
    let d = drive(&input, &c.expectations, &mut state, &mut applier);
    t.assert_true(
        &format!("{id}.engine-rejected"),
        matches!(
            d.outcome,
            GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier { .. }
        ),
    );
    t.assert_true(&format!("{id}.no-consume"), d.outcome.no_consume());
    t.assert_true(&format!("{id}.no-applier"), !d.applier_invoked());
    t.assert_true(&format!("{id}.attempts-zero"), applier.attempts() == 0);
    t.assert_true(&format!("{id}.state-unchanged"), state.len() == before);
}

/// Helper: a rejecting replay observation that must never reach mutation/applier.
fn replay_reject(
    t: &mut Table,
    id: &str,
    replay: DurableReplayObservation,
    expected: &str,
) {
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = c.pipeline_input(
        GovernanceModeledEndToEndPipelinePolicy::wired(),
        EvaluatorCallsiteAuthorization::Authorized,
        replay,
        ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
        ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
    );
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = devnet_applier();
    let d = drive(&input, &c.expectations, &mut state, &mut applier);
    t.check_outcome(&format!("{id}.outcome"), expected, &d.outcome);
    t.assert_true(&format!("{id}.no-consume"), d.outcome.no_consume());
    t.assert_true(&format!("{id}.before-mutation-engine"), d.mutation_engine.is_none());
    t.assert_true(&format!("{id}.attempts-zero"), applier.attempts() == 0);
    t.assert_true(&format!("{id}.state-empty"), state.is_empty());
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("rejection");

    // B1 — evaluator rejection before replay: no mutation, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Rejected {
                reason: "evaluator rejected".to_string(),
            },
            DurableReplayObservation::MutationAuthorized,
            ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(
            "B1.evaluator-rejected",
            matches!(
                d.outcome,
                GovernanceModeledEndToEndPipelineOutcome::EvaluatorRejectedBeforeReplay { .. }
            ),
        );
        t.assert_true("B1.no-consume", d.outcome.no_consume());
        t.assert_true("B1.before-mutation-engine", d.mutation_engine.is_none());
        t.assert_true("B1.attempts-zero", applier.attempts() == 0);
        t.assert_true("B1.state-empty", state.is_empty());
    }

    // B2 — call-site (legacy bypass) rejection before replay: legacy bypass, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::LegacyBypass,
            DurableReplayObservation::MutationAuthorized,
            ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("B2.outcome", "proceed-legacy-bypass-no-mutation", &d.outcome);
        t.assert_true("B2.no-consume", d.outcome.no_consume());
        t.assert_true("B2.attempts-zero", applier.attempts() == 0);
    }

    // B3..B13 — binding mismatches rejected before snapshot at the mutation-engine gate.
    engine_reject(&mut t, "B3", |c| c.env.environment = TrustBundleEnvironment::Testnet);
    engine_reject(&mut t, "B4", |c| c.env.chain_id = "qbind-other".to_string());
    engine_reject(&mut t, "B5", |c| c.env.genesis_hash = "genesis-wrong".to_string());
    engine_reject(&mut t, "B6", |c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
    engine_reject(&mut t, "B7", |c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle
    });
    engine_reject(&mut t, "B8", |c| {
        c.mutation.candidate_digest = "candidate-wrong".to_string()
    });
    engine_reject(&mut t, "B9", |c| {
        c.mutation.decision_digest = "decision-wrong".to_string()
    });
    engine_reject(&mut t, "B10", |c| {
        c.mutation.proposal_id = "proposal-wrong".to_string()
    });
    engine_reject(&mut t, "B11", |c| {
        c.mutation.decision_id = "decision-id-wrong".to_string()
    });
    engine_reject(&mut t, "B12", |c| {
        c.mutation.authority_domain_sequence = 99;
        c.runtime.authority_domain_sequence = 99;
    });
    engine_reject(&mut t, "B13", |c| {
        c.mutation.lifecycle_action = LocalLifecycleAction::Retire
    });
    // B14 — malformed modeled mutation (AddTrustRoot with empty root id).
    engine_reject(&mut t, "B14", |c| c.mutation.root_id = String::new());

    // B15 — read-only validation surface rejected before snapshot.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            GovernanceExecutionRuntimeSurface::ReloadCheck,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(
            "B15.before-snapshot",
            matches!(
                d.outcome,
                GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeSnapshot { .. }
            ),
        );
        t.assert_true("B15.no-consume", d.outcome.no_consume());
        t.assert_true("B15.no-applier", !d.applier_invoked());
        t.assert_true("B15.attempts-zero", applier.attempts() == 0);
        t.assert_true("B15.state-empty", state.is_empty());
    }

    // B16..B20 — replay rejections cannot reach mutation or consume.
    replay_reject(&mut t, "B16", DurableReplayObservation::StaleOrExpired, "replay-stale-or-expired-no-consume");
    replay_reject(&mut t, "B17", DurableReplayObservation::Consumed, "replay-consumed-no-consume");
    replay_reject(&mut t, "B18", DurableReplayObservation::Superseded, "replay-superseded-no-consume");
    replay_reject(&mut t, "B19", DurableReplayObservation::BackendUnavailable, "backend-unavailable-no-consume");
    replay_reject(&mut t, "B20", DurableReplayObservation::DeferredOrReadOnly, "durable-replay-rejected-before-mutation");
    replay_reject(&mut t, "B21", DurableReplayObservation::ProductionUnavailable, "production-unavailable-no-consume");
    replay_reject(&mut t, "B22", DurableReplayObservation::MainNetUnavailable, "mainnet-unavailable-no-consume");

    // B23 — consume before modeled applier success is rejected (apply failed).
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedBeforeMutation);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("B23.outcome", "modeled-applier-apply-failed-no-consume", &d.outcome);
        t.assert_true("B23.no-consume", d.outcome.no_consume());
        t.assert_true("B23.applier-invoked", d.applier_invoked());
        t.assert_true("B23.state-empty", state.is_empty());
    }

    // B24 — consume after modeled rollback is rejected.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedRolledBack);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("B24.outcome", "modeled-applier-rolled-back-no-consume", &d.outcome);
        t.assert_true("B24.no-consume", d.outcome.no_consume());
        t.assert_true("B24.state-empty", state.is_empty());
    }

    // B25 — consume after rollback-failed is rejected (fatal).
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::RollbackFailedFatal);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "B25.outcome",
            "modeled-applier-rollback-failed-fatal-no-consume",
            &d.outcome,
        );
        t.assert_true("B25.no-consume", d.outcome.no_consume());
    }

    // B26 — consume after ambiguous window is rejected.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::AmbiguousAfterApply);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome(
            "B26.outcome",
            "modeled-applier-ambiguous-fail-closed-no-consume",
            &d.outcome,
        );
        t.assert_true("B26.no-consume", d.outcome.no_consume());
    }

    // B27 — retiring a missing root rejects before apply (snapshot then reject), no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::RetireTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(
            "B27.before-apply",
            matches!(
                d.outcome,
                GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply { .. }
            ),
        );
        t.assert_true("B27.no-consume", d.outcome.no_consume());
        t.assert_true("B27.applier-invoked", d.applier_invoked());
        t.assert_true("B27.state-empty", state.is_empty());
    }

    // B28 — revoking a missing root rejects before apply, no consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::RevokeTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(
            "B28.before-apply",
            matches!(
                d.outcome,
                GovernanceModeledEndToEndPipelineOutcome::ModeledApplierRejectedBeforeApply { .. }
            ),
        );
        t.assert_true("B28.no-consume", d.outcome.no_consume());
    }

    // B29 — local operator / peer majority cannot satisfy MainNet authority (fail-closed helpers).
    t.assert_true(
        "B29.local-operator-cannot",
        modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "B29.peer-majority-cannot",
        modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // B30 — every rejected path proves the non-mutation invariant helpers in release mode.
    t.assert_true(
        "B30.rejection-non-mutating",
        modeled_end_to_end_pipeline_rejection_is_non_mutating(),
    );
    t.assert_true(
        "B30.never-run-070",
        modeled_end_to_end_pipeline_never_calls_run_070(),
    );
    t.assert_true(
        "B30.never-mutates-live",
        modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state(),
    );

    t.finish(out)
}

// ===========================================================================
// C — recovery / crash-window scenarios.
// ===========================================================================

fn run_recovery_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("recovery");
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);

    // C1 — after modeled report success authorizes durable consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationApplied,
        );
        t.check_outcome(
            "C1.outcome",
            "modeled-applier-applied-and-durable-consume-authorized",
            &o,
        );
        t.assert_true("C1.authorizes-consume", o.authorizes_durable_consume());
    }

    // C2 — after snapshot before apply rolls back / no consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationRolledBack,
        );
        t.check_outcome("C2.outcome", "modeled-applier-rolled-back-no-consume", &o);
        t.assert_true("C2.no-consume", o.no_consume());
    }

    // C3 — after modeled apply before report fails closed (apply-failed) / no consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationApplyFailed,
        );
        t.check_outcome("C3.outcome", "modeled-applier-apply-failed-no-consume", &o);
        t.assert_true("C3.no-consume", o.no_consume());
    }

    // C4 — ambiguous window fails closed / no consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed,
        );
        t.check_outcome(
            "C4.outcome",
            "modeled-applier-ambiguous-fail-closed-no-consume",
            &o,
        );
        t.assert_true("C4.no-consume", o.no_consume());
    }

    // C5 — rollback-failed window is fatal / fail-closed / no consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal,
        );
        t.check_outcome(
            "C5.outcome",
            "modeled-applier-rollback-failed-fatal-no-consume",
            &o,
        );
        t.assert_true("C5.no-consume", o.no_consume());
    }

    // C6 — not-attempted (before evaluator/replay window) recovers as legacy bypass / no consume.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ModeledMutationNotAttempted,
        );
        t.check_outcome("C6.outcome", "proceed-legacy-bypass-no-mutation", &o);
        t.assert_true("C6.no-consume", o.no_consume());
    }

    // C7 — production / MainNet recovery classification unavailable / fail-closed.
    {
        let o = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable,
        );
        t.check_outcome("C7.outcome", "production-unavailable-no-consume", &o);
        let o2 = recover_modeled_end_to_end_pipeline_window(
            &input,
            &ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable,
        );
        t.check_outcome("C7.mainnet-outcome", "mainnet-unavailable-no-consume", &o2);
    }

    // C8 — MainNet peer-driven apply refusal precedes recovery classification.
    {
        let c2 = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input2 = happy_devnet(&c2);
        let o = recover_modeled_end_to_end_pipeline_window(
            &input2,
            &ModeledTrustMutationOutcome::ModeledMutationApplied,
        );
        t.check_outcome("C8.outcome", "mainnet-peer-driven-apply-refused-no-consume", &o);
    }

    t.finish(out)
}

// ===========================================================================
// D — projection scenarios: only a modeled applier success consumes.
// ===========================================================================

fn run_projection_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("projection");

    // D1 — only modeled applier applied success reaches consume-authorized.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("D1.consume", d.authorizes_durable_consume());
        t.assert_true(
            "D1.projection-consume",
            d.durable_projection
                .as_ref()
                .unwrap()
                .projection
                .authorizes_durable_consume(),
        );
    }

    // D2 — evaluator success alone does not consume (deferred replay).
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::DeferredOrReadOnly,
            ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("D2.no-consume", !d.authorizes_durable_consume());
        t.assert_true("D2.before-mutation-engine", d.mutation_engine.is_none());
    }

    // D3 — mutation-engine authorization alone (apply failure) does not consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedBeforeMutation);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("D3.no-consume", !d.authorizes_durable_consume());
        t.assert_true(
            "D3.projection-no-consume",
            !d.durable_projection
                .as_ref()
                .unwrap()
                .projection
                .authorizes_durable_consume(),
        );
    }

    // D4 — rollback / rollback-failed / ambiguous do not consume.
    for (id, fault) in [
        ("D4a", ModeledApplierFault::ApplyFailedRolledBack),
        ("D4b", ModeledApplierFault::RollbackFailedFatal),
        ("D4c", ModeledApplierFault::AmbiguousAfterApply),
    ] {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(fault);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(&format!("{id}.no-consume"), !d.authorizes_durable_consume());
    }

    // D5 — production / MainNet unavailable do not consume.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            ModeledGovernanceTrustMutationPolicy::Production,
            ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = ProductionModeledTrustMutationApplier::default();
        let d = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("D5.no-consume", !d.authorizes_durable_consume());
    }

    // D6 — validator-set rotation / policy-change unsupported do not consume.
    for (id, action) in [
        ("D6a", ModeledTrustMutationAction::ValidatorSetRotationUnsupported),
        ("D6b", ModeledTrustMutationAction::PolicyChangeUnsupported),
    ] {
        let c = devnet_ctx(action);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(&format!("{id}.no-consume"), !d.authorizes_durable_consume());
    }

    t.finish(out)
}

// ===========================================================================
// E — stage-ordering scenarios.
// ===========================================================================

fn run_stage_ordering_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("stage_ordering");

    // E1 — MainNet peer-driven refusal precedes evaluator/replay/mutation/applier.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            ModeledTrustMutationAction::AddTrustRoot,
            ROOT,
        );
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.check_outcome("E1.outcome", "mainnet-peer-driven-apply-refused-no-consume", &d.outcome);
        t.assert_true("E1.no-mutation-engine", d.mutation_engine.is_none());
        t.assert_true("E1.no-applier", !d.applier_invoked());
        t.assert_true("E1.attempts-zero", applier.attempts() == 0);
    }

    // E2 — a rejection before replay leaves mutation-engine and applier unreached.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Rejected {
                reason: "evaluator rejected".to_string(),
            },
            DurableReplayObservation::MutationAuthorized,
            ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("E2.no-mutation-engine", d.mutation_engine.is_none());
        t.assert_true("E2.no-modeled-applier", d.modeled_applier.is_none());
        t.assert_true("E2.attempts-zero", applier.attempts() == 0);
    }

    // E3 — a replay rejection leaves mutation-engine and applier unreached.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::Consumed,
            ModeledGovernanceTrustMutationPolicy::FixtureDevNet,
            ModeledGovernanceTrustMutationApplierKind::FixtureDevNet,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("E3.no-mutation-engine", d.mutation_engine.is_none());
        t.assert_true("E3.no-modeled-applier", d.modeled_applier.is_none());
        t.assert_true("E3.attempts-zero", applier.attempts() == 0);
    }

    // E4 — a mutation-engine rejection leaves the modeled applier unreached (attempts zero).
    {
        let mut c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        c.env.genesis_hash = "genesis-wrong".to_string();
        let input = happy_devnet(&c);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(
            "E4.engine-rejected",
            matches!(
                d.outcome,
                GovernanceModeledEndToEndPipelineOutcome::MutationEngineRejectedBeforeApplier { .. }
            ),
        );
        t.assert_true("E4.no-applier", !d.applier_invoked());
        t.assert_true("E4.attempts-zero", applier.attempts() == 0);
    }

    // E5 — modeled applier failure/rollback/ambiguous leaves durable consume unauthorized.
    for (id, fault) in [
        ("E5a", ModeledApplierFault::ApplyFailedBeforeMutation),
        ("E5b", ModeledApplierFault::ApplyFailedRolledBack),
        ("E5c", ModeledApplierFault::AmbiguousAfterApply),
    ] {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(fault);
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true(&format!("{id}.applier-invoked"), d.applier_invoked());
        t.assert_true(&format!("{id}.no-consume"), !d.durable_consume_decision.authorized);
    }

    // E6 — modeled applier success is evaluated before durable consume authorization.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("E6.applier-invoked", d.applier_invoked());
        t.assert_true("E6.consume-authorized", d.durable_consume_decision.authorized);
        t.assert_true(
            "E6.modeled-applier-stage-present",
            d.modeled_applier.is_some(),
        );
    }

    t.finish(out)
}

// ===========================================================================
// F — non-mutation scenarios.
// ===========================================================================

fn run_non_mutation_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("non_mutation");

    // F1 — every rejected/unsupported helper path proves the explicit non-mutation invariants.
    t.assert_true(
        "F1.rejection-non-mutating",
        modeled_end_to_end_pipeline_rejection_is_non_mutating(),
    );
    t.assert_true("F1.never-run-070", modeled_end_to_end_pipeline_never_calls_run_070());
    t.assert_true(
        "F1.never-mutates-live",
        modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "F1.no-rocksdb-file-schema-migration",
        modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change(),
    );

    // F2 — the fixture applier mutates only ModeledGovernanceTrustState on success.
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = happy_devnet(&c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("F2.applied", d.authorizes_durable_consume());
        t.assert_true("F2.only-modeled-state", state.contains_active(ROOT));
    }

    // F3 — every binding-mismatch rejection leaves modeled state unchanged and applier unreached.
    {
        let mut c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        c.mutation.proposal_id = "proposal-wrong".to_string();
        let input = happy_devnet(&c);
        let mut state = state_with_active_root();
        let before = state.len();
        let mut applier = devnet_applier();
        let d = drive(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("F3.no-consume", d.outcome.no_consume());
        t.assert_true("F3.attempts-zero", applier.attempts() == 0);
        t.assert_true("F3.state-unchanged", state.len() == before);
    }

    // F4 — production / MainNet paths remain unavailable / fail-closed (no modeled mutation).
    {
        let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
        let input = c.pipeline_input(
            GovernanceModeledEndToEndPipelinePolicy::wired(),
            EvaluatorCallsiteAuthorization::Authorized,
            DurableReplayObservation::MutationAuthorized,
            ModeledGovernanceTrustMutationPolicy::Production,
            ModeledGovernanceTrustMutationApplierKind::ProductionUnavailable,
        );
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = ProductionModeledTrustMutationApplier::default();
        let d = run_modeled_end_to_end_pipeline(&input, &c.expectations, &mut state, &mut applier);
        t.assert_true("F4.no-consume", d.outcome.no_consume());
        t.assert_true("F4.state-empty", state.is_empty());
    }

    // F5 — production / MainNet unavailable invariant + unsupported actions.
    t.assert_true(
        "F5.production-mainnet-unavailable",
        modeled_end_to_end_pipeline_production_mainnet_unavailable(),
    );
    t.assert_true(
        "F5.validator-rotation-unsupported",
        modeled_end_to_end_pipeline_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "F5.policy-change-unsupported",
        modeled_end_to_end_pipeline_policy_change_unsupported(),
    );

    // F6 — MainNet peer-driven apply remains refused first (helper + driven case).
    t.assert_true(
        "F6.refused-mainnet",
        modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    t.assert_true(
        "F6.not-refused-devnet",
        !modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet,
        ),
    );

    t.finish(out)
}

// ===========================================================================
// G — reachability table. Drives every grep-verifiable invariant / fail-closed
// helper in release mode.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("reachability");

    t.assert_true(
        "G.rejection-non-mutating",
        modeled_end_to_end_pipeline_rejection_is_non_mutating(),
    );
    t.assert_true("G.never-calls-run-070", modeled_end_to_end_pipeline_never_calls_run_070());
    t.assert_true(
        "G.never-mutates-live",
        modeled_end_to_end_pipeline_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "G.success-required",
        modeled_end_to_end_pipeline_success_required_before_durable_consume(),
    );
    t.assert_true(
        "G.applier-success-required",
        modeled_end_to_end_pipeline_applier_success_required_before_consume(),
    );
    t.assert_true(
        "G.failed-apply-never-consumes",
        modeled_end_to_end_pipeline_failed_apply_never_consumes(),
    );
    t.assert_true(
        "G.rollback-never-consumes",
        modeled_end_to_end_pipeline_rollback_never_consumes(),
    );
    t.assert_true(
        "G.ambiguous-fails-closed",
        modeled_end_to_end_pipeline_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "G.production-mainnet-unavailable",
        modeled_end_to_end_pipeline_production_mainnet_unavailable(),
    );
    t.assert_true(
        "G.mainnet-refused-mainnet",
        modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Mainnet,
        ),
    );
    t.assert_true(
        "G.mainnet-refused-not-devnet",
        !modeled_end_to_end_pipeline_mainnet_peer_driven_apply_refused_first(
            TrustBundleEnvironment::Devnet,
        ),
    );
    t.assert_true(
        "G.validator-rotation-unsupported",
        modeled_end_to_end_pipeline_validator_set_rotation_unsupported(),
    );
    t.assert_true(
        "G.policy-change-unsupported",
        modeled_end_to_end_pipeline_policy_change_unsupported(),
    );
    t.assert_true(
        "G.no-rocksdb-file-schema-migration",
        modeled_end_to_end_pipeline_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "G.local-operator-cannot",
        modeled_end_to_end_pipeline_local_operator_cannot_satisfy_mainnet_authority(),
    );
    t.assert_true(
        "G.peer-majority-cannot",
        modeled_end_to_end_pipeline_peer_majority_cannot_satisfy_mainnet_authority(),
    );

    // Exercise the pipeline outcome taxonomy tags in release mode.
    t.check(
        "G.tag-consume-authorized",
        "modeled-applier-applied-and-durable-consume-authorized",
        GovernanceModeledEndToEndPipelineOutcome::ModeledApplierAppliedAndDurableConsumeAuthorized
            .tag(),
    );
    t.check(
        "G.tag-mainnet-refused",
        "mainnet-peer-driven-apply-refused-no-consume",
        GovernanceModeledEndToEndPipelineOutcome::MainNetPeerDrivenApplyRefusedNoConsume.tag(),
    );
    t.check(
        "G.tag-replay-consumed",
        "replay-consumed-no-consume",
        GovernanceModeledEndToEndPipelineOutcome::ReplayConsumedNoConsume.tag(),
    );
    t.check(
        "G.tag-backend-unavailable",
        "backend-unavailable-no-consume",
        GovernanceModeledEndToEndPipelineOutcome::BackendUnavailableNoConsume.tag(),
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump (decision values minted in release mode).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");

    // Full success lifecycle: pipeline -> outcome -> consume decision.
    let c = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    let input = happy_devnet(&c);
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = devnet_applier();
    let d = drive(&input, &c.expectations, &mut state, &mut applier);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} authorizes_consume={} applier_invoked={} root_status={} engine_map={}\n",
            d.outcome.tag(),
            d.authorizes_durable_consume(),
            d.applier_invoked(),
            state.status_of(ROOT).map(|s| s.tag()).unwrap_or("absent"),
            d.mutation_engine.as_ref().unwrap().outcome.tag(),
        ),
    );

    // Rejected lifecycle: wrong genesis -> mutation-engine reject-before-applier, no consume.
    let mut c2 = devnet_ctx(ModeledTrustMutationAction::AddTrustRoot);
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let input2 = happy_devnet(&c2);
    let mut state2 = state_with_active_root();
    let mut applier2 = devnet_applier();
    let d2 = drive(&input2, &c2.expectations, &mut state2, &mut applier2);
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} applier_attempts={} applier_invoked={} no_consume={} state_len={}\n",
            d2.outcome.tag(),
            applier2.attempts(),
            d2.applier_invoked(),
            d2.outcome.no_consume(),
            state2.len(),
        ),
    );

    // MainNet peer-driven refusal precedes everything.
    let c3 = ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT,
    );
    let input3 = happy_devnet(&c3);
    let mut state3 = ModeledGovernanceTrustState::new();
    let mut applier3 = devnet_applier();
    let d3 = drive(&input3, &c3.expectations, &mut state3, &mut applier3);
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} applier_attempts={} is_refusal={} mutation_engine_reached={}\n",
            d3.outcome.tag(),
            applier3.attempts(),
            d3.outcome.is_mainnet_peer_driven_apply_refused(),
            d3.mutation_engine.is_some(),
        ),
    );

    // Recovery window classifications.
    let mut windows = String::new();
    for (label, modeled) in [
        ("after-report-success", ModeledTrustMutationOutcome::ModeledMutationApplied),
        ("rolled-back", ModeledTrustMutationOutcome::ModeledMutationRolledBack),
        ("apply-failed", ModeledTrustMutationOutcome::ModeledMutationApplyFailed),
        ("ambiguous", ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed),
        ("rollback-failed", ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal),
        ("not-attempted", ModeledTrustMutationOutcome::ModeledMutationNotAttempted),
    ] {
        let o = recover_modeled_end_to_end_pipeline_window(&input, &modeled);
        windows.push_str(&format!("{label}={}\n", o.tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_247_governance_modeled_end_to_end_pipeline_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("stage_ordering", run_stage_ordering_table),
        ("non_mutation", run_non_mutation_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_247_governance_modeled_end_to_end_pipeline_release_binary_helper\nscope: Run 246 governance modeled end-to-end pipeline boundary (pqc_governance_modeled_end_to_end_pipeline: run_modeled_end_to_end_pipeline, recover_modeled_end_to_end_pipeline_window, the DefaultGovernanceModeledEndToEndPipelineExecutor/GovernanceModeledEndToEndPipelineExecutor trait boundary, the GovernanceModeledEndToEndPipelineInput/Expectations/Policy/Surface/EnvironmentBinding/RuntimeBinding/Candidate/ReplayBinding/MutationBinding bindings, the EvaluatorCallsiteStage/DurableReplayObserveStage/MutationEngineStage/ModeledApplierStage/DurableProjectionStage/DurableConsumeDecisionStage stage records, the GovernanceModeledEndToEndPipelineOutcome taxonomy, the GovernanceModeledEndToEndPipelineDecision result, the EvaluatorCallsiteAuthorization/DurableReplayObservation stage classifications, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed ordering/composition layer (the fixture applier mutates ONLY the in-memory ModeledGovernanceTrustState; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no durable consume of its own, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a disabled pipeline/evaluator-call-site policy is a legacy bypass with no modeled mutation and no applier invocation; MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation; evaluator/call-site authorization runs before durable replay consume; durable replay freshness runs before mutation-engine authorization; mutation-engine authorization runs before modeled applier invocation; modeled applier success runs before durable consume authorization; the only consume-authorizing outcome is ModeledApplierAppliedAndDurableConsumeAuthorized; evaluator success alone, durable replay freshness alone, and mutation-engine authorization alone are each insufficient; every rejection/unavailable/rollback/rollback-failed/ambiguous/read-only/validator-set-rotation/policy-change path is non-mutating and non-consuming, and a rejection before the applier stage leaves the applier invocation count at zero\n\n",
    );
    for (name, f) in tables {
        let (p, fcnt) = f(&out_dir);
        total_pass += p;
        total_fail += fcnt;
        summary.push_str(&format!("table {name}: pass={p} fail={fcnt}\n"));
    }
    run_fixture_dump(&out_dir);
    summary.push_str(&format!(
        "\ntotal_pass: {total_pass}\ntotal_fail: {total_fail}\nverdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
