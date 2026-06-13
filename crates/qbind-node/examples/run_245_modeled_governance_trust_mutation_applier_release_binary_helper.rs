//! Run 245 — release-built helper for the Run 244 governance **modeled
//! trust-state mutation applier boundary**
//! (`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`).
//!
//! Where Run 244 landed the pure, typed modeled trust-state mutation applier
//! boundary at the source/test level and captured **no** release-binary
//! evidence, Run 245 is that release-binary evidence. This helper drives an
//! accepted / rejection / recovery / projection / modeled-state / reachability
//! corpus through the **release-built** Run 244 symbols
//! (`evaluate_modeled_trust_mutation`, `recover_modeled_trust_mutation`,
//! `map_modeled_outcome_to_mutation_engine_outcome`,
//! `project_modeled_outcome_to_durable_completion`,
//! `modeled_outcome_authorizes_durable_consume`, the
//! `ModeledGovernanceTrustState` / `ModeledGovernanceTrustSnapshot` /
//! `ModeledGovernanceTrustRoot` / `ModeledTrustRootStatus` modeled state, the
//! `ModeledGovernanceTrustMutation` / `ModeledGovernanceTrustMutationInput` /
//! `ModeledGovernanceTrustMutationExpectations` /
//! `ModeledGovernanceTrustMutationPolicy` / `ModeledGovernanceTrustMutationSurface`
//! / `ModeledGovernanceTrustMutationEnvironmentBinding` /
//! `ModeledGovernanceTrustMutationRuntimeBinding` bindings, the
//! `ModeledTrustMutationAction` / `ModeledTrustMutationOutcome` taxonomy, the
//! pure/mockable `ModeledGovernanceTrustMutationApplier` trait with the
//! `FixtureModeledTrustMutationApplier` / `ProductionModeledTrustMutationApplier`
//! / `MainNetModeledTrustMutationApplier` implementations, and the
//! grep-verifiable invariant / fail-closed helpers), proving in release mode
//! that:
//!
//! * a default `Disabled` policy / `Disabled` applier kind is a legacy bypass
//!   that performs no modeled mutation and never invokes the applier;
//! * a DevNet/TestNet fixture modeled add/retire/revoke/emergency-revoke/noop
//!   succeeds and mutates **only** the in-memory `ModeledGovernanceTrustState`;
//! * a modeled apply success maps to
//!   `GovernanceMutationOutcome::MutationAppliedSuccessfully` and projects to a
//!   consume-eligible `DurableMutationCompletion::AppliedSuccessfully`;
//! * a rejection (before snapshot / before apply), an apply failure, a rollback,
//!   a rollback-failed-fatal, an ambiguous window, an unavailable production /
//!   MainNet applier, and an unsupported action never consume;
//! * production / MainNet applier kinds are reachable but always unavailable /
//!   fail-closed;
//! * MainNet peer-driven apply is refused before any snapshot and before applier
//!   invocation;
//! * every binding mismatch (wrong environment / chain / genesis / governance
//!   surface / mutation surface / candidate digest / decision digest / proposal
//!   id / decision id / authority-domain sequence / lifecycle action, or a
//!   malformed modeled mutation) is rejected before snapshot and never invokes
//!   the applier;
//! * validator-set rotation and policy-change actions remain unsupported;
//! * every rejected path is non-mutating and leaves modeled state unchanged.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, mutation engine, on-chain proof verifier, persistent replay
//! backend, KMS/HSM, or RemoteSigner backend. No RocksDB/file/schema/migration/
//! storage-format change. The appliers are pure in-process models and
//! DevNet/TestNet evidence-only. The fixture applier mutates only the modeled
//! in-memory `ModeledGovernanceTrustState`; it never mutates `LivePqcTrustState`,
//! calls Run 070, performs a real trust swap, evicts sessions, writes a sequence,
//! writes a marker, or performs a durable consume. MainNet peer-driven apply
//! remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_modeled_trust_mutation_applier::{
    evaluate_modeled_trust_mutation, local_operator_cannot_satisfy_modeled_trust_applier_authority,
    mainnet_peer_driven_apply_refused_by_modeled_trust_applier,
    map_modeled_outcome_to_mutation_engine_outcome,
    modeled_outcome_authorizes_durable_consume,
    modeled_trust_applier_ambiguous_window_fails_closed,
    modeled_trust_applier_failure_never_consumes,
    modeled_trust_applier_never_calls_run_070,
    modeled_trust_applier_never_mutates_live_pqc_trust_state,
    modeled_trust_applier_no_rocksdb_file_schema_migration_change,
    modeled_trust_applier_rejection_is_non_mutating,
    modeled_trust_applier_rollback_never_consumes,
    modeled_trust_applier_success_required_before_durable_consume,
    peer_majority_cannot_satisfy_modeled_trust_applier_authority,
    policy_change_unsupported_by_modeled_trust_applier,
    production_mainnet_modeled_trust_applier_unavailable, project_modeled_outcome_to_durable_completion,
    recover_modeled_trust_mutation, validator_set_rotation_unsupported_by_modeled_trust_applier,
    FixtureModeledTrustMutationApplier, MainNetModeledTrustMutationApplier, ModeledApplierFault,
    ModeledGovernanceTrustMutation, ModeledGovernanceTrustMutationApplier,
    ModeledGovernanceTrustMutationApplierKind, ModeledGovernanceTrustMutationEnvironmentBinding,
    ModeledGovernanceTrustMutationExpectations, ModeledGovernanceTrustMutationInput,
    ModeledGovernanceTrustMutationPolicy, ModeledGovernanceTrustMutationRuntimeBinding,
    ModeledGovernanceTrustMutationSurface, ModeledGovernanceTrustRoot, ModeledGovernanceTrustState,
    ModeledTrustMutationAction, ModeledTrustMutationOutcome, ModeledTrustMutationWindowObservation,
    ModeledTrustRootStatus, ProductionModeledTrustMutationApplier,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 244 corpus so the composed material binds to
// the same trust domain, proposal/decision identity, candidate digest).
// ===========================================================================

const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;
const ROOT_A: &str = "root-A";

// ===========================================================================
// Owned-context builder
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
    fn input(
        &self,
        kind: ModeledGovernanceTrustMutationApplierKind,
        policy: ModeledGovernanceTrustMutationPolicy,
    ) -> ModeledGovernanceTrustMutationInput<'_> {
        ModeledGovernanceTrustMutationInput {
            applier_kind: kind,
            policy,
            mutation: &self.mutation,
            environment_binding: &self.env,
            runtime_binding: &self.runtime,
        }
    }
}

/// DevNet modeled add-root context (binding consistent with its own
/// expectations).
fn devnet_add() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT_A,
    )
}

fn testnet_add() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT_A,
    )
}

fn devnet_action(action: ModeledTrustMutationAction, root_id: &str) -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        action,
        root_id,
    )
}

fn devnet_validation() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT_A,
    )
}

fn mainnet_peer_driven() -> Ctx {
    ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        ModeledTrustMutationAction::AddTrustRoot,
        ROOT_A,
    )
}

fn devnet_applier() -> FixtureModeledTrustMutationApplier {
    FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Devnet)
}

fn testnet_applier() -> FixtureModeledTrustMutationApplier {
    FixtureModeledTrustMutationApplier::new(TrustBundleEnvironment::Testnet)
}

fn devnet_applier_fault(fault: ModeledApplierFault) -> FixtureModeledTrustMutationApplier {
    FixtureModeledTrustMutationApplier::with_fault(TrustBundleEnvironment::Devnet, fault)
}

/// A modeled state pre-populated with one active root, for retire/revoke cases.
fn state_with_active_root() -> ModeledGovernanceTrustState {
    ModeledGovernanceTrustState::with_roots(vec![ModeledGovernanceTrustRoot::active(
        ROOT_A.to_string(),
    )])
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: &ModeledTrustMutationOutcome) {
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

/// Stable string tag for a modeled outcome's Run 242 mutation-engine mapping.
fn engine_tag(o: &ModeledTrustMutationOutcome) -> String {
    map_modeled_outcome_to_mutation_engine_outcome(o).tag().to_string()
}

/// Stable string tag for a modeled outcome's Run 240 durable projection
/// (consume-eligibility folded in).
fn projection_consume(o: &ModeledTrustMutationOutcome) -> bool {
    project_modeled_outcome_to_durable_completion(o).authorizes_durable_consume()
}

// ===========================================================================
// A — accepted / compatible scenarios exercised through the Run 244
// release-built modeled-applier boundary symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let mut t = Table::new("accepted");

    // A1 — disabled policy preserves legacy bypass and performs no modeled mutation.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::Disabled),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A1.outcome", "modeled-mutation-not-attempted", &o);
        t.assert_true("A1.no-applier", applier.attempts() == 0);
        t.assert_true("A1.state-empty", state.is_empty());
    }

    // A2 — disabled applier kind preserves legacy bypass and performs no modeled mutation.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::Disabled, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A2.outcome", "modeled-mutation-not-attempted", &o);
        t.assert_true("A2.no-applier", applier.attempts() == 0);
        t.assert_true("A2.state-empty", state.is_empty());
    }

    // A3 — DevNet fixture modeled add-root succeeds and mutates only modeled state.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A3.outcome", "modeled-mutation-applied", &o);
        t.assert_true("A3.applier-once", applier.attempts() == 1);
        t.assert_true("A3.root-active", state.contains_active(ROOT_A));
        t.assert_true("A3.only-one-root", state.len() == 1);
    }

    // A4 — TestNet fixture modeled add-root succeeds and mutates only modeled state.
    {
        let c = testnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = testnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureTestNet, P::FixtureTestNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A4.outcome", "modeled-mutation-applied", &o);
        t.assert_true("A4.applier-once", applier.attempts() == 1);
        t.assert_true("A4.root-active", state.contains_active(ROOT_A));
    }

    // A5 — modeled retire-root succeeds in fixture state only.
    {
        let c = devnet_action(ModeledTrustMutationAction::RetireTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A5.outcome", "modeled-mutation-applied", &o);
        t.check(
            "A5.status",
            "retired",
            state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"),
        );
    }

    // A6 — modeled revoke-root succeeds in fixture state only.
    {
        let c = devnet_action(ModeledTrustMutationAction::RevokeTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A6.outcome", "modeled-mutation-applied", &o);
        t.check(
            "A6.status",
            "revoked",
            state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"),
        );
    }

    // A7 — modeled emergency-revoke-root succeeds in fixture state only.
    {
        let c = devnet_action(ModeledTrustMutationAction::EmergencyRevokeTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A7.outcome", "modeled-mutation-applied", &o);
        t.check(
            "A7.status",
            "emergency-revoked",
            state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"),
        );
    }

    // A8 — modeled noop succeeds without state drift.
    {
        let c = devnet_action(ModeledTrustMutationAction::Noop, "");
        let mut state = state_with_active_root();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A8.outcome", "modeled-mutation-applied", &o);
        t.assert_true("A8.no-drift", state.snapshot() == before);
    }

    // A9 — duplicate root handled idempotently under an explicit typed outcome.
    {
        let c = devnet_add();
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A9.outcome", "modeled-mutation-applied", &o);
        t.assert_true("A9.idempotent-len", state.len() == 1);
        t.assert_true("A9.root-active", state.contains_active(ROOT_A));
    }

    // A10 — modeled apply success maps to MutationAppliedSuccessfully.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check("A10.engine-map", "mutation-applied-successfully", &engine_tag(&o));
    }

    // A11 — modeled apply success projects to consume-eligible durable completion.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.assert_true("A11.authorizes-consume", modeled_outcome_authorizes_durable_consume(&o));
        t.assert_true("A11.projection-consume", projection_consume(&o));
    }

    // A12 — production modeled applier path is reachable but unavailable/fail-closed.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = ProductionModeledTrustMutationApplier;
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::ProductionUnavailable, P::Production),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A12.outcome", "production-modeled-mutation-unavailable", &o);
        t.assert_true("A12.no-consume", o.no_consume());
        t.assert_true("A12.state-empty", state.is_empty());
    }

    // A13 — MainNet modeled applier path is reachable but unavailable/fail-closed.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = MainNetModeledTrustMutationApplier;
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A13.outcome", "mainnet-modeled-mutation-unavailable", &o);
        t.assert_true("A13.no-consume", o.no_consume());
        t.assert_true("A13.state-empty", state.is_empty());
    }

    // A14 — MainNet peer-driven apply refused before snapshot and before applier invocation.
    {
        let c = mainnet_peer_driven();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A14.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("A14.is-refusal", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("A14.no-applier", applier.attempts() == 0);
        t.assert_true("A14.applier-must-not-run", o.applier_must_not_run());
        t.assert_true("A14.state-empty", state.is_empty());
    }

    // A15 — validator-set rotation unsupported.
    {
        let c = devnet_action(ModeledTrustMutationAction::ValidatorSetRotationUnsupported, ROOT_A);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A15.outcome", "validator-set-rotation-unsupported", &o);
        t.assert_true("A15.no-applier", applier.attempts() == 0);
    }

    // A16 — policy-change unsupported.
    {
        let c = devnet_action(ModeledTrustMutationAction::PolicyChangeUnsupported, ROOT_A);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("A16.outcome", "policy-change-unsupported", &o);
        t.assert_true("A16.no-applier", applier.attempts() == 0);
    }

    t.finish(out)
}

// ===========================================================================
// B — rejection scenarios. Every rejected path is non-mutating, leaves modeled
// state unchanged, and (where rejection happens before apply) never invokes the
// applier.
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let mut t = Table::new("rejection");

    // Each entry mutates one field of the binding/expectations to force a
    // reject-before-snapshot. The applier attempt counter must stay at zero and
    // the modeled state must be unchanged.
    let mut reject_before_snapshot = |id: &str, mutate: &dyn Fn(&mut Ctx)| {
        let mut c = devnet_add();
        mutate(&mut c);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.assert_true(
            &format!("{id}.before-snapshot"),
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }),
        );
        t.assert_true(&format!("{id}.no-applier"), applier.attempts() == 0);
        t.assert_true(&format!("{id}.applier-must-not-run"), o.applier_must_not_run());
        t.assert_true(&format!("{id}.state-empty"), state.is_empty());
        t.assert_true(&format!("{id}.no-consume"), o.no_consume());
    };

    reject_before_snapshot("B-env", &|c| c.env.environment = TrustBundleEnvironment::Testnet);
    reject_before_snapshot("B-chain", &|c| c.env.chain_id = "wrong-chain".to_string());
    reject_before_snapshot("B-genesis", &|c| c.env.genesis_hash = "wrong-genesis".to_string());
    reject_before_snapshot("B-gov-surface", &|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain
    });
    reject_before_snapshot("B-mut-surface", &|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain
    });
    reject_before_snapshot("B-cand-digest", &|c| c.mutation.candidate_digest = "wrong".to_string());
    reject_before_snapshot("B-dec-digest", &|c| c.mutation.decision_digest = "wrong".to_string());
    reject_before_snapshot("B-proposal", &|c| c.mutation.proposal_id = "wrong".to_string());
    reject_before_snapshot("B-decision", &|c| c.mutation.decision_id = "wrong".to_string());
    reject_before_snapshot("B-authseq", &|c| c.mutation.authority_domain_sequence = 99);
    reject_before_snapshot("B-lifecycle", &|c| {
        c.mutation.lifecycle_action = LocalLifecycleAction::Retire
    });
    reject_before_snapshot("B-malformed", &|c| c.mutation.root_id = String::new());

    // B-readonly — read-only validation surface rejected before snapshot.
    {
        let c = devnet_validation();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.assert_true(
            "B-readonly.before-snapshot",
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }),
        );
        t.assert_true("B-readonly.no-applier", applier.attempts() == 0);
        t.assert_true("B-readonly.state-empty", state.is_empty());
    }

    // B-retire-missing — retiring a missing root snapshots then rejects-before-apply
    // with modeled state unchanged.
    {
        let c = devnet_action(ModeledTrustMutationAction::RetireTrustRoot, "absent-root");
        let mut state = ModeledGovernanceTrustState::new();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.assert_true(
            "B-retire-missing.before-apply",
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { .. }),
        );
        t.assert_true("B-retire-missing.applier-once", applier.attempts() == 1);
        t.assert_true("B-retire-missing.state-unchanged", state.snapshot() == before);
        t.assert_true("B-retire-missing.no-consume", o.no_consume());
    }

    // B-revoke-missing — revoking a missing root snapshots then rejects-before-apply.
    {
        let c = devnet_action(ModeledTrustMutationAction::RevokeTrustRoot, "absent-root");
        let mut state = ModeledGovernanceTrustState::new();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.assert_true(
            "B-revoke-missing.before-apply",
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { .. }),
        );
        t.assert_true("B-revoke-missing.state-unchanged", state.snapshot() == before);
        t.assert_true("B-revoke-missing.no-consume", o.no_consume());
    }

    // B-apply-failed — apply failure rolls back / never consumes (apply-failed before mutation).
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let before = state.snapshot();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedBeforeMutation);
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-apply-failed.outcome", "modeled-mutation-apply-failed", &o);
        t.assert_true("B-apply-failed.state-unchanged", state.snapshot() == before);
        t.assert_true("B-apply-failed.no-consume", o.no_consume());
    }

    // B-rolled-back — apply mutated then rolled back; never consumes; state restored.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let before = state.snapshot();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedRolledBack);
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-rolled-back.outcome", "modeled-mutation-rolled-back", &o);
        t.assert_true("B-rolled-back.state-restored", state.snapshot() == before);
        t.assert_true("B-rolled-back.no-consume", o.no_consume());
    }

    // B-rollback-failed — rollback failure is fatal/fail-closed; never consumes.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::RollbackFailedFatal);
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome(
            "B-rollback-failed.outcome",
            "modeled-mutation-rollback-failed-fatal",
            &o,
        );
        t.assert_true("B-rollback-failed.no-consume", o.no_consume());
    }

    // B-ambiguous — ambiguous after-apply window fails closed; never consumes.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::AmbiguousAfterApply);
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome(
            "B-ambiguous.outcome",
            "modeled-mutation-ambiguous-fail-closed",
            &o,
        );
        t.assert_true("B-ambiguous.no-consume", o.no_consume());
    }

    // B-production / B-mainnet — production / MainNet modeled appliers unavailable.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = ProductionModeledTrustMutationApplier;
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::ProductionUnavailable, P::Production),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-production.outcome", "production-modeled-mutation-unavailable", &o);
        t.assert_true("B-production.no-consume", o.no_consume());
    }
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = MainNetModeledTrustMutationApplier;
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-mainnet.outcome", "mainnet-modeled-mutation-unavailable", &o);
        t.assert_true("B-mainnet.no-consume", o.no_consume());
    }

    // B-validator-rotation / B-policy-change — unsupported actions never reach applier.
    {
        let c = devnet_action(ModeledTrustMutationAction::ValidatorSetRotationUnsupported, ROOT_A);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-validator-rotation.outcome", "validator-set-rotation-unsupported", &o);
        t.assert_true("B-validator-rotation.no-applier", applier.attempts() == 0);
        t.assert_true("B-validator-rotation.no-consume", o.no_consume());
    }
    {
        let c = devnet_action(ModeledTrustMutationAction::PolicyChangeUnsupported, ROOT_A);
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut state,
            &mut applier,
        );
        t.check_outcome("B-policy-change.outcome", "policy-change-unsupported", &o);
        t.assert_true("B-policy-change.no-applier", applier.attempts() == 0);
        t.assert_true("B-policy-change.no-consume", o.no_consume());
    }

    // B-authority — local operator key and peer majority cannot satisfy authority;
    // and durable-state non-consume invariants (stale/consumed/superseded/backend
    // unavailable) are folded into the projection helpers below.
    t.assert_true(
        "B-local-operator-cannot",
        local_operator_cannot_satisfy_modeled_trust_applier_authority(),
    );
    t.assert_true(
        "B-peer-majority-cannot",
        peer_majority_cannot_satisfy_modeled_trust_applier_authority(),
    );

    t.finish(out)
}

// ===========================================================================
// C — recovery scenarios. The recovery classifier is pure and fails closed on
// every ambiguous / unknown window.
// ===========================================================================

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let mut t = Table::new("recovery");

    let recover = |obs: ModeledTrustMutationWindowObservation| -> ModeledTrustMutationOutcome {
        let c = devnet_add();
        let applier = devnet_applier();
        recover_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs,
            &applier,
        )
    };

    // C1 — before-snapshot window recovers as not-attempted / no consume.
    {
        let o = recover(ModeledTrustMutationWindowObservation::default());
        t.check_outcome("C1.outcome", "modeled-mutation-not-attempted", &o);
        t.assert_true("C1.no-consume", o.no_consume());
    }

    // C2 — after-snapshot-before-apply rolls back modeled state / no consume.
    {
        let o = recover(ModeledTrustMutationWindowObservation {
            snapshotted: true,
            ..Default::default()
        });
        t.check_outcome("C2.outcome", "modeled-mutation-rolled-back", &o);
        t.assert_true("C2.no-consume", o.no_consume());
    }

    // C3 — after-apply-before-report fails closed unless an explicit success report exists.
    {
        let o = recover(ModeledTrustMutationWindowObservation {
            snapshotted: true,
            applied: true,
            ..Default::default()
        });
        t.check_outcome("C3.outcome", "modeled-mutation-ambiguous-fail-closed", &o);
        t.assert_true("C3.no-consume", o.no_consume());
    }

    // C4 — after-report-success recovers as modeled applied.
    {
        let o = recover(ModeledTrustMutationWindowObservation {
            snapshotted: true,
            applied: true,
            completion_reported: true,
            success_reported: true,
            rollback_failed: false,
        });
        t.check_outcome("C4.outcome", "modeled-mutation-applied", &o);
        t.assert_true("C4.consume", modeled_outcome_authorizes_durable_consume(&o));
    }

    // C5 — after-report-ambiguous window fails closed.
    {
        let o = recover(ModeledTrustMutationWindowObservation {
            snapshotted: true,
            applied: true,
            completion_reported: true,
            success_reported: false,
            rollback_failed: false,
        });
        t.check_outcome("C5.outcome", "modeled-mutation-ambiguous-fail-closed", &o);
        t.assert_true("C5.no-consume", o.no_consume());
    }

    // C6 — rollback-failed window is fatal / fail-closed.
    {
        let o = recover(ModeledTrustMutationWindowObservation {
            snapshotted: true,
            applied: true,
            rollback_failed: true,
            ..Default::default()
        });
        t.check_outcome("C6.outcome", "modeled-mutation-rollback-failed-fatal", &o);
        t.assert_true("C6.no-consume", o.no_consume());
    }

    // C7 — production recovery classification unavailable / fail-closed.
    {
        let c = devnet_add();
        let applier = ProductionModeledTrustMutationApplier;
        let o = recover_modeled_trust_mutation(
            &c.input(K::ProductionUnavailable, P::Production),
            &ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                completion_reported: true,
                success_reported: true,
                rollback_failed: false,
            },
            &applier,
        );
        t.check_outcome("C7.outcome", "production-modeled-mutation-unavailable", &o);
        t.assert_true("C7.no-consume", o.no_consume());
    }

    // C8 — MainNet recovery classification unavailable / fail-closed.
    {
        let c = devnet_add();
        let applier = MainNetModeledTrustMutationApplier;
        let o = recover_modeled_trust_mutation(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                completion_reported: true,
                success_reported: true,
                rollback_failed: false,
            },
            &applier,
        );
        t.check_outcome("C8.outcome", "mainnet-modeled-mutation-unavailable", &o);
        t.assert_true("C8.no-consume", o.no_consume());
    }

    // C9 — MainNet peer-driven apply refusal precedes recovery classification.
    {
        let c = mainnet_peer_driven();
        let applier = devnet_applier();
        let o = recover_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                completion_reported: true,
                success_reported: true,
                rollback_failed: false,
            },
            &applier,
        );
        t.check_outcome("C9.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("C9.no-consume", o.no_consume());
    }

    t.finish(out)
}

// ===========================================================================
// D — projection scenarios. Only ModeledMutationApplied projects to a
// consume-eligible durable completion; everything else never consumes.
// ===========================================================================

fn run_projection_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("projection");

    // D-applied — only ModeledMutationApplied consumes.
    let applied = ModeledTrustMutationOutcome::ModeledMutationApplied;
    t.check("D-applied.engine", "mutation-applied-successfully", &engine_tag(&applied));
    t.assert_true("D-applied.consume", modeled_outcome_authorizes_durable_consume(&applied));

    // Every non-applied outcome must not consume.
    let non_consuming: &[(&str, ModeledTrustMutationOutcome)] = &[
        ("not-attempted", ModeledTrustMutationOutcome::ModeledMutationNotAttempted),
        (
            "rejected-before-snapshot",
            ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot {
                reason: "x".to_string(),
            },
        ),
        (
            "rejected-before-apply",
            ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply {
                reason: "x".to_string(),
            },
        ),
        ("apply-failed", ModeledTrustMutationOutcome::ModeledMutationApplyFailed),
        ("rolled-back", ModeledTrustMutationOutcome::ModeledMutationRolledBack),
        (
            "rollback-failed-fatal",
            ModeledTrustMutationOutcome::ModeledMutationRollbackFailedFatal,
        ),
        (
            "ambiguous-fail-closed",
            ModeledTrustMutationOutcome::ModeledMutationAmbiguousFailClosed,
        ),
        (
            "production-unavailable",
            ModeledTrustMutationOutcome::ProductionModeledMutationUnavailable,
        ),
        (
            "mainnet-unavailable",
            ModeledTrustMutationOutcome::MainNetModeledMutationUnavailable,
        ),
        (
            "mainnet-peer-driven-refused",
            ModeledTrustMutationOutcome::MainNetPeerDrivenApplyRefused,
        ),
        (
            "validator-set-rotation-unsupported",
            ModeledTrustMutationOutcome::ValidatorSetRotationUnsupported,
        ),
        (
            "policy-change-unsupported",
            ModeledTrustMutationOutcome::PolicyChangeUnsupported,
        ),
    ];
    for (label, o) in non_consuming {
        t.assert_true(
            &format!("D-{label}.no-consume"),
            !modeled_outcome_authorizes_durable_consume(o),
        );
        t.assert_true(&format!("D-{label}.proj-no-consume"), !projection_consume(o));
    }

    t.finish(out)
}

// ===========================================================================
// E — modeled-state scenarios. Prove the modeled in-memory state is the only
// thing a fixture applier ever changes, and that no fixture case mutates
// LivePqcTrustState or writes any sequence/marker/durable state.
// ===========================================================================

fn run_modeled_state_table(out: &Path) -> (u64, u64) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let mut t = Table::new("modeled_state");

    let apply = |c: &Ctx,
                 state: &mut ModeledGovernanceTrustState,
                 applier: &mut FixtureModeledTrustMutationApplier|
     -> ModeledTrustMutationOutcome {
        evaluate_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            state,
            applier,
        )
    };

    // E1 — add-root changes only the modeled in-memory state.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E1.applied", o.is_applied());
        t.check("E1.status", "active", state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"));
    }

    // E2 — retire-root changes only the modeled state.
    {
        let c = devnet_action(ModeledTrustMutationAction::RetireTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E2.applied", o.is_applied());
        t.check("E2.status", "retired", state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"));
    }

    // E3 — revoke-root changes only the modeled state.
    {
        let c = devnet_action(ModeledTrustMutationAction::RevokeTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E3.applied", o.is_applied());
        t.check("E3.status", "revoked", state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"));
    }

    // E4 — emergency-revoke-root changes only the modeled state.
    {
        let c = devnet_action(ModeledTrustMutationAction::EmergencyRevokeTrustRoot, ROOT_A);
        let mut state = state_with_active_root();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E4.applied", o.is_applied());
        t.check(
            "E4.status",
            "emergency-revoked",
            state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"),
        );
    }

    // E5 — noop produces no modeled state drift.
    {
        let c = devnet_action(ModeledTrustMutationAction::Noop, "");
        let mut state = state_with_active_root();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E5.applied", o.is_applied());
        t.assert_true("E5.no-drift", state.snapshot() == before);
    }

    // E6 — rejected-before-snapshot leaves modeled state unchanged.
    {
        let mut c = devnet_add();
        c.env.genesis_hash = "wrong-genesis".to_string();
        let mut state = state_with_active_root();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true(
            "E6.before-snapshot",
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeSnapshot { .. }),
        );
        t.assert_true("E6.no-applier", applier.attempts() == 0);
        t.assert_true("E6.unchanged", state.snapshot() == before);
    }

    // E7 — rejected-before-apply leaves modeled state unchanged after snapshot.
    {
        let c = devnet_action(ModeledTrustMutationAction::RetireTrustRoot, "absent-root");
        let mut state = state_with_active_root();
        let before = state.snapshot();
        let mut applier = devnet_applier();
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true(
            "E7.before-apply",
            matches!(o, ModeledTrustMutationOutcome::ModeledMutationRejectedBeforeApply { .. }),
        );
        t.assert_true("E7.applier-once", applier.attempts() == 1);
        t.assert_true("E7.unchanged", state.snapshot() == before);
    }

    // E8 — apply failure rolls back modeled state.
    {
        let c = devnet_add();
        let mut state = state_with_active_root();
        let before = state.snapshot();
        let mut applier = devnet_applier_fault(ModeledApplierFault::ApplyFailedRolledBack);
        let o = apply(&c, &mut state, &mut applier);
        t.check_outcome("E8.outcome", "modeled-mutation-rolled-back", &o);
        t.assert_true("E8.rolled-back", state.snapshot() == before);
    }

    // E9 — rollback failure does not claim success and never consumes.
    {
        let c = devnet_add();
        let mut state = ModeledGovernanceTrustState::new();
        let mut applier = devnet_applier_fault(ModeledApplierFault::RollbackFailedFatal);
        let o = apply(&c, &mut state, &mut applier);
        t.assert_true("E9.not-applied", !o.is_applied());
        t.assert_true("E9.no-consume", o.no_consume());
    }

    // E10 — explicit invariant: no fixture case mutates LivePqcTrustState; no
    // fixture case writes sequence/marker/durable state.
    t.assert_true(
        "E10.never-mutates-live",
        modeled_trust_applier_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true("E10.never-run-070", modeled_trust_applier_never_calls_run_070());
    t.assert_true(
        "E10.rejection-non-mutating",
        modeled_trust_applier_rejection_is_non_mutating(),
    );

    t.finish(out)
}

// ===========================================================================
// F — reachability table. Drives every grep-verifiable invariant / fail-closed
// helper in release mode.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("reachability");

    t.assert_true(
        "F.rejection-non-mutating",
        modeled_trust_applier_rejection_is_non_mutating(),
    );
    t.assert_true("F.never-calls-run-070", modeled_trust_applier_never_calls_run_070());
    t.assert_true(
        "F.never-mutates-live",
        modeled_trust_applier_never_mutates_live_pqc_trust_state(),
    );
    t.assert_true(
        "F.success-required",
        modeled_trust_applier_success_required_before_durable_consume(),
    );
    t.assert_true(
        "F.failure-never-consumes",
        modeled_trust_applier_failure_never_consumes(),
    );
    t.assert_true(
        "F.rollback-never-consumes",
        modeled_trust_applier_rollback_never_consumes(),
    );
    t.assert_true(
        "F.ambiguous-fails-closed",
        modeled_trust_applier_ambiguous_window_fails_closed(),
    );
    t.assert_true(
        "F.production-mainnet-unavailable",
        production_mainnet_modeled_trust_applier_unavailable(),
    );
    t.assert_true(
        "F.mainnet-refused-mainnet",
        mainnet_peer_driven_apply_refused_by_modeled_trust_applier(TrustBundleEnvironment::Mainnet),
    );
    t.assert_true(
        "F.mainnet-refused-not-devnet",
        !mainnet_peer_driven_apply_refused_by_modeled_trust_applier(TrustBundleEnvironment::Devnet),
    );
    t.assert_true(
        "F.validator-rotation-unsupported",
        validator_set_rotation_unsupported_by_modeled_trust_applier(),
    );
    t.assert_true(
        "F.policy-change-unsupported",
        policy_change_unsupported_by_modeled_trust_applier(),
    );
    t.assert_true(
        "F.no-rocksdb-file-schema-migration",
        modeled_trust_applier_no_rocksdb_file_schema_migration_change(),
    );
    t.assert_true(
        "F.local-operator-cannot",
        local_operator_cannot_satisfy_modeled_trust_applier_authority(),
    );
    t.assert_true(
        "F.peer-majority-cannot",
        peer_majority_cannot_satisfy_modeled_trust_applier_authority(),
    );

    // Exercise the ModeledGovernanceTrustMutationApplier trait method directly in
    // release mode (pure read; performs no modeled mutation).
    {
        let applier = devnet_applier();
        let w = applier.recover_modeled_mutation_window(&ModeledTrustMutationWindowObservation {
            snapshotted: true,
            applied: true,
            completion_reported: true,
            success_reported: true,
            rollback_failed: false,
        });
        t.check("F.trait-recover", "after-report-success", w.tag());
    }

    // Exercise the modeled root-status taxonomy tags in release mode.
    t.check("F.status-active", "active", ModeledTrustRootStatus::Active.tag());
    t.check("F.status-retired", "retired", ModeledTrustRootStatus::Retired.tag());
    t.check("F.status-revoked", "revoked", ModeledTrustRootStatus::Revoked.tag());
    t.check(
        "F.status-emergency",
        "emergency-revoked",
        ModeledTrustRootStatus::EmergencyRevoked.tag(),
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump (modeled outcome / projection / window values minted in release
// mode).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use ModeledGovernanceTrustMutationApplierKind as K;
    use ModeledGovernanceTrustMutationPolicy as P;
    let dir = out.join("fixtures");

    // Full success lifecycle: evaluate -> outcome -> engine map -> durable projection.
    let c = devnet_add();
    let mut state = ModeledGovernanceTrustState::new();
    let mut applier = devnet_applier();
    let o = evaluate_modeled_trust_mutation(
        &c.input(K::FixtureDevNet, P::FixtureDevNet),
        &c.expectations,
        &mut state,
        &mut applier,
    );
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} applier_attempts={} root_status={} engine_map={} authorizes_consume={}\n",
            o.tag(),
            applier.attempts(),
            state.status_of(ROOT_A).map(|s| s.tag()).unwrap_or("absent"),
            engine_tag(&o),
            modeled_outcome_authorizes_durable_consume(&o),
        ),
    );

    // Rejected lifecycle: wrong genesis -> reject-before-snapshot, applier never
    // invoked, modeled state unchanged, no consume.
    let mut c2 = devnet_add();
    c2.env.genesis_hash = "wrong-genesis".to_string();
    let mut state2 = ModeledGovernanceTrustState::new();
    let mut applier2 = devnet_applier();
    let o2 = evaluate_modeled_trust_mutation(
        &c2.input(K::FixtureDevNet, P::FixtureDevNet),
        &c2.expectations,
        &mut state2,
        &mut applier2,
    );
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} applier_attempts={} state_empty={} no_consume={} applier_must_not_run={}\n",
            o2.tag(),
            applier2.attempts(),
            state2.is_empty(),
            o2.no_consume(),
            o2.applier_must_not_run(),
        ),
    );

    // MainNet peer-driven refusal precedes everything.
    let c3 = mainnet_peer_driven();
    let mut state3 = ModeledGovernanceTrustState::new();
    let mut applier3 = devnet_applier();
    let o3 = evaluate_modeled_trust_mutation(
        &c3.input(K::FixtureDevNet, P::FixtureDevNet),
        &c3.expectations,
        &mut state3,
        &mut applier3,
    );
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} applier_attempts={} is_refusal={}\n",
            o3.tag(),
            applier3.attempts(),
            o3.is_mainnet_peer_driven_apply_refused()
        ),
    );

    // Window classifications.
    let applier_w = devnet_applier();
    let mut windows = String::new();
    for (label, obs) in [
        ("before-snapshot", ModeledTrustMutationWindowObservation::default()),
        (
            "after-snapshot-before-apply",
            ModeledTrustMutationWindowObservation {
                snapshotted: true,
                ..Default::default()
            },
        ),
        (
            "after-apply-before-report",
            ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                ..Default::default()
            },
        ),
        (
            "after-report-success",
            ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                completion_reported: true,
                success_reported: true,
                rollback_failed: false,
            },
        ),
        (
            "rollback-failed",
            ModeledTrustMutationWindowObservation {
                snapshotted: true,
                applied: true,
                rollback_failed: true,
                ..Default::default()
            },
        ),
    ] {
        let w = recover_modeled_trust_mutation(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs,
            &applier_w,
        );
        windows.push_str(&format!("{label}={}\n", w.tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_245_modeled_governance_trust_mutation_applier_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("modeled_state", run_modeled_state_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_245_modeled_governance_trust_mutation_applier_release_binary_helper\nscope: Run 244 governance modeled trust-state mutation applier boundary (pqc_governance_modeled_trust_mutation_applier: evaluate_modeled_trust_mutation, recover_modeled_trust_mutation, map_modeled_outcome_to_mutation_engine_outcome, project_modeled_outcome_to_durable_completion, modeled_outcome_authorizes_durable_consume, the ModeledGovernanceTrustState/Snapshot/Root modeled state, the ModeledGovernanceTrustMutation/Input/Expectations/Policy/Surface/EnvironmentBinding/RuntimeBinding bindings, the ModeledTrustMutationAction/ModeledTrustMutationOutcome taxonomy, the ModeledGovernanceTrustMutationApplier trait with FixtureModeledTrustMutationApplier/ProductionModeledTrustMutationApplier/MainNetModeledTrustMutationApplier, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed boundary (the fixture applier mutates ONLY the in-memory ModeledGovernanceTrustState; no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no LivePqcTrustState mutation, no durable consume of its own, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a Disabled policy/applier kind is a legacy bypass with no modeled mutation and no applier invocation; binding validation runs before any snapshot and a mismatch is a non-mutating reject-before-snapshot that never reaches the applier; a read-only validation surface never mutates; retiring/revoking a missing root snapshots then rejects-before-apply with modeled state unchanged; only a modeled ModeledMutationApplied maps to MutationAppliedSuccessfully and projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully, while rejected/failed/rolled-back/rollback-failed/ambiguous/unavailable/unsupported outcomes never consume; production/MainNet modeled applier kinds are reachable but always unavailable/fail-closed; MainNet peer-driven apply is refused before any snapshot and before applier invocation; validator-set rotation and policy-change actions remain unsupported\n\n",
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
