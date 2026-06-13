//! Run 243 — release-built helper for the Run 242 governance execution
//! **mutation-engine boundary**
//! (`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`).
//!
//! Where Run 242 landed the pure, typed governance execution mutation-engine
//! boundary at the source/test level and captured **no** release-binary
//! evidence, Run 243 is that release-binary evidence. This helper drives an
//! accepted / rejection / recovery / projection / reachability corpus through
//! the **release-built** Run 242 symbols
//! (`evaluate_governance_mutation_engine`, `recover_governance_mutation_window`,
//! `wire_governance_mutation_engine_callsite`,
//! `project_mutation_outcome_to_durable_completion`, the
//! `GovernanceMutationEngineInput` / `GovernanceMutationEngineExpectations` /
//! `GovernanceMutationCandidate` / `GovernanceMutationSurface` /
//! `GovernanceMutationPolicy` / `GovernanceMutationEnvironmentBinding` /
//! `GovernanceMutationRuntimeBinding` bindings, the
//! `GovernanceMutationEngineKind` / `GovernanceMutationOutcome` taxonomy, the
//! pure/mockable `GovernanceMutationExecutor` trait with the
//! `FixtureMutationExecutor` / `ProductionMutationExecutor` /
//! `MainNetMutationExecutor` implementations, and the grep-verifiable invariant /
//! fail-closed helpers), proving in release mode that:
//!
//! * a default `Disabled` policy / `Disabled` engine kind is a legacy bypass that
//!   performs no mutation and never invokes the executor;
//! * a DevNet/TestNet fixture mutation success returns
//!   `MutationAppliedSuccessfully` and projects to a consume-eligible
//!   `DurableMutationCompletion::AppliedSuccessfully`;
//! * an authorized-not-applied, a read-only validation, a failed apply, and a
//!   rollback never consume;
//! * an ambiguous after-authorization / before-completion window fails closed;
//! * production / MainNet engine kinds are reachable but always unavailable /
//!   fail-closed;
//! * MainNet peer-driven apply is refused before binding validation and before
//!   the executor is invoked;
//! * every binding mismatch (wrong environment / chain / genesis / governance
//!   surface / mutation surface / candidate digest / decision digest / proposal
//!   id / decision id / authority-domain sequence / lifecycle action, or a
//!   malformed candidate) is rejected before the executor;
//! * validator-set rotation and policy-change actions remain unsupported;
//! * every rejected path is non-mutating and never invokes the executor.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, mutation engine, on-chain proof verifier, persistent replay
//! backend, KMS/HSM, or RemoteSigner backend. No RocksDB/file/schema/migration/
//! storage-format change. The executors are pure in-process models and
//! DevNet/TestNet evidence-only. MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_execution_mutation_engine::{
    evaluate_governance_mutation_engine, local_operator_cannot_satisfy_mutation_engine_authority,
    mainnet_peer_driven_apply_refused_by_mutation_engine,
    mutation_engine_rejection_is_non_mutating,
    mutation_failure_never_consumes_durable_replay_state,
    mutation_rollback_never_consumes_durable_replay_state,
    mutation_success_is_required_before_durable_consume,
    no_rocksdb_file_schema_migration_change_under_mutation_engine,
    peer_majority_cannot_satisfy_mutation_engine_authority,
    policy_change_unsupported_by_mutation_engine, production_mainnet_mutation_engine_unavailable,
    project_mutation_outcome_to_durable_completion, recover_governance_mutation_window,
    validator_set_rotation_unsupported_by_mutation_engine,
    wire_governance_mutation_engine_callsite, AuthorizedMutationRequest, FixtureMutationExecutor,
    GovernanceMutationAction, GovernanceMutationCandidate, GovernanceMutationEngineExpectations,
    GovernanceMutationEngineInput, GovernanceMutationEngineKind, GovernanceMutationEnvironmentBinding,
    GovernanceMutationExecutor, GovernanceMutationOutcome, GovernanceMutationPolicy,
    GovernanceMutationRuntimeBinding, GovernanceMutationSurface, MainNetMutationExecutor,
    MutationEngineDurableProjection, MutationExecutionResult, MutationWindow,
    MutationWindowObservation, ProductionMutationExecutor,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 242 corpus so the composed material binds to
// the same trust domain, proposal/decision identity, candidate digest).
// ===========================================================================

const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SEQUENCE: u64 = 7;

// ===========================================================================
// Owned-context builder
// ===========================================================================

struct Ctx {
    candidate: GovernanceMutationCandidate,
    env: GovernanceMutationEnvironmentBinding,
    runtime: GovernanceMutationRuntimeBinding,
    expectations: GovernanceMutationEngineExpectations,
}

fn ctx(
    environment: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    action: GovernanceMutationAction,
) -> Ctx {
    let candidate = GovernanceMutationCandidate {
        decision_digest: DECISION_DIGEST.to_string(),
        candidate_digest: CAND_DIGEST.to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_domain_sequence: SEQUENCE,
        lifecycle_action: LocalLifecycleAction::Rotate,
        action,
    };
    let env = GovernanceMutationEnvironmentBinding {
        environment,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
    };
    let runtime = GovernanceMutationRuntimeBinding {
        governance_surface: ms,
        mutation_surface: GovernanceMutationSurface {
            validation_surface: vs,
            mutation_surface: ms,
        },
        authority_domain_sequence: SEQUENCE,
    };
    let expectations = GovernanceMutationEngineExpectations {
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
        candidate,
        env,
        runtime,
        expectations,
    }
}

impl Ctx {
    fn input(
        &self,
        kind: GovernanceMutationEngineKind,
        policy: GovernanceMutationPolicy,
    ) -> GovernanceMutationEngineInput<'_> {
        GovernanceMutationEngineInput {
            engine_kind: kind,
            policy,
            candidate: &self.candidate,
            environment_binding: &self.env,
            runtime_binding: &self.runtime,
        }
    }
}

/// Standard fresh DevNet mutating apply context (binding consistent with its own
/// expectations).
fn devnet_mutating() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn testnet_mutating() -> Ctx {
    ctx(
        TrustBundleEnvironment::Testnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn devnet_validation() -> Ctx {
    ctx(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceExecutionRuntimeSurface::ReloadCheck,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn mainnet_peer_driven() -> Ctx {
    ctx(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        GovernanceMutationAction::ApplyAuthorizedCandidate,
    )
}

fn devnet_exec(result: MutationExecutionResult) -> FixtureMutationExecutor {
    FixtureMutationExecutor::new(TrustBundleEnvironment::Devnet, result)
}

fn testnet_exec(result: MutationExecutionResult) -> FixtureMutationExecutor {
    FixtureMutationExecutor::new(TrustBundleEnvironment::Testnet, result)
}

/// A source-test-only executor that classifies every recovery window as
/// [`MutationWindow::Unknown`] so the helper can prove an unknown window fails
/// closed. It is never reached on an evaluate path and performs no mutation.
struct UnknownWindowExecutor;
impl GovernanceMutationExecutor for UnknownWindowExecutor {
    fn execute_authorized_mutation(
        &mut self,
        _request: &AuthorizedMutationRequest<'_>,
    ) -> MutationExecutionResult {
        MutationExecutionResult::AmbiguousAfterAuthorization
    }
    fn recover_mutation_window(&self, _observation: &MutationWindowObservation) -> MutationWindow {
        MutationWindow::Unknown
    }
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: &GovernanceMutationOutcome) {
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

/// Stable string tag for a durable projection (consume-eligibility folded in).
fn projection_tag(p: &MutationEngineDurableProjection) -> String {
    match p {
        MutationEngineDurableProjection::DurableCompletion(c) => {
            format!("durable-completion:{}", c.tag())
        }
        MutationEngineDurableProjection::FailClosedBeforeDurable(o) => {
            format!("fail-closed-before-durable:{}", o.tag())
        }
    }
}

// ===========================================================================
// A — accepted / compatible scenarios exercised through the Run 242
// release-built mutation-engine boundary symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceMutationEngineKind as K;
    use GovernanceMutationPolicy as P;
    use MutationExecutionResult as R;
    let mut t = Table::new("accepted");

    // A1 — disabled policy preserves legacy bypass and performs no mutation.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::Disabled),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A1.outcome", "proceed-legacy-bypass-no-mutation", &o);
        t.assert_true("A1.no-executor", exec.attempts() == 0);
    }

    // A2 — disabled engine kind preserves legacy bypass and performs no mutation.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::Disabled, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A2.outcome", "proceed-legacy-bypass-no-mutation", &o);
        t.assert_true("A2.no-executor", exec.attempts() == 0);
    }

    // A3 — DevNet fixture mutation success returns MutationAppliedSuccessfully.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A3.outcome", "mutation-applied-successfully", &o);
        t.assert_true("A3.executor-once", exec.attempts() == 1);
    }

    // A4 — TestNet fixture mutation success returns MutationAppliedSuccessfully.
    {
        let c = testnet_mutating();
        let mut exec = testnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureTestNet, P::FixtureTestNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A4.outcome", "mutation-applied-successfully", &o);
        t.assert_true("A4.executor-once", exec.attempts() == 1);
    }

    // A5 — mutation success projects to DurableMutationCompletion::AppliedSuccessfully.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        let proj = project_mutation_outcome_to_durable_completion(&o);
        t.check(
            "A5.projection",
            "durable-completion:applied-successfully",
            &projection_tag(&proj),
        );
        t.assert_true("A5.authorizes-consume", proj.authorizes_durable_consume());
    }

    // A6 — authorized-not-applied does not consume.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AuthorizedNotApplied);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A6.outcome", "mutation-authorized", &o);
        t.assert_true("A6.no-consume", o.no_consume());
        let proj = project_mutation_outcome_to_durable_completion(&o);
        t.check(
            "A6.projection",
            "durable-completion:authorized-but-not-applied",
            &projection_tag(&proj),
        );
        t.assert_true("A6.proj-no-consume", !proj.authorizes_durable_consume());
    }

    // A7 — read-only validation never mutates.
    {
        let c = devnet_validation();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A7.outcome", "mutation-rejected-before-apply", &o);
        t.assert_true("A7.no-executor", exec.attempts() == 0);
        t.assert_true("A7.no-consume", o.no_consume());
    }

    // A8 — failed apply never consumes.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::ApplyFailed);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A8.outcome", "mutation-apply-failed", &o);
        t.assert_true("A8.no-consume", o.no_consume());
        let proj = project_mutation_outcome_to_durable_completion(&o);
        t.check(
            "A8.projection",
            "durable-completion:apply-failed",
            &projection_tag(&proj),
        );
        t.assert_true("A8.proj-no-consume", !proj.authorizes_durable_consume());
    }

    // A9 — rollback never consumes.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::RolledBack);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A9.outcome", "mutation-rolled-back", &o);
        t.assert_true("A9.no-consume", o.no_consume());
        let proj = project_mutation_outcome_to_durable_completion(&o);
        t.check(
            "A9.projection",
            "durable-completion:rolled-back",
            &projection_tag(&proj),
        );
    }

    // A10 — ambiguous after-authorization / before-completion window fails closed.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AmbiguousAfterAuthorization);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A10.outcome", "mutation-ambiguous-fail-closed", &o);
        t.assert_true("A10.fail-closed", o.is_fail_closed());
        t.assert_true("A10.no-consume", o.no_consume());
    }

    // A11 — production mutation path is reachable but unavailable/fail-closed.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::ProductionUnavailable, P::Production),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A11.outcome", "production-mutation-unavailable", &o);
        t.assert_true("A11.no-executor", exec.attempts() == 0);
        t.assert_true("A11.no-consume", o.no_consume());
    }

    // A12 — MainNet mutation path is reachable but unavailable/fail-closed.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::ApplyAuthorizedCandidate,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A12.outcome", "mainnet-mutation-unavailable", &o);
        t.assert_true("A12.no-executor", exec.attempts() == 0);
    }

    // A13 — MainNet peer-driven apply is refused before mutation, and the
    // refusal happens before binding validation and before executor invocation.
    {
        let c = mainnet_peer_driven();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A13.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("A13.no-executor", exec.attempts() == 0);
        t.assert_true(
            "A13.is-refusal",
            o.is_mainnet_peer_driven_apply_refused(),
        );
    }

    // A14 — MainNet peer-driven refusal precedes binding validation: even with a
    // deliberately broken binding (wrong chain id), the refusal still wins.
    {
        let mut c = mainnet_peer_driven();
        c.env.chain_id = "wrong-chain".to_string();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A14.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("A14.no-executor", exec.attempts() == 0);
    }

    // A15 — validator-set rotation remains unsupported.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::ValidatorSetRotation,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A15.outcome", "validator-set-rotation-unsupported", &o);
        t.assert_true("A15.no-executor", exec.attempts() == 0);
    }

    // A16 — policy-change action remains unsupported.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::PolicyChange,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("A16.outcome", "policy-change-unsupported", &o);
        t.assert_true("A16.no-executor", exec.attempts() == 0);
    }

    // A17 — existing Run 240 durable runtime projection remains compatible: a
    // legacy bypass projects to NotAttempted (no durable consume).
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::Disabled),
            &c.expectations,
            &mut exec,
        );
        let proj = project_mutation_outcome_to_durable_completion(&o);
        t.check(
            "A17.projection",
            "durable-completion:not-attempted",
            &projection_tag(&proj),
        );
        t.assert_true("A17.no-consume", !proj.authorizes_durable_consume());
    }

    // A18 — existing Run 238/236/232/230 behavior remains compatible: the only
    // consume-eligible durable completion is AppliedSuccessfully.
    {
        t.assert_true(
            "A18.consume-after-success-only",
            mutation_success_is_required_before_durable_consume(),
        );
        // A DevNet success is the unique projection that authorizes consume.
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.assert_true(
            "A18.success-authorizes",
            project_mutation_outcome_to_durable_completion(&o).authorizes_durable_consume(),
        );
    }

    // A19 — Run 242 call-site wiring returns Ok only on success and Err on
    // fail-closed outcomes.
    {
        // Success -> Ok.
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let r = wire_governance_mutation_engine_callsite(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.assert_true("A19.success-ok", r.is_ok());

        // Legacy bypass -> Ok (proceed).
        let c2 = devnet_mutating();
        let mut exec2 = devnet_exec(R::AppliedSuccessfully);
        let r2 = wire_governance_mutation_engine_callsite(
            &c2.input(K::FixtureDevNet, P::Disabled),
            &c2.expectations,
            &mut exec2,
        );
        t.assert_true("A19.bypass-ok", r2.is_ok());

        // Authorized-not-applied -> Ok (proceed hand-off).
        let c3 = devnet_mutating();
        let mut exec3 = devnet_exec(R::AuthorizedNotApplied);
        let r3 = wire_governance_mutation_engine_callsite(
            &c3.input(K::FixtureDevNet, P::FixtureDevNet),
            &c3.expectations,
            &mut exec3,
        );
        t.assert_true("A19.authorized-ok", r3.is_ok());

        // Failed apply -> Err (fail-closed).
        let c4 = devnet_mutating();
        let mut exec4 = devnet_exec(R::ApplyFailed);
        let r4 = wire_governance_mutation_engine_callsite(
            &c4.input(K::FixtureDevNet, P::FixtureDevNet),
            &c4.expectations,
            &mut exec4,
        );
        t.assert_true("A19.fail-apply-err", r4.is_err());

        // MainNet peer-driven -> Err and flagged as refusal.
        let c5 = mainnet_peer_driven();
        let mut exec5 = devnet_exec(R::AppliedSuccessfully);
        let r5 = wire_governance_mutation_engine_callsite(
            &c5.input(K::FixtureDevNet, P::FixtureDevNet),
            &c5.expectations,
            &mut exec5,
        );
        match r5 {
            Ok(_) => t.assert_true("A19.refusal-err", false),
            Err(e) => {
                t.assert_true("A19.refusal-err", e.is_mainnet_peer_driven_apply_refused())
            }
        }
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios: every binding mismatch is rejected before the
// executor and is non-mutating.
// ===========================================================================

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceMutationEngineKind as K;
    use GovernanceMutationPolicy as P;
    use MutationExecutionResult as R;
    let mut t = Table::new("rejection");

    // Each rejection scenario mutates exactly one binding field away from the
    // canonical expectations and proves a non-mutating reject-before-apply with
    // a never-invoked executor.
    let mut rejection_case = |id: &str, mutate: &dyn Fn(&mut Ctx)| {
        let mut c = devnet_mutating();
        mutate(&mut c);
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome(&format!("{id}.outcome"), "mutation-rejected-before-apply", &o);
        t.assert_true(&format!("{id}.no-executor"), exec.attempts() == 0);
        t.assert_true(&format!("{id}.no-consume"), o.no_consume());
        t.assert_true(&format!("{id}.fail-closed"), o.is_fail_closed());
        t.assert_true(&format!("{id}.executor-must-not-run"), o.executor_must_not_run());
    };

    // R1 — wrong environment.
    rejection_case("R1", &|c| c.env.environment = TrustBundleEnvironment::Testnet);
    // R2 — wrong chain.
    rejection_case("R2", &|c| c.env.chain_id = "wrong-chain".to_string());
    // R3 — wrong genesis.
    rejection_case("R3", &|c| c.env.genesis_hash = "wrong-genesis".to_string());
    // R4 — wrong governance surface.
    rejection_case("R4", &|c| {
        c.runtime.governance_surface = GovernanceExecutionRuntimeSurface::Sighup
    });
    // R5 — wrong mutation surface.
    rejection_case("R5", &|c| {
        c.runtime.mutation_surface.mutation_surface =
            GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle
    });
    // R6 — wrong candidate digest.
    rejection_case("R6", &|c| c.candidate.candidate_digest = "wrong-candidate".to_string());
    // R7 — wrong decision digest.
    rejection_case("R7", &|c| c.candidate.decision_digest = "wrong-decision".to_string());
    // R8 — wrong proposal id.
    rejection_case("R8", &|c| c.candidate.proposal_id = "wrong-proposal".to_string());
    // R9 — wrong decision id.
    rejection_case("R9", &|c| c.candidate.decision_id = "wrong-decision-id".to_string());
    // R10 — wrong authority-domain sequence.
    rejection_case("R10", &|c| c.candidate.authority_domain_sequence = 99);
    // R11 — wrong lifecycle action.
    rejection_case("R11", &|c| c.candidate.lifecycle_action = LocalLifecycleAction::Revoke);
    // R12 — malformed candidate (empty mandatory field).
    rejection_case("R12", &|c| c.candidate.candidate_digest = String::new());

    // R13 — production mutation engine unavailable (reachable, never consumes).
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::ProductionUnavailable, P::Production),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("R13.outcome", "production-mutation-unavailable", &o);
        t.assert_true("R13.no-executor", exec.attempts() == 0);
        t.assert_true("R13.no-consume", o.no_consume());
        t.assert_true("R13.executor-must-not-run", o.executor_must_not_run());
    }

    // R14 — MainNet mutation engine unavailable.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::ApplyAuthorizedCandidate,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("R14.outcome", "mainnet-mutation-unavailable", &o);
        t.assert_true("R14.no-executor", exec.attempts() == 0);
        t.assert_true("R14.executor-must-not-run", o.executor_must_not_run());
    }

    // R15 — validator-set rotation attempt unsupported.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::ValidatorSetRotation,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("R15.outcome", "validator-set-rotation-unsupported", &o);
        t.assert_true("R15.no-executor", exec.attempts() == 0);
    }

    // R16 — policy-change attempt unsupported.
    {
        let c = ctx(
            TrustBundleEnvironment::Devnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::PolicyChange,
        );
        let mut exec = devnet_exec(R::AppliedSuccessfully);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.check_outcome("R16.outcome", "policy-change-unsupported", &o);
        t.assert_true("R16.no-executor", exec.attempts() == 0);
    }

    // R17 — consume before mutation success rejected (authorized-not-applied
    // never authorizes a durable consume).
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::AuthorizedNotApplied);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.assert_true(
            "R17.no-consume",
            !project_mutation_outcome_to_durable_completion(&o).authorizes_durable_consume(),
        );
    }

    // R18 — consume after failed apply rejected.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::ApplyFailed);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.assert_true(
            "R18.no-consume",
            !project_mutation_outcome_to_durable_completion(&o).authorizes_durable_consume(),
        );
        t.assert_true(
            "R18.failure-never-consumes",
            mutation_failure_never_consumes_durable_replay_state(),
        );
    }

    // R19 — consume after rollback rejected.
    {
        let c = devnet_mutating();
        let mut exec = devnet_exec(R::RolledBack);
        let o = evaluate_governance_mutation_engine(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &c.expectations,
            &mut exec,
        );
        t.assert_true(
            "R19.no-consume",
            !project_mutation_outcome_to_durable_completion(&o).authorizes_durable_consume(),
        );
        t.assert_true(
            "R19.rollback-never-consumes",
            mutation_rollback_never_consumes_durable_replay_state(),
        );
    }

    // R20 — local operator key cannot satisfy MainNet authority.
    t.assert_true(
        "R20.local-operator-cannot",
        local_operator_cannot_satisfy_mutation_engine_authority(),
    );
    // R21 — peer majority cannot satisfy MainNet authority.
    t.assert_true(
        "R21.peer-majority-cannot",
        peer_majority_cannot_satisfy_mutation_engine_authority(),
    );

    // R22 — every rejected path produces no Run 070 call, no live trust swap, no
    // session eviction, no sequence write, no marker write, no durable consume,
    // and no executor invocation (grep-verifiable invariant).
    t.assert_true(
        "R22.rejection-non-mutating",
        mutation_engine_rejection_is_non_mutating(),
    );

    t.finish(out)
}

// ===========================================================================
// V — recovery scenarios: every in-flight / after-authorization window fails
// closed; production / MainNet recovery is unavailable; MainNet peer-driven
// apply refusal precedes recovery classification.
// ===========================================================================

fn run_recovery_table(out: &Path) -> (u64, u64) {
    use GovernanceMutationEngineKind as K;
    use GovernanceMutationPolicy as P;
    use MutationExecutionResult as R;
    let mut t = Table::new("recovery");

    let obs = |authorized, apply_attempted, completion_reported| MutationWindowObservation {
        authorized,
        apply_attempted,
        completion_reported,
    };

    // V1 — before-authorization window recovers as rejected-before-apply / no
    // consume.
    {
        let c = devnet_mutating();
        let exec = devnet_exec(R::AppliedSuccessfully);
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(false, false, false),
            &exec,
        );
        t.check_outcome("V1.outcome", "mutation-rejected-before-apply", &o);
        t.assert_true("V1.no-consume", o.no_consume());
    }

    // V2 — after-authorization-before-executor (before-apply) window fails closed.
    {
        let c = devnet_mutating();
        let exec = devnet_exec(R::AppliedSuccessfully);
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(true, false, false),
            &exec,
        );
        t.check_outcome("V2.outcome", "mutation-ambiguous-fail-closed", &o);
        t.assert_true("V2.fail-closed", o.is_fail_closed());
    }

    // V3 — after-apply-before-report window fails closed.
    {
        let c = devnet_mutating();
        let exec = devnet_exec(R::AppliedSuccessfully);
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(true, true, false),
            &exec,
        );
        t.check_outcome("V3.outcome", "mutation-ambiguous-fail-closed", &o);
    }

    // V4 — after-report (ambiguous) window fails closed.
    {
        let c = devnet_mutating();
        let exec = devnet_exec(R::AppliedSuccessfully);
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(true, true, true),
            &exec,
        );
        t.check_outcome("V4.outcome", "mutation-ambiguous-fail-closed", &o);
    }

    // V5 — unknown window fails closed.
    {
        let c = devnet_mutating();
        let exec = UnknownWindowExecutor;
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(true, false, false),
            &exec,
        );
        t.check_outcome("V5.outcome", "mutation-ambiguous-fail-closed", &o);
        t.assert_true("V5.fail-closed", o.is_fail_closed());
    }

    // V6 — production recovery classification is unavailable/fail-closed.
    {
        let c = devnet_mutating();
        let exec = ProductionMutationExecutor;
        let o = recover_governance_mutation_window(
            &c.input(K::ProductionUnavailable, P::Production),
            &obs(true, true, false),
            &exec,
        );
        t.check_outcome("V6.outcome", "production-mutation-unavailable", &o);
    }

    // V7 — MainNet recovery classification is unavailable/fail-closed.
    {
        let c = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceExecutionRuntimeSurface::ReloadApply,
            GovernanceMutationAction::ApplyAuthorizedCandidate,
        );
        let exec = MainNetMutationExecutor;
        let o = recover_governance_mutation_window(
            &c.input(K::MainNetUnavailable, P::MainNet),
            &obs(true, true, false),
            &exec,
        );
        t.check_outcome("V7.outcome", "mainnet-mutation-unavailable", &o);
    }

    // V8 — MainNet peer-driven apply refusal precedes recovery classification.
    {
        let c = mainnet_peer_driven();
        let exec = devnet_exec(R::AppliedSuccessfully);
        let o = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &obs(true, true, true),
            &exec,
        );
        t.check_outcome("V8.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true(
            "V8.is-refusal",
            o.is_mainnet_peer_driven_apply_refused(),
        );
    }

    t.finish(out)
}

// ===========================================================================
// J — projection scenarios: only MutationAppliedSuccessfully projects to a
// consume-eligible durable completion; everything else does not consume.
// ===========================================================================

fn run_projection_table(out: &Path) -> (u64, u64) {
    use GovernanceMutationOutcome as O;
    let mut t = Table::new("projection");

    // J1 — only MutationAppliedSuccessfully projects to consume-eligible.
    {
        let p = project_mutation_outcome_to_durable_completion(&O::MutationAppliedSuccessfully);
        t.check(
            "J1.projection",
            "durable-completion:applied-successfully",
            &projection_tag(&p),
        );
        t.assert_true("J1.consume", p.authorizes_durable_consume());
    }

    // Helper closure for the no-consume variants.
    let mut no_consume = |id: &str, outcome: O, expected: &str| {
        let p = project_mutation_outcome_to_durable_completion(&outcome);
        t.check(&format!("{id}.projection"), expected, &projection_tag(&p));
        t.assert_true(&format!("{id}.no-consume"), !p.authorizes_durable_consume());
    };

    // J2 — MutationAuthorized does not consume.
    no_consume(
        "J2",
        O::MutationAuthorized,
        "durable-completion:authorized-but-not-applied",
    );
    // J3 — MutationApplyFailed does not consume.
    no_consume(
        "J3",
        O::MutationApplyFailed,
        "durable-completion:apply-failed",
    );
    // J4 — MutationRolledBack does not consume.
    no_consume("J4", O::MutationRolledBack, "durable-completion:rolled-back");
    // J5 — MutationAmbiguousFailClosed does not consume.
    no_consume(
        "J5",
        O::MutationAmbiguousFailClosed,
        "fail-closed-before-durable:mutation-ambiguous-fail-closed",
    );
    // J6 — ProductionMutationUnavailable does not consume.
    no_consume(
        "J6",
        O::ProductionMutationUnavailable,
        "fail-closed-before-durable:production-mutation-unavailable",
    );
    // J7 — MainNetMutationUnavailable does not consume.
    no_consume(
        "J7",
        O::MainNetMutationUnavailable,
        "fail-closed-before-durable:mainnet-mutation-unavailable",
    );
    // J8 — MainNetPeerDrivenApplyRefused does not consume.
    no_consume(
        "J8",
        O::MainNetPeerDrivenApplyRefused,
        "fail-closed-before-durable:mainnet-peer-driven-apply-refused",
    );
    // J9 — ValidatorSetRotationUnsupported does not consume.
    no_consume(
        "J9",
        O::ValidatorSetRotationUnsupported,
        "fail-closed-before-durable:validator-set-rotation-unsupported",
    );
    // J10 — PolicyChangeUnsupported does not consume.
    no_consume(
        "J10",
        O::PolicyChangeUnsupported,
        "fail-closed-before-durable:policy-change-unsupported",
    );
    // J11 — MutationRejectedBeforeApply does not consume.
    no_consume(
        "J11",
        O::MutationRejectedBeforeApply {
            reason: "x".to_string(),
        },
        "fail-closed-before-durable:mutation-rejected-before-apply",
    );
    // J12 — legacy bypass projects to NotAttempted (no consume).
    no_consume(
        "J12",
        O::ProceedLegacyBypassNoMutation,
        "durable-completion:not-attempted",
    );

    t.finish(out)
}

// ===========================================================================
// T — reachability: outcome / kind tags are stable and the grep-verifiable
// invariant helpers all hold in release mode.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceMutationOutcome as O;
    let mut t = Table::new("reachability");

    // Outcome tags reachable / stable.
    for (id, expected, o) in [
        (
            "T.legacy-bypass",
            "proceed-legacy-bypass-no-mutation",
            O::ProceedLegacyBypassNoMutation,
        ),
        ("T.authorized", "mutation-authorized", O::MutationAuthorized),
        (
            "T.applied",
            "mutation-applied-successfully",
            O::MutationAppliedSuccessfully,
        ),
        (
            "T.rejected",
            "mutation-rejected-before-apply",
            O::MutationRejectedBeforeApply {
                reason: "x".to_string(),
            },
        ),
        ("T.apply-failed", "mutation-apply-failed", O::MutationApplyFailed),
        ("T.rolled-back", "mutation-rolled-back", O::MutationRolledBack),
        (
            "T.ambiguous",
            "mutation-ambiguous-fail-closed",
            O::MutationAmbiguousFailClosed,
        ),
        (
            "T.production-unavailable",
            "production-mutation-unavailable",
            O::ProductionMutationUnavailable,
        ),
        (
            "T.mainnet-unavailable",
            "mainnet-mutation-unavailable",
            O::MainNetMutationUnavailable,
        ),
        (
            "T.peer-driven-refused",
            "mainnet-peer-driven-apply-refused",
            O::MainNetPeerDrivenApplyRefused,
        ),
        (
            "T.validator-rotation",
            "validator-set-rotation-unsupported",
            O::ValidatorSetRotationUnsupported,
        ),
        (
            "T.policy-change",
            "policy-change-unsupported",
            O::PolicyChangeUnsupported,
        ),
    ] {
        t.check(id, expected, o.tag());
    }

    // Engine kind tags.
    for (id, expected, k) in [
        ("K.disabled", "disabled", GovernanceMutationEngineKind::Disabled),
        (
            "K.fixture-devnet",
            "fixture-devnet",
            GovernanceMutationEngineKind::FixtureDevNet,
        ),
        (
            "K.fixture-testnet",
            "fixture-testnet",
            GovernanceMutationEngineKind::FixtureTestNet,
        ),
        (
            "K.production-unavailable",
            "production-unavailable",
            GovernanceMutationEngineKind::ProductionUnavailable,
        ),
        (
            "K.mainnet-unavailable",
            "mainnet-unavailable",
            GovernanceMutationEngineKind::MainNetUnavailable,
        ),
    ] {
        t.check(id, expected, k.tag());
    }

    // Engine kind predicates.
    t.assert_true(
        "K.fixture-devnet-is-fixture",
        GovernanceMutationEngineKind::FixtureDevNet.is_fixture(),
    );
    t.assert_true(
        "K.production-is-unavailable",
        GovernanceMutationEngineKind::ProductionUnavailable.is_unavailable(),
    );

    // Policy predicates.
    t.assert_true(
        "P.disabled-not-wired",
        !GovernanceMutationPolicy::Disabled.is_wired(),
    );
    t.assert_true(
        "P.fixture-devnet-wired",
        GovernanceMutationPolicy::FixtureDevNet.is_wired(),
    );

    // Outcome predicate partitions.
    {
        let applied = O::MutationAppliedSuccessfully;
        t.assert_true("PR.applied-success", applied.is_applied_successfully());
        t.assert_true("PR.applied-not-no-consume", !applied.no_consume());
        let authorized = O::MutationAuthorized;
        t.assert_true("PR.authorized-not-applied", authorized.is_authorized_not_applied());
        t.assert_true("PR.authorized-no-consume", authorized.no_consume());
        let bypass = O::ProceedLegacyBypassNoMutation;
        t.assert_true("PR.bypass-is-bypass", bypass.is_legacy_bypass());
        t.assert_true("PR.bypass-not-fail-closed", !bypass.is_fail_closed());
        let refused = O::MainNetPeerDrivenApplyRefused;
        t.assert_true("PR.refused", refused.is_mainnet_peer_driven_apply_refused());
        t.assert_true("PR.refused-executor-must-not-run", refused.executor_must_not_run());
    }

    // Grep-verifiable invariant / fail-closed helper invariants.
    {
        t.assert_true(
            "G.rejection-non-mutating",
            mutation_engine_rejection_is_non_mutating(),
        );
        t.assert_true(
            "G.success-required-before-consume",
            mutation_success_is_required_before_durable_consume(),
        );
        t.assert_true(
            "G.failure-never-consumes",
            mutation_failure_never_consumes_durable_replay_state(),
        );
        t.assert_true(
            "G.rollback-never-consumes",
            mutation_rollback_never_consumes_durable_replay_state(),
        );
        t.assert_true(
            "G.production-mainnet-unavailable",
            production_mainnet_mutation_engine_unavailable(),
        );
        t.assert_true(
            "G.no-rocksdb-file-schema-migration",
            no_rocksdb_file_schema_migration_change_under_mutation_engine(),
        );
        t.assert_true(
            "G.validator-rotation-unsupported",
            validator_set_rotation_unsupported_by_mutation_engine(),
        );
        t.assert_true(
            "G.policy-change-unsupported",
            policy_change_unsupported_by_mutation_engine(),
        );
        t.assert_true(
            "G.local-operator-cannot",
            local_operator_cannot_satisfy_mutation_engine_authority(),
        );
        t.assert_true(
            "G.peer-majority-cannot",
            peer_majority_cannot_satisfy_mutation_engine_authority(),
        );
        t.assert_true(
            "G.mainnet-refused-mainnet",
            mainnet_peer_driven_apply_refused_by_mutation_engine(TrustBundleEnvironment::Mainnet),
        );
        t.assert_true(
            "G.mainnet-refused-not-devnet",
            !mainnet_peer_driven_apply_refused_by_mutation_engine(TrustBundleEnvironment::Devnet),
        );
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (mutation-engine outcome / projection / window values minted in
// release mode).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use GovernanceMutationEngineKind as K;
    use GovernanceMutationPolicy as P;
    use MutationExecutionResult as R;
    let dir = out.join("fixtures");

    // Full success lifecycle: evaluate -> outcome -> durable projection.
    let c = devnet_mutating();
    let mut exec = devnet_exec(R::AppliedSuccessfully);
    let o = evaluate_governance_mutation_engine(
        &c.input(K::FixtureDevNet, P::FixtureDevNet),
        &c.expectations,
        &mut exec,
    );
    let proj = project_mutation_outcome_to_durable_completion(&o);
    write_file(
        &dir.join("success_lifecycle.txt"),
        &format!(
            "outcome={} executor_attempts={} projection={} authorizes_consume={}\n",
            o.tag(),
            exec.attempts(),
            projection_tag(&proj),
            proj.authorizes_durable_consume()
        ),
    );

    // Rejected lifecycle: wrong chain id -> reject-before-apply, executor never
    // invoked, no consume.
    let mut c2 = devnet_mutating();
    c2.env.chain_id = "wrong-chain".to_string();
    let mut exec2 = devnet_exec(R::AppliedSuccessfully);
    let o2 = evaluate_governance_mutation_engine(
        &c2.input(K::FixtureDevNet, P::FixtureDevNet),
        &c2.expectations,
        &mut exec2,
    );
    write_file(
        &dir.join("rejected_lifecycle.txt"),
        &format!(
            "outcome={} executor_attempts={} no_consume={} executor_must_not_run={}\n",
            o2.tag(),
            exec2.attempts(),
            o2.no_consume(),
            o2.executor_must_not_run()
        ),
    );

    // MainNet peer-driven refusal precedes everything.
    let c3 = mainnet_peer_driven();
    let mut exec3 = devnet_exec(R::AppliedSuccessfully);
    let o3 = evaluate_governance_mutation_engine(
        &c3.input(K::FixtureDevNet, P::FixtureDevNet),
        &c3.expectations,
        &mut exec3,
    );
    write_file(
        &dir.join("mainnet_peer_driven_refusal.txt"),
        &format!(
            "outcome={} executor_attempts={} is_refusal={}\n",
            o3.tag(),
            exec3.attempts(),
            o3.is_mainnet_peer_driven_apply_refused()
        ),
    );

    // Window classifications.
    let exec_w = devnet_exec(R::AppliedSuccessfully);
    let mut windows = String::new();
    for (label, authorized, apply_attempted, completion_reported) in [
        ("before-authorization", false, false, false),
        ("after-authorization-before-apply", true, false, false),
        ("after-apply-before-report", true, true, false),
        ("after-report", true, true, true),
    ] {
        let w = recover_governance_mutation_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet),
            &MutationWindowObservation {
                authorized,
                apply_attempted,
                completion_reported,
            },
            &exec_w,
        );
        windows.push_str(&format!("{label}={}\n", w.tag()));
    }
    write_file(&dir.join("window_classifications.txt"), &windows);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_243_governance_execution_mutation_engine_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("recovery", run_recovery_table),
        ("projection", run_projection_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from(
        "run_243_governance_execution_mutation_engine_release_binary_helper\nscope: Run 242 governance execution mutation-engine boundary (pqc_governance_execution_mutation_engine: evaluate_governance_mutation_engine, recover_governance_mutation_window, wire_governance_mutation_engine_callsite, project_mutation_outcome_to_durable_completion, the GovernanceMutationEngineInput/Expectations/Candidate/Surface/Policy/EnvironmentBinding/RuntimeBinding bindings, the GovernanceMutationEngineKind/GovernanceMutationOutcome taxonomy, the GovernanceMutationExecutor trait with FixtureMutationExecutor/ProductionMutationExecutor/MainNetMutationExecutor, and the grep-verifiable invariant/fail-closed helpers) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed boundary (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no durable consume of its own, no persistent storage, no RocksDB/file/schema/migration/storage-format change); a Disabled policy/engine kind is a legacy bypass with no mutation and no executor invocation; binding validation runs before any apply and a mismatch is a non-mutating reject-before-apply that never reaches the executor; a read-only validation surface never mutates; only a modeled MutationAppliedSuccessfully projects to the consume-eligible DurableMutationCompletion::AppliedSuccessfully, while authorized-not-applied, failed apply, rollback, and ambiguous after-authorization windows never consume; production/MainNet engine kinds are reachable but always unavailable/fail-closed; MainNet peer-driven apply is refused before binding validation and before executor invocation; validator-set rotation and policy-change actions remain unsupported\n\n",
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
