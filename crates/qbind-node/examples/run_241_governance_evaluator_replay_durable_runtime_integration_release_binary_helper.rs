//! Run 241 — release-built helper for the Run 240 governance evaluator
//! **durable replay backend runtime integration**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`).
//!
//! Where Run 240 landed the pure, typed durable replay-backend runtime
//! integration at the source/test level and captured **no** release-binary
//! evidence, Run 241 is that release-binary evidence. This helper drives the
//! A1–A27 / R1–R38 matrix from `task/RUN_241_TASK.txt` through the
//! **release-built** Run 240 symbols (`integrate_durable_replay_runtime`,
//! `recover_durable_replay_runtime_crash_window`,
//! `wire_durable_replay_runtime_callsite`, the
//! `DurableReplayRuntimeIntegrationInput` binding, the
//! `DurableReplayRuntimeOutcome` taxonomy, and the grep-verifiable invariant /
//! refusal helpers), composing the Run 238 durable backend
//! (`FixtureDurableReplayBackend`, reader/writer/atomic traits,
//! `compare_and_mark_consumed`, `classify_crash_window`) with the Run 230 / 232
//! replay/freshness state path, proving in release mode that:
//!
//! * a default `Disabled` policy is a Run 214 legacy bypass that performs no
//!   durable write;
//! * a durable read/observe happens **before** mutation authorization, and a
//!   mutation is authorized only on a fresh / known-fresh durable state after the
//!   Run 230 / 232 runtime agrees fresh;
//! * a durable compare-and-mark-consumed happens **only** after a modeled
//!   `AppliedSuccessfully` mutation completion, after which the same decision
//!   reads consumed / fail-closed;
//! * a read-only validation surface observes but never consumes; a deferral never
//!   authorizes mutation; a failed apply, a rollback, and a consume before
//!   observe / before success never consume;
//! * an ambiguous (after-mutation-before-consume / unknown / after-consume) crash
//!   window is typed and fails closed;
//! * fixture restart snapshot durability preserves observed and consumed state
//!   through the integration (an in-process value clone, never a file format);
//! * production / MainNet durable backends are reached but always fail closed
//!   unavailable, and MainNet peer-driven apply remains refused even when the
//!   durable state reads fresh;
//! * every rejection is pure and non-mutating (the fixture records nothing on a
//!   rejected observe and never marks consumed on a rejected consume).
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, mutation engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. No RocksDB/file/schema/migration/storage-format change.
//! The `FixtureDurableReplayBackend` is an in-process map only and DevNet/TestNet
//! evidence-only. MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_runtime_integration::{
    consume_integrated_as_after_success_only_post_mutation_step,
    fresh_required_before_mutation_authorization_under_consume_runtime,
    mainnet_peer_driven_apply_remains_refused_under_consume_runtime,
};
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    compare_and_mark_consumed as durable_compare_and_mark_consumed, durable_backend_key_digest,
    mainnet_peer_driven_apply_remains_refused_under_durable_backend,
    production_mainnet_durable_backend_remains_unavailable, CrashWindow, CrashWindowObservation,
    DurableBackendDecisionExpectations, DurableBackendDecisionInput, DurableBackendKind,
    DurableBackendOutcome, DurableMutationCompletion, DurableRecordState,
    FixtureDurableReplayBackend, GovernanceEvaluatorReplayDurableBackendReader,
};
use qbind_node::pqc_governance_evaluator_replay_durable_runtime_integration::{
    consume_only_after_successful_mutation_under_durable_runtime,
    crash_window_ambiguity_fails_closed_under_durable_runtime,
    durable_observe_happens_before_mutation_authorization,
    durable_runtime_rejection_is_non_mutating, integrate_durable_replay_runtime,
    local_operator_cannot_satisfy_durable_runtime_policy,
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
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput, PreviouslySeenState,
    ReplayStatePolicy, SeenDecisionRecord,
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
// Shared constants (mirror the Run 220 / 222 / 230 / 234 / 238 / 240 corpora so
// the composed material binds to the same trust domain, proposal/decision
// identity, candidate digest, replay nonce).
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
// input/expectations consistent with one another (mirrors the Run 240 tests).
// ===========================================================================

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

fn crash_obs(
    kind: DurableBackendKind,
    observed: bool,
    mutation_attempted: bool,
    mutation_succeeded: bool,
    rolled_back: bool,
    apply_failed: bool,
    consumed: bool,
) -> CrashWindowObservation {
    CrashWindowObservation {
        backend_kind: kind,
        observed,
        mutation_attempted,
        mutation_succeeded,
        rolled_back,
        apply_failed,
        consumed,
    }
}

// ===========================================================================
// Output table helper
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: &DurableReplayRuntimeOutcome) {
        self.check(id, expected, o.tag());
    }
    fn check_state(&mut self, id: &str, expected: &str, s: DurableRecordState) {
        self.check(id, expected, s.tag());
    }
    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

// ===========================================================================
// A — accepted / compatible scenarios (A1–A27) exercised through the Run 240
// release-built durable replay-backend runtime integration symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use GovernanceExecutionRuntimeSurface as S;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — default Disabled / legacy bypass performs no durable write.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::Disabled, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A1.outcome", "proceed-legacy-bypass-no-durable-write", &o);
        t.assert_true("A1.no-durable-write", backend.is_empty());
    }

    // A2 — first-seen DevNet fixture decision is observed as fresh.
    {
        let c = fresh_devnet_validation();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A2.outcome", "proceed-fresh-observed", &o);
        t.check_state("A2.state", "observed-fresh", backend.read_durable_state(&c.key()));
    }

    // A3 — first-seen TestNet fixture decision is observed as fresh.
    {
        let c = ctx(
            Env::Testnet,
            S::ReloadCheck,
            S::ReloadCheck,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = FixtureDurableReplayBackend::new(Env::Testnet);
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureTestNet, P::FixtureTestNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A3.outcome", "proceed-fresh-observed", &o);
        t.check_state("A3.state", "observed-fresh", backend.read_durable_state(&c.key()));
    }

    // A4 — known fresh decision proceeds as known fresh.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let first = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A4.first", "proceed-mutation-authorized", &first);
        let second = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A4.second", "proceed-known-fresh", &second);
    }

    // A5 — deferred decision is observed but does not authorize mutation.
    {
        let c = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            50, // canonical < effective => deferred
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A5.outcome", "proceed-deferred-observed", &o);
        t.assert_true("A5.not-authorized", !o.authorizes_mutation());
        t.check_state(
            "A5.state",
            "observed-deferred",
            backend.read_durable_state(&c.key()),
        );
    }

    // A6 — fresh observed decision authorizes mutation only after replay/runtime
    // agreement, and only after the durable observe recorded the decision.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A6.outcome", "proceed-mutation-authorized", &o);
        t.assert_true("A6.authorizes", o.authorizes_mutation());
        t.check_state(
            "A6.observed-before-auth",
            "observed-fresh",
            backend.read_durable_state(&c.key()),
        );
        t.assert_true("A6.not-consumed", !backend.is_consumed(&c.key()));
    }

    // A7 — AppliedSuccessfully performs compare-and-mark-consumed in DevNet fixture.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let consume = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("A7.outcome", "consume-durable-after-mutation-success", &consume);
        t.assert_true("A7.authorizes-consume", consume.authorizes_consume());
        t.assert_true("A7.is-consumed", backend.is_consumed(&c.key()));
    }

    // A8 — AppliedSuccessfully performs compare-and-mark-consumed in TestNet fixture.
    {
        let c = ctx(
            Env::Testnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = FixtureDurableReplayBackend::new(Env::Testnet);
        integrate_durable_replay_runtime(
            &c.input(K::FixtureTestNet, P::FixtureTestNet, MC::NotAttempted),
            &mut backend,
        );
        let consume = integrate_durable_replay_runtime(
            &c.input(K::FixtureTestNet, P::FixtureTestNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("A8.outcome", "consume-durable-after-mutation-success", &consume);
        t.assert_true("A8.is-consumed", backend.is_consumed(&c.key()));
    }

    // A9 — same decision after durable consume reads consumed / fail-closed.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        let again = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A9.outcome", "durable-replay-fail-closed", &again);
        t.assert_true(
            "A9.consumed-cause",
            again
                == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
                    DurableBackendOutcome::FailClosedConsumed,
                ),
        );
    }

    // A10 — read-only validation observes/reads but does not consume even with a
    // modeled successful mutation.
    {
        let c = fresh_devnet_validation();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("A10.outcome", "proceed-fresh-observed", &o);
        t.check_state(
            "A10.state",
            "observed-fresh",
            backend.read_durable_state(&c.key()),
        );
        t.assert_true("A10.not-consumed", !backend.is_consumed(&c.key()));
    }

    // A11 — apply failed after observe does not consume.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::ApplyFailed),
            &mut backend,
        );
        t.check_outcome("A11.outcome", "do-not-consume-apply-failed", &o);
        t.assert_true("A11.not-consumed", !backend.is_consumed(&c.key()));
    }

    // A12 — rollback after observe does not consume.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::RolledBack),
            &mut backend,
        );
        t.check_outcome("A12.outcome", "do-not-consume-rolled-back", &o);
        t.assert_true("A12.not-consumed", !backend.is_consumed(&c.key()));
    }

    // A13 — after-mutation-before-consume crash window is typed and fails closed.
    {
        let c = fresh_devnet_mutating();
        let obs = crash_obs(K::FixtureDevNet, true, true, true, false, false, false);
        let o = recover_durable_replay_runtime_crash_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &obs,
        );
        t.check_outcome("A13.outcome", "crash-window-fail-closed", &o);
        t.assert_true(
            "A13.amc",
            o == DurableReplayRuntimeOutcome::CrashWindowFailClosed(
                CrashWindow::AfterMutationBeforeConsume,
            ),
        );
        t.assert_true("A13.is-fail-closed", o.is_fail_closed());
    }

    // A14 — after-consume crash window reads consumed / fail-closed.
    {
        let c = fresh_devnet_mutating();
        let obs = crash_obs(K::FixtureDevNet, true, true, true, false, false, true);
        let o = recover_durable_replay_runtime_crash_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &obs,
        );
        t.check_outcome("A14.outcome", "crash-window-fail-closed", &o);
        t.assert_true(
            "A14.after-consume",
            o == DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::AfterConsume),
        );
    }

    // A15 — fixture restart snapshot preserves observed state through integration.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let snapshot = backend.restart_snapshot();
        t.check("A15.snapshot-len", "1", &snapshot.len().to_string());
        let mut restored = FixtureDurableReplayBackend::from_snapshot(snapshot);
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut restored,
        );
        t.check_outcome("A15.outcome", "proceed-known-fresh", &o);
        t.assert_true("A15.not-consumed", !restored.is_consumed(&c.key()));
    }

    // A16 — fixture restart snapshot preserves consumed state through integration.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        let mut restored = FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
        t.assert_true("A16.is-consumed", restored.is_consumed(&c.key()));
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut restored,
        );
        t.check_outcome("A16.outcome", "durable-replay-fail-closed", &o);
        t.assert_true(
            "A16.consumed-cause",
            o == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
                DurableBackendOutcome::FailClosedConsumed,
            ),
        );
    }

    // A17 — production durable backend path is reached and fails closed unavailable.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::Production, P::Production, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A17.outcome", "production-durable-unavailable", &o);
        t.assert_true("A17.no-write", backend.is_empty());
        t.assert_true(
            "A17.guard",
            production_mainnet_durable_remains_unavailable_under_durable_runtime(),
        );
    }

    // A18 — MainNet durable backend path is reached and fails closed
    // unavailable/refused (non-peer-driven MainNet surface).
    {
        let c = ctx(
            Env::Mainnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::MainNet, P::MainNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A18.outcome", "mainnet-durable-unavailable", &o);
        t.assert_true("A18.no-write", backend.is_empty());
    }

    // A19 — MainNet peer-driven apply remains refused even if durable state is fresh.
    {
        let c = ctx(
            Env::Mainnet,
            S::PeerDrivenDrain,
            S::PeerDrivenDrain,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("A19.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("A19.is-refused", o.is_mainnet_peer_driven_apply_refused());
        t.assert_true("A19.no-write", backend.is_empty());
    }

    // A20 — Run 236 replay consume runtime integration remains compatible.
    {
        t.assert_true(
            "A20.after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
        t.assert_true(
            "A20.fresh-required",
            fresh_required_before_mutation_authorization_under_consume_runtime(),
        );
        t.assert_true(
            "A20.mainnet-refused",
            mainnet_peer_driven_apply_remains_refused_under_consume_runtime(Env::Mainnet),
        );
    }

    // A21 — Run 238 durable backend boundary remains compatible.
    {
        t.assert_true(
            "A21.mainnet-refused",
            mainnet_peer_driven_apply_remains_refused_under_durable_backend(Env::Mainnet),
        );
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.assert_true("A21.proceeds", o.is_proceed());
    }

    // A22 — Run 239 release durable-backend behavior remains compatible: a fresh
    // DevNet decision observes fresh and the production/MainNet guard still holds.
    {
        let c = fresh_devnet_validation();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A22.observe-fresh", "proceed-fresh-observed", &o);
        t.assert_true(
            "A22.prod-mainnet-unavailable",
            production_mainnet_durable_backend_remains_unavailable(),
        );
    }

    // A23 — Run 237 release consume-runtime behavior remains compatible.
    {
        t.assert_true(
            "A23.consume-after-success-only",
            consume_only_after_successful_mutation_under_durable_runtime(),
        );
        t.assert_true(
            "A23.consume-runtime-after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
    }

    // A24 — Run 235 release consume-boundary behavior remains compatible: a fresh
    // observe then a successful mutation consumes only after success.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let observe = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A24.observe", "proceed-mutation-authorized", &observe);
        let consume = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("A24.consume", "consume-durable-after-mutation-success", &consume);
    }

    // A25 — integrate_durable_replay_runtime proves durable read/observe occurs
    // before mutation authorization.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        t.assert_true("A25.empty-before", backend.is_empty());
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("A25.authorized", "proceed-mutation-authorized", &o);
        t.check_state(
            "A25.observed-first",
            "observed-fresh",
            backend.read_durable_state(&c.key()),
        );
        t.assert_true(
            "A25.guard",
            durable_observe_happens_before_mutation_authorization(),
        );
    }

    // A26 — compare-and-mark-consumed is reachable only after AppliedSuccessfully.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        // Every non-AppliedSuccessfully completion never consumes.
        for (i, mc) in [MC::AuthorizedButNotApplied, MC::ApplyFailed, MC::RolledBack]
            .into_iter()
            .enumerate()
        {
            let o = integrate_durable_replay_runtime(
                &c.input(K::FixtureDevNet, P::FixtureDevNet, mc),
                &mut backend,
            );
            t.assert_true(&format!("A26.no-consume.{i}"), o.no_consume());
            t.assert_true(&format!("A26.not-consumed.{i}"), !backend.is_consumed(&c.key()));
        }
        // AppliedSuccessfully consumes.
        let consume = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.assert_true("A26.consumes", consume.authorizes_consume());
    }

    // A27 — crash-window recovery helper returns typed fail-closed outcomes for
    // ambiguous windows.
    {
        let c = fresh_devnet_mutating();
        // ambiguous: mutation attempted but neither succeeded, failed, nor rolled back.
        let obs = crash_obs(K::FixtureDevNet, true, true, false, false, false, false);
        let o = recover_durable_replay_runtime_crash_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &obs,
        );
        t.check_outcome("A27.outcome", "crash-window-fail-closed", &o);
        t.assert_true(
            "A27.unknown",
            o == DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::UnknownCrashWindow),
        );
        t.assert_true(
            "A27.guard",
            crash_window_ambiguity_fails_closed_under_durable_runtime(),
        );
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R38).
// ===========================================================================

/// Tamper a single durable input field against canonical expectations and assert
/// the integration fails closed durable-malformed without recording anything.
fn assert_durable_binding_rejected(
    t: &mut Table,
    id: &str,
    tamper: impl FnOnce(&mut DurableBackendDecisionInput),
) {
    let mut c = fresh_devnet_mutating();
    tamper(&mut c.durable_input);
    let mut backend = devnet_backend();
    let o = integrate_durable_replay_runtime(
        &c.input(
            DurableBackendKind::FixtureDevNet,
            ReplayStatePolicy::FixtureDevNet,
            DurableMutationCompletion::NotAttempted,
        ),
        &mut backend,
    );
    t.check_outcome(&format!("{id}.outcome"), "durable-replay-fail-closed", &o);
    t.assert_true(
        &format!("{id}.malformed"),
        o == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
            DurableBackendOutcome::FailClosedMalformedRecord,
        ),
    );
    t.assert_true(&format!("{id}.backend-empty"), backend.is_empty());
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use DurableRecordState as RS;
    use GovernanceExecutionRuntimeSurface as S;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1 — expired durable state rejected before mutation.
    {
        let c = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            250, // canonical >= expiry => expired
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("R1.outcome", "replay-runtime-fail-closed", &o);
        t.assert_true("R1.fail-closed", o.is_fail_closed());
        t.assert_true("R1.backend-empty", backend.is_empty());
    }

    // R2 — stale durable state rejected before mutation.
    {
        let c = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            EXPIRY,
            EFFECTIVE, // degenerate window => stale
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("R2.outcome", "replay-runtime-fail-closed", &o);
        t.assert_true("R2.backend-empty", backend.is_empty());
    }

    // R3 — replay detected rejected before mutation.
    {
        let c = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::Seen(seen_record(false, false)),
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("R3.outcome", "replay-runtime-fail-closed", &o);
        t.assert_true("R3.backend-empty", backend.is_empty());
    }

    // R4 — consumed decision rejected before mutation.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.assert_true(
            "R4.consumed",
            o == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
                DurableBackendOutcome::FailClosedConsumed,
            ),
        );
    }

    // R5 — superseded decision rejected before mutation.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        backend.mark_superseded(&c.key());
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.assert_true(
            "R5.superseded",
            o == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
                DurableBackendOutcome::FailClosedSuperseded,
            ),
        );
    }

    // R6 — malformed durable record rejected before mutation.
    assert_durable_binding_rejected(&mut t, "R6.malformed", |i| i.replay_nonce = String::new());

    // R7 — backend unavailable rejected (fixture kind keyed for a MainNet
    // non-peer-driven environment is unavailable).
    {
        let c = ctx(
            Env::Mainnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.assert_true(
            "R7.backend-unavailable",
            o == DurableReplayRuntimeOutcome::DurableReplayFailClosed(
                DurableBackendOutcome::FailClosedBackendUnavailable,
            ),
        );
    }

    // R8 — production durable backend unavailable rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::Production, P::Production, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("R8.outcome", "production-durable-unavailable", &o);
    }

    // R9 — MainNet durable backend unavailable/refused rejected.
    {
        let c = ctx(
            Env::Mainnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::MainNet, P::MainNet, MC::NotAttempted),
            &mut backend,
        );
        t.check_outcome("R9.outcome", "mainnet-durable-unavailable", &o);
    }

    // R10–R26 — wrong-binding / malformed (fail-closed durable-malformed, non-mutating).
    assert_durable_binding_rejected(&mut t, "R10.wrong-environment", |i| {
        i.environment = Env::Testnet
    });
    assert_durable_binding_rejected(&mut t, "R11.wrong-chain", |i| i.chain_id = "wrong".to_string());
    assert_durable_binding_rejected(&mut t, "R12.wrong-genesis", |i| {
        i.genesis_hash = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R13.wrong-validation-surface", |i| {
        i.validation_surface = S::Sighup
    });
    assert_durable_binding_rejected(&mut t, "R14.wrong-mutation-surface", |i| {
        i.mutation_surface = S::Sighup
    });
    assert_durable_binding_rejected(&mut t, "R15.wrong-replay-state-key", |i| {
        i.replay_state_key_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R16.wrong-source-identity", |i| {
        i.evaluator_source_identity_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R17.wrong-request", |i| {
        i.evaluator_request_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R18.wrong-response", |i| {
        i.evaluator_response_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R19.wrong-transcript", |i| {
        i.evaluator_transcript_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R20.wrong-decision-digest", |i| {
        i.governance_execution_decision_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R21.wrong-proposal-id", |i| {
        i.proposal_id = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R22.wrong-decision-id", |i| {
        i.decision_id = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R23.wrong-lifecycle-action", |i| {
        i.lifecycle_action = LocalLifecycleAction::Retire
    });
    assert_durable_binding_rejected(&mut t, "R24.wrong-candidate", |i| {
        i.candidate_digest = "wrong".to_string()
    });
    assert_durable_binding_rejected(&mut t, "R25.wrong-sequence", |i| {
        i.authority_domain_sequence = 999
    });
    assert_durable_binding_rejected(&mut t, "R26.wrong-replay-nonce", |i| {
        i.replay_nonce = "wrong".to_string()
    });

    // R27 — compare-and-mark-consumed wrong expected state rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = durable_compare_and_mark_consumed(
            K::FixtureDevNet,
            &c.durable_input,
            &c.durable_expectations,
            RS::Consumed, // wrong expected (actual is ObservedFresh)
            MC::AppliedSuccessfully,
            &mut backend,
        );
        t.check("R27.outcome", "rejected-wrong-expected-state", o.tag());
        t.assert_true("R27.not-consumed", !backend.is_consumed(&c.key()));
    }

    // R28 — consume attempted before observe rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("R28.outcome", "consume-runtime-fail-closed", &o);
        t.assert_true("R28.backend-empty", backend.is_empty());
    }

    // R29 — consume attempted before successful mutation rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AuthorizedButNotApplied),
            &mut backend,
        );
        t.check_outcome("R29.outcome", "do-not-consume-before-apply", &o);
        t.assert_true("R29.not-consumed", !backend.is_consumed(&c.key()));
    }

    // R30 — consume attempted after failed apply rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::ApplyFailed),
            &mut backend,
        );
        t.check_outcome("R30.outcome", "do-not-consume-apply-failed", &o);
        t.assert_true("R30.not-consumed", !backend.is_consumed(&c.key()));
    }

    // R31 — consume attempted after rollback rejected.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::RolledBack),
            &mut backend,
        );
        t.check_outcome("R31.outcome", "do-not-consume-rolled-back", &o);
        t.assert_true("R31.not-consumed", !backend.is_consumed(&c.key()));
    }

    // R32 — ambiguous crash window rejected.
    {
        let c = fresh_devnet_mutating();
        let obs = crash_obs(K::FixtureDevNet, true, true, false, false, false, false);
        let o = recover_durable_replay_runtime_crash_window(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &obs,
        );
        t.assert_true(
            "R32.unknown",
            o == DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::UnknownCrashWindow),
        );
        t.assert_true("R32.fail-closed", o.is_fail_closed());
    }

    // R33 — local operator cannot satisfy durable replay backend policy.
    t.assert_true(
        "R33.local-operator-cannot",
        local_operator_cannot_satisfy_durable_runtime_policy(),
    );
    // R34 — peer majority cannot satisfy durable replay backend policy.
    t.assert_true(
        "R34.peer-majority-cannot",
        peer_majority_cannot_satisfy_durable_runtime_policy(),
    );
    // R35 — validator-set rotation unsupported rejected.
    t.assert_true(
        "R35.validator-rotation-unsupported",
        validator_set_rotation_remains_unsupported_under_durable_runtime(),
    );
    // R36 — policy-change action unsupported rejected.
    t.assert_true(
        "R36.policy-change-unsupported",
        policy_change_action_remains_unsupported_under_durable_runtime(),
    );

    // R37 — rejection produces no Run 070 call, no live trust swap, no session
    // eviction, no sequence write, and no marker write (non-mutating). A
    // replay-runtime rejection leaves the durable backend untouched.
    {
        let c = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::Seen(seen_record(false, false)),
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend,
        );
        t.assert_true("R37.fail-closed", o.is_fail_closed());
        t.assert_true("R37.backend-empty", backend.is_empty());
        t.assert_true("R37.non-mutating", durable_runtime_rejection_is_non_mutating());

        // A rejected consume after a legitimate observe leaves the record
        // unconsumed and the backend length unchanged.
        let good = fresh_devnet_mutating();
        let mut backend2 = devnet_backend();
        integrate_durable_replay_runtime(
            &good.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut backend2,
        );
        let len_before = backend2.len();
        let rejected = integrate_durable_replay_runtime(
            &good.input(K::FixtureDevNet, P::FixtureDevNet, MC::ApplyFailed),
            &mut backend2,
        );
        t.assert_true("R37.rejected-no-consume", rejected.no_consume());
        t.assert_true("R37.not-consumed", !backend2.is_consumed(&good.key()));
        t.assert_true("R37.len-unchanged", backend2.len() == len_before);
    }

    // R38 — MainNet peer-driven apply remains refused even when durable backend
    // says fresh, and never consumes.
    {
        let mainnet = ctx(
            Env::Mainnet,
            S::PeerDrivenDrain,
            S::PeerDrivenDrain,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut backend = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &mainnet.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
            &mut backend,
        );
        t.check_outcome("R38.outcome", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true("R38.backend-empty", backend.is_empty());
        t.assert_true(
            "R38.guard",
            mainnet_peer_driven_apply_remains_refused_under_durable_runtime(Env::Mainnet),
        );
    }

    t.finish(out)
}

// ===========================================================================
// Reachability + invariant + taxonomy table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("reachability");

    // Run 240 outcome tags reachable / stable.
    for (id, expected, o) in [
        (
            "T.legacy-bypass",
            "proceed-legacy-bypass-no-durable-write",
            DurableReplayRuntimeOutcome::ProceedLegacyBypassNoDurableWrite,
        ),
        (
            "T.deferred-observed",
            "proceed-deferred-observed",
            DurableReplayRuntimeOutcome::ProceedDeferredObserved,
        ),
        (
            "T.fresh-observed",
            "proceed-fresh-observed",
            DurableReplayRuntimeOutcome::ProceedFreshObserved,
        ),
        (
            "T.known-fresh",
            "proceed-known-fresh",
            DurableReplayRuntimeOutcome::ProceedKnownFresh,
        ),
        (
            "T.mutation-authorized",
            "proceed-mutation-authorized",
            DurableReplayRuntimeOutcome::ProceedMutationAuthorized,
        ),
        (
            "T.consume-after-success",
            "consume-durable-after-mutation-success",
            DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess,
        ),
        (
            "T.do-not-consume-before-apply",
            "do-not-consume-before-apply",
            DurableReplayRuntimeOutcome::DoNotConsumeBeforeApply,
        ),
        (
            "T.do-not-consume-apply-failed",
            "do-not-consume-apply-failed",
            DurableReplayRuntimeOutcome::DoNotConsumeApplyFailed,
        ),
        (
            "T.do-not-consume-rolled-back",
            "do-not-consume-rolled-back",
            DurableReplayRuntimeOutcome::DoNotConsumeRolledBack,
        ),
        (
            "T.crash-window-fail-closed",
            "crash-window-fail-closed",
            DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::AfterMutationBeforeConsume),
        ),
        (
            "T.durable-replay-fail-closed",
            "durable-replay-fail-closed",
            DurableReplayRuntimeOutcome::DurableReplayFailClosed(DurableBackendOutcome::FailClosedConsumed),
        ),
        (
            "T.consume-runtime-fail-closed",
            "consume-runtime-fail-closed",
            DurableReplayRuntimeOutcome::ConsumeRuntimeFailClosed {
                reason: "x".to_string(),
            },
        ),
        (
            "T.production-durable-unavailable",
            "production-durable-unavailable",
            DurableReplayRuntimeOutcome::ProductionDurableUnavailable,
        ),
        (
            "T.mainnet-durable-unavailable",
            "mainnet-durable-unavailable",
            DurableReplayRuntimeOutcome::MainNetDurableUnavailable,
        ),
        (
            "T.mainnet-peer-driven-apply-refused",
            "mainnet-peer-driven-apply-refused",
            DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused,
        ),
    ] {
        t.check(id, expected, o.tag());
    }

    // Outcome predicate partitions.
    {
        let consume = DurableReplayRuntimeOutcome::ConsumeDurableAfterMutationSuccess;
        t.assert_true("P.consume-authorizes", consume.authorizes_consume());
        t.assert_true("P.consume-proceeds", consume.is_proceed());
        let authorized = DurableReplayRuntimeOutcome::ProceedMutationAuthorized;
        t.assert_true("P.authorized-mutation", authorized.authorizes_mutation());
        t.assert_true("P.authorized-no-consume", authorized.no_consume());
        let deferred = DurableReplayRuntimeOutcome::ProceedDeferredObserved;
        t.assert_true("P.deferred-is-deferred", deferred.is_deferred());
        t.assert_true("P.deferred-not-proceed", !deferred.is_proceed());
        let crash = DurableReplayRuntimeOutcome::CrashWindowFailClosed(CrashWindow::AfterConsume);
        t.assert_true("P.crash-is-fail-closed", crash.is_fail_closed());
        t.assert_true("P.crash-is-crash", crash.is_crash_window_fail_closed());
        let refused = DurableReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused;
        t.assert_true("P.refused", refused.is_mainnet_peer_driven_apply_refused());
    }

    // Grep-verifiable invariant / fail-closed helper invariants.
    {
        t.assert_true(
            "G.observe-before-auth",
            durable_observe_happens_before_mutation_authorization(),
        );
        t.assert_true(
            "G.consume-after-success-only",
            consume_only_after_successful_mutation_under_durable_runtime(),
        );
        t.assert_true(
            "G.crash-ambiguity-fail-closed",
            crash_window_ambiguity_fails_closed_under_durable_runtime(),
        );
        t.assert_true(
            "G.restart-snapshot-source-test-only",
            restart_snapshot_is_fixture_source_test_only_under_durable_runtime(),
        );
        t.assert_true(
            "G.production-mainnet-unavailable",
            production_mainnet_durable_remains_unavailable_under_durable_runtime(),
        );
        t.assert_true(
            "G.local-operator-cannot",
            local_operator_cannot_satisfy_durable_runtime_policy(),
        );
        t.assert_true(
            "G.peer-majority-cannot",
            peer_majority_cannot_satisfy_durable_runtime_policy(),
        );
        t.assert_true(
            "G.validator-rotation-unsupported",
            validator_set_rotation_remains_unsupported_under_durable_runtime(),
        );
        t.assert_true(
            "G.policy-change-unsupported",
            policy_change_action_remains_unsupported_under_durable_runtime(),
        );
        t.assert_true(
            "G.no-rocksdb-file-schema-migration",
            no_rocksdb_file_schema_migration_change_under_durable_runtime(),
        );
        t.assert_true(
            "G.non-mutating-rejection",
            durable_runtime_rejection_is_non_mutating(),
        );
        t.assert_true(
            "G.mainnet-refused-mainnet",
            mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
                TrustBundleEnvironment::Mainnet,
            ),
        );
        t.assert_true(
            "G.mainnet-refused-not-devnet",
            !mainnet_peer_driven_apply_remains_refused_under_durable_runtime(
                TrustBundleEnvironment::Devnet,
            ),
        );
    }

    // Callsite wiring proceed/fail-closed.
    {
        let c = fresh_devnet_mutating();
        let mut backend = devnet_backend();
        let ok = wire_durable_replay_runtime_callsite(
            &c.input(
                DurableBackendKind::FixtureDevNet,
                ReplayStatePolicy::FixtureDevNet,
                DurableMutationCompletion::NotAttempted,
            ),
            &mut backend,
        );
        t.assert_true("W.callsite-proceed-ok", ok.is_ok());

        let mn = ctx(
            TrustBundleEnvironment::Mainnet,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut mn_backend = devnet_backend();
        let err = wire_durable_replay_runtime_callsite(
            &mn.input(
                DurableBackendKind::FixtureDevNet,
                ReplayStatePolicy::FixtureDevNet,
                DurableMutationCompletion::NotAttempted,
            ),
            &mut mn_backend,
        );
        match err {
            Ok(_) => t.assert_true("W.callsite-fail-closed-err", false),
            Err(e) => t.assert_true(
                "W.callsite-fail-closed-err",
                e.is_mainnet_peer_driven_apply_refused(),
            ),
        }
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (durable runtime outcome values, before/after fixture durable
// backend snapshots, crash-window values, restart snapshots).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use GovernanceExecutionRuntimeSurface as S;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let c = fresh_devnet_mutating();
    let key = c.key();

    // Deterministic durable backend key digest (release mode).
    write_file(&dir.join("durable_backend_key_digest.txt"), &format!("{key}\n"));

    // Before / after fixture durable backend snapshots across the full runtime
    // observe -> authorize -> consume lifecycle.
    let mut backend = devnet_backend();
    let snap_before = format!(
        "len={} contains={} is_consumed={} state={}\n",
        backend.len(),
        backend.contains(&key),
        backend.is_consumed(&key),
        backend.read_durable_state(&key).tag()
    );
    let authorize = integrate_durable_replay_runtime(
        &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
        &mut backend,
    );
    let snap_observed = format!(
        "outcome={} len={} contains={} is_consumed={} state={}\n",
        authorize.tag(),
        backend.len(),
        backend.contains(&key),
        backend.is_consumed(&key),
        backend.read_durable_state(&key).tag()
    );
    // Restart snapshot durability across the observed/authorized state.
    let restarted_observed = FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
    let snap_restart_observed = format!(
        "restart len={} contains={} is_consumed={} state={}\n",
        restarted_observed.len(),
        restarted_observed.contains(&key),
        restarted_observed.is_consumed(&key),
        restarted_observed.read_durable_state(&key).tag()
    );
    let consume = integrate_durable_replay_runtime(
        &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::AppliedSuccessfully),
        &mut backend,
    );
    let snap_consumed = format!(
        "outcome={} len={} contains={} is_consumed={} state={}\n",
        consume.tag(),
        backend.len(),
        backend.contains(&key),
        backend.is_consumed(&key),
        backend.read_durable_state(&key).tag()
    );
    let restarted_consumed = FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
    let snap_restart_consumed = format!(
        "restart len={} contains={} is_consumed={} state={}\n",
        restarted_consumed.len(),
        restarted_consumed.contains(&key),
        restarted_consumed.is_consumed(&key),
        restarted_consumed.read_durable_state(&key).tag()
    );
    write_file(
        &dir.join("fixture_backend_snapshots.txt"),
        &format!(
            "before:           {snap_before}\
             observed:         {snap_observed}\
             restart-observed: {snap_restart_observed}\
             consumed:         {snap_consumed}\
             restart-consumed: {snap_restart_consumed}"
        ),
    );

    // Durable runtime outcome values across a range of freshness windows.
    for (label, eff, exp_epoch, can) in [
        ("fresh", EFFECTIVE, EXPIRY, CANONICAL),
        ("deferred", EFFECTIVE, EXPIRY, 50u64),
        ("expired", EFFECTIVE, EXPIRY, 250u64),
        ("stale", EXPIRY, EFFECTIVE, CANONICAL),
    ] {
        let cc = ctx(
            Env::Devnet,
            S::ReloadApply,
            S::ReloadApply,
            eff,
            exp_epoch,
            can,
            PreviouslySeenState::FirstSeen,
        );
        let mut b = devnet_backend();
        let o = integrate_durable_replay_runtime(
            &cc.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
            &mut b,
        );
        write_file(
            &dir.join(format!("{label}_outcome.txt")),
            &format!(
                "window={label} outcome={} state={}\n",
                o.tag(),
                b.read_durable_state(&cc.key()).tag()
            ),
        );
    }

    // Crash-window outcome values dump.
    {
        let mut s = String::new();
        for (label, obs) in [
            (
                "after-mutation-before-consume",
                crash_obs(K::FixtureDevNet, true, true, true, false, false, false),
            ),
            (
                "after-consume",
                crash_obs(K::FixtureDevNet, true, true, true, false, false, true),
            ),
            (
                "unknown",
                crash_obs(K::FixtureDevNet, true, true, false, false, false, false),
            ),
            (
                "rollback",
                crash_obs(K::FixtureDevNet, true, true, false, true, false, false),
            ),
            (
                "apply-failed",
                crash_obs(K::FixtureDevNet, true, true, false, false, true, false),
            ),
        ] {
            let o = recover_durable_replay_runtime_crash_window(
                &c.input(K::FixtureDevNet, P::FixtureDevNet, MC::NotAttempted),
                &obs,
            );
            s.push_str(&format!("{label}\t{}\n", o.tag()));
        }
        // Production / MainNet crash-window classification is unavailable.
        let prod = recover_durable_replay_runtime_crash_window(
            &c.input(K::Production, P::Production, MC::NotAttempted),
            &crash_obs(K::Production, true, true, true, false, false, true),
        );
        s.push_str(&format!("production\t{}\n", prod.tag()));
        write_file(&dir.join("crash_window_outcomes.txt"), &s);
    }

    // Production / MainNet unavailable dump.
    {
        let mut prod_backend = devnet_backend();
        let prod = integrate_durable_replay_runtime(
            &c.input(K::Production, P::Production, MC::NotAttempted),
            &mut prod_backend,
        );
        let mn = ctx(
            Env::Mainnet,
            S::ReloadApply,
            S::ReloadApply,
            EFFECTIVE,
            EXPIRY,
            CANONICAL,
            PreviouslySeenState::FirstSeen,
        );
        let mut mn_backend = devnet_backend();
        let mn_o = integrate_durable_replay_runtime(
            &mn.input(K::MainNet, P::MainNet, MC::NotAttempted),
            &mut mn_backend,
        );
        write_file(
            &dir.join("production_mainnet_unavailable.txt"),
            &format!(
                "production_outcome={} production_backend_empty={} mainnet_outcome={} mainnet_backend_empty={}\n",
                prod.tag(),
                prod_backend.is_empty(),
                mn_o.tag(),
                mn_backend.is_empty()
            ),
        );
    }

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_durable_runtime_integration\n");
    for entry in [
        "type\tDurableReplayRuntimeIntegrationInput",
        "type\tDurableReplayRuntimeOutcome",
        "type\tDurableReplayRuntimeCallsiteFailClosed",
        "fn\tintegrate_durable_replay_runtime",
        "fn\trecover_durable_replay_runtime_crash_window",
        "fn\twire_durable_replay_runtime_callsite",
        "guard\tdurable_observe_happens_before_mutation_authorization",
        "guard\tconsume_only_after_successful_mutation_under_durable_runtime",
        "guard\tcrash_window_ambiguity_fails_closed_under_durable_runtime",
        "guard\trestart_snapshot_is_fixture_source_test_only_under_durable_runtime",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_durable_runtime",
        "guard\tproduction_mainnet_durable_remains_unavailable_under_durable_runtime",
        "guard\tlocal_operator_cannot_satisfy_durable_runtime_policy",
        "guard\tpeer_majority_cannot_satisfy_durable_runtime_policy",
        "guard\tvalidator_set_rotation_remains_unsupported_under_durable_runtime",
        "guard\tpolicy_change_action_remains_unsupported_under_durable_runtime",
        "guard\tno_rocksdb_file_schema_migration_change_under_durable_runtime",
        "guard\tdurable_runtime_rejection_is_non_mutating",
        "compose\tRun 238 compare_and_mark_consumed / classify_crash_window",
        "compose\tRun 238 FixtureDurableReplayBackend restart_snapshot / from_snapshot",
        "compose\tRun 230 / 232 evaluate_evaluator_replay_freshness",
        "compose\tRun 236 consume runtime integration",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("durable_runtime_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper <OUT_DIR>"
        );
        std::process::exit(2);
    });
    fs::create_dir_all(&out_dir).unwrap();
    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("reachability", run_reachability_table),
    ];
    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut summary = String::from("run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper\nscope: Run 240 governance evaluator durable replay backend runtime integration (pqc_governance_evaluator_replay_durable_runtime_integration: integrate_durable_replay_runtime, recover_durable_replay_runtime_crash_window, wire_durable_replay_runtime_callsite, DurableReplayRuntimeIntegrationInput, DurableReplayRuntimeOutcome, and the grep-verifiable invariant/refusal helpers) exercised through release-built library symbols (release binary), composing the Run 238 durable backend with the Run 230/232 replay/freshness state path and the Run 236 consume runtime integration\nnote: fixture-only; pure typed composition (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no persistent storage, no RocksDB/file/schema/migration/storage-format change); default Disabled is a Run 214 legacy bypass with no durable write; durable read/observe happens before mutation authorization; mutation is authorized only on fresh/known-fresh after the Run 230/232 runtime agrees fresh; compare-and-mark-consumed happens only after a modeled AppliedSuccessfully mutation, after which the decision reads consumed/fail-closed; read-only validation, deferral, failed apply, rollback, and consume-before-observe/before-success never consume; an ambiguous (after-mutation-before-consume/unknown/after-consume) crash window is typed and fails closed; fixture restart snapshot preserves observed and consumed state through the integration (value clone, never a file format); production/MainNet durable backends are reached but always fail closed unavailable; MainNet peer-driven apply remains refused even when the durable state reads fresh; rejections are pure and non-mutating; validator-set rotation and policy-change actions remain unsupported\n\n");
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
