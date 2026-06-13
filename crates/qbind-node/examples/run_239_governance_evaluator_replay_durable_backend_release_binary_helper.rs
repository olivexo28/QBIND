//! Run 239 — release-built helper for the Run 238 governance evaluator
//! **durable replay state backend boundary**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`).
//!
//! Where Run 238 landed the pure, typed durable backend contract at the
//! source/test level and captured **no** release-binary evidence, Run 239 is
//! that release-binary evidence. This helper drives the A1–A25 / R1–R37 matrix
//! from `task/RUN_239_TASK.txt` through the **release-built** Run 238 symbols
//! (`read_decision_state`, `observe_decision_if_absent`,
//! `mark_consumed_after_success`, `compare_and_mark_consumed`,
//! `classify_crash_window`, the deterministic digest helpers, the
//! `DurableBackendDecisionInput` / `DurableBackendDecisionExpectations` binding,
//! the `DurableRecordState` / `DurableBackendOutcome` / `DurableConsumeOutcome`
//! / `CrashWindow` / `DurableBackendKind` / `DurableMutationCompletion`
//! taxonomies, the reader/writer/atomic traits and the
//! `FixtureDurableReplayBackend` with its `restart_snapshot` / `from_snapshot`
//! durability model, and the grep-verifiable invariant / refusal helpers),
//! proving in release mode that:
//!
//! * a first-seen DevNet/TestNet fixture decision records `ObservedFresh` and
//!   reads `ProceedKnownFresh`; not-yet-effective reads deferred (not a mutation
//!   approval); expired / stale read fail-closed;
//! * an explicit consume after a successful mutation marks consumed, after which
//!   the same decision reads `FailClosedConsumed`; read-only validation never
//!   consumes; rollback / failed-apply never consume;
//! * observe-only and consumed state both survive a fixture restart snapshot
//!   (an in-process value clone, never a file format);
//! * `compare_and_mark_consumed` consumes only on an exactly-`ObservedFresh`
//!   record and rejects a wrong expected state — atomicity is release-evidenced;
//! * the crash-window classifier types every window, never silently approving
//!   an after-mutation-before-consume window;
//! * the durable backend key / record / operation-transcript / crash-window
//!   transcript digests are deterministic in release mode;
//! * production / MainNet durable backends are callable but always fail closed
//!   unavailable, and MainNet peer-driven apply remains refused even when the
//!   fixture would otherwise read fresh;
//! * every rejection is pure and non-mutating (the fixture records nothing on a
//!   malformed observe and never marks consumed on a rejected consume).
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
};
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    classify_crash_window, compare_and_mark_consumed, crash_window_transcript_digest,
    durable_backend_key_digest, durable_consume_only_after_successful_mutation,
    durable_operation_transcript_digest, durable_record_digest,
    local_operator_cannot_satisfy_durable_backend_policy,
    mainnet_peer_driven_apply_remains_refused_under_durable_backend, mark_consumed_after_success,
    no_rocksdb_file_schema_migration_change_under_durable_backend, observe_decision_if_absent,
    peer_majority_cannot_satisfy_durable_backend_policy,
    policy_change_action_remains_unsupported_under_durable_backend,
    production_mainnet_durable_backend_remains_unavailable, read_decision_state,
    restart_durability_is_fixture_snapshot_only,
    validator_set_rotation_remains_unsupported_under_durable_backend, CrashWindow,
    CrashWindowObservation, DurableBackendDecisionExpectations, DurableBackendDecisionInput,
    DurableBackendKind, DurableBackendOutcome, DurableConsumeOutcome, DurableMutationCompletion,
    DurableRecordState, FixtureDurableReplayBackend,
    GovernanceEvaluatorReplayDurableBackendReader, MainnetDurableReplayBackend,
    ProductionDurableReplayBackend,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, replay_state_key_digest,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, PreviouslySeenState,
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
// Shared constants (mirror the Run 220 / 222 / 230 / 234 / 238 corpora so the
// composed material binds to the same trust domain, proposal/decision identity,
// candidate digest, replay nonce).
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
// Run 230 freshness input / Run 238 durable input + expectations builders
// ===========================================================================

fn fresh_in(
    env: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    effective: u64,
    expiry: u64,
    canonical: u64,
) -> EvaluatorReplayFreshnessInput {
    let identity = ev_identity(env);
    let request = ev_request(&identity, effective, expiry);
    let response = ev_response(&request, effective, expiry);
    EvaluatorReplayFreshnessInput::from_evaluator_material(
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
        PreviouslySeenState::FirstSeen,
    )
}

fn di(
    env: TrustBundleEnvironment,
    vs: GovernanceExecutionRuntimeSurface,
    ms: GovernanceExecutionRuntimeSurface,
    effective: u64,
    expiry: u64,
    canonical: u64,
) -> (
    DurableBackendDecisionInput,
    DurableBackendDecisionExpectations,
) {
    let f = fresh_in(env, vs, effective, expiry, canonical);
    (
        DurableBackendDecisionInput::from_freshness_input(&f, ms),
        DurableBackendDecisionExpectations::from_freshness_input(&f, ms),
    )
}

/// Standard fresh DevNet decision (effective 100, expiry 200, canonical 150).
fn fresh_devnet() -> (
    DurableBackendDecisionInput,
    DurableBackendDecisionExpectations,
) {
    di(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        100,
        200,
        150,
    )
}

fn key_of(input: &DurableBackendDecisionInput) -> String {
    durable_backend_key_digest(input)
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: DurableBackendOutcome) {
        self.check(id, expected, o.tag());
    }
    fn check_consume(&mut self, id: &str, expected: &str, o: DurableConsumeOutcome) {
        self.check(id, expected, o.tag());
    }
    fn check_state(&mut self, id: &str, expected: &str, s: DurableRecordState) {
        self.check(id, expected, s.tag());
    }
    fn check_window(&mut self, id: &str, expected: &str, w: CrashWindow) {
        self.check(id, expected, w.tag());
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
// A — accepted / compatible scenarios (A1–A25) exercised through the Run 238
// release-built durable replay-state backend boundary symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — first-seen DevNet fixture decision records ObservedFresh.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        let o = observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_outcome("A1.observe", "proceed-first-seen", o);
        t.check_state(
            "A1.state",
            "observed-fresh",
            backend.read_durable_state(&key_of(&input)),
        );
    }

    // A2 — first-seen TestNet fixture decision records ObservedFresh.
    {
        let (input, exp) = di(Env::Testnet, S::ReloadApply, S::ReloadApply, 100, 200, 150);
        let mut backend = FixtureDurableReplayBackend::new(Env::Testnet);
        let o = observe_decision_if_absent(K::FixtureTestNet, &input, &exp, &mut backend);
        t.check_outcome("A2.observe", "proceed-first-seen", o);
        t.check_state(
            "A2.state",
            "observed-fresh",
            backend.read_durable_state(&key_of(&input)),
        );
    }

    // A3 — known fresh decision reads ProceedKnownFresh.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        let o = read_decision_state(K::FixtureDevNet, &input, &exp, &backend);
        t.check_outcome("A3.read", "proceed-known-fresh", o);
        t.assert_true("A3.authorizes", o.authorizes_proceed());
    }

    // A4 — not-yet-effective decision records/reads deferred and is not approval.
    {
        let (input, exp) = di(Env::Devnet, S::ReloadApply, S::ReloadApply, 100, 200, 50);
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        let o = observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_outcome("A4.observe", "proceed-deferred", o);
        t.assert_true("A4.is-deferred", o.is_deferred());
        t.assert_true("A4.not-approval", !o.authorizes_proceed());
        t.check_state(
            "A4.state",
            "observed-deferred",
            backend.read_durable_state(&key_of(&input)),
        );
        t.check_outcome(
            "A4.read",
            "proceed-deferred",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
    }

    // A5 — expired decision records/reads fail-closed expired.
    {
        let (input, exp) = di(Env::Devnet, S::ReloadApply, S::ReloadApply, 100, 200, 250);
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        let o = observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_outcome("A5.observe", "fail-closed-expired", o);
        t.assert_true("A5.is-fail-closed", o.is_fail_closed());
        t.check_outcome(
            "A5.read",
            "fail-closed-expired",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
    }

    // A6 — stale decision records/reads fail-closed stale.
    {
        let (input, exp) = di(Env::Devnet, S::ReloadApply, S::ReloadApply, 200, 100, 150);
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        let o = observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_outcome("A6.observe", "fail-closed-stale", o);
        t.check_outcome(
            "A6.read",
            "fail-closed-stale",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
    }

    // A7 — explicit consume after a successful mutation marks consumed.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        let o = mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::AppliedSuccessfully,
            &mut backend,
        );
        t.check_consume("A7.consume", "consumed-after-success", o);
        t.assert_true("A7.authorizes", o.authorizes_consume());
        t.assert_true("A7.is-consumed", backend.is_consumed(&key_of(&input)));
    }

    // A8 — same decision after consume reads consumed / fail-closed.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::AppliedSuccessfully,
            &mut backend,
        );
        t.check_outcome(
            "A8.read",
            "fail-closed-consumed",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
        t.check_outcome(
            "A8.observe-again",
            "fail-closed-consumed",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
    }

    // A9 — read-only validation does not mark consumed.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        for i in 0..3 {
            t.check_outcome(
                &format!("A9.read.{i}"),
                "proceed-known-fresh",
                read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
            );
        }
        t.assert_true("A9.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // A10 — observe-only state survives fixture restart snapshot.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        let snapshot = backend.restart_snapshot();
        t.check("A10.snapshot-len", "1", &snapshot.len().to_string());
        let restarted = FixtureDurableReplayBackend::from_snapshot(snapshot);
        t.assert_true("A10.contains", restarted.contains(&key_of(&input)));
        t.check_outcome(
            "A10.read-after-restart",
            "proceed-known-fresh",
            read_decision_state(K::FixtureDevNet, &input, &exp, &restarted),
        );
        t.assert_true(
            "A10.not-consumed",
            !restarted.is_consumed(&key_of(&input)),
        );
    }

    // A11 — consumed state survives fixture restart snapshot.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::AppliedSuccessfully,
            &mut backend,
        );
        let restarted = FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
        t.assert_true("A11.is-consumed", restarted.is_consumed(&key_of(&input)));
        t.check_outcome(
            "A11.read-after-restart",
            "fail-closed-consumed",
            read_decision_state(K::FixtureDevNet, &input, &exp, &restarted),
        );
    }

    // A12 — rollback after observe does not mark consumed.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        let o = mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::RolledBack,
            &mut backend,
        );
        t.check_consume("A12.consume", "rejected-rolled-back", o);
        t.assert_true("A12.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // A13 — apply-failed after observe does not mark consumed.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        let o = mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::ApplyFailed,
            &mut backend,
        );
        t.check_consume("A13.consume", "rejected-apply-failed", o);
        t.assert_true("A13.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // A14 — after-mutation-before-consume crash window is typed and not approved.
    {
        let obs = CrashWindowObservation {
            backend_kind: K::FixtureDevNet,
            observed: true,
            mutation_attempted: true,
            mutation_succeeded: true,
            rolled_back: false,
            apply_failed: false,
            consumed: false,
        };
        let w = classify_crash_window(&obs);
        t.check_window("A14.window", "after-mutation-before-consume", w);
        t.assert_true("A14.is-amc", w.is_after_mutation_before_consume());
        t.assert_true("A14.fail-closed-recovery", w.requires_fail_closed_recovery());
    }

    // A15 — after-consume crash window reads consumed / fail-closed for repeat.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::AppliedSuccessfully,
            &mut backend,
        );
        let obs = CrashWindowObservation {
            backend_kind: K::FixtureDevNet,
            observed: true,
            mutation_attempted: true,
            mutation_succeeded: true,
            rolled_back: false,
            apply_failed: false,
            consumed: true,
        };
        t.check_window("A15.window", "after-consume", classify_crash_window(&obs));
        t.check_outcome(
            "A15.read",
            "fail-closed-consumed",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
    }

    // A16 — durable backend key digest is deterministic in release mode.
    {
        let (input, _) = fresh_devnet();
        t.assert_true(
            "A16.stable",
            durable_backend_key_digest(&input) == durable_backend_key_digest(&input),
        );
        let mut other = input.clone();
        other.replay_nonce = "different-nonce".to_string();
        t.assert_true(
            "A16.nonce-bound",
            durable_backend_key_digest(&input) != durable_backend_key_digest(&other),
        );
    }

    // A17 — durable record digest is deterministic in release mode.
    {
        let (input, _) = fresh_devnet();
        let a = durable_record_digest(&input, DurableRecordState::ObservedFresh, 1);
        let b = durable_record_digest(&input, DurableRecordState::ObservedFresh, 1);
        t.assert_true("A17.stable", a == b);
        t.assert_true(
            "A17.state-bound",
            a != durable_record_digest(&input, DurableRecordState::Consumed, 1),
        );
    }

    // A18 — durable operation transcript digest is deterministic in release mode.
    {
        let (input, _) = fresh_devnet();
        let a = durable_operation_transcript_digest(&input, "observe", "proceed-first-seen");
        let b = durable_operation_transcript_digest(&input, "observe", "proceed-first-seen");
        t.assert_true("A18.stable", a == b);
        t.assert_true(
            "A18.outcome-bound",
            a != durable_operation_transcript_digest(&input, "observe", "fail-closed-replay"),
        );
    }

    // A19 — crash-window transcript digest is deterministic in release mode.
    {
        let (input, _) = fresh_devnet();
        let obs = CrashWindowObservation {
            backend_kind: K::FixtureDevNet,
            observed: true,
            mutation_attempted: true,
            mutation_succeeded: true,
            rolled_back: false,
            apply_failed: false,
            consumed: false,
        };
        let a = crash_window_transcript_digest(&input, &obs, CrashWindow::AfterMutationBeforeConsume);
        let b = crash_window_transcript_digest(&input, &obs, CrashWindow::AfterMutationBeforeConsume);
        t.assert_true("A19.stable", a == b);
        t.assert_true(
            "A19.window-bound",
            a != crash_window_transcript_digest(&input, &obs, CrashWindow::AfterConsume),
        );
    }

    // A20 — production durable backend is callable and fails closed unavailable.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = ProductionDurableReplayBackend;
        t.check_outcome(
            "A20.read",
            "fail-closed-production-unavailable",
            read_decision_state(K::Production, &input, &exp, &backend),
        );
        t.check_outcome(
            "A20.observe",
            "fail-closed-production-unavailable",
            observe_decision_if_absent(K::Production, &input, &exp, &mut backend),
        );
        t.check_consume(
            "A20.consume",
            "fail-closed-production-unavailable",
            mark_consumed_after_success(
                K::Production,
                &input,
                &exp,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
        t.assert_true(
            "A20.guard",
            production_mainnet_durable_backend_remains_unavailable(),
        );
    }

    // A21 — MainNet durable backend is callable and fails closed unavailable/refused.
    {
        let (input, exp) = di(Env::Mainnet, S::ReloadApply, S::ReloadApply, 100, 200, 150);
        let mut backend = MainnetDurableReplayBackend;
        t.check_outcome(
            "A21.read",
            "fail-closed-mainnet-unavailable",
            read_decision_state(K::MainNet, &input, &exp, &backend),
        );
        t.check_outcome(
            "A21.observe",
            "fail-closed-mainnet-unavailable",
            observe_decision_if_absent(K::MainNet, &input, &exp, &mut backend),
        );
        t.check_consume(
            "A21.consume",
            "fail-closed-mainnet-unavailable",
            mark_consumed_after_success(
                K::MainNet,
                &input,
                &exp,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
    }

    // A22 — Run 236 consume runtime integration remains compatible when the
    // durable backend is not wired (the invariants hold and the durable key
    // composes from the same Run 230 replay-state key).
    {
        t.assert_true(
            "A22.after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
        t.assert_true(
            "A22.fresh-required",
            fresh_required_before_mutation_authorization_under_consume_runtime(),
        );
        let f = fresh_in(Env::Devnet, S::ReloadApply, 100, 200, 150);
        let input = DurableBackendDecisionInput::from_freshness_input(&f, S::ReloadApply);
        t.check(
            "A22.key-matches",
            &replay_state_key_digest(&f),
            &input.replay_state_key_digest,
        );
    }

    // A23 — Run 237 release consume-runtime behaviour remains compatible: the
    // after-success-only / fresh-required guards still hold and the durable
    // consume contract is after-success-only.
    {
        t.assert_true(
            "A23.consume-runtime-after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
        t.assert_true(
            "A23.durable-after-success-only",
            durable_consume_only_after_successful_mutation(),
        );
    }

    // A24 — Run 235 release consume-boundary behaviour remains compatible: a
    // fresh DevNet decision still observes fresh and the after-success consume
    // path records consumed only after a successful mutation.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        t.check_outcome(
            "A24.observe-fresh",
            "proceed-first-seen",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
        t.check_consume(
            "A24.consume-after-success",
            "consumed-after-success",
            mark_consumed_after_success(
                K::FixtureDevNet,
                &input,
                &exp,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
    }

    // A25 — Run 233 release replay/freshness runtime behaviour remains
    // compatible: the Run 230 standalone boundary still classifies a fresh
    // first-seen decision ProceedFresh.
    {
        let identity = ev_identity(Env::Devnet);
        let request = ev_request(&identity, 100, 200);
        let response = ev_response(&request, 100, 200);
        let input = EvaluatorReplayFreshnessInput::from_evaluator_material(
            &identity, &request, &response, TRANSCRIPT_DIGEST, DECISION_DIGEST, Env::Devnet,
            CHAIN, GENESIS, S::ReloadApply, 150, PreviouslySeenState::FirstSeen,
        );
        let exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
            &identity, &request, &response, TRANSCRIPT_DIGEST, DECISION_DIGEST, Env::Devnet,
            CHAIN, GENESIS, S::ReloadApply,
        );
        t.check(
            "A25.run230-fresh",
            "proceed-fresh",
            match evaluate_evaluator_replay_freshness(&input, &exp) {
                EvaluatorReplayFreshnessOutcome::ProceedFresh => "proceed-fresh",
                _ => "other",
            },
        );
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R37).
// ===========================================================================

/// Observe a tampered input against the canonical expectations and assert the
/// boundary fails closed malformed without recording anything (non-mutating).
fn assert_wrong_binding_rejected(
    t: &mut Table,
    id: &str,
    tamper: impl FnOnce(&mut DurableBackendDecisionInput),
) {
    let (mut input, exp) = fresh_devnet();
    tamper(&mut input);
    let mut backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
    let o = observe_decision_if_absent(DurableBackendKind::FixtureDevNet, &input, &exp, &mut backend);
    t.check_outcome(&format!("{id}.outcome"), "fail-closed-malformed-record", o);
    t.assert_true(&format!("{id}.backend-empty"), backend.is_empty());
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use DurableRecordState as RS;
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1–R20 — wrong-binding / malformed observe (fail-closed, non-mutating).
    assert_wrong_binding_rejected(&mut t, "R1.wrong-replay-state-key", |i| {
        i.replay_state_key_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R2.wrong-source-identity", |i| {
        i.evaluator_source_identity_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R3.wrong-request", |i| {
        i.evaluator_request_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R4.wrong-response", |i| {
        i.evaluator_response_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R5.wrong-transcript", |i| {
        i.evaluator_transcript_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R6.wrong-decision-digest", |i| {
        i.governance_execution_decision_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R7.wrong-proposal-id", |i| {
        i.proposal_id = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R8.wrong-decision-id", |i| {
        i.decision_id = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R9.wrong-lifecycle-action", |i| {
        i.lifecycle_action = LocalLifecycleAction::Retire
    });
    assert_wrong_binding_rejected(&mut t, "R10.wrong-candidate", |i| {
        i.candidate_digest = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R11.wrong-sequence", |i| {
        i.authority_domain_sequence = 999
    });
    assert_wrong_binding_rejected(&mut t, "R12.wrong-effective-epoch", |i| {
        i.effective_epoch = 999
    });
    assert_wrong_binding_rejected(&mut t, "R13.wrong-expiry-epoch", |i| {
        i.expiry_epoch = 999
    });
    assert_wrong_binding_rejected(&mut t, "R14.wrong-replay-nonce", |i| {
        i.replay_nonce = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R15.wrong-environment", |i| {
        i.environment = Env::Testnet
    });
    assert_wrong_binding_rejected(&mut t, "R16.wrong-chain", |i| {
        i.chain_id = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R17.wrong-genesis", |i| {
        i.genesis_hash = "wrong".to_string()
    });
    assert_wrong_binding_rejected(&mut t, "R18.wrong-validation-surface", |i| {
        i.validation_surface = S::Sighup
    });
    assert_wrong_binding_rejected(&mut t, "R19.wrong-mutation-surface", |i| {
        i.mutation_surface = S::Sighup
    });
    assert_wrong_binding_rejected(&mut t, "R20.malformed-backend-record", |i| {
        i.replay_nonce = String::new()
    });

    // R21 — replay detected rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_outcome(
            "R21.replay",
            "fail-closed-replay",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
    }

    // R22 — consumed decision rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        mark_consumed_after_success(
            K::FixtureDevNet,
            &input,
            &exp,
            MC::AppliedSuccessfully,
            &mut backend,
        );
        t.check_outcome(
            "R22.consumed",
            "fail-closed-consumed",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
    }

    // R23 — superseded decision rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.assert_true("R23.mark-superseded", backend.mark_superseded(&key_of(&input)));
        t.check_outcome(
            "R23.read",
            "fail-closed-superseded",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
        t.check_outcome(
            "R23.observe",
            "fail-closed-superseded",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
    }

    // R24 — backend unavailable rejected (fixture kind, MainNet-bound input).
    {
        let (input, exp) = di(Env::Mainnet, S::ReloadApply, S::ReloadApply, 100, 200, 150);
        // Force a binding-consistent MainNet input on a non-peer-driven surface
        // so the generic backend-unavailable guard (not the MainNet-refusal
        // guard) is exercised.
        let backend = FixtureDurableReplayBackend::new(Env::Devnet);
        t.check_outcome(
            "R24.backend-unavailable",
            "fail-closed-backend-unavailable",
            read_decision_state(K::FixtureDevNet, &input, &exp, &backend),
        );
    }

    // R25 — production backend unavailable rejected.
    {
        let (input, exp) = fresh_devnet();
        let backend = ProductionDurableReplayBackend;
        t.check_outcome(
            "R25.production-unavailable",
            "fail-closed-production-unavailable",
            read_decision_state(K::Production, &input, &exp, &backend),
        );
    }

    // R26 — MainNet backend unavailable/refused rejected.
    {
        let (input, exp) = di(Env::Mainnet, S::ReloadApply, S::ReloadApply, 100, 200, 150);
        let backend = MainnetDurableReplayBackend;
        t.check_outcome(
            "R26.mainnet-unavailable",
            "fail-closed-mainnet-unavailable",
            read_decision_state(K::MainNet, &input, &exp, &backend),
        );
    }

    // R27 — compare-and-mark-consumed with wrong expected state rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        // Current state is ObservedFresh; expect ObservedDeferred -> rejected.
        t.check_consume(
            "R27.wrong-expected",
            "rejected-wrong-expected-state",
            compare_and_mark_consumed(
                K::FixtureDevNet,
                &input,
                &exp,
                RS::ObservedDeferred,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
        t.assert_true("R27.not-consumed", !backend.is_consumed(&key_of(&input)));
        // The correct expected state succeeds atomically.
        t.check_consume(
            "R27.correct-expected",
            "consumed-after-success",
            compare_and_mark_consumed(
                K::FixtureDevNet,
                &input,
                &exp,
                RS::ObservedFresh,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
        t.assert_true("R27.consumed", backend.is_consumed(&key_of(&input)));
    }

    // R28 — consume attempted before observe rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        t.check_consume(
            "R28.not-observed",
            "rejected-not-observed",
            mark_consumed_after_success(
                K::FixtureDevNet,
                &input,
                &exp,
                MC::AppliedSuccessfully,
                &mut backend,
            ),
        );
        t.assert_true("R28.backend-empty", backend.is_empty());
    }

    // R29 — consume attempted before successful mutation rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        for (i, completion) in [MC::NotAttempted, MC::AuthorizedButNotApplied]
            .into_iter()
            .enumerate()
        {
            t.check_consume(
                &format!("R29.{i}"),
                "rejected-not-successful-mutation",
                mark_consumed_after_success(K::FixtureDevNet, &input, &exp, completion, &mut backend),
            );
        }
        t.assert_true("R29.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // R30 — consume attempted after failed apply rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_consume(
            "R30.apply-failed",
            "rejected-apply-failed",
            mark_consumed_after_success(K::FixtureDevNet, &input, &exp, MC::ApplyFailed, &mut backend),
        );
        t.assert_true("R30.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // R31 — consume attempted after rollback rejected.
    {
        let (input, exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
        t.check_consume(
            "R31.rolled-back",
            "rejected-rolled-back",
            mark_consumed_after_success(K::FixtureDevNet, &input, &exp, MC::RolledBack, &mut backend),
        );
        t.assert_true("R31.not-consumed", !backend.is_consumed(&key_of(&input)));
    }

    // R32 — local operator cannot satisfy durable replay backend policy.
    t.assert_true(
        "R32.local-operator-cannot",
        local_operator_cannot_satisfy_durable_backend_policy(),
    );
    // R33 — peer majority cannot satisfy durable replay backend policy.
    t.assert_true(
        "R33.peer-majority-cannot",
        peer_majority_cannot_satisfy_durable_backend_policy(),
    );
    // R34 — validator-set rotation unsupported rejected.
    t.assert_true(
        "R34.validator-rotation-unsupported",
        validator_set_rotation_remains_unsupported_under_durable_backend(),
    );
    // R35 — policy-change action unsupported rejected.
    t.assert_true(
        "R35.policy-change-unsupported",
        policy_change_action_remains_unsupported_under_durable_backend(),
    );

    // R36 — rejection produces no Run 070 call, no live trust swap, no session
    // eviction, no sequence write, and no marker write (non-mutating). The
    // boundary is pure, so a malformed observe records nothing and a rejected
    // consume after a legitimate observe leaves the record unconsumed.
    {
        let (mut input, exp) = fresh_devnet();
        input.replay_nonce = "tampered".to_string();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        t.check_outcome(
            "R36.malformed-observe",
            "fail-closed-malformed-record",
            observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend),
        );
        t.assert_true("R36.backend-empty", backend.is_empty());

        let (good, good_exp) = fresh_devnet();
        let mut backend2 = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &good, &good_exp, &mut backend2);
        let len_before = backend2.len();
        let rejected = mark_consumed_after_success(
            K::FixtureDevNet,
            &good,
            &good_exp,
            MC::ApplyFailed,
            &mut backend2,
        );
        t.assert_true("R36.rejected-no-consume", rejected.no_consume());
        t.assert_true("R36.not-consumed", !backend2.is_consumed(&key_of(&good)));
        t.assert_true("R36.len-unchanged", backend2.len() == len_before);
    }

    // R37 — MainNet peer-driven apply remains refused even when the DevNet
    // fixture would otherwise read fresh.
    {
        // DevNet fixture has the decision observed fresh.
        let (devnet_input, devnet_exp) = fresh_devnet();
        let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
        observe_decision_if_absent(K::FixtureDevNet, &devnet_input, &devnet_exp, &mut backend);
        t.check_outcome(
            "R37.fixture-fresh",
            "proceed-known-fresh",
            read_decision_state(K::FixtureDevNet, &devnet_input, &devnet_exp, &backend),
        );

        // A MainNet peer-driven apply variant is refused regardless.
        let (mn_input, mn_exp) = di(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain, 100, 200, 150);
        let mut mn_backend = FixtureDurableReplayBackend::new(Env::Devnet);
        t.check_outcome(
            "R37.observe-refused",
            "fail-closed-mainnet-unavailable",
            observe_decision_if_absent(K::FixtureDevNet, &mn_input, &mn_exp, &mut mn_backend),
        );
        t.check_consume(
            "R37.consume-refused",
            "fail-closed-mainnet-unavailable",
            mark_consumed_after_success(
                K::FixtureDevNet,
                &mn_input,
                &mn_exp,
                MC::AppliedSuccessfully,
                &mut mn_backend,
            ),
        );
        t.assert_true("R37.mn-backend-empty", mn_backend.is_empty());
        t.assert_true(
            "R37.guard",
            mainnet_peer_driven_apply_remains_refused_under_durable_backend(Env::Mainnet),
        );
    }

    t.finish(out)
}

// ===========================================================================
// Reachability + invariant + taxonomy table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use DurableBackendKind as K;
    let mut t = Table::new("reachability");

    // Durable backend outcome tags reachable / stable.
    for (id, expected, o) in [
        ("T.proceed-first-seen", "proceed-first-seen", DurableBackendOutcome::ProceedFirstSeen),
        ("T.proceed-known-fresh", "proceed-known-fresh", DurableBackendOutcome::ProceedKnownFresh),
        ("T.proceed-deferred", "proceed-deferred", DurableBackendOutcome::ProceedDeferred),
        ("T.fail-closed-expired", "fail-closed-expired", DurableBackendOutcome::FailClosedExpired),
        ("T.fail-closed-stale", "fail-closed-stale", DurableBackendOutcome::FailClosedStale),
        ("T.fail-closed-replay", "fail-closed-replay", DurableBackendOutcome::FailClosedReplay),
        ("T.fail-closed-consumed", "fail-closed-consumed", DurableBackendOutcome::FailClosedConsumed),
        ("T.fail-closed-superseded", "fail-closed-superseded", DurableBackendOutcome::FailClosedSuperseded),
        ("T.fail-closed-malformed", "fail-closed-malformed-record", DurableBackendOutcome::FailClosedMalformedRecord),
        ("T.fail-closed-backend-unavail", "fail-closed-backend-unavailable", DurableBackendOutcome::FailClosedBackendUnavailable),
        ("T.fail-closed-prod-unavail", "fail-closed-production-unavailable", DurableBackendOutcome::FailClosedProductionUnavailable),
        ("T.fail-closed-mainnet-unavail", "fail-closed-mainnet-unavailable", DurableBackendOutcome::FailClosedMainNetUnavailable),
    ] {
        t.check(id, expected, o.tag());
    }

    // Durable consume outcome tags reachable / stable.
    for (id, expected, o) in [
        ("C.consumed-after-success", "consumed-after-success", DurableConsumeOutcome::ConsumedAfterSuccess),
        ("C.rejected-not-observed", "rejected-not-observed", DurableConsumeOutcome::RejectedNotObserved),
        ("C.rejected-not-successful", "rejected-not-successful-mutation", DurableConsumeOutcome::RejectedNotSuccessfulMutation),
        ("C.rejected-apply-failed", "rejected-apply-failed", DurableConsumeOutcome::RejectedApplyFailed),
        ("C.rejected-rolled-back", "rejected-rolled-back", DurableConsumeOutcome::RejectedRolledBack),
        ("C.rejected-wrong-expected", "rejected-wrong-expected-state", DurableConsumeOutcome::RejectedWrongExpectedState),
        ("C.rejected-already-consumed", "rejected-already-consumed", DurableConsumeOutcome::RejectedAlreadyConsumed),
        ("C.rejected-superseded", "rejected-superseded", DurableConsumeOutcome::RejectedSuperseded),
        ("C.rejected-malformed", "rejected-malformed-record", DurableConsumeOutcome::RejectedMalformedRecord),
        ("C.fail-closed-backend-unavail", "fail-closed-backend-unavailable", DurableConsumeOutcome::FailClosedBackendUnavailable),
        ("C.fail-closed-prod-unavail", "fail-closed-production-unavailable", DurableConsumeOutcome::FailClosedProductionUnavailable),
        ("C.fail-closed-mainnet-unavail", "fail-closed-mainnet-unavailable", DurableConsumeOutcome::FailClosedMainNetUnavailable),
    ] {
        t.check(id, expected, o.tag());
    }

    // Durable record state tags reachable / stable.
    for (id, expected, s) in [
        ("S.missing", "missing", DurableRecordState::Missing),
        ("S.observed-fresh", "observed-fresh", DurableRecordState::ObservedFresh),
        ("S.observed-deferred", "observed-deferred", DurableRecordState::ObservedDeferred),
        ("S.observed-expired", "observed-expired", DurableRecordState::ObservedExpired),
        ("S.observed-stale", "observed-stale", DurableRecordState::ObservedStale),
        ("S.consumed", "consumed", DurableRecordState::Consumed),
        ("S.replay-detected", "replay-detected", DurableRecordState::ReplayDetected),
        ("S.superseded", "superseded", DurableRecordState::Superseded),
        ("S.malformed-record", "malformed-record", DurableRecordState::MalformedRecord),
        ("S.backend-unavailable", "backend-unavailable", DurableRecordState::BackendUnavailable),
        ("S.prod-backend-unavailable", "production-backend-unavailable", DurableRecordState::ProductionBackendUnavailable),
        ("S.mainnet-backend-unavailable", "mainnet-backend-unavailable", DurableRecordState::MainNetBackendUnavailable),
    ] {
        t.check(id, expected, s.tag());
    }

    // Crash-window classification — full coverage through the release classifier.
    let base = |kind: K| CrashWindowObservation {
        backend_kind: kind,
        observed: false,
        mutation_attempted: false,
        mutation_succeeded: false,
        rolled_back: false,
        apply_failed: false,
        consumed: false,
    };
    {
        let obs = base(K::FixtureDevNet);
        t.check_window("W.before-observe", "before-observe", classify_crash_window(&obs));
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        t.check_window(
            "W.after-observe-before-mutation",
            "after-observe-before-mutation",
            classify_crash_window(&obs),
        );
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        obs.mutation_attempted = true;
        obs.mutation_succeeded = true;
        t.check_window(
            "W.after-mutation-before-consume",
            "after-mutation-before-consume",
            classify_crash_window(&obs),
        );
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        obs.mutation_attempted = true;
        obs.mutation_succeeded = true;
        obs.consumed = true;
        let w = classify_crash_window(&obs);
        t.check_window("W.after-consume", "after-consume", w);
        t.assert_true("W.after-consume-no-recovery", !w.requires_fail_closed_recovery());
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        obs.mutation_attempted = true;
        obs.rolled_back = true;
        t.check_window("W.rollback-after-observe", "rollback-after-observe", classify_crash_window(&obs));
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        obs.mutation_attempted = true;
        obs.apply_failed = true;
        t.check_window(
            "W.apply-failed-after-observe",
            "apply-failed-after-observe",
            classify_crash_window(&obs),
        );
    }
    {
        let mut obs = base(K::FixtureDevNet);
        obs.observed = true;
        obs.mutation_attempted = true;
        t.check_window("W.unknown", "unknown-crash-window", classify_crash_window(&obs));
    }
    {
        let mut prod = base(K::Production);
        prod.observed = true;
        prod.consumed = true;
        t.check_window(
            "W.production-unavailable",
            "production-crash-window-unavailable",
            classify_crash_window(&prod),
        );
        let mut mn = base(K::MainNet);
        mn.observed = true;
        mn.consumed = true;
        t.check_window(
            "W.mainnet-unavailable",
            "mainnet-crash-window-unavailable",
            classify_crash_window(&mn),
        );
    }

    // Backend-kind tags + fixture-serves predicate.
    {
        t.check("K.fixture-devnet", "fixture-devnet", K::FixtureDevNet.tag());
        t.check("K.fixture-testnet", "fixture-testnet", K::FixtureTestNet.tag());
        t.check("K.production", "production", K::Production.tag());
        t.check("K.mainnet", "mainnet", K::MainNet.tag());
        t.assert_true("K.fixture-is-fixture", K::FixtureDevNet.is_fixture());
        t.assert_true("K.production-not-fixture", !K::Production.is_fixture());
        let backend = FixtureDurableReplayBackend::new(TrustBundleEnvironment::Devnet);
        t.assert_true("K.serves-devnet", backend.serves(TrustBundleEnvironment::Devnet));
        t.assert_true("K.not-serve-mainnet", !backend.serves(TrustBundleEnvironment::Mainnet));
    }

    // Grep-verifiable invariant / fail-closed helper invariants.
    {
        t.assert_true(
            "G.durable-after-success-only",
            durable_consume_only_after_successful_mutation(),
        );
        t.assert_true(
            "G.production-mainnet-unavailable",
            production_mainnet_durable_backend_remains_unavailable(),
        );
        t.assert_true(
            "G.restart-snapshot-only",
            restart_durability_is_fixture_snapshot_only(),
        );
        t.assert_true(
            "G.local-operator-cannot",
            local_operator_cannot_satisfy_durable_backend_policy(),
        );
        t.assert_true(
            "G.peer-majority-cannot",
            peer_majority_cannot_satisfy_durable_backend_policy(),
        );
        t.assert_true(
            "G.validator-rotation-unsupported",
            validator_set_rotation_remains_unsupported_under_durable_backend(),
        );
        t.assert_true(
            "G.policy-change-unsupported",
            policy_change_action_remains_unsupported_under_durable_backend(),
        );
        t.assert_true(
            "G.no-rocksdb-file-schema-migration",
            no_rocksdb_file_schema_migration_change_under_durable_backend(),
        );
        t.assert_true(
            "G.mainnet-refused-mainnet",
            mainnet_peer_driven_apply_remains_refused_under_durable_backend(
                TrustBundleEnvironment::Mainnet,
            ),
        );
        t.assert_true(
            "G.mainnet-refused-not-devnet",
            !mainnet_peer_driven_apply_remains_refused_under_durable_backend(
                TrustBundleEnvironment::Devnet,
            ),
        );
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (digests, before/after backend snapshots, outcome / state /
// crash-window values).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use DurableBackendKind as K;
    use DurableMutationCompletion as MC;
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let (input, exp) = fresh_devnet();
    let key = key_of(&input);

    // Deterministic durable digests (release mode).
    write_file(&dir.join("durable_backend_key_digest.txt"), &format!("{key}\n"));
    write_file(
        &dir.join("durable_record_digest.txt"),
        &format!(
            "{}\n",
            durable_record_digest(&input, DurableRecordState::ObservedFresh, 1)
        ),
    );
    write_file(
        &dir.join("durable_operation_transcript_digest.txt"),
        &format!(
            "{}\n",
            durable_operation_transcript_digest(&input, "observe", "proceed-first-seen")
        ),
    );
    {
        let obs = CrashWindowObservation {
            backend_kind: K::FixtureDevNet,
            observed: true,
            mutation_attempted: true,
            mutation_succeeded: true,
            rolled_back: false,
            apply_failed: false,
            consumed: false,
        };
        write_file(
            &dir.join("crash_window_transcript_digest.txt"),
            &format!(
                "{}\n",
                crash_window_transcript_digest(&input, &obs, CrashWindow::AfterMutationBeforeConsume)
            ),
        );
    }

    // Before / after fixture durable backend snapshots across observe + consume.
    let mut backend = FixtureDurableReplayBackend::new(Env::Devnet);
    let snap_before = format!(
        "len={} contains={} is_consumed={} state={}\n",
        backend.len(),
        backend.contains(&key),
        backend.is_consumed(&key),
        backend.read_durable_state(&key).tag()
    );
    let observe = observe_decision_if_absent(K::FixtureDevNet, &input, &exp, &mut backend);
    let snap_observed = format!(
        "outcome={} len={} contains={} is_consumed={} state={}\n",
        observe.tag(),
        backend.len(),
        backend.contains(&key),
        backend.is_consumed(&key),
        backend.read_durable_state(&key).tag()
    );
    // Restart snapshot durability across the observe-only state.
    let restarted_observed =
        FixtureDurableReplayBackend::from_snapshot(backend.restart_snapshot());
    let snap_restart_observed = format!(
        "restart len={} contains={} is_consumed={} state={}\n",
        restarted_observed.len(),
        restarted_observed.contains(&key),
        restarted_observed.is_consumed(&key),
        restarted_observed.read_durable_state(&key).tag()
    );
    let consume = mark_consumed_after_success(
        K::FixtureDevNet,
        &input,
        &exp,
        MC::AppliedSuccessfully,
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
    // Restart snapshot durability across the consumed state.
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

    // Outcome values across observe/read for a range of freshness windows.
    for (label, eff, exp_epoch, can) in [
        ("fresh", 100u64, 200u64, 150u64),
        ("deferred", 100, 200, 50),
        ("expired", 100, 200, 250),
        ("stale", 200, 100, 150),
    ] {
        let (di_input, di_exp) =
            di(Env::Devnet, S::ReloadApply, S::ReloadApply, eff, exp_epoch, can);
        let mut b = FixtureDurableReplayBackend::new(Env::Devnet);
        let o = observe_decision_if_absent(K::FixtureDevNet, &di_input, &di_exp, &mut b);
        let r = read_decision_state(K::FixtureDevNet, &di_input, &di_exp, &b);
        write_file(
            &dir.join(format!("{label}_outcome.txt")),
            &format!(
                "window={label} observe={} read={} state={:#?}\n",
                o.tag(),
                r.tag(),
                b.read_durable_state(&key_of(&di_input))
            ),
        );
    }

    // Production / MainNet unavailable dump.
    {
        let prod = ProductionDurableReplayBackend;
        let mn = MainnetDurableReplayBackend;
        write_file(
            &dir.join("production_mainnet_unavailable.txt"),
            &format!(
                "production_read={:?} mainnet_read={:?}\n",
                read_decision_state(K::Production, &input, &exp, &prod),
                {
                    let (mn_input, mn_exp) =
                        di(Env::Mainnet, S::ReloadApply, S::ReloadApply, 100, 200, 150);
                    read_decision_state(K::MainNet, &mn_input, &mn_exp, &mn)
                }
            ),
        );
    }

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_durable_backend\n");
    for entry in [
        "type\tDurableBackendDecisionInput",
        "type\tDurableBackendDecisionExpectations",
        "type\tDurableRecordState",
        "type\tDurableBackendOutcome",
        "type\tDurableConsumeOutcome",
        "type\tCrashWindow",
        "type\tCrashWindowObservation",
        "type\tDurableBackendKind",
        "type\tDurableMutationCompletion",
        "type\tDurableBackendSnapshot",
        "type\tFixtureDurableReplayBackend",
        "type\tProductionDurableReplayBackend",
        "type\tMainnetDurableReplayBackend",
        "trait\tGovernanceEvaluatorReplayDurableBackendReader",
        "trait\tGovernanceEvaluatorReplayDurableBackendWriter",
        "trait\tGovernanceEvaluatorReplayDurableBackendAtomic",
        "fn\tread_decision_state",
        "fn\tobserve_decision_if_absent",
        "fn\tmark_consumed_after_success",
        "fn\tcompare_and_mark_consumed",
        "fn\tclassify_crash_window",
        "fn\tdurable_backend_key_digest",
        "fn\tdurable_record_digest",
        "fn\tdurable_operation_transcript_digest",
        "fn\tcrash_window_transcript_digest",
        "fn\trestart_snapshot",
        "fn\tfrom_snapshot",
        "guard\tdurable_consume_only_after_successful_mutation",
        "guard\tproduction_mainnet_durable_backend_remains_unavailable",
        "guard\trestart_durability_is_fixture_snapshot_only",
        "guard\tlocal_operator_cannot_satisfy_durable_backend_policy",
        "guard\tpeer_majority_cannot_satisfy_durable_backend_policy",
        "guard\tvalidator_set_rotation_remains_unsupported_under_durable_backend",
        "guard\tpolicy_change_action_remains_unsupported_under_durable_backend",
        "guard\tno_rocksdb_file_schema_migration_change_under_durable_backend",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_durable_backend",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("durable_backend_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_239_governance_evaluator_replay_durable_backend_release_binary_helper <OUT_DIR>"
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
    let mut summary = String::from("run_239_governance_evaluator_replay_durable_backend_release_binary_helper\nscope: Run 238 governance evaluator durable replay state backend boundary (pqc_governance_evaluator_replay_durable_backend: read_decision_state, observe_decision_if_absent, mark_consumed_after_success, compare_and_mark_consumed, classify_crash_window, durable_backend_key_digest, durable_record_digest, durable_operation_transcript_digest, crash_window_transcript_digest, DurableBackendDecisionInput/Expectations, DurableRecordState, DurableBackendOutcome, DurableConsumeOutcome, CrashWindow, DurableBackendKind, DurableMutationCompletion, reader/writer/atomic traits, FixtureDurableReplayBackend restart_snapshot/from_snapshot, Production/Mainnet durable backends) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure typed contract (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no persistent storage, no RocksDB/file/schema/migration/storage-format change); first-seen DevNet/TestNet records ObservedFresh and reads ProceedKnownFresh; not-yet-effective reads deferred (not a mutation approval); expired/stale read fail-closed; explicit consume after a successful mutation marks consumed, after which the decision reads FailClosedConsumed; read-only validation, rollback, and failed-apply never consume; observe-only and consumed state both survive an in-process fixture restart snapshot (value clone, never a file format); compare-and-mark-consumed consumes only on an exactly-ObservedFresh record and rejects a wrong expected state; the crash-window classifier types every window and never silently approves an after-mutation-before-consume window; the durable digests are deterministic in release mode; production/MainNet durable backends are callable but always fail closed unavailable; MainNet peer-driven apply remains refused even when the fixture reads fresh; validator-set rotation and policy-change actions remain unsupported\n\n");
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
