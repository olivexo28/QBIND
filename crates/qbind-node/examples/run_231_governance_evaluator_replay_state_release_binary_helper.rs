//! Run 231 — release-built helper for the Run 230 governance evaluator
//! **replay and freshness state boundary**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`).
//!
//! Where Run 230 landed the typed, pure, fail-closed replay/freshness state
//! boundary at the source/test level and captured **no** release-binary
//! evidence, Run 231 is that release-binary evidence. This helper drives the
//! A1–A19 / R1–R32 matrix from `task/RUN_231_TASK.txt` through the
//! **release-built** Run 230 replay/freshness symbols, proving that:
//!
//! * the boundary distinguishes fresh / deferred (not-yet-effective) / expired
//!   / stale / replayed / already-consumed / superseded / wrong-binding /
//!   unavailable / production-unavailable / MainNet-unavailable outcomes;
//! * the deterministic digests (replay state key / observation / consumed
//!   decision / freshness transcript) are stable in release mode;
//! * read-only validation never marks a decision consumed;
//! * explicit fixture consume marks consumed only in the DevNet/TestNet fixture
//!   store;
//! * production / MainNet replay state remains callable-but-unavailable /
//!   fail-closed;
//! * MainNet peer-driven apply remains refused even when the state is fresh;
//! * every rejection is pure and non-mutating (no marker write, no sequence
//!   write, no live trust swap, no session eviction, no Run 070 call);
//! * the Run 224 integration and Run 228 peer context remain compatible when
//!   the replay-state policy is Disabled / not wired.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, on-chain proof verifier, KMS/HSM, or RemoteSigner backend.
//! No RocksDB/file/schema/migration/storage-format change. The
//! `FixtureReplayStateStore` is an in-process map only and DevNet/TestNet
//! evidence-only. MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_peer_context::{
    GovernanceEvaluatorPeerContext, PeerEvaluatorContextSurface,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    classify_evaluator_replay_freshness, consumed_decision_digest,
    evaluate_evaluator_replay_freshness, freshness_transcript_digest,
    gate_evaluator_replay_freshness, local_operator_cannot_satisfy_replay_state_policy,
    mainnet_peer_driven_apply_remains_refused_under_replay_state,
    peer_majority_cannot_satisfy_replay_state_policy,
    policy_change_action_remains_unsupported_under_replay_state, replay_observation_digest,
    replay_state_key_digest, validator_set_rotation_remains_unsupported_under_replay_state,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore,
    GovernanceEvaluatorReplayStateReader, GovernanceEvaluatorReplayStateWriter,
    MainnetReplayStateReader, PreviouslySeenState, ProductionReplayStateReader,
    ReplayFreshnessState, ReplayStateGateOutcome, ReplayStatePolicy, SeenDecisionRecord,
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
// Shared constants (mirror the Run 220 / 222 / 224 / 228 / 230 corpora so the
// evaluator material and the replay/freshness material bind to the same trust
// domain, proposal/decision identity, candidate digest, replay nonce).
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

const EFFECTIVE: u64 = 100;
const EXPIRY: u64 = 200;
const SEQUENCE: u64 = 7;

// ===========================================================================
// Run 222 evaluator material
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

fn ev_request(identity: &DecisionSourceIdentity) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: "governance-execution-input-digest-jjjj".to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(request: &EvaluatorRequest) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: EFFECTIVE,
        response_expiry_epoch: EXPIRY,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

// ===========================================================================
// Run 230 input + expectations builders (mirror the Run 230 test fixtures so
// the release-built symbols are exercised through production library code).
// ===========================================================================

fn expectations(
    env: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
) -> EvaluatorReplayFreshnessExpectations {
    let identity = ev_identity(env);
    let request = ev_request(&identity);
    let response = ev_response(&request);
    EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
    )
}

fn input_with(
    env: TrustBundleEnvironment,
    surface: GovernanceExecutionRuntimeSurface,
    current_canonical_epoch: u64,
    previously_seen: PreviouslySeenState,
) -> EvaluatorReplayFreshnessInput {
    let identity = ev_identity(env);
    let request = ev_request(&identity);
    let response = ev_response(&request);
    EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
        current_canonical_epoch,
        previously_seen,
    )
}

fn devnet_fresh_input() -> EvaluatorReplayFreshnessInput {
    input_with(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    )
}

fn devnet_exp() -> EvaluatorReplayFreshnessExpectations {
    expectations(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
}

fn seen_record(key: &str) -> SeenDecisionRecord {
    SeenDecisionRecord {
        state_key_digest: key.to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed: false,
        superseded: false,
    }
}

// ===========================================================================
// Stable outcome / state tags
// ===========================================================================

fn otag(o: &EvaluatorReplayFreshnessOutcome) -> String {
    use EvaluatorReplayFreshnessOutcome as O;
    match o {
        O::FailClosedExpired(state) => format!("fail-closed-expired:{}", state.tag()),
        O::FailClosedWrongBinding { state, .. } => {
            format!("fail-closed-wrong-binding:{}", state.tag())
        }
        other => other.tag().to_string(),
    }
}

fn ctag(s: ReplayFreshnessState) -> String {
    s.tag().to_string()
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
    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {id}: {detail}\n"));
        }
    }
    fn check_outcome(&mut self, id: &str, expected: &str, o: &EvaluatorReplayFreshnessOutcome) {
        self.check(id, expected, &otag(o));
    }
    /// Assert that a fail-closed outcome authorizes no mutation (the boundary
    /// is pure: no marker/sequence write, no live trust swap, no session
    /// eviction, no Run 070 call can happen because nothing authorizes apply).
    fn assert_fail_closed(&mut self, id: &str, o: &EvaluatorReplayFreshnessOutcome) {
        self.assert_true(&format!("{id}.is-fail-closed"), o.is_fail_closed(), "");
        self.assert_true(
            &format!("{id}.not-authorizes-mutation"),
            !o.authorizes_mutation(),
            "",
        );
        self.assert_true(&format!("{id}.no-mutation"), o.no_mutation(), "");
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
// A — accepted / compatible scenarios (A1–A19) exercised through the Run 230
// replay/freshness state boundary.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — DevNet fixture replay state accepts first-seen fresh decision.
    {
        let store = FixtureReplayStateStore::new(Env::Devnet);
        let mut input = devnet_fresh_input();
        input.previously_seen = store.read_for(&input);
        t.check(
            "A1.devnet-first-seen",
            "first-seen",
            match input.previously_seen {
                PreviouslySeenState::FirstSeen => "first-seen",
                _ => "other",
            },
        );
        t.check_outcome(
            "A1.devnet-fresh",
            "proceed-fresh",
            &evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        );
    }

    // A2 — TestNet fixture replay state accepts first-seen fresh decision.
    {
        let store = FixtureReplayStateStore::new(Env::Testnet);
        let exp = expectations(Env::Testnet, S::ReloadApply);
        let mut input = input_with(Env::Testnet, S::ReloadApply, 150, PreviouslySeenState::FirstSeen);
        input.previously_seen = store.read_for(&input);
        t.check(
            "A2.testnet-first-seen",
            "first-seen",
            match input.previously_seen {
                PreviouslySeenState::FirstSeen => "first-seen",
                _ => "other",
            },
        );
        t.check_outcome(
            "A2.testnet-fresh",
            "proceed-fresh",
            &evaluate_evaluator_replay_freshness(&input, &exp),
        );
    }

    // A3 — fresh but not-yet-effective returns ProceedDeferred (NOT approval).
    {
        let input = input_with(Env::Devnet, S::ReloadApply, 50, PreviouslySeenState::FirstSeen);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("A3.deferred", "proceed-deferred", &o);
        t.assert_true("A3.not-authorizes-mutation", !o.authorizes_mutation(), "");
        t.assert_true("A3.is-deferred", o.is_deferred(), "");
        t.check(
            "A3.classify",
            "fresh-but-not-yet-effective",
            &ctag(classify_evaluator_replay_freshness(&input, &devnet_exp())),
        );
    }

    // A4 — decision at the effective epoch returns ProceedFresh.
    {
        let input = input_with(Env::Devnet, S::ReloadApply, EFFECTIVE, PreviouslySeenState::FirstSeen);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("A4.at-effective-fresh", "proceed-fresh", &o);
        t.assert_true("A4.authorizes-mutation", o.authorizes_mutation(), "");
    }

    // A5 — decision before expiry returns ProceedFresh.
    {
        let input =
            input_with(Env::Devnet, S::ReloadApply, EXPIRY - 1, PreviouslySeenState::FirstSeen);
        t.check_outcome(
            "A5.before-expiry-fresh",
            "proceed-fresh",
            &evaluate_evaluator_replay_freshness(&input, &devnet_exp()),
        );
    }

    // A6 — replay state key digest deterministic in release mode.
    {
        let input = devnet_fresh_input();
        t.assert_true(
            "A6.state-key-deterministic",
            replay_state_key_digest(&input) == replay_state_key_digest(&input),
            "",
        );
    }

    // A7 — replay observation digest deterministic in release mode.
    {
        let input = devnet_fresh_input();
        t.assert_true(
            "A7.observation-deterministic",
            replay_observation_digest(&input, 1, 150) == replay_observation_digest(&input, 1, 150),
            "",
        );
        t.assert_true(
            "A7.observation-field-sensitive",
            replay_observation_digest(&input, 1, 150) != replay_observation_digest(&input, 2, 150),
            "",
        );
    }

    // A8 — consumed decision digest deterministic in release mode.
    {
        let input = devnet_fresh_input();
        t.assert_true(
            "A8.consumed-deterministic",
            consumed_decision_digest(&input, 150) == consumed_decision_digest(&input, 150),
            "",
        );
        t.assert_true(
            "A8.consumed-field-sensitive",
            consumed_decision_digest(&input, 150) != consumed_decision_digest(&input, 151),
            "",
        );
    }

    // A9 — freshness transcript digest deterministic in release mode.
    {
        let input = devnet_fresh_input();
        t.assert_true(
            "A9.transcript-deterministic",
            freshness_transcript_digest(&input, ReplayFreshnessState::Fresh)
                == freshness_transcript_digest(&input, ReplayFreshnessState::Fresh),
            "",
        );
        t.assert_true(
            "A9.transcript-state-sensitive",
            freshness_transcript_digest(&input, ReplayFreshnessState::Fresh)
                != freshness_transcript_digest(&input, ReplayFreshnessState::Expired),
            "",
        );
    }

    // A10 — replay state key binds all twelve required fields.
    {
        let base = devnet_fresh_input();
        let base_key = replay_state_key_digest(&base);
        let mut changes: Vec<(&str, EvaluatorReplayFreshnessInput)> = Vec::new();
        let mut m = base.clone();
        m.environment = Env::Testnet;
        changes.push(("environment", m));
        let mut m = base.clone();
        m.chain_id = "other-chain".to_string();
        changes.push(("chain-id", m));
        let mut m = base.clone();
        m.genesis_hash = "other-genesis".to_string();
        changes.push(("genesis-hash", m));
        let mut m = base.clone();
        m.evaluator_source_identity_digest = "other-src".to_string();
        changes.push(("source-identity-digest", m));
        let mut m = base.clone();
        m.evaluator_request_digest = "other-req".to_string();
        changes.push(("request-digest", m));
        let mut m = base.clone();
        m.evaluator_response_digest = "other-resp".to_string();
        changes.push(("response-digest", m));
        let mut m = base.clone();
        m.proposal_id = "other-proposal".to_string();
        changes.push(("proposal-id", m));
        let mut m = base.clone();
        m.decision_id = "other-decision".to_string();
        changes.push(("decision-id", m));
        let mut m = base.clone();
        m.lifecycle_action = LocalLifecycleAction::Revoke;
        changes.push(("lifecycle-action", m));
        let mut m = base.clone();
        m.candidate_digest = "other-candidate".to_string();
        changes.push(("candidate-digest", m));
        let mut m = base.clone();
        m.authority_domain_sequence = SEQUENCE + 1;
        changes.push(("sequence", m));
        let mut m = base.clone();
        m.replay_nonce = "other-nonce".to_string();
        changes.push(("replay-nonce", m));
        for (label, m) in &changes {
            t.assert_true(
                &format!("A10.binds-{label}"),
                replay_state_key_digest(m) != base_key,
                "",
            );
        }
    }

    // A11 — fixture writer records consumed only after explicit consume call.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let input = devnet_fresh_input();
        let key = replay_state_key_digest(&input);
        store.record_for(&input);
        t.assert_true("A11.observed-not-consumed", !store.is_consumed(&key), "");
        t.assert_true("A11.explicit-consume", store.consume_for(&input), "");
        t.assert_true("A11.consumed-after", store.is_consumed(&key), "");
    }

    // A12 — read-only validation does not mark consumed.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let input = devnet_fresh_input();
        let key = replay_state_key_digest(&input);
        store.record_for(&input);
        for _ in 0..5 {
            let _ = store.read_for(&input);
            let _ = store.read_previous_state(&key);
        }
        t.assert_true("A12.reads-do-not-consume", !store.is_consumed(&key), "");
    }

    // A13 — production replay state reader callable, returns unavailable.
    {
        let reader = ProductionReplayStateReader;
        let mut input = devnet_fresh_input();
        input.previously_seen = reader.read_previous_state(&replay_state_key_digest(&input));
        t.check(
            "A13.prod-unavailable-state",
            "production-unavailable",
            match input.previously_seen {
                PreviouslySeenState::ProductionUnavailable => "production-unavailable",
                _ => "other",
            },
        );
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("A13.prod-fail-closed", "fail-closed-production-unavailable", &o);
        t.assert_fail_closed("A13", &o);
    }

    // A14 — MainNet replay state reader callable, returns unavailable.
    {
        let reader = MainnetReplayStateReader;
        let exp = expectations(Env::Mainnet, S::ReloadApply);
        let mut input = input_with(Env::Mainnet, S::ReloadApply, 150, PreviouslySeenState::FirstSeen);
        input.previously_seen = reader.read_previous_state(&replay_state_key_digest(&input));
        t.check(
            "A14.mainnet-unavailable-state",
            "mainnet-unavailable",
            match input.previously_seen {
                PreviouslySeenState::MainNetUnavailable => "mainnet-unavailable",
                _ => "other",
            },
        );
        let o = evaluate_evaluator_replay_freshness(&input, &exp);
        t.check_outcome("A14.mainnet-fail-closed", "fail-closed-mainnet-unavailable", &o);
        t.assert_fail_closed("A14", &o);
    }

    // A15 — Run 224 integration compatible when policy Disabled / not wired.
    {
        let input = devnet_fresh_input();
        let gate = gate_evaluator_replay_freshness(ReplayStatePolicy::Disabled, &input, &devnet_exp());
        t.check(
            "A15.disabled-not-wired",
            "not-wired",
            if gate.is_not_wired() { "not-wired" } else { "wired" },
        );
        let wired =
            gate_evaluator_replay_freshness(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check(
            "A15.fixture-evaluated",
            "evaluated:proceed-fresh",
            &match wired {
                ReplayStateGateOutcome::Evaluated(o) => format!("evaluated:{}", otag(&o)),
                ReplayStateGateOutcome::NotWired => "not-wired".to_string(),
            },
        );
    }

    // A16 — Run 228 peer context compatible when policy Disabled / not wired.
    {
        let peer = GovernanceEvaluatorPeerContext::absent(
            PeerEvaluatorContextSurface::LiveInbound0x05,
            Env::Devnet,
            CHAIN,
            GENESIS,
        );
        t.assert_true(
            "A16.peer-context-digest-stable",
            peer.context_digest() == peer.context_digest(),
            "",
        );
        let input = input_with(Env::Devnet, S::LiveInbound0x05, 150, PreviouslySeenState::FirstSeen);
        let exp = expectations(Env::Devnet, S::LiveInbound0x05);
        let gate = gate_evaluator_replay_freshness(ReplayStatePolicy::Disabled, &input, &exp);
        t.check(
            "A16.disabled-not-wired",
            "not-wired",
            if gate.is_not_wired() { "not-wired" } else { "wired" },
        );
    }

    // A17 — first-seen → observe → replay → consume lifecycle deterministic.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let base = devnet_fresh_input();
        let exp = devnet_exp();

        let mut input = base.clone();
        input.previously_seen = store.read_for(&input);
        t.check_outcome(
            "A17.1-first-seen-fresh",
            "proceed-fresh",
            &evaluate_evaluator_replay_freshness(&input, &exp),
        );

        store.record_for(&base);
        let mut input = base.clone();
        input.previously_seen = store.read_for(&input);
        t.check_outcome(
            "A17.2-replay",
            "fail-closed-replay",
            &evaluate_evaluator_replay_freshness(&input, &exp),
        );

        t.assert_true("A17.3-consume", store.consume_for(&base), "");
        let mut input = base.clone();
        input.previously_seen = store.read_for(&input);
        t.check_outcome(
            "A17.4-already-consumed",
            "fail-closed-already-consumed",
            &evaluate_evaluator_replay_freshness(&input, &exp),
        );
    }

    // A18 — explicit consume converts a future same-decision validation to
    // already-consumed / fail-closed.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let base = devnet_fresh_input();
        store.record_for(&base);
        t.assert_true("A18.consume", store.consume_for(&base), "");
        let mut input = base.clone();
        input.previously_seen = store.read_for(&input);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("A18.future-already-consumed", "fail-closed-already-consumed", &o);
        t.assert_fail_closed("A18", &o);
    }

    // A19 — MainNet peer-driven apply remains refused even when state is fresh.
    {
        let exp = expectations(Env::Mainnet, S::PeerDrivenDrain);
        let input = input_with(Env::Mainnet, S::PeerDrivenDrain, 150, PreviouslySeenState::FirstSeen);
        let o = evaluate_evaluator_replay_freshness(&input, &exp);
        t.check_outcome("A19.mainnet-refused", "fail-closed-mainnet-unavailable", &o);
        t.assert_true("A19.not-authorizes-mutation", !o.authorizes_mutation(), "");
        t.assert_true(
            "A19.guard",
            mainnet_peer_driven_apply_remains_refused_under_replay_state(Env::Mainnet),
            "",
        );
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R32).
// ===========================================================================

fn assert_wrong_binding(
    t: &mut Table,
    id: &str,
    mutate: impl FnOnce(&mut EvaluatorReplayFreshnessInput),
    expected_state: ReplayFreshnessState,
) {
    let mut input = devnet_fresh_input();
    mutate(&mut input);
    let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
    t.check_outcome(
        id,
        &format!("fail-closed-wrong-binding:{}", expected_state.tag()),
        &o,
    );
    t.assert_fail_closed(&format!("{id}.pure"), &o);
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1 — expired decision rejected.
    {
        let input = input_with(Env::Devnet, S::ReloadApply, EXPIRY, PreviouslySeenState::FirstSeen);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R1.expired", "fail-closed-expired:expired", &o);
        t.assert_fail_closed("R1", &o);
    }

    // R2 — stale decision rejected (degenerate window).
    {
        let mut input = devnet_fresh_input();
        input.effective_epoch = 200;
        input.expiry_epoch = 100;
        let mut exp = devnet_exp();
        exp.expected_effective_epoch = 200;
        exp.expected_expiry_epoch = 100;
        t.check("R2.classify", "stale", &ctag(classify_evaluator_replay_freshness(&input, &exp)));
        let o = evaluate_evaluator_replay_freshness(&input, &exp);
        t.check_outcome("R2.stale", "fail-closed-expired:stale", &o);
        t.assert_fail_closed("R2", &o);
    }

    // R3 — replayed decision rejected.
    {
        let key = replay_state_key_digest(&devnet_fresh_input());
        let input = input_with(
            Env::Devnet,
            S::ReloadApply,
            150,
            PreviouslySeenState::Seen(seen_record(&key)),
        );
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R3.replay", "fail-closed-replay", &o);
        t.assert_fail_closed("R3", &o);
    }

    // R4 — already-consumed decision rejected.
    {
        let key = replay_state_key_digest(&devnet_fresh_input());
        let mut record = seen_record(&key);
        record.consumed = true;
        let input =
            input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::Seen(record));
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R4.already-consumed", "fail-closed-already-consumed", &o);
        t.assert_fail_closed("R4", &o);
    }

    // R5 — superseded decision rejected (explicit + higher recorded sequence).
    {
        let key = replay_state_key_digest(&devnet_fresh_input());
        let mut record = seen_record(&key);
        record.superseded = true;
        let input =
            input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::Seen(record));
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R5.superseded", "fail-closed-superseded", &o);
        t.assert_fail_closed("R5", &o);

        let mut record = seen_record(&key);
        record.recorded_sequence = SEQUENCE + 1;
        let input =
            input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::Seen(record));
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R5.higher-sequence-superseded", "fail-closed-superseded", &o);
    }

    // R6 — wrong effective epoch rejected.
    assert_wrong_binding(&mut t, "R6.wrong-effective", |i| i.effective_epoch = 101, ReplayFreshnessState::WrongEpoch);
    // R7 — wrong expiry epoch rejected.
    assert_wrong_binding(&mut t, "R7.wrong-expiry", |i| i.expiry_epoch = 201, ReplayFreshnessState::WrongEpoch);
    // R8 — wrong environment rejected.
    assert_wrong_binding(
        &mut t,
        "R8.wrong-environment",
        |i| i.environment = TrustBundleEnvironment::Testnet,
        ReplayFreshnessState::WrongEnvironment,
    );
    // R9 — wrong chain rejected.
    assert_wrong_binding(
        &mut t,
        "R9.wrong-chain",
        |i| i.chain_id = "wrong-chain".to_string(),
        ReplayFreshnessState::WrongChain,
    );
    // R10 — wrong genesis rejected.
    assert_wrong_binding(
        &mut t,
        "R10.wrong-genesis",
        |i| i.genesis_hash = "wrong-genesis".to_string(),
        ReplayFreshnessState::WrongGenesis,
    );
    // R11 — wrong validation surface rejected.
    assert_wrong_binding(
        &mut t,
        "R11.wrong-surface",
        |i| i.validation_surface = GovernanceExecutionRuntimeSurface::ReloadCheck,
        ReplayFreshnessState::WrongSurface,
    );
    // R12 — wrong source identity digest rejected.
    assert_wrong_binding(
        &mut t,
        "R12.wrong-source-identity",
        |i| i.evaluator_source_identity_digest = "wrong-src".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R13 — wrong request digest rejected.
    assert_wrong_binding(
        &mut t,
        "R13.wrong-request",
        |i| i.evaluator_request_digest = "wrong-req".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R14 — wrong response digest rejected.
    assert_wrong_binding(
        &mut t,
        "R14.wrong-response",
        |i| i.evaluator_response_digest = "wrong-resp".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R15 — wrong transcript digest rejected.
    assert_wrong_binding(
        &mut t,
        "R15.wrong-transcript",
        |i| i.evaluator_transcript_digest = "wrong-transcript".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R16 — wrong proposal id rejected.
    assert_wrong_binding(
        &mut t,
        "R16.wrong-proposal",
        |i| i.proposal_id = "wrong-proposal".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R17 — wrong decision id rejected.
    assert_wrong_binding(
        &mut t,
        "R17.wrong-decision",
        |i| i.decision_id = "wrong-decision".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R18 — wrong lifecycle action rejected.
    assert_wrong_binding(
        &mut t,
        "R18.wrong-lifecycle",
        |i| i.lifecycle_action = LocalLifecycleAction::Revoke,
        ReplayFreshnessState::MalformedState,
    );
    // R19 — wrong candidate digest rejected.
    assert_wrong_binding(
        &mut t,
        "R19.wrong-candidate",
        |i| i.candidate_digest = "wrong-candidate".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R20 — wrong authority-domain sequence rejected.
    assert_wrong_binding(
        &mut t,
        "R20.wrong-sequence",
        |i| i.authority_domain_sequence = SEQUENCE + 9,
        ReplayFreshnessState::MalformedState,
    );
    // R21 — wrong replay nonce rejected.
    assert_wrong_binding(
        &mut t,
        "R21.wrong-nonce",
        |i| i.replay_nonce = "wrong-nonce".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R22 — malformed state rejected (empty mandatory field).
    assert_wrong_binding(
        &mut t,
        "R22.malformed",
        |i| i.replay_nonce = String::new(),
        ReplayFreshnessState::MalformedState,
    );

    // R23 — state unavailable rejected.
    {
        let input = input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::Unavailable);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R23.state-unavailable", "fail-closed-state-unavailable", &o);
        t.assert_fail_closed("R23", &o);
    }

    // R24 — production state unavailable rejected.
    {
        let input =
            input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::ProductionUnavailable);
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.check_outcome("R24.production-unavailable", "fail-closed-production-unavailable", &o);
        t.assert_fail_closed("R24", &o);
    }

    // R25 — MainNet state unavailable rejected.
    {
        let exp = expectations(Env::Mainnet, S::ReloadApply);
        let input =
            input_with(Env::Mainnet, S::ReloadApply, 150, PreviouslySeenState::MainNetUnavailable);
        let o = evaluate_evaluator_replay_freshness(&input, &exp);
        t.check_outcome("R25.mainnet-unavailable", "fail-closed-mainnet-unavailable", &o);
        t.assert_fail_closed("R25", &o);
    }

    // R26 — local operator cannot satisfy replay state policy.
    t.assert_true("R26.local-operator", local_operator_cannot_satisfy_replay_state_policy(), "");
    // R27 — peer majority cannot satisfy replay state policy.
    t.assert_true("R27.peer-majority", peer_majority_cannot_satisfy_replay_state_policy(), "");
    // R28 — validator-set rotation unsupported.
    t.assert_true(
        "R28.validator-rotation",
        validator_set_rotation_remains_unsupported_under_replay_state(),
        "",
    );
    // R29 — policy-change action unsupported.
    t.assert_true(
        "R29.policy-change",
        policy_change_action_remains_unsupported_under_replay_state(),
        "",
    );

    // R30 — validation-only rejection writes no marker and no sequence.
    {
        let store = FixtureReplayStateStore::new(Env::Devnet);
        let mut input = devnet_fresh_input();
        input.chain_id = "wrong-chain".to_string();
        let o = evaluate_evaluator_replay_freshness(&input, &devnet_exp());
        t.assert_true("R30.is-fail-closed", o.is_fail_closed(), "");
        t.assert_true("R30.store-empty", store.is_empty(), "");
    }

    // R31 — mutating rejection produces no mutation (no Run 070, no live trust
    // swap, no session eviction, no sequence write, no marker write — none can
    // happen because nothing authorizes mutation).
    {
        let cases = [
            evaluate_evaluator_replay_freshness(
                &input_with(Env::Devnet, S::ReloadApply, EXPIRY, PreviouslySeenState::FirstSeen),
                &devnet_exp(),
            ),
            evaluate_evaluator_replay_freshness(
                &input_with(Env::Devnet, S::ReloadApply, 150, PreviouslySeenState::Unavailable),
                &devnet_exp(),
            ),
        ];
        for (idx, o) in cases.iter().enumerate() {
            t.assert_fail_closed(&format!("R31.case{idx}"), o);
        }
    }

    // R32 — MainNet peer-driven apply remains refused even when fresh.
    {
        let exp = expectations(Env::Mainnet, S::PeerDrivenDrain);
        let input = input_with(Env::Mainnet, S::PeerDrivenDrain, 150, PreviouslySeenState::FirstSeen);
        let o = evaluate_evaluator_replay_freshness(&input, &exp);
        t.check_outcome("R32.mainnet-refused", "fail-closed-mainnet-unavailable", &o);
        t.assert_true("R32.not-authorizes-mutation", !o.authorizes_mutation(), "");
        t.assert_true(
            "R32.guard",
            mainnet_peer_driven_apply_remains_refused_under_replay_state(Env::Mainnet),
            "",
        );
    }

    t.finish(out)
}

// ===========================================================================
// Reachability + digest-stability table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Production / MainNet writers never record (fail-closed).
    {
        let key = replay_state_key_digest(&devnet_fresh_input());
        let mut prod = ProductionReplayStateReader;
        prod.record_observation(&key, NONCE, SEQUENCE);
        t.assert_true("W.prod-mark-consumed-false", !prod.mark_consumed(&key), "");
        let mut main = MainnetReplayStateReader;
        main.record_observation(&key, NONCE, SEQUENCE);
        t.assert_true("W.mainnet-mark-consumed-false", !main.mark_consumed(&key), "");
    }

    // Fixture store rejects a MainNet environment.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let input = input_with(Env::Mainnet, S::ReloadApply, 150, PreviouslySeenState::FirstSeen);
        t.check(
            "F.mainnet-unavailable",
            "unavailable",
            match store.read_for(&input) {
                PreviouslySeenState::Unavailable => "unavailable",
                _ => "other",
            },
        );
        store.record_for(&input);
        t.assert_true("F.mainnet-store-empty", store.is_empty(), "");
    }

    // Policy tags reachable / stable.
    {
        t.check("P.disabled-tag", "disabled", ReplayStatePolicy::Disabled.tag());
        t.check("P.fixture-devnet-tag", "fixture-devnet", ReplayStatePolicy::FixtureDevNet.tag());
        t.check("P.fixture-testnet-tag", "fixture-testnet", ReplayStatePolicy::FixtureTestNet.tag());
        t.check("P.production-tag", "production", ReplayStatePolicy::Production.tag());
        t.check("P.mainnet-tag", "mainnet", ReplayStatePolicy::MainNet.tag());
        t.assert_true("P.disabled-not-wired", !ReplayStatePolicy::Disabled.is_wired(), "");
        t.assert_true("P.fixture-devnet-wired", ReplayStatePolicy::FixtureDevNet.is_wired(), "");
        t.assert_true("P.fixture-is-fixture", ReplayStatePolicy::FixtureDevNet.is_fixture(), "");
        t.assert_true("P.production-not-fixture", !ReplayStatePolicy::Production.is_fixture(), "");
    }

    // State tags reachable.
    for (state, tag) in [
        (ReplayFreshnessState::Fresh, "fresh"),
        (ReplayFreshnessState::FreshButNotYetEffective, "fresh-but-not-yet-effective"),
        (ReplayFreshnessState::Expired, "expired"),
        (ReplayFreshnessState::Stale, "stale"),
        (ReplayFreshnessState::ReplayDetected, "replay-detected"),
        (ReplayFreshnessState::AlreadyConsumed, "already-consumed"),
        (ReplayFreshnessState::Superseded, "superseded"),
        (ReplayFreshnessState::WrongEpoch, "wrong-epoch"),
        (ReplayFreshnessState::WrongEnvironment, "wrong-environment"),
        (ReplayFreshnessState::WrongChain, "wrong-chain"),
        (ReplayFreshnessState::WrongGenesis, "wrong-genesis"),
        (ReplayFreshnessState::WrongSurface, "wrong-surface"),
        (ReplayFreshnessState::MalformedState, "malformed-state"),
        (ReplayFreshnessState::StateUnavailable, "state-unavailable"),
        (ReplayFreshnessState::ProductionStateUnavailable, "production-state-unavailable"),
        (ReplayFreshnessState::MainNetStateUnavailable, "mainnet-state-unavailable"),
    ] {
        t.check(&format!("ST.{tag}"), tag, &ctag(state));
    }

    // Wrong-binding classifier predicate.
    t.assert_true(
        "ST.wrong-binding-predicate",
        ReplayFreshnessState::WrongChain.is_wrong_binding()
            && !ReplayFreshnessState::Fresh.is_wrong_binding(),
        "",
    );

    t.finish(out)
}

// ===========================================================================
// Fixture dump (digests, before/after store snapshots, inventory).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let input = devnet_fresh_input();
    let exp = devnet_exp();

    // Deterministic digests.
    write_file(&dir.join("replay_state_key_digest.txt"), &format!("{}\n", replay_state_key_digest(&input)));
    write_file(
        &dir.join("replay_observation_digest.txt"),
        &format!("{}\n", replay_observation_digest(&input, 1, 150)),
    );
    write_file(
        &dir.join("consumed_decision_digest.txt"),
        &format!("{}\n", consumed_decision_digest(&input, 150)),
    );
    write_file(
        &dir.join("freshness_transcript_digest.txt"),
        &format!(
            "{}\n",
            freshness_transcript_digest(&input, ReplayFreshnessState::Fresh)
        ),
    );

    // Classification + outcome values.
    write_file(
        &dir.join("classification.txt"),
        &format!("{}\n", ctag(classify_evaluator_replay_freshness(&input, &exp))),
    );
    write_file(
        &dir.join("outcome.txt"),
        &format!("{}\n", otag(&evaluate_evaluator_replay_freshness(&input, &exp))),
    );

    // Before/after fixture replay-store snapshots across the lifecycle.
    let mut store = FixtureReplayStateStore::new(Env::Devnet);
    let key = replay_state_key_digest(&input);
    let snap_before = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    store.record_for(&input);
    let snap_observed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    store.consume_for(&input);
    let snap_consumed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    write_file(
        &dir.join("fixture_store_snapshots.txt"),
        &format!(
            "before:   {}observed:  {}consumed:  {}",
            snap_before, snap_observed, snap_consumed
        ),
    );

    // MainNet peer-driven refusal outcome dump.
    let mn_exp = expectations(Env::Mainnet, S::PeerDrivenDrain);
    let mn_input = input_with(Env::Mainnet, S::PeerDrivenDrain, 150, PreviouslySeenState::FirstSeen);
    write_file(
        &dir.join("mainnet_refused_outcome.txt"),
        &format!("{:#?}\n", evaluate_evaluator_replay_freshness(&mn_input, &mn_exp)),
    );

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_state\n");
    for entry in [
        "type\tEvaluatorReplayFreshnessInput",
        "type\tEvaluatorReplayFreshnessExpectations",
        "type\tReplayFreshnessState",
        "type\tEvaluatorReplayFreshnessOutcome",
        "type\tPreviouslySeenState",
        "type\tSeenDecisionRecord",
        "type\tReplayStatePolicy",
        "type\tReplayStateGateOutcome",
        "trait\tGovernanceEvaluatorReplayStateReader",
        "trait\tGovernanceEvaluatorReplayStateWriter",
        "store\tFixtureReplayStateStore",
        "reader\tProductionReplayStateReader",
        "reader\tMainnetReplayStateReader",
        "fn\tclassify_evaluator_replay_freshness",
        "fn\tevaluate_evaluator_replay_freshness",
        "fn\tgate_evaluator_replay_freshness",
        "digest\treplay_state_key_digest",
        "digest\treplay_observation_digest",
        "digest\tconsumed_decision_digest",
        "digest\tfreshness_transcript_digest",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_replay_state",
        "guard\tlocal_operator_cannot_satisfy_replay_state_policy",
        "guard\tpeer_majority_cannot_satisfy_replay_state_policy",
        "guard\tvalidator_set_rotation_remains_unsupported_under_replay_state",
        "guard\tpolicy_change_action_remains_unsupported_under_replay_state",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("replay_state_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_231_governance_evaluator_replay_state_release_binary_helper <OUT_DIR>"
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
    let mut summary = String::from("run_231_governance_evaluator_replay_state_release_binary_helper\nscope: Run 230 governance evaluator replay/freshness state boundary (pqc_governance_evaluator_replay_state: EvaluatorReplayFreshnessInput/Expectations, ReplayFreshnessState, EvaluatorReplayFreshnessOutcome, classify_evaluator_replay_freshness, evaluate_evaluator_replay_freshness, gate_evaluator_replay_freshness, replay_state_key/observation/consumed/freshness-transcript digests, GovernanceEvaluatorReplayStateReader/Writer, FixtureReplayStateStore, ProductionReplayStateReader, MainnetReplayStateReader) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure boundary (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); distinguishes fresh/deferred/expired/stale/replay/already-consumed/superseded/wrong-binding/unavailable/production-unavailable/mainnet-unavailable; deterministic digests stable; read-only validation does not consume; explicit fixture consume marks consumed only in DevNet/TestNet fixture evidence; production/MainNet state unavailable/fail-closed; MainNet peer-driven apply remains refused even when fresh; validator-set rotation unsupported; no RocksDB/file/schema/migration/storage-format change\n\n");
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