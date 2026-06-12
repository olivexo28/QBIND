//! Run 233 — release-built helper for the Run 232 governance evaluator
//! **replay/freshness runtime integration**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`).
//!
//! Where Run 232 landed the pure integration layer that composes the Run 224
//! evaluator-runtime integration with the Run 230 replay/freshness state
//! boundary as a mandatory pre-mutation gate at the source/test level and
//! captured **no** release-binary evidence, Run 233 is that release-binary
//! evidence. This helper drives the A1–A17 / R1–R27 matrix from
//! `task/RUN_233_TASK.txt` through the **release-built** Run 232 symbols
//! (`integrate_governance_evaluator_replay_runtime`,
//! `wire_governance_evaluator_replay_runtime_callsite`,
//! `wire_governance_evaluator_replay_runtime_peer_context`, the typed
//! `GovernanceEvaluatorReplayRuntimeOutcome`, and the grep-verifiable refusal
//! helpers), proving that:
//!
//! * replay/freshness validation is composed into the evaluator runtime
//!   integration path;
//! * `ProceedFresh` is the only replay/freshness outcome that authorizes a
//!   mutation, and only after the Run 224 layer authorized a mutate **and** the
//!   Run 230 state classified the decision fresh;
//! * `ProceedDeferred` (fresh-but-not-yet-effective) is **not** approval;
//! * expired / stale / replayed / consumed / superseded / wrong-bound /
//!   malformed / unavailable replay states fail closed **before** mutation;
//! * read-only validation never marks a decision consumed;
//! * explicit consume marks consumed only after a successful fixture
//!   authorization (caller-side, fixture-only);
//! * production / MainNet replay readers are reached and fail closed
//!   unavailable;
//! * MainNet peer-driven apply remains refused even when the replay state is
//!   fresh;
//! * the Run 230 / 228 / 226 / 224 layers remain compatible;
//! * every rejection is pure and non-mutating (no marker write, no sequence
//!   write, no live trust swap, no session eviction, no Run 070 call).
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

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_peer_context::{
    GovernanceEvaluatorPeerContext, PeerEvaluatorContextSurface, PeerEvaluatorSourceClass,
};
use qbind_node::pqc_governance_evaluator_replay_runtime_integration::{
    deferred_is_never_mutation_approval, fresh_replay_state_required_before_mutation,
    integrate_governance_evaluator_replay_runtime,
    mainnet_peer_driven_apply_remains_refused_under_replay_runtime,
    policy_change_action_remains_unsupported_under_replay_runtime,
    production_mainnet_replay_state_remains_unavailable,
    validator_set_rotation_remains_unsupported_under_replay_runtime,
    wire_governance_evaluator_replay_runtime_callsite,
    wire_governance_evaluator_replay_runtime_peer_context,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, replay_state_key_digest,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore, GovernanceEvaluatorReplayStateReader,
    MainnetReplayStateReader, PreviouslySeenState, ProductionReplayStateReader,
    ReplayFreshnessState, ReplayStatePolicy, SeenDecisionRecord,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorExpectations, EvaluatorOutcome, EvaluatorPolicy,
    EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    FixtureGovernanceExecutionEvaluatorInterface, MainnetDecisionSourceEvaluatorInterface,
    ProductionDecisionSourceEvaluatorInterface, ProductionGovernanceExecutionEvaluator,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::{
    integrate_governance_evaluator_runtime_consumption,
    GovernanceEvaluatorRuntimeIntegrationContext,
};
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionOutcome,
    GovernanceExecutionPolicy, GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 230 / 232 corpora so the
// composed material binds to the same trust domain, proposal/decision
// identity, candidate digest, replay nonce).
// ===========================================================================

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CUR_KEY: &str = "curcurcurcurcurcurcurcurcurcurcurcurcurc";
const CAND_KEY: &str = "candcandcandcandcandcandcandcandcandcand";
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

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

// ===========================================================================
// Run 211 governance-execution carrier material (drives Run 220 consumption)
// ===========================================================================

fn rotate_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    GovernanceExecutionInput {
        execution_version: GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
        environment: env,
        chain_id: CHAIN.to_string(),
        genesis_hash: GENESIS.to_string(),
        governance_class: GovernanceExecutionClass::FixtureGovernance,
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        current_signing_key_fingerprint: CUR_KEY.to_string(),
        candidate_signing_key_fingerprint: CAND_KEY.to_string(),
        revoked_signing_key_fingerprint: None,
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: SEQUENCE,
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
    }
}

fn rotate_decision() -> GovernanceExecutionDecision {
    GovernanceExecutionDecision {
        execution_version: GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_authority_root_fingerprint: ROOT_FP.to_string(),
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_sequence: SEQUENCE,
        effective_epoch: EFFECTIVE,
        expiry_epoch: EXPIRY,
        decision_commitment: "decision-commitment-eeeeeeeeeeeeeeeeeeee".to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        emergency_flag: false,
        replay_nonce: NONCE.to_string(),
    }
}

fn rotate_gov_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    GovernanceExecutionExpectations {
        expected_environment: env,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_governance_action: GovernanceAction::Rotate,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_effective_epoch: EFFECTIVE,
        expected_replay_nonce: NONCE.to_string(),
        now_epoch: 150,
    }
}

fn available_from(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts to parts"))
}

// ===========================================================================
// Run 222 evaluator material (the next evaluation stage)
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

fn ev_request(identity: &DecisionSourceIdentity, input_digest: &str) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: input_digest.to_string(),
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

fn ev_expectations(env: TrustBundleEnvironment, input_digest: &str) -> EvaluatorExpectations {
    EvaluatorExpectations {
        expected_evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        expected_environment: env,
        expected_chain_id: CHAIN.to_string(),
        expected_genesis_hash: GENESIS.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_proposal_id: PROPOSAL.to_string(),
        expected_decision_id: DECISION.to_string(),
        expected_governance_action: GovernanceAction::Rotate,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: CAND_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQUENCE,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_effective_epoch: EFFECTIVE,
        expected_expiry_epoch: EXPIRY,
        expected_replay_nonce: NONCE.to_string(),
        expected_governance_execution_input_digest: input_digest.to_string(),
        now_epoch: 150,
    }
}

// ===========================================================================
// Owned-material fixture bundle (mirrors the Run 232 test Fixture so a scenario
// can mutate any field then borrow it into the composed integration context).
// ===========================================================================

struct Fixture {
    arming: GovernanceExecutionRuntimeArmingConfig,
    surface: GovernanceExecutionRuntimeSurface,
    td: AuthorityTrustDomain,
    load: GovernanceExecutionLoadStatus,
    gov_exp: GovernanceExecutionExpectations,
    identity: DecisionSourceIdentity,
    request: EvaluatorRequest,
    response: EvaluatorResponse,
    ev_exp: EvaluatorExpectations,
    ev_policy: EvaluatorPolicy,
    peer_driven: bool,
    replay_policy: ReplayStatePolicy,
    replay_input: EvaluatorReplayFreshnessInput,
    replay_exp: EvaluatorReplayFreshnessExpectations,
}

impl Fixture {
    fn context<'a, E: ProductionGovernanceExecutionEvaluator>(
        &'a self,
        evaluator: &'a E,
    ) -> GovernanceEvaluatorReplayRuntimeIntegrationContext<'a, E> {
        GovernanceEvaluatorReplayRuntimeIntegrationContext {
            integration: GovernanceEvaluatorRuntimeIntegrationContext {
                arming: &self.arming,
                surface: self.surface,
                trust_domain: &self.td,
                load_status: &self.load,
                governance_execution_expectations: &self.gov_exp,
                evaluator,
                identity: &self.identity,
                request: &self.request,
                response: &self.response,
                evaluator_expectations: &self.ev_exp,
                evaluator_policy: self.ev_policy,
                is_peer_driven_apply_preflight: self.peer_driven,
            },
            replay_policy: self.replay_policy,
            replay_input: &self.replay_input,
            replay_expectations: &self.replay_exp,
        }
    }

    fn run_with<E: ProductionGovernanceExecutionEvaluator>(
        &self,
        evaluator: &E,
    ) -> GovernanceEvaluatorReplayRuntimeOutcome {
        integrate_governance_evaluator_replay_runtime(&self.context(evaluator))
    }

    fn run(&self) -> GovernanceEvaluatorReplayRuntimeOutcome {
        self.run_with(&FixtureGovernanceExecutionEvaluatorInterface)
    }
}

/// A fully-consistent fixture-rotate composed integration on `env` that, with
/// the default fixture evaluator, a wired fixture replay policy, a first-seen
/// fresh replay state, and a mutating (non-peer-driven) surface, reaches
/// [`GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh`].
fn rotate_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request(&identity, &input_digest);
    let response = ev_response(&request);
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;

    let replay_exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
    );
    let replay_input = EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        CHAIN,
        GENESIS,
        surface,
        150, // canonical epoch in the middle of [EFFECTIVE, EXPIRY)
        PreviouslySeenState::FirstSeen,
    );

    let replay_policy = match env {
        TrustBundleEnvironment::Testnet => ReplayStatePolicy::FixtureTestNet,
        _ => ReplayStatePolicy::FixtureDevNet,
    };

    Fixture {
        arming: GovernanceExecutionRuntimeArmingConfig::with_policy(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        ),
        surface,
        td: trust_domain(env),
        load: available_from(&input, &decision),
        gov_exp: rotate_gov_expectations(env),
        ev_exp: ev_expectations(env, &input_digest),
        identity,
        request,
        response,
        ev_policy: EvaluatorPolicy::FixtureDecisionSourceAllowed,
        peer_driven: false,
        replay_policy,
        replay_input,
        replay_exp,
    }
}

// ===========================================================================
// Stable outcome tag for the composed Run 232 outcome.
// ===========================================================================

fn otag(o: &GovernanceEvaluatorReplayRuntimeOutcome) -> String {
    use GovernanceEvaluatorReplayRuntimeOutcome as O;
    match o {
        O::ReplayFreshnessFailClosed(inner) => {
            format!("{}:{}", o.tag(), replay_inner_tag(inner))
        }
        other => other.tag().to_string(),
    }
}

fn replay_inner_tag(o: &EvaluatorReplayFreshnessOutcome) -> String {
    use EvaluatorReplayFreshnessOutcome as O;
    match o {
        O::FailClosedExpired(state) => format!("fail-closed-expired:{}", state.tag()),
        O::FailClosedWrongBinding { state, .. } => {
            format!("fail-closed-wrong-binding:{}", state.tag())
        }
        other => other.tag().to_string(),
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
    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {id}: {detail}\n"));
        }
    }
    fn check_outcome(&mut self, id: &str, expected: &str, o: &GovernanceEvaluatorReplayRuntimeOutcome) {
        self.check(id, expected, &otag(o));
    }
    /// Assert a composed outcome is a non-mutating fail-closed: the integration
    /// is pure, so no marker/sequence write, no live trust swap, no session
    /// eviction, and no Run 070 call can happen because nothing authorizes
    /// apply.
    fn assert_fail_closed(&mut self, id: &str, o: &GovernanceEvaluatorReplayRuntimeOutcome) {
        self.assert_true(&format!("{id}.is-fail-closed"), o.is_fail_closed(), "");
        self.assert_true(
            &format!("{id}.not-mutate-authorized"),
            !o.is_mutate_authorized(),
            "",
        );
        self.assert_true(&format!("{id}.not-proceed"), !o.is_proceed(), "");
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
// A — accepted / compatible scenarios (A1–A17) exercised through the Run 232
// composed replay/freshness runtime integration.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — Disabled policy + absent carrier preserves ProceedLegacyBypass; the
    // replay/freshness boundary is never reached.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        fx.load = GovernanceExecutionLoadStatus::Absent;
        let o = fx.run();
        t.check_outcome("A1.legacy-bypass", "proceed-legacy-bypass", &o);
        t.assert_true("A1.is-proceed", o.is_proceed(), "");
        t.assert_true("A1.is-legacy-bypass", o.is_legacy_bypass(), "");
        t.assert_true("A1.not-mutate-authorized", !o.is_mutate_authorized(), "");
    }

    // A2 — DevNet fixture evaluator decision with fresh replay state reaches
    // ProceedFresh.
    {
        let fx = rotate_fixture(Env::Devnet);
        let o = fx.run();
        t.check_outcome("A2.devnet-fresh", "proceed-fresh", &o);
        t.assert_true("A2.mutate-authorized", o.is_mutate_authorized(), "");
        if let GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh {
            runtime_consumption,
            evaluator,
            lifecycle_action,
            candidate_digest,
            authority_domain_sequence,
        } = &o
        {
            t.assert_true(
                "A2.runtime-consumption-accepted",
                matches!(
                    runtime_consumption,
                    GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. }
                ),
                "",
            );
            t.assert_true(
                "A2.evaluator-authorized",
                matches!(evaluator, EvaluatorOutcome::EvaluatorResponseAuthorized { .. }),
                "",
            );
            t.check("A2.lifecycle", "Rotate", &format!("{:?}", lifecycle_action));
            t.check("A2.candidate", CAND_DIGEST, candidate_digest);
            t.check("A2.sequence", &SEQUENCE.to_string(), &authority_domain_sequence.to_string());
        } else {
            t.assert_true("A2.is-proceed-fresh", false, "expected ProceedFresh");
        }
    }

    // A3 — TestNet fixture evaluator decision with fresh replay state reaches
    // ProceedFresh.
    {
        let fx = rotate_fixture(Env::Testnet);
        let o = fx.run();
        t.check_outcome("A3.testnet-fresh", "proceed-fresh", &o);
        t.assert_true("A3.mutate-authorized", o.is_mutate_authorized(), "");
    }

    // A4 — not-yet-effective decision reaches ProceedDeferred, not mutation
    // authorization (the Run 224 layer still authorizes a mutate on its own).
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_input.current_canonical_epoch = 50;
        // Sanity: the Run 224 layer authorizes a mutate.
        let integration = integrate_governance_evaluator_runtime_consumption(
            &fx.context(&FixtureGovernanceExecutionEvaluatorInterface)
                .integration,
        );
        t.assert_true("A4.run224-mutate-authorized", integration.is_mutate_authorized(), "");
        let o = fx.run();
        t.check_outcome("A4.deferred", "proceed-deferred", &o);
        t.assert_true("A4.is-deferred", o.is_deferred(), "");
        t.assert_true("A4.not-mutate-authorized", !o.is_mutate_authorized(), "");
        t.assert_true("A4.is-fail-closed", o.is_fail_closed(), "");
    }

    // A5 — fresh decision at the effective epoch authorizes only after the
    // evaluator and the replay state both agree.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_input.current_canonical_epoch = EFFECTIVE;
        let o = fx.run();
        t.check_outcome("A5.at-effective", "proceed-fresh", &o);
        t.assert_true("A5.mutate-authorized", o.is_mutate_authorized(), "");
    }

    // A6 — explicit consume marks consumed only after successful fixture
    // authorization (caller-side, fixture-only).
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let fx = rotate_fixture(Env::Devnet);
        t.assert_true("A6.store-empty-before", store.is_empty(), "");
        let o = fx.run();
        t.assert_true("A6.authorized", o.is_mutate_authorized(), "");
        // ONLY after a successful authorization does the caller explicitly
        // consume.
        store.record_for(&fx.replay_input);
        t.assert_true("A6.explicit-consume", store.consume_for(&fx.replay_input), "");
        t.assert_true(
            "A6.consumed-after",
            store.is_consumed(&replay_state_key_digest(&fx.replay_input)),
            "",
        );
        // A re-evaluation now classifies the decision already-consumed.
        let mut replayed = fx.replay_input.clone();
        replayed.previously_seen = store.read_for(&replayed);
        let mut fx2 = rotate_fixture(Env::Devnet);
        fx2.replay_input = replayed;
        t.check_outcome(
            "A6.future-already-consumed",
            "replay-freshness-fail-closed:fail-closed-already-consumed",
            &fx2.run(),
        );
    }

    // A7 — read-only validation does not mark consumed.
    {
        let store = FixtureReplayStateStore::new(Env::Devnet);
        let fx = rotate_fixture(Env::Devnet);
        // Run the composed integration repeatedly (a pure, read-only
        // validation).
        for _ in 0..5 {
            t.assert_true("A7.iter-authorized", fx.run().is_mutate_authorized(), "");
        }
        t.assert_true("A7.store-empty", store.is_empty(), "");
        t.assert_true(
            "A7.not-consumed",
            !store.is_consumed(&replay_state_key_digest(&fx.replay_input)),
            "",
        );
    }

    // A8 — production replay reader is reached and fails closed unavailable.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_policy = ReplayStatePolicy::Production;
        let key = replay_state_key_digest(&fx.replay_input);
        fx.replay_input.previously_seen = ProductionReplayStateReader.read_previous_state(&key);
        t.check(
            "A8.prod-unavailable-state",
            "production-unavailable",
            match fx.replay_input.previously_seen {
                PreviouslySeenState::ProductionUnavailable => "production-unavailable",
                _ => "other",
            },
        );
        let o = fx.run();
        t.check_outcome(
            "A8.prod-fail-closed",
            "replay-freshness-fail-closed:fail-closed-production-unavailable",
            &o,
        );
        t.assert_fail_closed("A8", &o);
    }

    // A9 — MainNet replay reader is reached and fails closed unavailable/refused.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_policy = ReplayStatePolicy::MainNet;
        let key = replay_state_key_digest(&fx.replay_input);
        fx.replay_input.previously_seen = MainnetReplayStateReader.read_previous_state(&key);
        t.check(
            "A9.mainnet-unavailable-state",
            "mainnet-unavailable",
            match fx.replay_input.previously_seen {
                PreviouslySeenState::MainNetUnavailable => "mainnet-unavailable",
                _ => "other",
            },
        );
        let o = fx.run();
        t.check_outcome(
            "A9.mainnet-fail-closed",
            "replay-freshness-fail-closed:fail-closed-mainnet-unavailable",
            &o,
        );
        t.assert_fail_closed("A9", &o);
    }

    // A10 — MainNet peer-driven apply remains refused even when the replay
    // state is fresh.
    {
        let mut fx = rotate_fixture(Env::Mainnet);
        fx.surface = S::PeerDrivenDrain;
        fx.peer_driven = true;
        fx.replay_input.environment = Env::Mainnet;
        fx.replay_exp.expected_environment = Env::Mainnet;
        fx.replay_input.validation_surface = S::PeerDrivenDrain;
        fx.replay_exp.expected_validation_surface = S::PeerDrivenDrain;
        fx.replay_input.previously_seen = PreviouslySeenState::FirstSeen;
        let o = fx.run();
        t.check_outcome("A10.mainnet-refused", "mainnet-peer-driven-apply-refused", &o);
        t.assert_true(
            "A10.is-mainnet-refused",
            o.is_mainnet_peer_driven_apply_refused(),
            "",
        );
        t.assert_true("A10.not-mutate-authorized", !o.is_mutate_authorized(), "");
    }

    // A11 — ProceedFresh is the only replay/freshness outcome that authorizes
    // mutation. Flip only the replay state from fresh to expired and the
    // composed outcome stops authorizing a mutate.
    {
        let fresh = rotate_fixture(Env::Devnet);
        t.assert_true("A11.fresh-authorizes", fresh.run().is_mutate_authorized(), "");
        let mut expired = rotate_fixture(Env::Devnet);
        expired.replay_input.current_canonical_epoch = EXPIRY + 1;
        t.assert_true("A11.expired-not-authorizes", !expired.run().is_mutate_authorized(), "");
        // Helper invariant.
        t.assert_true("A11.fresh-required", fresh_replay_state_required_before_mutation(), "");
    }

    // A12 — ProceedDeferred is release-evidenced as not approval (also via the
    // call-site wiring, which surfaces a deferral as an Err).
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_input.current_canonical_epoch = 1; // before effective
        let err = wire_governance_evaluator_replay_runtime_callsite(
            &fx.context(&FixtureGovernanceExecutionEvaluatorInterface),
        )
        .err();
        t.assert_true("A12.callsite-err", err.is_some(), "");
        if let Some(fc) = err {
            t.assert_true("A12.is-deferred", fc.outcome.is_deferred(), "");
            t.assert_true("A12.not-mutate-authorized", !fc.outcome.is_mutate_authorized(), "");
        }
        t.assert_true("A12.deferred-not-approval", deferred_is_never_mutation_approval(), "");
    }

    // A13 — Run 230 replay/freshness boundary release behavior remains
    // compatible: the boundary alone classifies fresh, and the composed Run 232
    // outcome agrees.
    {
        let fx = rotate_fixture(Env::Devnet);
        t.check(
            "A13.run230-alone",
            "proceed-fresh",
            match evaluate_evaluator_replay_freshness(&fx.replay_input, &fx.replay_exp) {
                EvaluatorReplayFreshnessOutcome::ProceedFresh => "proceed-fresh",
                _ => "other",
            },
        );
        t.assert_true("A13.composed-authorizes", fx.run().is_mutate_authorized(), "");
    }

    // A14 — Run 231 replay/freshness standalone release behavior remains
    // compatible: the standalone boundary still distinguishes expired from
    // fresh, independent of the composition.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_input.current_canonical_epoch = EXPIRY + 10;
        t.check(
            "A14.standalone-expired",
            "fail-closed-expired:expired",
            &replay_inner_tag(&evaluate_evaluator_replay_freshness(
                &fx.replay_input,
                &fx.replay_exp,
            )),
        );
    }

    // A15 — Run 228 peer evaluator context behavior remains compatible: a
    // representable Present peer context routes through the Run 226 wiring into
    // the Run 224 integration, and the Run 232 peer-context entry point applies
    // the Run 230 replay/freshness gate on top.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.surface = S::LiveInbound0x05;
        fx.replay_input.validation_surface = S::LiveInbound0x05;
        fx.replay_exp.expected_validation_surface = S::LiveInbound0x05;
        let ctx = fx.context(&FixtureGovernanceExecutionEvaluatorInterface);
        let peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PeerEvaluatorContextSurface::LiveInbound0x05,
            PeerEvaluatorSourceClass::LiveInboundPeer,
            "peer-0001",
            &ctx.integration,
            None,
            None,
        );
        let o = wire_governance_evaluator_replay_runtime_peer_context(&peer, &ctx);
        t.check_outcome("A15.peer-context-fresh", "proceed-fresh", &o);
        t.assert_true("A15.peer-context-authorizes", o.is_mutate_authorized(), "");
    }

    // A16 — Run 226 call-site integration behavior remains compatible: the
    // call-site wiring returns Ok for a fresh mutate and Ok for the legacy
    // bypass.
    {
        let fresh = rotate_fixture(Env::Devnet);
        t.assert_true(
            "A16.callsite-fresh-ok",
            wire_governance_evaluator_replay_runtime_callsite(
                &fresh.context(&FixtureGovernanceExecutionEvaluatorInterface),
            )
            .is_ok(),
            "",
        );
        let mut bypass = rotate_fixture(Env::Devnet);
        bypass.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        bypass.load = GovernanceExecutionLoadStatus::Absent;
        t.assert_true(
            "A16.callsite-bypass-ok",
            wire_governance_evaluator_replay_runtime_callsite(
                &bypass.context(&FixtureGovernanceExecutionEvaluatorInterface),
            )
            .is_ok(),
            "",
        );
    }

    // A17 — Run 224 evaluator runtime integration behavior remains compatible:
    // the underlying Run 224 layer still authorizes a mutate on its own, and
    // the composed Run 232 outcome agrees.
    {
        let fx = rotate_fixture(Env::Devnet);
        let integration = integrate_governance_evaluator_runtime_consumption(
            &fx.context(&FixtureGovernanceExecutionEvaluatorInterface)
                .integration,
        );
        t.assert_true("A17.run224-mutate-authorized", integration.is_mutate_authorized(), "");
        t.assert_true("A17.composed-authorizes", fx.run().is_mutate_authorized(), "");
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R27): replay/freshness fail-closed before
// mutation, surfaced through the composed Run 232 runtime integration.
// ===========================================================================

/// Run the composed integration with a mutated replay input that keeps the Run
/// 224 layer authorizing a mutate, and assert the precise composed
/// replay/freshness fail-closed outcome tag.
fn assert_replay_fail_closed(
    t: &mut Table,
    id: &str,
    mutate: impl FnOnce(&mut Fixture),
    expected_inner: &str,
) {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    mutate(&mut fx);
    let o = fx.run();
    t.check_outcome(id, &format!("replay-freshness-fail-closed:{expected_inner}"), &o);
    t.assert_fail_closed(id, &o);
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1 — expired decision rejected before mutation.
    assert_replay_fail_closed(
        &mut t,
        "R1.expired",
        |fx| fx.replay_input.current_canonical_epoch = EXPIRY + 50,
        "fail-closed-expired:expired",
    );

    // R2 — stale decision rejected before mutation (degenerate window).
    assert_replay_fail_closed(
        &mut t,
        "R2.stale",
        |fx| {
            fx.replay_input.effective_epoch = 200;
            fx.replay_input.expiry_epoch = 100;
            fx.replay_exp.expected_effective_epoch = 200;
            fx.replay_exp.expected_expiry_epoch = 100;
        },
        "fail-closed-expired:stale",
    );

    // R3 — replayed decision rejected before mutation.
    assert_replay_fail_closed(
        &mut t,
        "R3.replay",
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(seen_record(false, false));
        },
        "fail-closed-replay",
    );

    // R4 — already-consumed decision rejected before mutation.
    assert_replay_fail_closed(
        &mut t,
        "R4.already-consumed",
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(seen_record(true, false));
        },
        "fail-closed-already-consumed",
    );

    // R5 — superseded decision rejected before mutation.
    assert_replay_fail_closed(
        &mut t,
        "R5.superseded",
        |fx| {
            fx.replay_input.previously_seen = PreviouslySeenState::Seen(seen_record(false, true));
        },
        "fail-closed-superseded",
    );

    // R6–R17 — wrong-binding rejections.
    assert_wrong_binding(
        &mut t,
        "R6.wrong-environment",
        |fx| fx.replay_input.environment = Env::Testnet,
        ReplayFreshnessState::WrongEnvironment,
    );
    assert_wrong_binding(
        &mut t,
        "R7.wrong-chain",
        |fx| fx.replay_input.chain_id = "wrong-chain".to_string(),
        ReplayFreshnessState::WrongChain,
    );
    assert_wrong_binding(
        &mut t,
        "R8.wrong-genesis",
        |fx| fx.replay_input.genesis_hash = "wrong-genesis".to_string(),
        ReplayFreshnessState::WrongGenesis,
    );
    assert_wrong_binding(
        &mut t,
        "R9.wrong-surface",
        |fx| fx.replay_input.validation_surface = S::ReloadCheck,
        ReplayFreshnessState::WrongSurface,
    );
    assert_wrong_binding(
        &mut t,
        "R10.wrong-source-identity",
        |fx| fx.replay_input.evaluator_source_identity_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R11.wrong-request",
        |fx| fx.replay_input.evaluator_request_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R12.wrong-response",
        |fx| fx.replay_input.evaluator_response_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R13.wrong-transcript",
        |fx| fx.replay_input.evaluator_transcript_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R14.wrong-proposal",
        |fx| fx.replay_input.proposal_id = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R15.wrong-decision",
        |fx| fx.replay_input.decision_id = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R16.wrong-lifecycle",
        |fx| fx.replay_input.lifecycle_action = LocalLifecycleAction::Revoke,
        ReplayFreshnessState::MalformedState,
    );
    assert_wrong_binding(
        &mut t,
        "R17.wrong-candidate",
        |fx| fx.replay_input.candidate_digest = "wrong".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R18 — wrong authority-domain sequence rejected.
    assert_wrong_binding(
        &mut t,
        "R18.wrong-sequence",
        |fx| fx.replay_input.authority_domain_sequence = SEQUENCE + 1,
        ReplayFreshnessState::MalformedState,
    );
    // R19 — wrong replay nonce rejected.
    assert_wrong_binding(
        &mut t,
        "R19.wrong-nonce",
        |fx| fx.replay_input.replay_nonce = "wrong-nonce".to_string(),
        ReplayFreshnessState::MalformedState,
    );
    // R20 — malformed replay state rejected (empty mandatory field).
    assert_wrong_binding(
        &mut t,
        "R20.malformed",
        |fx| {
            fx.replay_input.proposal_id = String::new();
            fx.replay_exp.expected_proposal_id = String::new();
        },
        ReplayFreshnessState::MalformedState,
    );

    // R21 — replay state unavailable rejected.
    assert_replay_fail_closed(
        &mut t,
        "R21.state-unavailable",
        |fx| fx.replay_input.previously_seen = PreviouslySeenState::Unavailable,
        "fail-closed-state-unavailable",
    );

    // R22 — production replay state unavailable rejected.
    assert_replay_fail_closed(
        &mut t,
        "R22.production-unavailable",
        |fx| {
            fx.replay_policy = ReplayStatePolicy::Production;
            fx.replay_input.previously_seen = PreviouslySeenState::ProductionUnavailable;
        },
        "fail-closed-production-unavailable",
    );

    // R23 — MainNet replay state unavailable/refused rejected.
    assert_replay_fail_closed(
        &mut t,
        "R23.mainnet-unavailable",
        |fx| {
            fx.replay_policy = ReplayStatePolicy::MainNet;
            fx.replay_input.previously_seen = PreviouslySeenState::MainNetUnavailable;
        },
        "fail-closed-mainnet-unavailable",
    );

    // R24 — validator-set rotation unsupported rejected.
    t.assert_true(
        "R24.validator-rotation",
        validator_set_rotation_remains_unsupported_under_replay_runtime(),
        "",
    );
    // R25 — policy-change action unsupported rejected.
    t.assert_true(
        "R25.policy-change",
        policy_change_action_remains_unsupported_under_replay_runtime(),
        "",
    );

    // R26 — validation-only rejection writes no marker and no sequence.
    {
        let store = FixtureReplayStateStore::new(Env::Devnet);
        let mut fx = rotate_fixture(Env::Devnet);
        fx.surface = S::ReloadCheck; // validation-only
        fx.replay_input.validation_surface = S::ReloadCheck;
        fx.replay_exp.expected_validation_surface = S::ReloadCheck;
        fx.replay_input.current_canonical_epoch = EXPIRY + 50; // expired => fail-closed
        let o = fx.run();
        t.assert_true("R26.is-fail-closed", o.is_fail_closed(), "");
        t.assert_true("R26.store-empty", store.is_empty(), "");
    }

    // R27 — mutating rejection produces no Run 070 call, no live trust swap, no
    // session eviction, no sequence write, and no marker write (none can happen
    // because the pure integration authorizes no mutation and records nothing).
    {
        let store = FixtureReplayStateStore::new(Env::Devnet);
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_input.current_canonical_epoch = EXPIRY + 50; // mutating surface, expired
        let err = wire_governance_evaluator_replay_runtime_callsite(
            &fx.context(&FixtureGovernanceExecutionEvaluatorInterface),
        )
        .err();
        t.assert_true("R27.callsite-err", err.is_some(), "");
        if let Some(fc) = err {
            t.assert_true("R27.is-fail-closed", fc.outcome.is_fail_closed(), "");
            t.assert_true("R27.not-mutate-authorized", !fc.outcome.is_mutate_authorized(), "");
        }
        t.assert_true("R27.store-empty", store.is_empty(), "");
    }

    t.finish(out)
}

fn seen_record(consumed: bool, superseded: bool) -> SeenDecisionRecord {
    SeenDecisionRecord {
        state_key_digest: "k".to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed,
        superseded,
    }
}

fn assert_wrong_binding(
    t: &mut Table,
    id: &str,
    mutate: impl FnOnce(&mut Fixture),
    state: ReplayFreshnessState,
) {
    let mut fx = rotate_fixture(TrustBundleEnvironment::Devnet);
    mutate(&mut fx);
    let o = fx.run();
    t.check_outcome(
        id,
        &format!(
            "replay-freshness-fail-closed:fail-closed-wrong-binding:{}",
            state.tag()
        ),
        &o,
    );
    t.assert_fail_closed(id, &o);
}

// ===========================================================================
// Reachability + runtime-integration fail-closed table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // A Run 224 / Run 226 fail-closed (the evaluator policy requires a
    // production source but a fixture source is supplied) surfaces as a runtime
    // integration fail-closed and never reaches the replay/freshness boundary.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.ev_policy = EvaluatorPolicy::ProductionDecisionSourceRequired;
        let o = fx.run_with(&ProductionDecisionSourceEvaluatorInterface);
        t.check_outcome("RI.runtime-integration-fail-closed", "runtime-integration-fail-closed", &o);
        t.assert_fail_closed("RI", &o);
    }

    // When the replay-state boundary is not wired (Disabled) but the Run 224
    // layer authorizes a mutate, the composed integration fails closed: a
    // mutate is never authorized without a wired, fresh replay/freshness gate.
    {
        let mut fx = rotate_fixture(Env::Devnet);
        fx.replay_policy = ReplayStatePolicy::Disabled;
        let o = fx.run();
        t.check_outcome(
            "NW.not-wired-fails-closed",
            "replay-freshness-fail-closed:fail-closed-state-unavailable",
            &o,
        );
        t.assert_fail_closed("NW", &o);
    }

    // MainNet fixture evaluator never authorizes (Run 222/211 stages refuse the
    // fixture source on a MainNet trust domain) — fail-closed before the
    // replay/freshness boundary.
    {
        let fx = rotate_fixture(Env::Mainnet);
        let o = fx.run();
        t.assert_true("MN.is-fail-closed", o.is_fail_closed(), "");
        t.assert_true("MN.not-mutate-authorized", !o.is_mutate_authorized(), "");
    }

    // MainNet evaluator-interface unavailable surfaces as runtime integration
    // fail-closed.
    {
        let mut fx = rotate_fixture(Env::Mainnet);
        fx.ev_policy = EvaluatorPolicy::MainnetDecisionSourceRequired;
        let o = fx.run_with(&MainnetDecisionSourceEvaluatorInterface);
        t.assert_true(
            "MN.evaluator-unavailable-runtime-fail-closed",
            matches!(
                o,
                GovernanceEvaluatorReplayRuntimeOutcome::RuntimeIntegrationFailClosed(_)
            ),
            "",
        );
    }

    // Run 228 peer-context MainNet peer-driven apply remains refused even when
    // the replay state would be fresh.
    {
        let mut fx = rotate_fixture(Env::Mainnet);
        fx.surface = S::PeerDrivenDrain;
        fx.peer_driven = true;
        fx.replay_input.environment = Env::Mainnet;
        fx.replay_exp.expected_environment = Env::Mainnet;
        fx.replay_input.validation_surface = S::PeerDrivenDrain;
        fx.replay_exp.expected_validation_surface = S::PeerDrivenDrain;
        let ctx = fx.context(&FixtureGovernanceExecutionEvaluatorInterface);
        let peer = GovernanceEvaluatorPeerContext::present_from_integration(
            PeerEvaluatorContextSurface::PeerDrivenDrain,
            PeerEvaluatorSourceClass::DrainStagedPeer,
            "peer-0002",
            &ctx.integration,
            None,
            None,
        );
        t.check_outcome(
            "PC.mainnet-peer-driven-refused",
            "mainnet-peer-driven-apply-refused",
            &wire_governance_evaluator_replay_runtime_peer_context(&peer, &ctx),
        );
    }

    // Composed outcome tags reachable / stable.
    {
        t.check(
            "T.legacy-bypass",
            "proceed-legacy-bypass",
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass.tag(),
        );
        t.check(
            "T.deferred",
            "proceed-deferred",
            GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred.tag(),
        );
        t.check(
            "T.mainnet-refused",
            "mainnet-peer-driven-apply-refused",
            GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused.tag(),
        );
        t.check(
            "T.replay-fail-closed",
            "replay-freshness-fail-closed",
            GovernanceEvaluatorReplayRuntimeOutcome::ReplayFreshnessFailClosed(
                EvaluatorReplayFreshnessOutcome::FailClosedStateUnavailable,
            )
            .tag(),
        );
    }

    // Grep-verifiable refusal / fail-closed helper invariants.
    {
        t.assert_true(
            "G.mainnet-refused-mainnet",
            mainnet_peer_driven_apply_remains_refused_under_replay_runtime(Env::Mainnet),
            "",
        );
        t.assert_true(
            "G.mainnet-refused-not-devnet",
            !mainnet_peer_driven_apply_remains_refused_under_replay_runtime(Env::Devnet),
            "",
        );
        t.assert_true("G.fresh-required", fresh_replay_state_required_before_mutation(), "");
        t.assert_true("G.deferred-not-approval", deferred_is_never_mutation_approval(), "");
        t.assert_true(
            "G.production-mainnet-unavailable",
            production_mainnet_replay_state_remains_unavailable(),
            "",
        );
        t.assert_true(
            "G.validator-rotation-unsupported",
            validator_set_rotation_remains_unsupported_under_replay_runtime(),
            "",
        );
        t.assert_true(
            "G.policy-change-unsupported",
            policy_change_action_remains_unsupported_under_replay_runtime(),
            "",
        );
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (digests, before/after store snapshots, outcome values).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use GovernanceExecutionRuntimeSurface as S;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let fx = rotate_fixture(Env::Devnet);

    // Replay state / freshness transcript digests (Run 230 inputs to the
    // composed gate).
    write_file(
        &dir.join("replay_state_key_digest.txt"),
        &format!("{}\n", replay_state_key_digest(&fx.replay_input)),
    );

    // Composed outcome value (ProceedFresh).
    write_file(&dir.join("composed_outcome.txt"), &format!("{:#?}\n", fx.run()));
    write_file(&dir.join("composed_outcome_tag.txt"), &format!("{}\n", otag(&fx.run())));

    // Before/after fixture replay-store snapshots across an explicit consume
    // performed only after a successful fixture authorization.
    let mut store = FixtureReplayStateStore::new(Env::Devnet);
    let key = replay_state_key_digest(&fx.replay_input);
    let snap_before = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    let authorized = fx.run().is_mutate_authorized();
    let snap_after_auth = format!(
        "authorized={} len={} is_consumed={}\n",
        authorized,
        store.len(),
        store.is_consumed(&key)
    );
    store.record_for(&fx.replay_input);
    let snap_observed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    store.consume_for(&fx.replay_input);
    let snap_consumed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    write_file(
        &dir.join("fixture_store_snapshots.txt"),
        &format!(
            "before:        {}after-auth:    {}observed:       {}consumed:       {}",
            snap_before, snap_after_auth, snap_observed, snap_consumed
        ),
    );

    // Deferred / expired / MainNet-refused outcome dumps.
    let mut deferred = rotate_fixture(Env::Devnet);
    deferred.replay_input.current_canonical_epoch = 1;
    write_file(&dir.join("deferred_outcome.txt"), &format!("{:#?}\n", deferred.run()));

    let mut expired = rotate_fixture(Env::Devnet);
    expired.replay_input.current_canonical_epoch = EXPIRY + 50;
    write_file(&dir.join("expired_outcome.txt"), &format!("{:#?}\n", expired.run()));

    let mut mn = rotate_fixture(Env::Mainnet);
    mn.surface = S::PeerDrivenDrain;
    mn.peer_driven = true;
    mn.replay_input.environment = Env::Mainnet;
    mn.replay_exp.expected_environment = Env::Mainnet;
    mn.replay_input.validation_surface = S::PeerDrivenDrain;
    mn.replay_exp.expected_validation_surface = S::PeerDrivenDrain;
    write_file(&dir.join("mainnet_refused_outcome.txt"), &format!("{:#?}\n", mn.run()));

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_runtime_integration\n");
    for entry in [
        "type\tGovernanceEvaluatorReplayRuntimeIntegrationContext",
        "type\tGovernanceEvaluatorReplayRuntimeOutcome",
        "type\tGovernanceEvaluatorReplayRuntimeCallsiteFailClosed",
        "variant\tProceedLegacyBypass",
        "variant\tProceedDeferred",
        "variant\tProceedFresh",
        "variant\tReplayFreshnessFailClosed",
        "variant\tRuntimeIntegrationFailClosed",
        "variant\tMainNetPeerDrivenApplyRefused",
        "fn\tintegrate_governance_evaluator_replay_runtime",
        "fn\twire_governance_evaluator_replay_runtime_callsite",
        "fn\twire_governance_evaluator_replay_runtime_peer_context",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_replay_runtime",
        "guard\tfresh_replay_state_required_before_mutation",
        "guard\tdeferred_is_never_mutation_approval",
        "guard\tproduction_mainnet_replay_state_remains_unavailable",
        "guard\tvalidator_set_rotation_remains_unsupported_under_replay_runtime",
        "guard\tpolicy_change_action_remains_unsupported_under_replay_runtime",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("runtime_integration_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_233_governance_evaluator_replay_runtime_integration_release_binary_helper <OUT_DIR>"
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
    let mut summary = String::from("run_233_governance_evaluator_replay_runtime_integration_release_binary_helper\nscope: Run 232 governance evaluator replay/freshness runtime integration (pqc_governance_evaluator_replay_runtime_integration: integrate_governance_evaluator_replay_runtime, wire_governance_evaluator_replay_runtime_callsite, wire_governance_evaluator_replay_runtime_peer_context, GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome { ProceedLegacyBypass, ProceedDeferred, ProceedFresh, ReplayFreshnessFailClosed, RuntimeIntegrationFailClosed, MainNetPeerDrivenApplyRefused }) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure composition (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); replay/freshness validation is a mandatory pre-mutation gate composed into the Run 224 evaluator runtime integration path; ProceedFresh is the only mutation-authorizing outcome and is produced only after the Run 224 layer authorized a mutate AND the Run 230 state classified the decision fresh; ProceedDeferred is not approval; expired/stale/replay/consumed/superseded/wrong-binding/unavailable replay states fail closed before mutation; read-only validation does not consume; explicit consume marks consumed only after a successful fixture authorization (caller-side, fixture-only); production/MainNet replay state unavailable/fail-closed; MainNet peer-driven apply remains refused even when fresh; validator-set rotation and policy-change actions unsupported; no RocksDB/file/schema/migration/storage-format change\n\n");
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
