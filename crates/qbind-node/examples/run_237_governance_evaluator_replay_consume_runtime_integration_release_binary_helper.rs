//! Run 237 — release-built helper for the Run 236 governance evaluator
//! **replay consume runtime integration**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`).
//!
//! Where Run 236 landed the pure composition that ties the Run 232
//! replay/freshness runtime integration into the Run 234 post-mutation consume
//! boundary at the source/test level and captured **no** release-binary
//! evidence, Run 237 is that release-binary evidence. This helper drives the
//! A1–A23 / R1–R35 matrix from `task/RUN_237_TASK.txt` through the
//! **release-built** Run 236 symbols (`integrate_replay_consume_runtime`,
//! `wire_replay_consume_runtime_callsite`, the typed
//! `ReplayConsumeRuntimeIntegrationInput` / `ReplayConsumeRuntimeOutcome`, and
//! the grep-verifiable invariant / refusal helpers), composing the real Run 232
//! replay/freshness runtime integration and the real Run 234 consume boundary,
//! proving that:
//!
//! * the Run 232 replay/freshness runtime integration runs **first** — any
//!   non-`ProceedFresh` outcome maps directly to a non-consuming Run 236 outcome
//!   without ever calling the consume writer;
//! * **fresh is required before mutation authorization**: only a Run 232
//!   `ProceedFresh` reaches the consume boundary;
//! * consume is **after-success-only**: only
//!   `ConsumeFixtureAfterMutationSuccess` (after a Run 232 `ProceedFresh` and a
//!   modeled `MutationCompletionStatus::AppliedSuccessfully`) authorizes a
//!   fixture consume;
//! * deferred, validation-only, before-apply, failed-apply, rolled-back,
//!   unsupported-surface, and MainNet-refused outcomes never consume;
//! * the DevNet/TestNet `FixtureReplayStateStore` writer records consumed only
//!   on the explicit after-success consume path (and only with a prior
//!   observation), and a re-validation then classifies the decision
//!   already-consumed through the Run 230 state;
//! * the production / MainNet consume writers are reached but always fail closed
//!   unavailable;
//! * MainNet peer-driven apply remains refused and never consumes even when the
//!   replay state is fresh and the modeled mutation completion is successful;
//! * the consume authorization is overridden with the exact Run 232 freshness
//!   result so the freshness and consume layers cannot disagree;
//! * every rejection is pure and non-mutating (no marker write, no sequence
//!   write, no live trust swap, no session eviction, no Run 070 call) and the
//!   writer is never called on a non-consume path.
//!
//! Fixture-only: no network/backend I/O, no live mutation, no real governance
//! execution engine, mutation engine, on-chain proof verifier, KMS/HSM, or
//! RemoteSigner backend. No RocksDB/file/schema/migration/storage-format change.
//! The `FixtureReplayStateStore` is an in-process map only and DevNet/TestNet
//! evidence-only. MainNet peer-driven apply remains refused.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_consume_boundary::{
    consume_authorization_digest, consume_transcript_digest,
    local_operator_cannot_satisfy_consume_policy, peer_majority_cannot_satisfy_consume_policy,
    post_mutation_consume_record_digest, ConsumeBoundaryOutcome, MutationAuthorizationOutcome,
    MutationCompletionStatus, PostMutationConsumeExpectations, PostMutationConsumeInput,
};
use qbind_node::pqc_governance_evaluator_replay_consume_runtime_integration::{
    consume_integrated_as_after_success_only_post_mutation_step,
    deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime,
    fresh_required_before_mutation_authorization_under_consume_runtime,
    integrate_replay_consume_runtime,
    mainnet_peer_driven_apply_remains_refused_under_consume_runtime,
    policy_change_action_remains_unsupported_under_consume_runtime,
    production_mainnet_consume_remains_unavailable_under_consume_runtime,
    validator_set_rotation_remains_unsupported_under_consume_runtime,
    wire_replay_consume_runtime_callsite, ReplayConsumeRuntimeIntegrationInput,
    ReplayConsumeRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_runtime_integration::{
    integrate_governance_evaluator_replay_runtime,
    GovernanceEvaluatorReplayRuntimeIntegrationContext, GovernanceEvaluatorReplayRuntimeOutcome,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    evaluate_evaluator_replay_freshness, replay_state_key_digest,
    EvaluatorReplayFreshnessExpectations, EvaluatorReplayFreshnessInput,
    EvaluatorReplayFreshnessOutcome, FixtureReplayStateStore,
    GovernanceEvaluatorReplayStateWriter, MainnetReplayStateReader, PreviouslySeenState,
    ProductionReplayStateReader, ReplayStatePolicy, SeenDecisionRecord,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorExpectations, EvaluatorPolicy, EvaluatorRequest,
    EvaluatorResponse, EvaluatorSourceKind, FixtureGovernanceExecutionEvaluatorInterface,
    ProductionGovernanceExecutionEvaluator, EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_evaluator_runtime_integration::GovernanceEvaluatorRuntimeIntegrationContext;
use qbind_node::pqc_governance_execution_payload_carrying::{
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadWire,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionPolicy,
    GovernanceQuorumThreshold, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_runtime_arming::{
    GovernanceExecutionRuntimeArmingConfig, GovernanceExecutionRuntimeSurface,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared constants (mirror the Run 220 / 222 / 224 / 230 / 232 / 234 / 236
// corpora so the composed material binds to the same trust domain,
// proposal/decision identity, candidate digest, replay nonce).
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
const CANONICAL: u64 = 150;

// ===========================================================================
// Run 211 governance-execution carrier material
// ===========================================================================

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN, GENESIS, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

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
        now_epoch: CANONICAL,
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
        now_epoch: CANONICAL,
    }
}

// ===========================================================================
// Owned-material fixture bundle (Run 232 context + Run 234 consume layer)
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
    consume_input: PostMutationConsumeInput,
    consume_exp: PostMutationConsumeExpectations,
    consume_policy: ReplayStatePolicy,
}

impl Fixture {
    fn replay_context<'a, E: ProductionGovernanceExecutionEvaluator>(
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

    /// Run the composed Run 236 integration against `store`.
    fn run(&self, store: &mut FixtureReplayStateStore) -> ReplayConsumeRuntimeOutcome {
        let evaluator = FixtureGovernanceExecutionEvaluatorInterface;
        let replay_ctx = self.replay_context(&evaluator);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &self.consume_input,
            consume_expectations: &self.consume_exp,
            consume_policy: self.consume_policy,
        };
        integrate_replay_consume_runtime(&input, store)
    }

    /// Run the composed Run 236 integration through the call-site wiring.
    fn run_callsite(
        &self,
        store: &mut FixtureReplayStateStore,
    ) -> Result<ReplayConsumeRuntimeOutcome, ReplayConsumeRuntimeOutcome> {
        let evaluator = FixtureGovernanceExecutionEvaluatorInterface;
        let replay_ctx = self.replay_context(&evaluator);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &self.consume_input,
            consume_expectations: &self.consume_exp,
            consume_policy: self.consume_policy,
        };
        wire_replay_consume_runtime_callsite(&input, store).map_err(|e| e.outcome)
    }
}

fn rotate_fixture(
    env: TrustBundleEnvironment,
    mutation_surface: GovernanceExecutionRuntimeSurface,
    completion: MutationCompletionStatus,
    consume_policy: ReplayStatePolicy,
) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request(&identity, &input_digest);
    let response = ev_response(&request);
    let surface = GovernanceExecutionRuntimeSurface::ReloadApply;

    let replay_exp = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
        &identity, &request, &response, TRANSCRIPT_DIGEST, DECISION_DIGEST, env, CHAIN, GENESIS,
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
        CANONICAL,
        PreviouslySeenState::FirstSeen,
    );

    let consume_input = PostMutationConsumeInput::from_freshness_input(
        &replay_input,
        mutation_surface,
        MutationAuthorizationOutcome::AuthorizedFresh,
        completion,
    );
    let consume_exp =
        PostMutationConsumeExpectations::from_freshness_input(&replay_input, mutation_surface);

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
        consume_input,
        consume_exp,
        consume_policy,
    }
}

/// The consume-eligible DevNet happy-path fixture.
fn devnet_success_fixture() -> Fixture {
    rotate_fixture(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::FixtureDevNet,
    )
}

/// A fresh store with the fixture's decision already observed (so the fixture
/// writer can mark it consumed after a successful mutation).
fn store_with_observation(fx: &Fixture) -> FixtureReplayStateStore {
    let mut store = FixtureReplayStateStore::new(match fx.consume_policy {
        ReplayStatePolicy::FixtureTestNet => TrustBundleEnvironment::Testnet,
        _ => TrustBundleEnvironment::Devnet,
    });
    store.record_for(&fx.replay_input);
    store
}

/// Build and run a MainNet peer-driven-drain fixture (used by A12/A15/R35).
fn mainnet_peer_driven_outcome() -> ReplayConsumeRuntimeOutcome {
    let mut fx = rotate_fixture(
        TrustBundleEnvironment::Mainnet,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationCompletionStatus::AppliedSuccessfully,
        ReplayStatePolicy::MainNet,
    );
    fx.surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.peer_driven = true;
    fx.replay_input.validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_exp.expected_validation_surface = GovernanceExecutionRuntimeSurface::PeerDrivenDrain;
    fx.replay_input.previously_seen = PreviouslySeenState::FirstSeen;
    fx.consume_input = PostMutationConsumeInput::from_freshness_input(
        &fx.replay_input,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    );
    fx.consume_exp = PostMutationConsumeExpectations::from_freshness_input(
        &fx.replay_input,
        GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
    );
    let mut store = FixtureReplayStateStore::new(TrustBundleEnvironment::Devnet);
    fx.run(&mut store)
}

fn seen_record(consumed: bool, superseded: bool) -> PreviouslySeenState {
    PreviouslySeenState::Seen(SeenDecisionRecord {
        state_key_digest: "k".to_string(),
        replay_nonce: NONCE.to_string(),
        recorded_sequence: SEQUENCE,
        recorded_effective_epoch: EFFECTIVE,
        recorded_expiry_epoch: EXPIRY,
        observation_count: 1,
        consumed,
        superseded,
    })
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: &ReplayConsumeRuntimeOutcome) {
        self.check(id, expected, o.tag());
    }
    /// Assert an outcome is non-consuming: it never authorizes a consume. The
    /// composition is pure, so a non-consume necessarily performs no
    /// marker/sequence write, no live trust swap, no session eviction, and no
    /// Run 070 call.
    fn assert_no_consume(&mut self, id: &str, o: &ReplayConsumeRuntimeOutcome) {
        self.assert_true(&format!("{id}.no-consume"), o.no_consume());
        self.assert_true(
            &format!("{id}.not-authorizes-consume"),
            !o.authorizes_consume(),
        );
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
// A — accepted / compatible scenarios (A1–A23) exercised through the Run 236
// release-built replay consume runtime integration symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationCompletionStatus as MC;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — legacy bypass produces no consume.
    {
        let mut fx = devnet_success_fixture();
        fx.arming = GovernanceExecutionRuntimeArmingConfig::disabled();
        fx.load = GovernanceExecutionLoadStatus::Absent;
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("A1.legacy-bypass", "proceed-legacy-bypass-no-consume", &o);
        t.assert_no_consume("A1", &o);
        t.assert_true(
            "A1.store-not-consumed",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A2 — deferred replay/freshness produces no consume and no mutation
    // authorization.
    {
        let mut fx = devnet_success_fixture();
        fx.replay_input.current_canonical_epoch = 50;
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("A2.deferred", "proceed-deferred-no-consume", &o);
        t.assert_no_consume("A2", &o);
        t.assert_true(
            "A2.store-not-consumed",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A3 — validation-only fresh decision produces no consume.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::LocalPeerCandidateCheck,
            MC::AppliedSuccessfully,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A3.validation-only",
            "proceed-validation-only-no-consume",
            &o,
        );
        t.assert_no_consume("A3", &o);
    }

    // A4 — fresh decision authorizes mutation but does not consume before apply.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::NotAttempted, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A4.before-apply",
            "proceed-fresh-mutation-authorized",
            &o,
        );
        t.assert_true("A4.is-proceed", o.is_proceed());
        t.assert_no_consume("A4", &o);
    }

    // A5 — fresh decision plus AppliedSuccessfully consumes in DevNet fixture only.
    {
        let fx = devnet_success_fixture();
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A5.devnet-consume",
            "consume-fixture-after-mutation-success",
            &o,
        );
        t.assert_true("A5.authorizes-consume", o.authorizes_consume());
        t.assert_true(
            "A5.store-consumed",
            store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A6 — fresh decision plus AppliedSuccessfully consumes in TestNet fixture only.
    {
        let fx = rotate_fixture(
            Env::Testnet,
            S::ReloadApply,
            MC::AppliedSuccessfully,
            P::FixtureTestNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A6.testnet-consume",
            "consume-fixture-after-mutation-success",
            &o,
        );
        t.assert_true(
            "A6.store-consumed",
            store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A7 — after fixture consume, same decision validates as already-consumed /
    // fail-closed through Run 230 state.
    {
        let fx = devnet_success_fixture();
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.assert_true("A7.first-consumes", o.authorizes_consume());
        t.assert_true(
            "A7.store-consumed",
            store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
        // Re-validate the same decision: Run 230 state now classifies it
        // already-consumed before any mutation authorization.
        let mut fx2 = devnet_success_fixture();
        fx2.replay_input.previously_seen = store.read_for(&fx2.replay_input);
        let o2 = fx2.run(&mut store);
        t.assert_true(
            "A7.revalidate-fail-closed",
            matches!(o2, ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)),
        );
        t.assert_no_consume("A7.revalidate", &o2);
    }

    // A8 — read-only validation path never consumes.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::LocalPeerCandidateCheck,
            MC::ValidationOnly,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.assert_no_consume("A8", &o);
        t.assert_true(
            "A8.store-not-consumed",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A9 — failed apply never consumes.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::ApplyFailed, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("A9.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_no_consume("A9", &o);
    }

    // A10 — rollback never consumes.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::RolledBack, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("A10.rolled-back", "do-not-consume-rolled-back", &o);
        t.assert_no_consume("A10", &o);
    }

    // A11 — unsupported surface never consumes.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::UnsupportedSurface,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A11.unsupported-surface",
            "do-not-consume-unsupported-surface",
            &o,
        );
        t.assert_no_consume("A11", &o);
    }

    // A12 — MainNet refused never consumes.
    {
        let o = mainnet_peer_driven_outcome();
        t.check_outcome("A12.mainnet-refused", "mainnet-peer-driven-apply-refused", &o);
        t.assert_no_consume("A12", &o);
        t.assert_true(
            "A12.guard",
            mainnet_peer_driven_apply_remains_refused_under_consume_runtime(Env::Mainnet),
        );
    }

    // A13 — production consume writer path is reached and fails closed unavailable.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::AppliedSuccessfully,
            P::Production,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A13.production-unavailable",
            "production-consume-unavailable",
            &o,
        );
        t.assert_no_consume("A13", &o);
        // The production writer never marks consumed even when called directly.
        let mut prod = ProductionReplayStateReader;
        let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &fx.consume_input,
            consume_expectations: &fx.consume_exp,
            consume_policy: P::Production,
        };
        t.check_outcome(
            "A13.production-perform",
            "production-consume-unavailable",
            &integrate_replay_consume_runtime(&input, &mut prod),
        );
        t.assert_true(
            "A13.writer-fails-closed",
            !prod.mark_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A14 — MainNet consume writer path is reached and fails closed
    // unavailable/refused (DevNet-bound fresh decision, MainNet consume selector,
    // non-peer-driven surface so the refusal guard does not pre-empt it).
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::AppliedSuccessfully,
            P::MainNet,
        );
        let mut mainnet = MainnetReplayStateReader;
        let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &fx.consume_input,
            consume_expectations: &fx.consume_exp,
            consume_policy: P::MainNet,
        };
        let o = integrate_replay_consume_runtime(&input, &mut mainnet);
        t.check_outcome("A14.mainnet-unavailable", "mainnet-consume-unavailable", &o);
        t.assert_no_consume("A14", &o);
        t.assert_true(
            "A14.writer-fails-closed",
            !mainnet.mark_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // A15 — MainNet peer-driven apply remains refused even when replay state is
    // fresh and mutation completion is modeled successful.
    {
        let o = mainnet_peer_driven_outcome();
        t.check_outcome(
            "A15.mainnet-peer-driven-refused",
            "mainnet-peer-driven-apply-refused",
            &o,
        );
        t.assert_true(
            "A15.is-mainnet-refused",
            o.is_mainnet_peer_driven_apply_refused(),
        );
        t.assert_no_consume("A15", &o);
    }

    // A16 — Run 232 replay/freshness runtime integration remains compatible.
    {
        let fx = devnet_success_fixture();
        let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
        let replay_outcome = integrate_governance_evaluator_replay_runtime(&replay_ctx);
        t.assert_true(
            "A16.run232-proceed-fresh",
            matches!(
                replay_outcome,
                GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. }
            ),
        );
        t.check(
            "A16.projects-authorized-fresh",
            "authorized-fresh",
            MutationAuthorizationOutcome::from_replay_runtime_outcome(&replay_outcome).tag(),
        );
    }

    // A17 — Run 234 consume boundary remains compatible (the composed
    // after-success path honours the Run 234 after-success-only contract).
    {
        let fx = devnet_success_fixture();
        let mut store = store_with_observation(&fx);
        t.check_outcome(
            "A17.consume-boundary",
            "consume-fixture-after-mutation-success",
            &fx.run(&mut store),
        );
        t.assert_true(
            "A17.after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
    }

    // A18 — Run 235 release consume-boundary behaviour remains compatible: the
    // Run 234 consume transcript digest binds the composed outcome.
    {
        let fx = devnet_success_fixture();
        let d1 = consume_transcript_digest(
            &fx.consume_input,
            &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess,
        );
        let d2 = consume_transcript_digest(
            &fx.consume_input,
            &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess,
        );
        t.assert_true("A18.transcript-stable", d1 == d2);
        t.assert_true(
            "A18.transcript-outcome-bound",
            consume_transcript_digest(
                &fx.consume_input,
                &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess,
            ) != consume_transcript_digest(
                &fx.consume_input,
                &ConsumeBoundaryOutcome::DoNotConsumeBeforeApply,
            ),
        );
    }

    // A19 — Run 233 release replay/freshness runtime behaviour remains
    // compatible: the composed consume input references exactly the Run 230
    // replay state key digest the Run 232/233 integration would bind.
    {
        let fx = devnet_success_fixture();
        t.check(
            "A19.run230-key-matches",
            &replay_state_key_digest(&fx.replay_input),
            &fx.consume_input.replay_state_key_digest,
        );
    }

    // A20 — Run 231 release replay/freshness standalone behaviour remains
    // compatible: the standalone boundary still classifies a fresh first-seen
    // decision ProceedFresh.
    {
        let fx = devnet_success_fixture();
        let exp230 = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
            &fx.identity, &fx.request, &fx.response, TRANSCRIPT_DIGEST, DECISION_DIGEST,
            Env::Devnet, CHAIN, GENESIS, S::ReloadApply,
        );
        t.check(
            "A20.run230-alone-fresh",
            "proceed-fresh",
            match evaluate_evaluator_replay_freshness(&fx.replay_input, &exp230) {
                EvaluatorReplayFreshnessOutcome::ProceedFresh => "proceed-fresh",
                _ => "other",
            },
        );
    }

    // A21 — integrate_replay_consume_runtime runs replay/freshness before
    // consume: a replay-side rejection fails closed before the consume boundary
    // is reached and the writer is never invoked.
    {
        let mut fx = devnet_success_fixture();
        fx.replay_input.current_canonical_epoch = EXPIRY + 50; // expired
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.assert_true(
            "A21.replay-before-consume",
            matches!(o, ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)),
        );
        t.assert_no_consume("A21", &o);
        t.assert_true(
            "A21.writer-untouched",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
        t.assert_true(
            "A21.fresh-required",
            fresh_required_before_mutation_authorization_under_consume_runtime(),
        );
    }

    // A22 — non-ProceedFresh outcomes do not call the writer: a failed-apply path
    // performed against a store with a prior observation never marks consumed.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::ApplyFailed, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let len_before = store.len();
        let o = fx.run(&mut store);
        t.check_outcome("A22.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_true(
            "A22.writer-not-called",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
        t.assert_true("A22.store-len-unchanged", store.len() == len_before);
    }

    // A23 — consume authorization uses the exact Run 232 freshness result: even
    // when the consume input carries a deliberately wrong mutation-authorization
    // outcome, the composition overrides it with the Run 232-derived
    // AuthorizedFresh and consumes after success.
    {
        let mut fx = devnet_success_fixture();
        fx.consume_input.mutation_authorization_outcome = MutationAuthorizationOutcome::Deferred;
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "A23.override-consumes",
            "consume-fixture-after-mutation-success",
            &o,
        );
        t.assert_true(
            "A23.store-consumed",
            store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R35).
// ===========================================================================

/// Assert a replay-side perturbation fails closed before consume (a Run 232
/// replay-runtime fail-closed), performing no consume.
fn assert_replay_runtime_fail_closed(
    t: &mut Table,
    id: &str,
    mutate: impl FnOnce(&mut Fixture),
) {
    let mut fx = devnet_success_fixture();
    mutate(&mut fx);
    let mut store = store_with_observation(&fx);
    let o = fx.run(&mut store);
    t.assert_true(
        &format!("{id}.replay-runtime-fail-closed"),
        matches!(o, ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)),
    );
    t.assert_true(&format!("{id}.is-fail-closed"), o.is_fail_closed());
    t.assert_no_consume(id, &o);
    t.assert_true(
        &format!("{id}.writer-untouched"),
        !store.is_consumed(&fx.consume_input.replay_state_key_digest),
    );
}

/// Assert a consume-side perturbation fails closed on the consume binding (a Run
/// 234 consume fail-closed), performing no consume.
fn assert_consume_fail_closed(t: &mut Table, id: &str, mutate: impl FnOnce(&mut Fixture)) {
    let mut fx = devnet_success_fixture();
    mutate(&mut fx);
    let mut store = store_with_observation(&fx);
    let o = fx.run(&mut store);
    t.assert_true(
        &format!("{id}.consume-fail-closed"),
        matches!(o, ReplayConsumeRuntimeOutcome::ConsumeFailClosed { .. }),
    );
    t.assert_no_consume(id, &o);
    t.assert_true(
        &format!("{id}.writer-untouched"),
        !store.is_consumed(&fx.consume_input.replay_state_key_digest),
    );
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationCompletionStatus as MC;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1. expired decision rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R1.expired", |fx| {
        fx.replay_input.current_canonical_epoch = EXPIRY + 50
    });
    // R2. stale decision rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R2.stale", |fx| {
        fx.replay_input.effective_epoch = 200;
        fx.replay_input.expiry_epoch = 100;
        fx.replay_exp.expected_effective_epoch = 200;
        fx.replay_exp.expected_expiry_epoch = 100;
    });
    // R3. replayed decision rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R3.replayed", |fx| {
        fx.replay_input.previously_seen = seen_record(false, false)
    });
    // R4. already-consumed decision rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R4.already-consumed", |fx| {
        fx.replay_input.previously_seen = seen_record(true, false)
    });
    // R5. superseded decision rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R5.superseded", |fx| {
        fx.replay_input.previously_seen = seen_record(false, true)
    });
    // R6. wrong environment rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R6.wrong-environment", |fx| {
        fx.replay_input.environment = Env::Testnet
    });
    // R7. wrong chain rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R7.wrong-chain", |fx| {
        fx.replay_input.chain_id = "wrong-chain".to_string()
    });
    // R8. wrong genesis rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R8.wrong-genesis", |fx| {
        fx.replay_input.genesis_hash = "wrong-genesis".to_string()
    });
    // R9. wrong validation surface rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R9.wrong-validation-surface", |fx| {
        fx.replay_input.validation_surface = S::ReloadCheck
    });
    // R10. wrong mutation surface rejected before consume (consume-binding).
    assert_consume_fail_closed(&mut t, "R10.wrong-mutation-surface", |fx| {
        fx.consume_input.mutation_surface = S::Sighup
    });
    // R11. wrong source identity digest rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R11.wrong-source-identity", |fx| {
        fx.replay_input.evaluator_source_identity_digest = "wrong".to_string()
    });
    // R12. wrong request digest rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R12.wrong-request", |fx| {
        fx.replay_input.evaluator_request_digest = "wrong".to_string()
    });
    // R13. wrong response digest rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R13.wrong-response", |fx| {
        fx.replay_input.evaluator_response_digest = "wrong".to_string()
    });
    // R14. wrong transcript digest rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R14.wrong-transcript", |fx| {
        fx.replay_input.evaluator_transcript_digest = "wrong".to_string()
    });
    // R15. wrong proposal id rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R15.wrong-proposal", |fx| {
        fx.replay_input.proposal_id = "wrong".to_string()
    });
    // R16. wrong decision id rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R16.wrong-decision-id", |fx| {
        fx.replay_input.decision_id = "wrong".to_string()
    });
    // R17. wrong lifecycle action rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R17.wrong-lifecycle", |fx| {
        fx.replay_input.lifecycle_action = LocalLifecycleAction::Revoke
    });
    // R18. wrong candidate digest rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R18.wrong-candidate", |fx| {
        fx.replay_input.candidate_digest = "wrong".to_string()
    });
    // R19. wrong authority-domain sequence rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R19.wrong-sequence", |fx| {
        fx.replay_input.authority_domain_sequence = SEQUENCE + 1
    });
    // R20. wrong replay nonce rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R20.wrong-replay-nonce", |fx| {
        fx.replay_input.replay_nonce = "wrong".to_string()
    });
    // R21. malformed replay state rejected before consume.
    assert_replay_runtime_fail_closed(&mut t, "R21.malformed-replay-state", |fx| {
        fx.replay_input.evaluator_request_digest = String::new()
    });
    // R22. malformed consume state rejected.
    assert_consume_fail_closed(&mut t, "R22.malformed-consume-state", |fx| {
        fx.consume_input.replay_state_key_digest = String::new()
    });

    // R23. consume attempted before apply rejected.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::AuthorizedButNotApplied,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("R23.before-apply", "do-not-consume-before-apply", &o);
        t.assert_no_consume("R23", &o);
    }
    // R24. consume attempted after failed apply rejected.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::ApplyFailed, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("R24.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_no_consume("R24", &o);
    }
    // R25. consume attempted after rollback rejected.
    {
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::RolledBack, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("R25.rolled-back", "do-not-consume-rolled-back", &o);
        t.assert_no_consume("R25", &o);
    }
    // R26. consume attempted on validation-only surface rejected.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::LocalPeerCandidateCheck,
            MC::AppliedSuccessfully,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "R26.validation-only",
            "proceed-validation-only-no-consume",
            &o,
        );
        t.assert_no_consume("R26", &o);
    }
    // R27. consume attempted on unsupported surface rejected.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::UnsupportedSurface,
            P::FixtureDevNet,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome(
            "R27.unsupported-surface",
            "do-not-consume-unsupported-surface",
            &o,
        );
        t.assert_no_consume("R27", &o);
    }
    // R28. production consume unavailable rejected.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::AppliedSuccessfully,
            P::Production,
        );
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("R28.production", "production-consume-unavailable", &o);
        t.assert_no_consume("R28", &o);
        t.assert_true(
            "R28.unavailable-guard",
            production_mainnet_consume_remains_unavailable_under_consume_runtime(),
        );
    }
    // R29. MainNet consume unavailable/refused rejected.
    {
        let fx = rotate_fixture(
            Env::Devnet,
            S::ReloadApply,
            MC::AppliedSuccessfully,
            P::MainNet,
        );
        let mut mainnet = MainnetReplayStateReader;
        let replay_ctx = fx.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
        let input = ReplayConsumeRuntimeIntegrationInput {
            replay_runtime: &replay_ctx,
            consume_input: &fx.consume_input,
            consume_expectations: &fx.consume_exp,
            consume_policy: P::MainNet,
        };
        let o = integrate_replay_consume_runtime(&input, &mut mainnet);
        t.check_outcome("R29.mainnet", "mainnet-consume-unavailable", &o);
        t.assert_no_consume("R29", &o);
    }
    // R30. local operator cannot satisfy consume policy.
    t.assert_true(
        "R30.local-operator-cannot",
        local_operator_cannot_satisfy_consume_policy(),
    );
    // R31. peer majority cannot satisfy consume policy.
    t.assert_true(
        "R31.peer-majority-cannot",
        peer_majority_cannot_satisfy_consume_policy(),
    );
    // R32. validator-set rotation unsupported rejected.
    t.assert_true(
        "R32.validator-rotation-unsupported",
        validator_set_rotation_remains_unsupported_under_consume_runtime(),
    );
    // R33. policy-change action unsupported rejected.
    t.assert_true(
        "R33.policy-change-unsupported",
        policy_change_action_remains_unsupported_under_consume_runtime(),
    );
    // R34. rejection produces no Run 070 call, no live trust swap, no session
    // eviction, no sequence write, and no marker write (non-mutating).
    {
        // A failed-apply rejection against a store with a prior observation
        // records no consume.
        let fx = rotate_fixture(Env::Devnet, S::ReloadApply, MC::ApplyFailed, P::FixtureDevNet);
        let mut store = store_with_observation(&fx);
        let o = fx.run(&mut store);
        t.check_outcome("R34.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_true(
            "R34.not-consumed",
            !store.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
        // A replay-side rejection against an empty store records nothing at all.
        let mut fx2 = devnet_success_fixture();
        fx2.replay_input.current_canonical_epoch = EXPIRY + 50;
        let mut empty = FixtureReplayStateStore::new(Env::Devnet);
        let o2 = fx2.run(&mut empty);
        t.assert_true(
            "R34.empty-replay-fail-closed",
            matches!(o2, ReplayConsumeRuntimeOutcome::ReplayRuntimeFailClosed(_)),
        );
        t.assert_true("R34.store-empty", empty.is_empty());
    }
    // R35. MainNet peer-driven apply remains refused and does not consume even if
    // replay state is fresh.
    {
        let o = mainnet_peer_driven_outcome();
        t.check_outcome(
            "R35.mainnet-peer-driven-refused",
            "mainnet-peer-driven-apply-refused",
            &o,
        );
        t.assert_no_consume("R35", &o);
    }

    t.finish(out)
}

// ===========================================================================
// Reachability + invariant + call-site wiring table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationCompletionStatus as MC;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Consume-after-success-only across every completion status (fresh-authorized
    // mutating surface).
    {
        for completion in [
            MC::NotAttempted,
            MC::AuthorizedButNotApplied,
            MC::AppliedSuccessfully,
            MC::ApplyFailed,
            MC::RolledBack,
            MC::ValidationOnly,
            MC::UnsupportedSurface,
        ] {
            let fx = rotate_fixture(Env::Devnet, S::ReloadApply, completion, P::FixtureDevNet);
            let mut store = store_with_observation(&fx);
            let o = fx.run(&mut store);
            let id = format!("AS.completion.{}", completion.tag());
            if completion == MC::AppliedSuccessfully {
                t.assert_true(&id, o.authorizes_consume());
                t.assert_true(
                    &format!("{id}.store-consumed"),
                    store.is_consumed(&fx.consume_input.replay_state_key_digest),
                );
            } else {
                t.assert_true(&id, o.no_consume());
                t.assert_true(
                    &format!("{id}.store-not-consumed"),
                    !store.is_consumed(&fx.consume_input.replay_state_key_digest),
                );
            }
        }
        t.assert_true(
            "AS.fresh-required",
            fresh_required_before_mutation_authorization_under_consume_runtime(),
        );
        t.assert_true(
            "AS.deferred-validation-failed-rollback-no-consume",
            deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime(),
        );
    }

    // Fixture consume without a prior observation fails closed unavailable and
    // records nothing.
    {
        let fx = devnet_success_fixture();
        let mut empty = FixtureReplayStateStore::new(Env::Devnet);
        let o = fx.run(&mut empty);
        t.assert_true(
            "FC.no-observation-fails-closed",
            matches!(o, ReplayConsumeRuntimeOutcome::ConsumeFailClosed { .. }),
        );
        t.assert_true(
            "FC.not-consumed",
            !empty.is_consumed(&fx.consume_input.replay_state_key_digest),
        );
    }

    // Call-site wiring partitions proceed and fail-closed.
    {
        // Proceed (successful consume).
        let fx = devnet_success_fixture();
        let mut store = store_with_observation(&fx);
        t.assert_true("CW.consume-ok", fx.run_callsite(&mut store).is_ok());
        // Fail-closed (failed apply).
        let fx2 = rotate_fixture(Env::Devnet, S::ReloadApply, MC::ApplyFailed, P::FixtureDevNet);
        let mut store2 = store_with_observation(&fx2);
        match fx2.run_callsite(&mut store2) {
            Ok(_) => t.assert_true("CW.apply-failed-err", false),
            Err(o) => t.check_outcome("CW.apply-failed-err", "do-not-consume-apply-failed", &o),
        }
    }

    // Outcome tags reachable / stable.
    {
        t.check(
            "T.consume",
            "consume-fixture-after-mutation-success",
            ReplayConsumeRuntimeOutcome::ConsumeFixtureAfterMutationSuccess.tag(),
        );
        t.check(
            "T.proceed-fresh",
            "proceed-fresh-mutation-authorized",
            ReplayConsumeRuntimeOutcome::ProceedFreshMutationAuthorized.tag(),
        );
        t.check(
            "T.legacy-bypass",
            "proceed-legacy-bypass-no-consume",
            ReplayConsumeRuntimeOutcome::ProceedLegacyBypassNoConsume.tag(),
        );
        t.check(
            "T.deferred",
            "proceed-deferred-no-consume",
            ReplayConsumeRuntimeOutcome::ProceedDeferredNoConsume.tag(),
        );
        t.check(
            "T.validation-only",
            "proceed-validation-only-no-consume",
            ReplayConsumeRuntimeOutcome::ProceedValidationOnlyNoConsume.tag(),
        );
        t.check(
            "T.before-apply",
            "do-not-consume-before-apply",
            ReplayConsumeRuntimeOutcome::DoNotConsumeBeforeApply.tag(),
        );
        t.check(
            "T.apply-failed",
            "do-not-consume-apply-failed",
            ReplayConsumeRuntimeOutcome::DoNotConsumeApplyFailed.tag(),
        );
        t.check(
            "T.rolled-back",
            "do-not-consume-rolled-back",
            ReplayConsumeRuntimeOutcome::DoNotConsumeRolledBack.tag(),
        );
        t.check(
            "T.unsupported-surface",
            "do-not-consume-unsupported-surface",
            ReplayConsumeRuntimeOutcome::DoNotConsumeUnsupportedSurface.tag(),
        );
        t.check(
            "T.mainnet-refused",
            "do-not-consume-mainnet-refused",
            ReplayConsumeRuntimeOutcome::DoNotConsumeMainNetRefused.tag(),
        );
        t.check(
            "T.production-unavailable",
            "production-consume-unavailable",
            ReplayConsumeRuntimeOutcome::ProductionConsumeUnavailable.tag(),
        );
        t.check(
            "T.mainnet-unavailable",
            "mainnet-consume-unavailable",
            ReplayConsumeRuntimeOutcome::MainNetConsumeUnavailable.tag(),
        );
        t.check(
            "T.mainnet-peer-driven-refused",
            "mainnet-peer-driven-apply-refused",
            ReplayConsumeRuntimeOutcome::MainNetPeerDrivenApplyRefused.tag(),
        );
    }

    // Grep-verifiable invariant / fail-closed helper invariants.
    {
        t.assert_true(
            "G.after-success-only",
            consume_integrated_as_after_success_only_post_mutation_step(),
        );
        t.assert_true(
            "G.fresh-required",
            fresh_required_before_mutation_authorization_under_consume_runtime(),
        );
        t.assert_true(
            "G.deferred-validation-failed-rollback-no-consume",
            deferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime(),
        );
        t.assert_true(
            "G.mainnet-refused-mainnet",
            mainnet_peer_driven_apply_remains_refused_under_consume_runtime(Env::Mainnet),
        );
        t.assert_true(
            "G.mainnet-refused-not-devnet",
            !mainnet_peer_driven_apply_remains_refused_under_consume_runtime(Env::Devnet),
        );
        t.assert_true(
            "G.production-mainnet-unavailable",
            production_mainnet_consume_remains_unavailable_under_consume_runtime(),
        );
        t.assert_true(
            "G.validator-rotation-unsupported",
            validator_set_rotation_remains_unsupported_under_consume_runtime(),
        );
        t.assert_true(
            "G.policy-change-unsupported",
            policy_change_action_remains_unsupported_under_consume_runtime(),
        );
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (digests, before/after store snapshots, outcome values).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationCompletionStatus as MC;
    use ReplayStatePolicy as P;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let fx = devnet_success_fixture();
    let key = fx.consume_input.replay_state_key_digest.clone();

    // Deterministic consume digests (Run 234 binding the composed material).
    write_file(
        &dir.join("consume_authorization_digest.txt"),
        &format!("{}\n", consume_authorization_digest(&fx.consume_input)),
    );
    write_file(
        &dir.join("consume_transcript_digest.txt"),
        &format!(
            "{}\n",
            consume_transcript_digest(
                &fx.consume_input,
                &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess,
            )
        ),
    );
    write_file(
        &dir.join("post_mutation_consume_record_digest.txt"),
        &format!(
            "{}\n",
            post_mutation_consume_record_digest(&fx.consume_input, CANONICAL)
        ),
    );
    write_file(&dir.join("replay_state_key_digest.txt"), &format!("{key}\n"));

    // Before/after fixture replay-store snapshots across the composed
    // after-success consume. Consume records consumed only after success.
    let mut store = FixtureReplayStateStore::new(Env::Devnet);
    let snap_before = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    store.record_for(&fx.replay_input);
    let snap_observed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    let outcome = fx.run(&mut store);
    let snap_consumed = format!(
        "outcome={} len={} is_consumed={}\n",
        outcome.tag(),
        store.len(),
        store.is_consumed(&key)
    );
    write_file(
        &dir.join("fixture_store_snapshots.txt"),
        &format!("before:    {snap_before}observed:   {snap_observed}consumed:   {snap_consumed}"),
    );

    // Composed outcome / replay runtime outcome / completion status values for a
    // range of completion states.
    for (label, completion) in [
        ("not_attempted", MC::NotAttempted),
        ("authorized_but_not_applied", MC::AuthorizedButNotApplied),
        ("applied_successfully", MC::AppliedSuccessfully),
        ("apply_failed", MC::ApplyFailed),
        ("rolled_back", MC::RolledBack),
    ] {
        let f = rotate_fixture(Env::Devnet, S::ReloadApply, completion, P::FixtureDevNet);
        let mut s = store_with_observation(&f);
        let replay_ctx = f.replay_context(&FixtureGovernanceExecutionEvaluatorInterface);
        let replay_outcome = integrate_governance_evaluator_replay_runtime(&replay_ctx);
        let o = f.run(&mut s);
        write_file(
            &dir.join(format!("{label}_outcome.txt")),
            &format!(
                "completion={} replay_runtime_outcome={:?} consume_runtime_outcome={:#?}\n",
                completion.tag(),
                replay_outcome,
                o
            ),
        );
    }

    // MainNet-refused composed outcome dump.
    write_file(
        &dir.join("mainnet_refused_outcome.txt"),
        &format!("{:#?}\n", mainnet_peer_driven_outcome()),
    );

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_consume_runtime_integration\n");
    for entry in [
        "type\tReplayConsumeRuntimeIntegrationInput",
        "type\tReplayConsumeRuntimeOutcome",
        "fn\tintegrate_replay_consume_runtime",
        "fn\twire_replay_consume_runtime_callsite",
        "variant\tProceedLegacyBypassNoConsume",
        "variant\tProceedDeferredNoConsume",
        "variant\tProceedValidationOnlyNoConsume",
        "variant\tProceedFreshMutationAuthorized",
        "variant\tConsumeFixtureAfterMutationSuccess",
        "variant\tDoNotConsumeBeforeApply",
        "variant\tDoNotConsumeApplyFailed",
        "variant\tDoNotConsumeRolledBack",
        "variant\tDoNotConsumeUnsupportedSurface",
        "variant\tDoNotConsumeMainNetRefused",
        "variant\tReplayRuntimeFailClosed",
        "variant\tConsumeFailClosed",
        "variant\tProductionConsumeUnavailable",
        "variant\tMainNetConsumeUnavailable",
        "variant\tMainNetPeerDrivenApplyRefused",
        "guard\tconsume_integrated_as_after_success_only_post_mutation_step",
        "guard\tfresh_required_before_mutation_authorization_under_consume_runtime",
        "guard\tdeferred_validation_only_failed_rollback_do_not_consume_under_consume_runtime",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_consume_runtime",
        "guard\tproduction_mainnet_consume_remains_unavailable_under_consume_runtime",
        "guard\tvalidator_set_rotation_remains_unsupported_under_consume_runtime",
        "guard\tpolicy_change_action_remains_unsupported_under_consume_runtime",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("consume_runtime_integration_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper <OUT_DIR>"
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
    let mut summary = String::from("run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper\nscope: Run 236 governance evaluator replay consume runtime integration (pqc_governance_evaluator_replay_consume_runtime_integration: integrate_replay_consume_runtime, wire_replay_consume_runtime_callsite, ReplayConsumeRuntimeIntegrationInput, ReplayConsumeRuntimeOutcome { ProceedLegacyBypassNoConsume, ProceedDeferredNoConsume, ProceedValidationOnlyNoConsume, ProceedFreshMutationAuthorized, ConsumeFixtureAfterMutationSuccess, DoNotConsume{BeforeApply, ApplyFailed, RolledBack, UnsupportedSurface, MainNetRefused}, ReplayRuntimeFailClosed, ConsumeFailClosed, ProductionConsumeUnavailable, MainNetConsumeUnavailable, MainNetPeerDrivenApplyRefused }) exercised through release-built library symbols, composing the real Run 232 replay/freshness runtime integration and the real Run 234 post-mutation consume boundary (release binary)\nnote: fixture-only; pure composition (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no persistent storage); replay/freshness runtime integration runs first and any non-ProceedFresh outcome maps to a non-consuming outcome without calling the writer; fresh is required before mutation authorization; consume is after-success-only — only ConsumeFixtureAfterMutationSuccess (after a Run 232 ProceedFresh and a modeled AppliedSuccessfully) authorizes a fixture consume; deferred/validation-only/before-apply/failed-apply/rolled-back/unsupported-surface/MainNet-refused never consume; the DevNet/TestNet fixture writer records consumed only on the explicit after-success path with a prior observation and a re-validation then classifies the decision already-consumed through Run 230; production/MainNet consume writers are reached but always fail closed unavailable; the consume authorization is overridden with the exact Run 232 freshness result; MainNet peer-driven apply remains refused and never consumes even when fresh; validator-set rotation and policy-change actions unsupported; no RocksDB/file/schema/migration/storage-format change\n\n");
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
