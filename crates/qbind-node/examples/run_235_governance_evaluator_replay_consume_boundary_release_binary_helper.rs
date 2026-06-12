//! Run 235 — release-built helper for the Run 234 governance evaluator
//! **post-mutation replay consume boundary**
//! (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`).
//!
//! Where Run 234 landed the pure post-mutation consume boundary at the
//! source/test level and captured **no** release-binary evidence, Run 235 is
//! that release-binary evidence. This helper drives the A1–A21 / R1–R33 matrix
//! from `task/RUN_235_TASK.txt` through the **release-built** Run 234 symbols
//! (`evaluate_post_mutation_consume`, `perform_post_mutation_consume`, the typed
//! `MutationAuthorizationOutcome` / `MutationCompletionStatus` /
//! `ConsumeBoundaryOutcome`, the deterministic digest helpers, and the
//! grep-verifiable refusal helpers), proving that:
//!
//! * consume is **after-success-only**: only `ConsumeFixtureAfterSuccess` (after
//!   `MutationCompletionStatus::AppliedSuccessfully`) authorizes a fixture
//!   consume;
//! * legacy bypass, deferral, validation-only, authorized-but-not-applied,
//!   failed apply, rolled-back, unsupported surface, and MainNet-refused
//!   outcomes never consume;
//! * the DevNet/TestNet fixture writer records consumed only on an explicit
//!   after-success `perform_post_mutation_consume` call, and a re-validation
//!   then classifies the decision already-consumed through the Run 230 state;
//! * the production / MainNet consume writers are callable but always fail
//!   closed unavailable;
//! * MainNet peer-driven apply remains refused and never consumes even when the
//!   replay state would otherwise be fresh;
//! * the consume authorization / transcript / record digests are deterministic
//!   in release mode and bind the full A15 field set;
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
use qbind_node::pqc_governance_evaluator_replay_consume_boundary::{
    consume_authorization_digest, consume_only_after_successful_mutation,
    consume_transcript_digest, deferred_is_never_consumed, evaluate_post_mutation_consume,
    local_operator_cannot_satisfy_consume_policy,
    mainnet_peer_driven_apply_remains_refused_under_consume_boundary,
    peer_majority_cannot_satisfy_consume_policy, perform_post_mutation_consume,
    policy_change_action_remains_unsupported_under_consume_boundary,
    post_mutation_consume_record_digest, production_mainnet_consume_remains_unavailable,
    surface_is_validation_only, validation_only_is_never_consumed,
    validator_set_rotation_remains_unsupported_under_consume_boundary, ConsumeBoundaryOutcome,
    MutationAuthorizationOutcome, MutationCompletionStatus, PostMutationConsumeExpectations,
    PostMutationConsumeInput,
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
    ProductionReplayStateReader, ReplayStatePolicy,
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
// Shared constants (mirror the Run 220 / 222 / 224 / 230 / 232 / 234 corpora so
// the composed material binds to the same trust domain, proposal/decision
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
const CANONICAL: u64 = 150;

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
// Run 230 freshness input / Run 234 consume input + expectations builders
// ===========================================================================

fn freshness_input(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
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
        validation_surface,
        CANONICAL,
        previously_seen,
    )
}

fn consume_input(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
    mutation_surface: GovernanceExecutionRuntimeSurface,
    auth: MutationAuthorizationOutcome,
    completion: MutationCompletionStatus,
) -> PostMutationConsumeInput {
    let fresh = freshness_input(env, validation_surface, PreviouslySeenState::FirstSeen);
    PostMutationConsumeInput::from_freshness_input(&fresh, mutation_surface, auth, completion)
}

fn consume_exp(
    env: TrustBundleEnvironment,
    validation_surface: GovernanceExecutionRuntimeSurface,
    mutation_surface: GovernanceExecutionRuntimeSurface,
) -> PostMutationConsumeExpectations {
    let fresh = freshness_input(env, validation_surface, PreviouslySeenState::FirstSeen);
    PostMutationConsumeExpectations::from_freshness_input(&fresh, mutation_surface)
}

/// DevNet, mutating ReloadApply surface, authorized-fresh, applied-successfully:
/// the consume-eligible happy path with a wired DevNet fixture policy.
fn devnet_success_input() -> PostMutationConsumeInput {
    consume_input(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        MutationAuthorizationOutcome::AuthorizedFresh,
        MutationCompletionStatus::AppliedSuccessfully,
    )
}

fn devnet_exp() -> PostMutationConsumeExpectations {
    consume_exp(
        TrustBundleEnvironment::Devnet,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    )
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
    fn check_outcome(&mut self, id: &str, expected: &str, o: &ConsumeBoundaryOutcome) {
        self.check(id, expected, o.tag());
    }
    /// Assert a consume outcome is a non-consuming result: it never authorizes a
    /// consume. The boundary is pure, so a non-consume necessarily performs no
    /// marker/sequence write, no live trust swap, no session eviction, and no
    /// Run 070 call.
    fn assert_no_consume(&mut self, id: &str, o: &ConsumeBoundaryOutcome) {
        self.assert_true(&format!("{id}.no-consume"), o.no_consume(), "");
        self.assert_true(
            &format!("{id}.not-authorizes-consume"),
            !o.authorizes_consume(),
            "",
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
// A18 support — full Run 232 integration fixture (compatibility check).
// Mirrors the Run 234 test Fixture so the composed Run 232 outcome can be
// projected into the consume boundary's authorization view.
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

fn ev_request_with_digest(identity: &DecisionSourceIdentity, input_digest: &str) -> EvaluatorRequest {
    let mut request = ev_request(identity);
    request.governance_execution_input_digest = input_digest.to_string();
    request
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

    fn run(&self) -> GovernanceEvaluatorReplayRuntimeOutcome {
        integrate_governance_evaluator_replay_runtime(
            &self.context(&FixtureGovernanceExecutionEvaluatorInterface),
        )
    }
}

fn rotate_fixture(env: TrustBundleEnvironment) -> Fixture {
    let input = rotate_input(env);
    let decision = rotate_decision();
    let input_digest = input.input_digest();
    let identity = ev_identity(env);
    let request = ev_request_with_digest(&identity, &input_digest);
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
        replay_policy: ReplayStatePolicy::FixtureDevNet,
        replay_input,
        replay_exp,
    }
}

// ===========================================================================
// A — accepted / compatible scenarios (A1–A21) exercised through the Run 234
// release-built post-mutation consume boundary symbols.
// ===========================================================================

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationAuthorizationOutcome as MA;
    use MutationCompletionStatus as MC;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — legacy bypass does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::LegacyBypass, MC::NotAttempted);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A1.legacy-bypass", "do-not-consume-legacy-bypass", &o);
        t.assert_no_consume("A1", &o);
    }

    // A2 — ProceedDeferred does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::Deferred, MC::NotAttempted);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A2.deferred", "do-not-consume-deferred", &o);
        t.assert_no_consume("A2", &o);
        t.assert_true("A2.deferred-never-consumed", deferred_is_never_consumed(), "");
    }

    // A3 — validation-only success does not consume.
    {
        let exp = consume_exp(Env::Devnet, S::ReloadCheck, S::ReloadCheck);
        let input = consume_input(Env::Devnet, S::ReloadCheck, S::ReloadCheck, MA::AuthorizedFresh, MC::ValidationOnly);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp);
        t.check_outcome("A3.validation-only", "do-not-consume-validation-only", &o);
        t.assert_no_consume("A3", &o);
    }

    // A4 — authorized-but-not-applied does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AuthorizedButNotApplied);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A4.before-apply", "do-not-consume-before-apply", &o);
        t.assert_no_consume("A4", &o);
    }

    // A5 — apply failed does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::ApplyFailed);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A5.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_no_consume("A5", &o);
    }

    // A6 — rolled back does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::RolledBack);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A6.rolled-back", "do-not-consume-rolled-back", &o);
        t.assert_no_consume("A6", &o);
    }

    // A7 — unsupported surface does not consume.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::UnsupportedSurface);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A7.unsupported-surface", "do-not-consume-unsupported-surface", &o);
        t.assert_no_consume("A7", &o);
    }

    // A8 — MainNet refused does not consume.
    {
        let exp = consume_exp(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain);
        let input = consume_input(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp);
        t.check_outcome("A8.mainnet-refused", "do-not-consume-mainnet-refused", &o);
        t.assert_no_consume("A8", &o);
        t.assert_true(
            "A8.mainnet-refused-guard",
            mainnet_peer_driven_apply_remains_refused_under_consume_boundary(Env::Mainnet),
            "",
        );
    }

    // A9 — DevNet fixture consume records consumed only after AppliedSuccessfully.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let input = devnet_success_input();
        // Pure evaluation authorizes a consume.
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("A9.evaluate", "consume-fixture-after-success", &o);
        t.assert_true("A9.authorizes-consume", o.authorizes_consume(), "");
        // The fixture writer records consumed only after an explicit
        // after-success perform call (with a prior observation).
        t.assert_true("A9.not-consumed-before", !store.is_consumed(&input.replay_state_key_digest), "");
        store.record_for(&freshness_input(Env::Devnet, S::ReloadApply, PreviouslySeenState::FirstSeen));
        let performed = perform_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp(), &mut store);
        t.check_outcome("A9.perform", "consume-fixture-after-success", &performed);
        t.assert_true("A9.consumed-after", store.is_consumed(&input.replay_state_key_digest), "");
    }

    // A10 — TestNet fixture consume records consumed only after AppliedSuccessfully.
    {
        let mut store = FixtureReplayStateStore::new(Env::Testnet);
        let exp = consume_exp(Env::Testnet, S::ReloadApply, S::ReloadApply);
        let input = consume_input(Env::Testnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureTestNet, &input, &exp);
        t.check_outcome("A10.evaluate", "consume-fixture-after-success", &o);
        store.record_for(&freshness_input(Env::Testnet, S::ReloadApply, PreviouslySeenState::FirstSeen));
        let performed = perform_post_mutation_consume(ReplayStatePolicy::FixtureTestNet, &input, &exp, &mut store);
        t.check_outcome("A10.perform", "consume-fixture-after-success", &performed);
        t.assert_true("A10.consumed-after", store.is_consumed(&input.replay_state_key_digest), "");
    }

    // A11 — after fixture consume, the same decision validates as
    // already-consumed / fail-closed through the Run 230 state.
    {
        let env = Env::Devnet;
        let mut store = FixtureReplayStateStore::new(env);
        let fresh = freshness_input(env, S::ReloadApply, PreviouslySeenState::FirstSeen);
        store.record_for(&fresh);
        let input = devnet_success_input();
        let performed = perform_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp(), &mut store);
        t.check_outcome("A11.perform", "consume-fixture-after-success", &performed);
        t.assert_true("A11.consumed", store.is_consumed(&input.replay_state_key_digest), "");
        // Re-validate through the Run 230 state.
        let mut after = freshness_input(env, S::ReloadApply, PreviouslySeenState::FirstSeen);
        after.previously_seen = store.read_for(&after);
        let exp230 = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
            &ev_identity(env), &ev_request(&ev_identity(env)), &ev_response(&ev_request(&ev_identity(env))),
            TRANSCRIPT_DIGEST, DECISION_DIGEST, env, CHAIN, GENESIS, S::ReloadApply,
        );
        t.check(
            "A11.run230-already-consumed",
            "fail-closed-already-consumed",
            match evaluate_evaluator_replay_freshness(&after, &exp230) {
                EvaluatorReplayFreshnessOutcome::FailClosedAlreadyConsumed => "fail-closed-already-consumed",
                _ => "other",
            },
        );
    }

    // A12 — consume authorization digest is deterministic in release mode.
    {
        let input = devnet_success_input();
        let twin = devnet_success_input();
        t.assert_true("A12.stable", consume_authorization_digest(&input) == consume_authorization_digest(&input), "");
        t.assert_true("A12.twin-equal", consume_authorization_digest(&input) == consume_authorization_digest(&twin), "");
    }

    // A13 — consume transcript digest is deterministic in release mode.
    {
        let input = devnet_success_input();
        let oc = ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess;
        t.assert_true("A13.stable", consume_transcript_digest(&input, &oc) == consume_transcript_digest(&input, &oc), "");
        t.assert_true(
            "A13.outcome-bound",
            consume_transcript_digest(&input, &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess)
                != consume_transcript_digest(&input, &ConsumeBoundaryOutcome::DoNotConsumeBeforeApply),
            "",
        );
    }

    // A14 — post-mutation consume record digest is deterministic in release mode.
    {
        let input = devnet_success_input();
        t.assert_true(
            "A14.stable",
            post_mutation_consume_record_digest(&input, CANONICAL) == post_mutation_consume_record_digest(&input, CANONICAL),
            "",
        );
        t.assert_true(
            "A14.epoch-bound",
            post_mutation_consume_record_digest(&input, CANONICAL) != post_mutation_consume_record_digest(&input, CANONICAL + 1),
            "",
        );
    }

    // A15 — consume binding includes every required field: changing any bound
    // field changes the consume authorization digest.
    {
        let base = devnet_success_input();
        let base_digest = consume_authorization_digest(&base);
        let mutators: Vec<(&str, Box<dyn Fn(&mut PostMutationConsumeInput)>)> = vec![
            ("replay_state_key_digest", Box::new(|i: &mut PostMutationConsumeInput| i.replay_state_key_digest = "x".to_string())),
            ("evaluator_request_digest", Box::new(|i| i.evaluator_request_digest = "x".to_string())),
            ("evaluator_response_digest", Box::new(|i| i.evaluator_response_digest = "x".to_string())),
            ("governance_execution_decision_digest", Box::new(|i| i.governance_execution_decision_digest = "x".to_string())),
            ("lifecycle_action", Box::new(|i| i.lifecycle_action = LocalLifecycleAction::Revoke)),
            ("candidate_digest", Box::new(|i| i.candidate_digest = "x".to_string())),
            ("authority_domain_sequence", Box::new(|i| i.authority_domain_sequence += 1)),
            ("replay_nonce", Box::new(|i| i.replay_nonce = "x".to_string())),
            ("environment", Box::new(|i| i.environment = TrustBundleEnvironment::Testnet)),
            ("chain_id", Box::new(|i| i.chain_id = "x".to_string())),
            ("genesis_hash", Box::new(|i| i.genesis_hash = "x".to_string())),
            ("validation_surface", Box::new(|i| i.validation_surface = S::Sighup)),
            ("mutation_surface", Box::new(|i| i.mutation_surface = S::Sighup)),
            ("mutation_completion_status", Box::new(|i| i.mutation_completion_status = MC::ApplyFailed)),
        ];
        for (field, mutate) in &mutators {
            let mut altered = base.clone();
            mutate(&mut altered);
            t.assert_true(
                &format!("A15.binds.{field}"),
                base_digest != consume_authorization_digest(&altered),
                "",
            );
        }
    }

    // A16 — production consume writer is callable and fails closed unavailable.
    {
        let exp = consume_exp(Env::Devnet, S::ReloadApply, S::ReloadApply);
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::Production, &input, &exp);
        t.check_outcome("A16.evaluate", "fail-closed-production-consume-unavailable", &o);
        let mut writer = ProductionReplayStateReader;
        t.assert_true("A16.writer-fails-closed", !writer.mark_consumed(&input.replay_state_key_digest), "");
        let performed = perform_post_mutation_consume(ReplayStatePolicy::Production, &input, &exp, &mut writer);
        t.check_outcome("A16.perform", "fail-closed-production-consume-unavailable", &performed);
    }

    // A17 — MainNet consume writer is callable and fails closed unavailable/refused.
    {
        // Non-peer-driven MainNet surface so the MainNet-refusal guard does not
        // pre-empt the consume-policy unavailability path.
        let exp = consume_exp(Env::Mainnet, S::ReloadApply, S::ReloadApply);
        let input = consume_input(Env::Mainnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp);
        t.check_outcome("A17.evaluate", "fail-closed-mainnet-consume-unavailable", &o);
        let mut writer = MainnetReplayStateReader;
        t.assert_true("A17.writer-fails-closed", !writer.mark_consumed(&input.replay_state_key_digest), "");
        let performed = perform_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp, &mut writer);
        t.check_outcome("A17.perform", "fail-closed-mainnet-consume-unavailable", &performed);
    }

    // A18 — Run 232 replay/freshness runtime integration remains compatible when
    // the consume boundary is not wired; its outcome projects into the
    // authorization view.
    {
        let fx = rotate_fixture(Env::Devnet);
        let outcome = fx.run();
        t.assert_true(
            "A18.run232-proceed-fresh",
            matches!(outcome, GovernanceEvaluatorReplayRuntimeOutcome::ProceedFresh { .. }),
            "",
        );
        t.check(
            "A18.projects-authorized-fresh",
            "authorized-fresh",
            MutationAuthorizationOutcome::from_replay_runtime_outcome(&outcome).tag(),
        );
        t.check(
            "A18.projects-legacy-bypass",
            "legacy-bypass",
            MutationAuthorizationOutcome::from_replay_runtime_outcome(
                &GovernanceEvaluatorReplayRuntimeOutcome::ProceedLegacyBypass,
            )
            .tag(),
        );
        t.check(
            "A18.projects-deferred",
            "deferred",
            MutationAuthorizationOutcome::from_replay_runtime_outcome(
                &GovernanceEvaluatorReplayRuntimeOutcome::ProceedDeferred,
            )
            .tag(),
        );
        t.check(
            "A18.projects-mainnet-refused",
            "mainnet-refused",
            MutationAuthorizationOutcome::from_replay_runtime_outcome(
                &GovernanceEvaluatorReplayRuntimeOutcome::MainNetPeerDrivenApplyRefused,
            )
            .tag(),
        );
    }

    // A19 — Run 233 release behavior remains compatible: a fresh consume input
    // references exactly the Run 230 replay state key digest the composed Run
    // 232/233 integration would bind.
    {
        let fresh = freshness_input(Env::Devnet, S::ReloadApply, PreviouslySeenState::FirstSeen);
        let input = devnet_success_input();
        t.check("A19.run230-key-matches", &replay_state_key_digest(&fresh), &input.replay_state_key_digest);
    }

    // A20 — Run 231 replay/freshness standalone release behavior remains
    // compatible: the standalone boundary still classifies a fresh first-seen
    // decision ProceedFresh.
    {
        let fresh = freshness_input(Env::Devnet, S::ReloadApply, PreviouslySeenState::FirstSeen);
        let exp230 = EvaluatorReplayFreshnessExpectations::from_evaluator_material(
            &ev_identity(Env::Devnet), &ev_request(&ev_identity(Env::Devnet)),
            &ev_response(&ev_request(&ev_identity(Env::Devnet))), TRANSCRIPT_DIGEST, DECISION_DIGEST,
            Env::Devnet, CHAIN, GENESIS, S::ReloadApply,
        );
        t.check(
            "A20.run230-alone-fresh",
            "proceed-fresh",
            match evaluate_evaluator_replay_freshness(&fresh, &exp230) {
                EvaluatorReplayFreshnessOutcome::ProceedFresh => "proceed-fresh",
                _ => "other",
            },
        );
    }

    // A21 — Run 229 peer evaluator-context release behavior remains compatible:
    // a live-inbound peer-candidate surface is validation-only and never
    // consumes through the consume boundary.
    {
        let exp = consume_exp(Env::Devnet, S::LiveInbound0x05, S::LiveInbound0x05);
        let input = consume_input(Env::Devnet, S::LiveInbound0x05, S::LiveInbound0x05, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp);
        t.check_outcome("A21.live-inbound-validation-only", "do-not-consume-validation-only", &o);
        t.assert_no_consume("A21", &o);
        t.assert_true("A21.surface-validation-only", surface_is_validation_only(S::LiveInbound0x05), "");
    }

    t.finish(out)
}

// ===========================================================================
// R — rejection scenarios (R1–R33).
// ===========================================================================

/// Build a consume-eligible DevNet input (authorized-fresh, applied-successfully,
/// mutating surfaces) so a single wrong binding field is the only reason a
/// consume is refused.
fn wrong_binding_base() -> PostMutationConsumeInput {
    devnet_success_input()
}

fn assert_wrong_binding(t: &mut Table, id: &str, mutate: impl FnOnce(&mut PostMutationConsumeInput)) {
    let mut input = wrong_binding_base();
    mutate(&mut input);
    let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
    t.assert_true(
        &format!("{id}.is-wrong-binding"),
        matches!(o, ConsumeBoundaryOutcome::FailClosedWrongBinding { .. }),
        "",
    );
    t.assert_true(&format!("{id}.is-fail-closed"), o.is_fail_closed(), "");
    t.assert_no_consume(id, &o);
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationAuthorizationOutcome as MA;
    use MutationCompletionStatus as MC;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1–R19 — wrong-binding rejections.
    assert_wrong_binding(&mut t, "R1.wrong-replay-state-key", |i| i.replay_state_key_digest = "wrong-key".to_string());
    assert_wrong_binding(&mut t, "R2.wrong-source-identity", |i| i.evaluator_source_identity_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R3.wrong-request", |i| i.evaluator_request_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R4.wrong-response", |i| i.evaluator_response_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R5.wrong-transcript", |i| i.evaluator_transcript_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R6.wrong-decision-digest", |i| i.governance_execution_decision_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R7.wrong-proposal", |i| i.proposal_id = "wrong".to_string());
    assert_wrong_binding(&mut t, "R8.wrong-decision-id", |i| i.decision_id = "wrong".to_string());
    assert_wrong_binding(&mut t, "R9.wrong-lifecycle", |i| i.lifecycle_action = LocalLifecycleAction::Revoke);
    assert_wrong_binding(&mut t, "R10.wrong-candidate", |i| i.candidate_digest = "wrong".to_string());
    assert_wrong_binding(&mut t, "R11.wrong-sequence", |i| i.authority_domain_sequence = SEQUENCE + 1);
    assert_wrong_binding(&mut t, "R12.wrong-effective-epoch", |i| i.effective_epoch = EFFECTIVE + 1);
    assert_wrong_binding(&mut t, "R13.wrong-expiry-epoch", |i| i.expiry_epoch = EXPIRY + 1);
    assert_wrong_binding(&mut t, "R14.wrong-replay-nonce", |i| i.replay_nonce = "wrong".to_string());
    assert_wrong_binding(&mut t, "R15.wrong-environment", |i| i.environment = TrustBundleEnvironment::Testnet);
    assert_wrong_binding(&mut t, "R16.wrong-chain", |i| i.chain_id = "wrong-chain".to_string());
    assert_wrong_binding(&mut t, "R17.wrong-genesis", |i| i.genesis_hash = "wrong-genesis".to_string());
    // A different, still-mutating surface so the validation-only short-circuit
    // does not pre-empt the binding mismatch.
    assert_wrong_binding(&mut t, "R18.wrong-validation-surface", |i| i.validation_surface = S::Sighup);
    assert_wrong_binding(&mut t, "R19.wrong-mutation-surface", |i| i.mutation_surface = S::Sighup);

    // R20 — consume attempted before apply rejected.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::NotAttempted);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("R20.before-apply", "do-not-consume-before-apply", &o);
        t.assert_no_consume("R20", &o);
    }

    // R21 — consume attempted after failed apply rejected.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::ApplyFailed);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("R21.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_no_consume("R21", &o);
    }

    // R22 — consume attempted after rollback rejected.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::RolledBack);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("R22.rolled-back", "do-not-consume-rolled-back", &o);
        t.assert_no_consume("R22", &o);
    }

    // R23 — consume attempted on a validation-only surface rejected.
    {
        let exp = consume_exp(Env::Devnet, S::LocalPeerCandidateCheck, S::LocalPeerCandidateCheck);
        let input = consume_input(Env::Devnet, S::LocalPeerCandidateCheck, S::LocalPeerCandidateCheck, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp);
        t.check_outcome("R23.validation-only", "do-not-consume-validation-only", &o);
        t.assert_no_consume("R23", &o);
    }

    // R24 — consume attempted on an unsupported surface rejected.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::UnsupportedSurface);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.check_outcome("R24.unsupported-surface", "do-not-consume-unsupported-surface", &o);
        t.assert_no_consume("R24", &o);
    }

    // R25 — production consume unavailable rejected.
    {
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::Production, &input, &devnet_exp());
        t.check_outcome("R25.production-unavailable", "fail-closed-production-consume-unavailable", &o);
        t.assert_no_consume("R25", &o);
        t.assert_true("R25.prod-mainnet-unavailable", production_mainnet_consume_remains_unavailable(), "");
    }

    // R26 — MainNet consume unavailable/refused rejected.
    {
        let exp = consume_exp(Env::Mainnet, S::ReloadApply, S::ReloadApply);
        let input = consume_input(Env::Mainnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp);
        t.check_outcome("R26.mainnet-unavailable", "fail-closed-mainnet-consume-unavailable", &o);
        t.assert_no_consume("R26", &o);
    }

    // R27 — local operator cannot satisfy consume policy.
    t.assert_true("R27.local-operator-cannot", local_operator_cannot_satisfy_consume_policy(), "");
    // R28 — peer majority cannot satisfy consume policy.
    t.assert_true("R28.peer-majority-cannot", peer_majority_cannot_satisfy_consume_policy(), "");
    // R29 — validator-set rotation unsupported rejected.
    t.assert_true("R29.validator-rotation-unsupported", validator_set_rotation_remains_unsupported_under_consume_boundary(), "");
    // R30 — policy-change action unsupported rejected.
    t.assert_true("R30.policy-change-unsupported", policy_change_action_remains_unsupported_under_consume_boundary(), "");

    // R31 — malformed consume state rejected (empty mandatory field).
    {
        let mut input = wrong_binding_base();
        input.replay_state_key_digest = String::new();
        t.assert_true("R31.not-well-formed", !input.is_well_formed(), "");
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
        t.assert_true("R31.is-wrong-binding", matches!(o, ConsumeBoundaryOutcome::FailClosedWrongBinding { .. }), "");
        t.assert_no_consume("R31", &o);
    }

    // R32 — consume rejection produces no consume and no observation: no Run 070
    // call, no live trust swap, no session eviction, no sequence write, no
    // marker write. Performed against a fixture store that records nothing.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        t.assert_true("R32.store-empty-before", store.is_empty(), "");
        let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, MC::ApplyFailed);
        let o = perform_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp(), &mut store);
        t.check_outcome("R32.apply-failed", "do-not-consume-apply-failed", &o);
        t.assert_true("R32.store-empty-after", store.is_empty(), "");
        t.assert_true("R32.not-consumed", !store.is_consumed(&input.replay_state_key_digest), "");
    }

    // R33 — MainNet peer-driven apply remains refused and does not consume even
    // when the replay state is fresh.
    {
        let exp = consume_exp(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain);
        let input = consume_input(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let o = perform_post_mutation_consume(ReplayStatePolicy::MainNet, &input, &exp, &mut store);
        t.check_outcome("R33.mainnet-refused", "do-not-consume-mainnet-refused", &o);
        t.assert_no_consume("R33", &o);
        t.assert_true("R33.store-empty", store.is_empty(), "");
    }

    t.finish(out)
}

// ===========================================================================
// Reachability + invariant table.
// ===========================================================================

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationAuthorizationOutcome as MA;
    use MutationCompletionStatus as MC;
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Consume-after-success-only across every completion status.
    {
        for completion in [
            MC::NotAttempted,
            MC::AuthorizedButNotApplied,
            MC::AppliedSuccessfully,
            MC::ApplyFailed,
            MC::RolledBack,
            MC::ValidationOnly,
            MC::UnsupportedSurface,
            MC::MainNetRefused,
        ] {
            let input = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, MA::AuthorizedFresh, completion);
            let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp());
            let id = format!("AS.completion.{}", completion.tag());
            if completion == MC::AppliedSuccessfully {
                t.assert_true(&id, o.authorizes_consume(), "");
            } else {
                t.assert_true(&id, o.no_consume(), "");
            }
        }
        t.assert_true("AS.invariant", consume_only_after_successful_mutation(), "");
    }

    // Validation-only surfaces never consume.
    {
        for surface in [S::ReloadCheck, S::LocalPeerCandidateCheck, S::LiveInbound0x05] {
            t.assert_true(&format!("VO.is-validation-only.{}", surface.tag()), surface_is_validation_only(surface), "");
            let exp = consume_exp(Env::Devnet, surface, surface);
            let input = consume_input(Env::Devnet, surface, surface, MA::AuthorizedFresh, MC::AppliedSuccessfully);
            let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &exp);
            t.check_outcome(&format!("VO.outcome.{}", surface.tag()), "do-not-consume-validation-only", &o);
        }
        t.assert_true("VO.invariant", validation_only_is_never_consumed(), "");
    }

    // Disabled-policy consume fails closed unavailable.
    {
        let input = devnet_success_input();
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::Disabled, &input, &devnet_exp());
        t.check_outcome("DP.disabled-fails-closed", "fail-closed-consume-unavailable", &o);
    }

    // Fixture consume without a prior observation fails closed unavailable.
    {
        let mut store = FixtureReplayStateStore::new(Env::Devnet);
        let input = devnet_success_input();
        let o = perform_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp(), &mut store);
        t.check_outcome("FC.no-observation-fails-closed", "fail-closed-consume-unavailable", &o);
        t.assert_true("FC.not-consumed", !store.is_consumed(&input.replay_state_key_digest), "");
    }

    // Outcome / status tags reachable / stable.
    {
        t.check("T.consume", "consume-fixture-after-success", ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess.tag());
        t.check("T.do-not-consume-deferred", "do-not-consume-deferred", ConsumeBoundaryOutcome::DoNotConsumeDeferred.tag());
        t.check("T.fail-closed-production", "fail-closed-production-consume-unavailable", ConsumeBoundaryOutcome::FailClosedProductionConsumeUnavailable.tag());
        t.check("T.fail-closed-mainnet", "fail-closed-mainnet-consume-unavailable", ConsumeBoundaryOutcome::FailClosedMainNetConsumeUnavailable.tag());
        t.check("T.auth-authorized-fresh", "authorized-fresh", MA::AuthorizedFresh.tag());
        t.check("T.completion-applied", "applied-successfully", MC::AppliedSuccessfully.tag());
        t.assert_true("T.authorizes-mutation", MA::AuthorizedFresh.authorizes_mutation(), "");
        t.assert_true("T.applied-is-success", MC::AppliedSuccessfully.is_applied_successfully(), "");
    }

    // Grep-verifiable refusal / fail-closed helper invariants.
    {
        t.assert_true("G.mainnet-refused-mainnet", mainnet_peer_driven_apply_remains_refused_under_consume_boundary(Env::Mainnet), "");
        t.assert_true("G.mainnet-refused-not-devnet", !mainnet_peer_driven_apply_remains_refused_under_consume_boundary(Env::Devnet), "");
        t.assert_true("G.consume-after-success-only", consume_only_after_successful_mutation(), "");
        t.assert_true("G.deferred-never-consumed", deferred_is_never_consumed(), "");
        t.assert_true("G.validation-only-never-consumed", validation_only_is_never_consumed(), "");
        t.assert_true("G.production-mainnet-unavailable", production_mainnet_consume_remains_unavailable(), "");
        t.assert_true("G.local-operator-cannot", local_operator_cannot_satisfy_consume_policy(), "");
        t.assert_true("G.peer-majority-cannot", peer_majority_cannot_satisfy_consume_policy(), "");
        t.assert_true("G.validator-rotation-unsupported", validator_set_rotation_remains_unsupported_under_consume_boundary(), "");
        t.assert_true("G.policy-change-unsupported", policy_change_action_remains_unsupported_under_consume_boundary(), "");
    }

    t.finish(out)
}

// ===========================================================================
// Fixture dump (digests, before/after store snapshots, outcome values).
// ===========================================================================

fn run_fixture_dump(out: &Path) {
    use GovernanceExecutionRuntimeSurface as S;
    use MutationAuthorizationOutcome as MA;
    use MutationCompletionStatus as MC;
    use TrustBundleEnvironment as Env;
    let dir = out.join("fixtures");

    let input = devnet_success_input();

    // Deterministic consume digests.
    write_file(&dir.join("consume_authorization_digest.txt"), &format!("{}\n", consume_authorization_digest(&input)));
    write_file(
        &dir.join("consume_transcript_digest.txt"),
        &format!("{}\n", consume_transcript_digest(&input, &ConsumeBoundaryOutcome::ConsumeFixtureAfterSuccess)),
    );
    write_file(
        &dir.join("post_mutation_consume_record_digest.txt"),
        &format!("{}\n", post_mutation_consume_record_digest(&input, CANONICAL)),
    );
    write_file(&dir.join("replay_state_key_digest.txt"), &format!("{}\n", input.replay_state_key_digest));

    // Consume boundary outcome values.
    write_file(
        &dir.join("consume_after_success_outcome.txt"),
        &format!("{:#?}\n", evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp())),
    );

    // Before/after fixture replay-store snapshots across an explicit after-success
    // consume. Consume records consumed only after success.
    let mut store = FixtureReplayStateStore::new(Env::Devnet);
    let key = input.replay_state_key_digest.clone();
    let snap_before = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    store.record_for(&freshness_input(Env::Devnet, S::ReloadApply, PreviouslySeenState::FirstSeen));
    let snap_observed = format!("len={} is_consumed={}\n", store.len(), store.is_consumed(&key));
    let performed = perform_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &input, &devnet_exp(), &mut store);
    let snap_consumed = format!(
        "outcome={} len={} is_consumed={}\n",
        performed.tag(),
        store.len(),
        store.is_consumed(&key)
    );
    write_file(
        &dir.join("fixture_store_snapshots.txt"),
        &format!("before:    {}observed:   {}consumed:   {}", snap_before, snap_observed, snap_consumed),
    );

    // Non-consume outcome dumps with mutation completion status values.
    for (label, completion) in [
        ("deferred", MC::NotAttempted),
        ("before_apply", MC::AuthorizedButNotApplied),
        ("apply_failed", MC::ApplyFailed),
        ("rolled_back", MC::RolledBack),
    ] {
        let auth = if label == "deferred" { MA::Deferred } else { MA::AuthorizedFresh };
        let i = consume_input(Env::Devnet, S::ReloadApply, S::ReloadApply, auth, completion);
        let o = evaluate_post_mutation_consume(ReplayStatePolicy::FixtureDevNet, &i, &devnet_exp());
        write_file(
            &dir.join(format!("{label}_outcome.txt")),
            &format!("auth={} completion={} outcome={:#?}\n", auth.tag(), completion.tag(), o),
        );
    }

    // MainNet-refused outcome dump.
    {
        let exp = consume_exp(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain);
        let i = consume_input(Env::Mainnet, S::PeerDrivenDrain, S::PeerDrivenDrain, MA::AuthorizedFresh, MC::AppliedSuccessfully);
        write_file(
            &dir.join("mainnet_refused_outcome.txt"),
            &format!("{:#?}\n", evaluate_post_mutation_consume(ReplayStatePolicy::MainNet, &i, &exp)),
        );
    }

    // Symbol inventory.
    let mut inv = String::new();
    inv.push_str("module\tpqc_governance_evaluator_replay_consume_boundary\n");
    for entry in [
        "type\tPostMutationConsumeInput",
        "type\tPostMutationConsumeExpectations",
        "type\tMutationAuthorizationOutcome",
        "type\tMutationCompletionStatus",
        "type\tConsumeBoundaryOutcome",
        "variant\tConsumeFixtureAfterSuccess",
        "variant\tDoNotConsumeBeforeApply",
        "variant\tDoNotConsumeMainNetRefused",
        "variant\tFailClosedConsumeUnavailable",
        "variant\tFailClosedProductionConsumeUnavailable",
        "variant\tFailClosedMainNetConsumeUnavailable",
        "variant\tFailClosedWrongBinding",
        "fn\tevaluate_post_mutation_consume",
        "fn\tperform_post_mutation_consume",
        "fn\tconsume_authorization_digest",
        "fn\tconsume_transcript_digest",
        "fn\tpost_mutation_consume_record_digest",
        "guard\tmainnet_peer_driven_apply_remains_refused_under_consume_boundary",
        "guard\tconsume_only_after_successful_mutation",
        "guard\tdeferred_is_never_consumed",
        "guard\tvalidation_only_is_never_consumed",
        "guard\tproduction_mainnet_consume_remains_unavailable",
        "guard\tlocal_operator_cannot_satisfy_consume_policy",
        "guard\tpeer_majority_cannot_satisfy_consume_policy",
        "guard\tvalidator_set_rotation_remains_unsupported_under_consume_boundary",
        "guard\tpolicy_change_action_remains_unsupported_under_consume_boundary",
    ] {
        inv.push_str(&format!("{entry}\n"));
    }
    write_file(&dir.join("consume_boundary_inventory.txt"), &inv);
}

fn main() {
    let out_dir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!(
            "usage: run_235_governance_evaluator_replay_consume_boundary_release_binary_helper <OUT_DIR>"
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
    let mut summary = String::from("run_235_governance_evaluator_replay_consume_boundary_release_binary_helper\nscope: Run 234 governance evaluator post-mutation replay consume boundary (pqc_governance_evaluator_replay_consume_boundary: evaluate_post_mutation_consume, perform_post_mutation_consume, MutationAuthorizationOutcome, MutationCompletionStatus, ConsumeBoundaryOutcome { DoNotConsume{LegacyBypass, Deferred, ValidationOnly, BeforeApply, ApplyFailed, RolledBack, UnsupportedSurface, MainNetRefused}, ConsumeFixtureAfterSuccess, FailClosed{ConsumeUnavailable, ProductionConsumeUnavailable, MainNetConsumeUnavailable, WrongBinding} }, consume_authorization_digest, consume_transcript_digest, post_mutation_consume_record_digest) exercised through release-built library symbols (release binary)\nnote: fixture-only; pure boundary (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call, no persistent storage); consume is after-success-only — only ConsumeFixtureAfterSuccess (after AppliedSuccessfully) authorizes a fixture consume; legacy-bypass/deferred/validation-only/authorized-but-not-applied/failed-apply/rolled-back/unsupported-surface/MainNet-refused never consume; the DevNet/TestNet fixture writer records consumed only after an explicit after-success perform call and a re-validation then classifies the decision already-consumed through Run 230; production/MainNet consume writers are callable but always fail closed unavailable; MainNet peer-driven apply remains refused and never consumes even when fresh; validator-set rotation and policy-change actions unsupported; no RocksDB/file/schema/migration/storage-format change\n\n");
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
