//! Run 214 — release-built helper that exercises the Run 213 **governance
//! execution payload carrying and production-context call-site wiring**
//! ([`qbind_node::pqc_governance_execution_payload_carrying`]) **in release
//! mode** through the production library symbols.
//!
//! Per `task/RUN_214_TASK.txt`, Run 214 is the release-binary evidence run
//! for the Run 213 source/test governance-execution payload carrying and
//! production-context preflight wiring (which itself layers over the Run 211
//! governance execution policy boundary). This helper is fixture-only tooling
//! and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, or
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond Run 213's additive optional `governance_execution`
//!   sibling on the v2 ratification sidecar JSON;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every wire conversion, sibling parse, load-status routing helper, and
//!   Run 211 evaluator exercised here is a pure function returning an owned
//!   typed outcome (the v2-sidecar loader performs read-only, in-memory
//!   parsing of bytes the helper itself produced);
//! * does NOT open any P2P socket and performs no network or backend I/O;
//! * does NOT implement any real governance execution engine, real
//!   on-chain governance proof verifier, real KMS/HSM backend, real
//!   RemoteSigner backend, or validator-set rotation; production / on-chain
//!   / MainNet governance execution always fails closed as unavailable;
//! * never elevates the DevNet/TestNet fixture governance execution into
//!   MainNet production governance (MainNet peer-driven apply always
//!   refuses at the typed peer-driven-drain boundary);
//! * exists alongside (and does NOT replace) the Run 213 source/test target
//!   `crates/qbind-node/tests/run_213_governance_execution_payload_callsite_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. legacy no-governance-execution payloads remain compatible under the
//!    default `Disabled` policy (absent carrier bypasses);
//! 2. fixture governance-execution material carried through the v2 sidecar
//!    sibling reaches the seven production-context call-site helpers and is
//!    accepted on DevNet/TestNet only under the explicit fixture policy;
//! 3. production / on-chain / MainNet governance-execution material reaches
//!    the Run 211 evaluator and fails closed as unavailable;
//! 4. malformed / unsupported-schema / required-but-absent carriers fail
//!    closed BEFORE the evaluator (no mutation);
//! 5. input/decision/transcript/policy digests stay deterministic and
//!    domain-bound through wire conversion;
//! 6. a lifecycle action is authorized only when the action, candidate
//!    digest, and sequence all match;
//! 7. validator-set rotation and policy-change actions remain unsupported;
//! 8. rejected carriers route with no mutation (pure, repeat-stable owned
//!    outcomes);
//! 9. MainNet peer-driven apply remains refused even with a fully-valid
//!    fixture governance approval;
//! 10. no real governance execution engine / on-chain proof verifier /
//!     KMS-HSM backend / RemoteSigner backend / validator-set rotation is
//!     claimed.
//!
//! Usage:
//! ```text
//! run_214_governance_execution_payload_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_execution_payload_carrying::{
    callsite_context_for_governance_execution, evaluate_loaded_governance_execution,
    evaluate_loaded_governance_execution_with_peer_driven_guard,
    load_v2_ratification_sidecar_with_governance_execution_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying,
    parse_optional_governance_execution_sibling_from_json_value,
    route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision,
    route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision,
    route_loaded_governance_execution_to_peer_driven_drain_callsite_decision,
    route_loaded_governance_execution_to_reload_apply_callsite_decision,
    route_loaded_governance_execution_to_reload_check_callsite_decision,
    route_loaded_governance_execution_to_sighup_callsite_decision,
    route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision,
    GovernanceExecutionActionWire, GovernanceExecutionCallsiteContext,
    GovernanceExecutionClassWire, GovernanceExecutionDecisionWire, GovernanceExecutionInputWire,
    GovernanceExecutionLoadStatus, GovernanceExecutionPayloadCarryingDecisionOutcome,
    GovernanceExecutionPayloadWire, GovernanceExecutionParts, GovernanceExecutionWireParseError,
    GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD, GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    governance_execution_policy_digest, governance_execution_transcript_digest, GovernanceAction,
    GovernanceExecutionClass, GovernanceExecutionComposedOutcome, GovernanceExecutionDecision,
    GovernanceExecutionExpectations, GovernanceExecutionInput, GovernanceExecutionOutcome,
    GovernanceExecutionPolicy, GovernanceQuorumThreshold,
    GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 211/213 source/test
// fixtures so the typed governance-execution semantics carry over end-to-end
// in release mode through the wire/carrying layer.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 213 source/test corpus exactly.
// ---------------------------------------------------------------------------

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
        authority_domain_sequence: 7,
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        effective_epoch: 100,
        expiry_epoch: 200,
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
        authorized_sequence: 7,
        effective_epoch: 100,
        expiry_epoch: 200,
        decision_commitment: "decision-commitment-eeeeeeeeeeeeeeeeeeee".to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        emergency_flag: false,
        replay_nonce: NONCE.to_string(),
    }
}

fn rotate_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
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
        expected_authority_domain_sequence: 7,
        expected_governance_proof_digest: GOV_PROOF.to_string(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_effective_epoch: 100,
        expected_replay_nonce: NONCE.to_string(),
        now_epoch: 150,
    }
}

fn revoke_triple(
    env: TrustBundleEnvironment,
) -> (
    GovernanceExecutionInput,
    GovernanceExecutionDecision,
    GovernanceExecutionExpectations,
) {
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    input.revoked_signing_key_fingerprint = Some(CUR_KEY.to_string());
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::Revoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    (input, decision, exp)
}

fn emergency_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::EmergencyCouncilFixture;
    input.governance_action = GovernanceAction::EmergencyRevoke;
    input.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    input.emergency_flag = true;
    input.revoked_signing_key_fingerprint = Some(CUR_KEY.to_string());
    input
}

fn emergency_decision() -> GovernanceExecutionDecision {
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::EmergencyRevoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    decision.emergency_flag = true;
    decision.issuer_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
    decision
}

fn emergency_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::EmergencyRevoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    exp
}

// ---------------------------------------------------------------------------
// Wire-carrying helpers — produce a typed `Available` load status by
// round-tripping the in-process parts through the Run 213 wire form (and, for
// the loader cases, through a JSON v2-sidecar sibling).
// ---------------------------------------------------------------------------

/// Build a `GovernanceExecutionLoadStatus::Available` by round-tripping
/// input + decision -> wire -> parts (the production conversion path).
fn available_from(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts to parts"))
}

/// Build an `Available` load status by round-tripping through a JSON sibling
/// value — exercises the full serialize/parse path used in production.
fn available_via_json(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    let value = serde_json::json!({
        GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_governance_execution_sibling_from_json_value(&value)
}

/// Build a v2 ratification sidecar JSON document, optionally carrying a
/// `governance_execution` sibling, exactly as Run 213's loader expects.
fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    sibling: Option<serde_json::Value>,
) -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
    use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
    use qbind_ledger::RatificationEnvironment;

    let ratification_env = match env {
        TrustBundleEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        TrustBundleEnvironment::Testnet => RatificationEnvironment::Testnet,
        TrustBundleEnvironment::Devnet => RatificationEnvironment::Devnet,
    };
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (target_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let mut auth_pk_hex = String::with_capacity(auth_pk.len() * 2);
    for b in &auth_pk {
        use std::fmt::Write;
        let _ = write!(&mut auth_pk_hex, "{:02x}", b);
    }
    let genesis_hash: qbind_ledger::genesis::GenesisHash = [0xaa; 32];
    let v2 = build_signed_ratification_v2(
        CHAIN,
        ratification_env,
        genesis_hash,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44 as u32,
        &auth_pk_hex,
        &auth_sk,
        &target_pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some("aa".repeat(20)),
        Some("bb".repeat(20)),
        None,
        None,
        None,
        None,
    );
    let mut value = serde_json::to_value(&v2).expect("ratification serializes");
    if let Some(p) = sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn outcome_tag(outcome: &GovernanceExecutionOutcome) -> &'static str {
    use GovernanceExecutionOutcome as O;
    match outcome {
        O::FixtureGovernanceAccepted { .. } => "accept:FixtureGovernanceAccepted",
        O::EmergencyCouncilFixtureAccepted { .. } => "accept:EmergencyCouncilFixtureAccepted",
        O::GovernanceExecutionDisabled => "reject:GovernanceExecutionDisabled",
        O::FixtureRejectedProductionRequired => "reject:FixtureRejectedProductionRequired",
        O::FixtureRejectedMainnetRequired => "reject:FixtureRejectedMainnetRequired",
        O::EmergencyFixtureRejectedProductionRequired => {
            "reject:EmergencyFixtureRejectedProductionRequired"
        }
        O::EmergencyFixtureRejectedMainnetRequired => {
            "reject:EmergencyFixtureRejectedMainnetRequired"
        }
        O::ProductionGovernanceUnavailable => "reject:ProductionGovernanceUnavailable",
        O::OnChainGovernanceUnavailable => "reject:OnChainGovernanceUnavailable",
        O::MainNetGovernanceUnavailable => "reject:MainNetGovernanceUnavailable",
        O::GovernanceClassPolicyMismatch { .. } => "reject:GovernanceClassPolicyMismatch",
        O::UnknownGovernanceClassRejected { .. } => "reject:UnknownGovernanceClassRejected",
        O::FixtureRejectedForMainNet => "reject:FixtureRejectedForMainNet",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongLifecycleAction { .. } => "reject:WrongLifecycleAction",
        O::WrongCandidateDigest { .. } => "reject:WrongCandidateDigest",
        O::WrongAuthorityDomainSequence { .. } => "reject:WrongAuthorityDomainSequence",
        O::WrongGovernanceProofDigest { .. } => "reject:WrongGovernanceProofDigest",
        O::WrongOnChainProofDigest { .. } => "reject:WrongOnChainProofDigest",
        O::WrongCustodyAttestationDigest { .. } => "reject:WrongCustodyAttestationDigest",
        O::WrongProposalId { .. } => "reject:WrongProposalId",
        O::WrongDecisionId { .. } => "reject:WrongDecisionId",
        O::WrongEffectiveEpoch { .. } => "reject:WrongEffectiveEpoch",
        O::ExpiredDecision { .. } => "reject:ExpiredDecision",
        O::StaleOrReplayedDecision => "reject:StaleOrReplayedDecision",
        O::QuorumThresholdInsufficient { .. } => "reject:QuorumThresholdInsufficient",
        O::EmergencyActionNotAuthorized => "reject:EmergencyActionNotAuthorized",
        O::ValidatorSetRotationUnsupported => "reject:ValidatorSetRotationUnsupported",
        O::PolicyChangeActionUnsupported => "reject:PolicyChangeActionUnsupported",
        O::GovernanceDecisionRejected => "reject:GovernanceDecisionRejected",
        O::MalformedExecutionInput { .. } => "reject:MalformedExecutionInput",
        O::MalformedExecutionDecision { .. } => "reject:MalformedExecutionDecision",
        O::UnsupportedGovernanceExecutionVersion { .. } => {
            "reject:UnsupportedGovernanceExecutionVersion"
        }
        O::LocalOperatorCannotSatisfyGovernanceExecution => {
            "reject:LocalOperatorCannotSatisfyGovernanceExecution"
        }
        O::PeerMajorityCannotSatisfyGovernanceExecution => {
            "reject:PeerMajorityCannotSatisfyGovernanceExecution"
        }
    }
}

fn decision_tag(outcome: &GovernanceExecutionPayloadCarryingDecisionOutcome) -> String {
    use GovernanceExecutionPayloadCarryingDecisionOutcome as D;
    match outcome {
        D::MalformedGovernanceExecutionPayload(_) => {
            "reject:MalformedGovernanceExecutionPayload".to_string()
        }
        D::GovernanceExecutionRequiredButAbsent { .. } => {
            "reject:GovernanceExecutionRequiredButAbsent".to_string()
        }
        D::NoGovernanceExecutionSupplied => "bypass:NoGovernanceExecutionSupplied".to_string(),
        D::MainNetPeerDrivenApplyRefused => "reject:MainNetPeerDrivenApplyRefused".to_string(),
        D::Callsite(o) => format!("callsite:{}", outcome_tag(o)),
    }
}

fn composed_tag(outcome: &GovernanceExecutionComposedOutcome) -> String {
    use GovernanceExecutionComposedOutcome as C;
    match outcome {
        C::Accepted(o) => format!("accepted:{}", outcome_tag(o)),
        C::Rejected(o) => format!("rejected:{}", outcome_tag(o)),
        C::MainNetPeerDrivenApplyRefused => "MainNetPeerDrivenApplyRefused".to_string(),
    }
}

/// Route carried fixture material through the reload-apply (mutating-preflight)
/// surface under the fixture policy on the given env.
fn route_apply_fixture(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
    exp: &GovernanceExecutionExpectations,
    env: TrustBundleEnvironment,
) -> GovernanceExecutionPayloadCarryingDecisionOutcome {
    let td = trust_domain(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &available_from(input, decision))
}

/// Route carried material into the Run 211 evaluator (via the grep-verifiable
/// reachability helper) under the given policy on the given env.
fn eval_loaded(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
    exp: &GovernanceExecutionExpectations,
    env: TrustBundleEnvironment,
    policy: GovernanceExecutionPolicy,
) -> GovernanceExecutionOutcome {
    let td = trust_domain(env);
    let ctx = callsite_context_for_governance_execution(&td, exp, policy);
    evaluate_loaded_governance_execution(&ctx, &available_from(input, decision))
        .expect("Available carrier routes to the Run 211 evaluator")
}

// ---------------------------------------------------------------------------
// Evidence writing helpers
// ---------------------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("create dir {parent:?}: {e}"));
    }
    let mut f = fs::File::create(path).unwrap_or_else(|e| panic!("create {path:?}: {e}"));
    f.write_all(contents.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// A small table recorder that accumulates `name<TAB>PASS|FAIL<TAB>detail`
/// rows plus an `expected`/`actual` ledger and writes them under `out`.
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
        Table {
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
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        self.rows.push_str(&format!(
            "{}\t{}\texpected={}\tactual={}\n",
            id,
            if ok { "PASS" } else { "FAIL" },
            expected,
            actual
        ));
        self.expected.push_str(&format!("{}\t{}\n", id, expected));
        self.actual.push_str(&format!("{}\t{}\n", id, actual));
    }

    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {}: {}\n", id, detail));
        }
    }

    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

// ---------------------------------------------------------------------------
// Table 1 — accepted / compatible carrying corpus (A1..A16).
// ---------------------------------------------------------------------------

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — absent carrier compatible under default Disabled (legacy
    // no-governance-execution payload bypass through reload-check).
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::Disabled,
        );
        let outcome = route_loaded_governance_execution_to_reload_check_callsite_decision(
            &ctx,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check("A1.absent-disabled-bypass", "bypass:NoGovernanceExecutionSupplied", &decision_tag(&outcome));
        t.assert_true("A1.is-bypassed", outcome.is_bypassed() && !outcome.is_reject(), "");
    }

    // A2 — DevNet fixture carried through reload-check accepted.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let outcome = route_loaded_governance_execution_to_reload_check_callsite_decision(
            &ctx,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check("A2.devnet-reload-check", "callsite:accept:FixtureGovernanceAccepted", &decision_tag(&outcome));
    }

    // A3 — TestNet fixture carried through reload-check accepted.
    {
        let env = Env::Testnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let outcome = route_loaded_governance_execution_to_reload_check_callsite_decision(
            &ctx,
            &available_from(&rotate_input(env), &rotate_decision()),
        );
        t.check("A3.testnet-reload-check", "callsite:accept:FixtureGovernanceAccepted", &decision_tag(&outcome));
    }

    // A4 — DevNet fixture carried through reload-apply accepted.
    {
        let env = Env::Devnet;
        let outcome = route_apply_fixture(&rotate_input(env), &rotate_decision(), &rotate_expectations(env), env);
        t.check("A4.devnet-reload-apply", "callsite:accept:FixtureGovernanceAccepted", &decision_tag(&outcome));
    }

    // A5 — input digest preserved through wire conversion.
    {
        let input = rotate_input(Env::Devnet);
        let back = GovernanceExecutionInputWire::from_input(&input)
            .to_input()
            .expect("wire converts");
        t.assert_true("A5.input-digest-preserved", input.input_digest() == back.input_digest(), "");
    }

    // A6 — decision digest preserved through wire conversion.
    {
        let decision = rotate_decision();
        let back = GovernanceExecutionDecisionWire::from_decision(&decision)
            .to_decision()
            .expect("wire converts");
        t.assert_true("A6.decision-digest-preserved", decision.decision_digest() == back.decision_digest(), "");
    }

    // A7 — transcript digest preserved through wire conversion.
    {
        let input = rotate_input(Env::Devnet);
        let decision = rotate_decision();
        let parts = GovernanceExecutionPayloadWire::from_parts(&input, &decision)
            .to_parts()
            .expect("wire converts");
        let before = governance_execution_transcript_digest(&input.input_digest(), &decision.decision_digest());
        let after = governance_execution_transcript_digest(&parts.input_digest(), &parts.decision_digest());
        t.assert_true("A7.transcript-digest-preserved", before == after, "");
    }

    // A8 — policy digest stable across carrying (policy is carried in the
    // call-site context, not the wire, so it is stable through conversion).
    {
        let before = governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance,
        );
        let parts = GovernanceExecutionPayloadWire::from_parts(&rotate_input(Env::Devnet), &rotate_decision())
            .to_parts()
            .unwrap();
        let after = governance_execution_policy_digest(
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            parts.input.governance_class,
        );
        t.assert_true("A8.policy-digest-stable", before == after, "");
    }

    // A9 — fixture governance routes to the Run 211 evaluator when present.
    {
        let env = Env::Devnet;
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("A9.routes-to-run211", "accept:FixtureGovernanceAccepted", outcome_tag(&outcome));
    }

    // A10 — rotate authorized only when carried decision authorizes rotate
    // with matching candidate digest and sequence.
    {
        let env = Env::Devnet;
        let ok = route_apply_fixture(&rotate_input(env), &rotate_decision(), &rotate_expectations(env), env);
        t.assert_true("A10.rotate-matching-accepted", ok.is_accept(), "");
        let mut bad = rotate_decision();
        bad.authorized_candidate_digest = "wrong-candidate".to_string();
        let rej = route_apply_fixture(&rotate_input(env), &bad, &rotate_expectations(env), env);
        t.assert_true("A10.rotate-mismatch-rejected", rej.is_reject(), "");
    }

    // A11 — revoke authorized only with matching candidate/revoked material
    // and sequence.
    {
        let env = Env::Devnet;
        let (input, decision, exp) = revoke_triple(env);
        let outcome = route_apply_fixture(&input, &decision, &exp, env);
        t.assert_true("A11.revoke-matching-accepted", outcome.is_accept(), "");
    }

    // A12 — emergency revoke accepted only under the emergency fixture policy.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = emergency_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
        );
        let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(
            &ctx,
            &available_from(&emergency_input(env), &emergency_decision()),
        );
        t.check(
            "A12.emergency-accepted",
            "callsite:accept:EmergencyCouncilFixtureAccepted",
            &decision_tag(&outcome),
        );
    }

    // A13 — combined lifecycle + governance proof + custody-attestation digest
    // + fixture governance accepted for the DevNet release-helper path.
    {
        let env = Env::Devnet;
        let mut input = rotate_input(env);
        input.on_chain_proof_digest = Some("onchain-digest-1111".to_string());
        input.custody_attestation_digest = Some("custody-att-digest-2222".to_string());
        let mut exp = rotate_expectations(env);
        exp.expected_on_chain_proof_digest = Some("onchain-digest-1111".to_string());
        exp.expected_custody_attestation_digest = Some("custody-att-digest-2222".to_string());
        let outcome = route_apply_fixture(&input, &rotate_decision(), &exp, env);
        t.assert_true("A13.combined-digests-accepted", outcome.is_accept(), "");
    }

    // A14 — proof-carrier behavior unchanged when policy is Disabled: an absent
    // carrier bypasses across validation-only and mutating surfaces.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::Disabled,
        );
        let a = route_loaded_governance_execution_to_reload_check_callsite_decision(
            &ctx,
            &GovernanceExecutionLoadStatus::Absent,
        );
        let b = route_loaded_governance_execution_to_sighup_callsite_decision(
            &ctx,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.assert_true("A14.disabled-bypass-both", a.is_bypassed() && b.is_bypassed(), "");
    }

    // A15 — custody / RemoteSigner / KMS-HSM / attestation paths remain
    // compatible when governance-execution policy is Disabled (absent carrier
    // bypasses on the startup --p2p-trust-bundle surface on TestNet).
    {
        let env = Env::Testnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::Disabled,
        );
        let outcome =
            route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision(
                &ctx,
                &GovernanceExecutionLoadStatus::Absent,
            );
        t.assert_true("A15.disabled-startup-bypass", outcome.is_bypassed(), "");
    }

    // A16 — production/on-chain/MainNet material reaches the evaluator and
    // returns the typed unavailable outcome under production-required policy.
    {
        let env = Env::Devnet;
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("A16.production-unavailable", "reject:ProductionGovernanceUnavailable", outcome_tag(&outcome));
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection carrying corpus (R1..R40).
// ---------------------------------------------------------------------------

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let env = Env::Devnet;

    // R1 — material absent where policy requires it -> required-but-absent.
    {
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(
            &ctx,
            &GovernanceExecutionLoadStatus::Absent,
        );
        t.check("R1.absent-required", "reject:GovernanceExecutionRequiredButAbsent", &decision_tag(&outcome));
        t.assert_true("R1.is-required-but-absent", outcome.is_required_but_absent() && outcome.is_reject(), "");
    }

    // R2 — malformed governance execution input wire rejected.
    {
        let mut wire = GovernanceExecutionInputWire::from_input(&rotate_input(env));
        wire.candidate_digest = String::new();
        let err = wire.to_input().unwrap_err();
        t.assert_true(
            "R2.malformed-input",
            err == GovernanceExecutionWireParseError::EmptyRequiredField { part: "input" },
            "",
        );
    }

    // R3 — malformed governance execution decision wire rejected.
    {
        let mut wire = GovernanceExecutionDecisionWire::from_decision(&rotate_decision());
        wire.decision_commitment = String::new();
        let err = wire.to_decision().unwrap_err();
        t.assert_true(
            "R3.malformed-decision",
            err == GovernanceExecutionWireParseError::EmptyRequiredField { part: "decision" },
            "",
        );
    }

    // R4 — malformed combined payload rejected (and routes fail closed).
    {
        let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: "not-an-object" });
        let loaded = parse_optional_governance_execution_sibling_from_json_value(&value);
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
        t.check("R4.malformed-combined", "reject:MalformedGovernanceExecutionPayload", &decision_tag(&outcome));
        t.assert_true("R4.is-malformed", loaded.is_malformed() && outcome.is_malformed_payload(), "");
    }

    // R5 — unsupported future schema version rejected.
    {
        let mut wire = GovernanceExecutionPayloadWire::from_parts(&rotate_input(env), &rotate_decision());
        wire.schema_version = 9_999;
        let wire_err = matches!(
            wire.to_parts().unwrap_err(),
            GovernanceExecutionWireParseError::UnknownSchemaVersion { .. }
        );
        let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap() });
        let malformed = parse_optional_governance_execution_sibling_from_json_value(&value).is_malformed();
        t.assert_true("R5.unsupported-schema-version", wire_err && malformed, "");
    }

    // R6 — fixture governance rejected under ProductionGovernanceRequired.
    {
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("R6.fixture-production-required", "reject:FixtureRejectedProductionRequired", outcome_tag(&outcome));
    }

    // R7 — emergency fixture rejected under ProductionGovernanceRequired.
    {
        let outcome = eval_loaded(
            &emergency_input(env),
            &emergency_decision(),
            &emergency_expectations(env),
            env,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check(
            "R7.emergency-production-required",
            "reject:EmergencyFixtureRejectedProductionRequired",
            outcome_tag(&outcome),
        );
    }

    // R8 — fixture governance rejected under MainnetGovernanceRequired.
    {
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
        );
        t.check("R8.fixture-mainnet-required", "reject:FixtureRejectedMainnetRequired", outcome_tag(&outcome));
    }

    // R9/R10/R11 — production / on-chain / MainNet governance unavailable.
    {
        for (id, class, expected) in [
            (
                "R9.production-unavailable",
                GovernanceExecutionClass::ProductionGovernanceUnavailable,
                "reject:ProductionGovernanceUnavailable",
            ),
            (
                "R10.onchain-unavailable",
                GovernanceExecutionClass::OnChainGovernanceUnavailable,
                "reject:OnChainGovernanceUnavailable",
            ),
            (
                "R11.mainnet-unavailable",
                GovernanceExecutionClass::MainnetGovernanceUnavailable,
                "reject:MainNetGovernanceUnavailable",
            ),
        ] {
            let mut input = rotate_input(env);
            input.governance_class = class;
            let outcome = eval_loaded(
                &input,
                &rotate_decision(),
                &rotate_expectations(env),
                env,
                GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            );
            t.check(id, expected, outcome_tag(&outcome));
        }
    }

    // R12 — unknown governance class rejected.
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::Unknown;
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R12.unknown-class", "reject:UnknownGovernanceClassRejected", outcome_tag(&outcome));
    }

    // R13..R25 — wrong-binding rejections, each carried through the wire layer
    // and routed into the Run 211 evaluator. Each mutates one bound field of
    // the input (and its expectation where the binding is optional).
    let wrong_cases: &[(&str, &str, fn(&mut GovernanceExecutionInput, &mut GovernanceExecutionExpectations))] = &[
        ("R13.wrong-environment", "reject:WrongEnvironment", |i, _e| {
            i.environment = TrustBundleEnvironment::Testnet;
        }),
        ("R14.wrong-chain", "reject:WrongChain", |i, _e| {
            i.chain_id = "wrong-chain".to_string();
        }),
        ("R15.wrong-genesis", "reject:WrongGenesis", |i, _e| {
            i.genesis_hash = "wrong-genesis".to_string();
        }),
        ("R16.wrong-authority-root", "reject:WrongAuthorityRoot", |i, _e| {
            i.authority_root_fingerprint = "wrong-root".to_string();
        }),
        ("R17.wrong-lifecycle-action", "reject:WrongLifecycleAction", |i, _e| {
            i.lifecycle_action = LocalLifecycleAction::Retire;
        }),
        ("R18.wrong-candidate-digest", "reject:WrongCandidateDigest", |i, _e| {
            i.candidate_digest = "wrong-candidate".to_string();
        }),
        ("R19.wrong-sequence", "reject:WrongAuthorityDomainSequence", |i, _e| {
            i.authority_domain_sequence = 99;
        }),
        ("R20.wrong-governance-proof", "reject:WrongGovernanceProofDigest", |i, _e| {
            i.governance_proof_digest = "wrong-proof".to_string();
        }),
        ("R21.wrong-onchain-proof", "reject:WrongOnChainProofDigest", |i, e| {
            i.on_chain_proof_digest = Some("wrong-onchain".to_string());
            e.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
        }),
        ("R22.wrong-custody-attestation", "reject:WrongCustodyAttestationDigest", |i, e| {
            i.custody_attestation_digest = Some("wrong-custody".to_string());
            e.expected_custody_attestation_digest = Some("expected-custody".to_string());
        }),
        ("R23.wrong-proposal-id", "reject:WrongProposalId", |i, _e| {
            i.proposal_id = "wrong-proposal".to_string();
        }),
        ("R24.wrong-decision-id", "reject:WrongDecisionId", |i, _e| {
            i.decision_id = "wrong-decision".to_string();
        }),
        ("R25.wrong-effective-epoch", "reject:WrongEffectiveEpoch", |i, _e| {
            i.effective_epoch = 101;
        }),
    ];
    for (id, expected, mutate) in wrong_cases {
        let mut input = rotate_input(env);
        let mut exp = rotate_expectations(env);
        mutate(&mut input, &mut exp);
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &exp,
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check(id, expected, outcome_tag(&outcome));
    }

    // R26 — expired decision rejected.
    {
        let mut exp = rotate_expectations(env);
        exp.now_epoch = 250;
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &exp,
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R26.expired-decision", "reject:ExpiredDecision", outcome_tag(&outcome));
    }

    // R27 — stale / replayed decision rejected.
    {
        let mut exp = rotate_expectations(env);
        exp.expected_replay_nonce = "fresh-nonce".to_string();
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &exp,
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R27.stale-replayed", "reject:StaleOrReplayedDecision", outcome_tag(&outcome));
    }

    // R28 — quorum threshold insufficient rejected.
    {
        let mut input = rotate_input(env);
        input.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R28.quorum-insufficient", "reject:QuorumThresholdInsufficient", outcome_tag(&outcome));
    }

    // R29 — emergency action not authorized (emergency action carried under
    // the non-emergency fixture class/policy).
    {
        let mut input = emergency_input(env);
        input.governance_class = GovernanceExecutionClass::FixtureGovernance;
        let mut decision = emergency_decision();
        decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
        let outcome = eval_loaded(
            &input,
            &decision,
            &emergency_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R29.emergency-not-authorized", "reject:EmergencyActionNotAuthorized", outcome_tag(&outcome));
    }

    // R30 — validator-set rotation unsupported rejected.
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R30.validator-set-rotation", "reject:ValidatorSetRotationUnsupported", outcome_tag(&outcome));
    }

    // R31 — policy-change action unsupported rejected.
    {
        let mut input = rotate_input(env);
        input.governance_action = GovernanceAction::PolicyChangeRequest;
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R31.policy-change-action", "reject:PolicyChangeActionUnsupported", outcome_tag(&outcome));
    }

    // R32/R33 — local operator / peer majority cannot satisfy production
    // governance execution: fixture material under ProductionGovernanceRequired
    // is rejected as fixture-rejected-production-required.
    {
        let outcome = eval_loaded(
            &rotate_input(env),
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("R32_R33.production-required", "reject:FixtureRejectedProductionRequired", outcome_tag(&outcome));
    }

    // R34 — governance valid but lifecycle action mismatch rejected (decision
    // authorizes revoke while input/expectations are rotate).
    {
        let mut decision = rotate_decision();
        decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
        decision.authorized_governance_action = GovernanceAction::Revoke;
        let outcome = eval_loaded(
            &rotate_input(env),
            &decision,
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R34.lifecycle-action-mismatch", "reject:WrongLifecycleAction", outcome_tag(&outcome));
    }

    // R35 — lifecycle valid but governance decision invalid (approved=false).
    {
        let mut decision = rotate_decision();
        decision.approved = false;
        let outcome = eval_loaded(
            &rotate_input(env),
            &decision,
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        t.check("R35.governance-decision-rejected", "reject:GovernanceDecisionRejected", outcome_tag(&outcome));
    }

    // R36 — lifecycle + governance proof + custody valid but production
    // governance execution unavailable rejected.
    {
        let mut input = rotate_input(env);
        input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
        let outcome = eval_loaded(
            &input,
            &rotate_decision(),
            &rotate_expectations(env),
            env,
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
        );
        t.check("R36.production-unavailable", "reject:ProductionGovernanceUnavailable", outcome_tag(&outcome));
    }

    // R37 — validation-only rejection is pure: two validation-only surfaces
    // produce equal reject outcomes and mutate nothing.
    {
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let mut decision = rotate_decision();
        decision.approved = false;
        let loaded = available_from(&rotate_input(env), &decision);
        let a = route_loaded_governance_execution_to_reload_check_callsite_decision(&ctx, &loaded);
        let b = route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision(&ctx, &loaded);
        t.assert_true("R37.validation-only-pure", a.is_reject() && a == b, "");
    }

    // R38 — mutating rejection is pure: a malformed carrier short-circuits to a
    // fail-closed outcome with no mutation.
    {
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: 42 });
        let loaded = parse_optional_governance_execution_sibling_from_json_value(&value);
        let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
        t.assert_true("R38.mutating-rejection-pure", outcome.is_malformed_payload() && outcome.is_reject(), "");
    }

    // R39 — invalid live 0x05 governance-execution candidate is not
    // propagated / staged / applied — the routing helper short-circuits.
    {
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: "garbage" });
        let loaded = parse_optional_governance_execution_sibling_from_json_value(&value);
        let outcome = route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision(&ctx, &loaded);
        t.assert_true("R39.live-0x05-not-propagated", outcome.is_reject() && outcome.is_malformed_payload(), "");
    }

    // R40 — MainNet peer-driven apply remains refused even with a fully-valid
    // fixture governance approval.
    {
        let menv = Env::Mainnet;
        let td = trust_domain(menv);
        let exp = rotate_expectations(menv);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let outcome = route_loaded_governance_execution_to_peer_driven_drain_callsite_decision(
            &ctx,
            &available_from(&rotate_input(menv), &rotate_decision()),
        );
        t.check("R40.mainnet-peer-driven-refused", "reject:MainNetPeerDrivenApplyRefused", &decision_tag(&outcome));
        t.assert_true(
            "R40.refusal-helper",
            outcome.is_mainnet_peer_driven_apply_refused()
                && mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(menv),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — reachability / loader / determinism / refusal.
// ---------------------------------------------------------------------------

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // T1 — all seven production-context surfaces reach the Run 211 evaluator
    // and accept the carried fixture material on a non-MainNet trust domain.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let loaded = available_from(&rotate_input(env), &rotate_decision());
        let six: [fn(
            &GovernanceExecutionCallsiteContext<'_>,
            &GovernanceExecutionLoadStatus,
        ) -> GovernanceExecutionPayloadCarryingDecisionOutcome; 6] = [
            route_loaded_governance_execution_to_reload_check_callsite_decision,
            route_loaded_governance_execution_to_reload_apply_callsite_decision,
            route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision,
            route_loaded_governance_execution_to_sighup_callsite_decision,
            route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision,
            route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision,
        ];
        let mut all_accept = true;
        for surface in six {
            all_accept &= surface(&ctx, &loaded).is_accept();
        }
        // 7th surface: peer-driven drain accepts on non-MainNet.
        all_accept &= route_loaded_governance_execution_to_peer_driven_drain_callsite_decision(&ctx, &loaded)
            .is_accept();
        t.assert_true("T1.seven-surfaces-reach-evaluator", all_accept, "");
    }

    // T2 — peer-driven guard composition accepts non-MainNet, refuses MainNet.
    {
        let env = Env::Devnet;
        let td = trust_domain(env);
        let exp = rotate_expectations(env);
        let ctx = callsite_context_for_governance_execution(
            &td,
            &exp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let accepted = evaluate_loaded_governance_execution_with_peer_driven_guard(
            &ctx,
            &available_from(&rotate_input(env), &rotate_decision()),
            true,
        )
        .expect("Available carrier composes");
        t.check("T2.guard-accept-devnet", "accepted:accept:FixtureGovernanceAccepted", &composed_tag(&accepted));

        let menv = Env::Mainnet;
        let mtd = trust_domain(menv);
        let mexp = rotate_expectations(menv);
        let mctx = callsite_context_for_governance_execution(
            &mtd,
            &mexp,
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        );
        let refused = evaluate_loaded_governance_execution_with_peer_driven_guard(
            &mctx,
            &available_from(&rotate_input(menv), &rotate_decision()),
            true,
        )
        .expect("Available carrier composes");
        t.check("T2.guard-refuse-mainnet", "MainNetPeerDrivenApplyRefused", &composed_tag(&refused));
    }

    // T3 — v2 sidecar loader: legacy (absent) / carrying (available) /
    // malformed sibling, through the production loader on bytes the helper
    // produced.
    {
        let env = Env::Devnet;
        let legacy = make_v2_sidecar_value(env, None);
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        let path = PathBuf::from("/dev/null/run-214-legacy.json");
        let loaded_legacy =
            load_v2_ratification_sidecar_with_governance_execution_from_bytes(&legacy_bytes, &path)
                .expect("legacy v2 sidecar parses");
        t.assert_true("T3.loader-legacy-absent", loaded_legacy.governance_execution.is_absent(), "");

        let input = rotate_input(env);
        let decision = rotate_decision();
        let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
        let carry = make_v2_sidecar_value(env, Some(serde_json::to_value(&wire).unwrap()));
        let carry_bytes = serde_json::to_vec(&carry).unwrap();
        let cpath = PathBuf::from("/dev/null/run-214-carry.json");
        let loaded_carry =
            load_v2_ratification_sidecar_with_governance_execution_from_bytes(&carry_bytes, &cpath)
                .expect("carrying v2 sidecar parses");
        t.assert_true(
            "T3.loader-carry-available",
            loaded_carry.governance_execution.is_available()
                && loaded_carry.governance_execution.as_parts()
                    == Some(&GovernanceExecutionParts { input, decision }),
            "",
        );

        let bad = make_v2_sidecar_value(env, Some(serde_json::json!({ "schema_version": 9_999 })));
        let bad_bytes = serde_json::to_vec(&bad).unwrap();
        let bpath = PathBuf::from("/dev/null/run-214-malformed.json");
        let loaded_bad =
            load_v2_ratification_sidecar_with_governance_execution_from_bytes(&bad_bytes, &bpath)
                .expect("v2 ratification still parses");
        t.assert_true("T3.loader-malformed", loaded_bad.governance_execution.is_malformed(), "");
    }

    // T4 — canonical sibling field + schema version + absent semantics.
    {
        t.check("T4.field", "governance_execution", GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD);
        t.check("T4.version", "1", &GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION.to_string());
        let missing = serde_json::json!({ "schema_version": 2 });
        let null = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: null });
        t.assert_true(
            "T4.absent-missing-or-null",
            parse_optional_governance_execution_sibling_from_json_value(&missing).is_absent()
                && parse_optional_governance_execution_sibling_from_json_value(&null).is_absent(),
            "",
        );
    }

    // T5 — full JSON round-trip yields identical parts (input/decision).
    {
        let env = Env::Devnet;
        let input = rotate_input(env);
        let decision = rotate_decision();
        let loaded = available_via_json(&input, &decision);
        t.assert_true(
            "T5.json-roundtrip-parts",
            loaded.as_parts() == Some(&GovernanceExecutionParts { input, decision }),
            "",
        );
    }

    // T6 — input/decision/transcript digests are deterministic and
    // domain-bound across repeats through the wire layer.
    {
        let env = Env::Devnet;
        let a = available_from(&rotate_input(env), &rotate_decision());
        let b = available_from(&rotate_input(env), &rotate_decision());
        let pa = a.as_parts().unwrap();
        let pb = b.as_parts().unwrap();
        let det = pa.input_digest() == pb.input_digest()
            && pa.decision_digest() == pb.decision_digest()
            && governance_execution_transcript_digest(&pa.input_digest(), &pa.decision_digest())
                == governance_execution_transcript_digest(&pb.input_digest(), &pb.decision_digest());
        // Domain-bound: mutating a bound field changes the digest.
        let mut other = rotate_input(env);
        other.replay_nonce = "other-nonce".to_string();
        let bound = pa.input_digest() != other.input_digest();
        t.assert_true("T6.digest-deterministic-bound", det && bound, "");
    }

    // T7 — wire class/action enum round-trip across all variants.
    {
        let mut ok = true;
        for c in [
            GovernanceExecutionClass::Disabled,
            GovernanceExecutionClass::FixtureGovernance,
            GovernanceExecutionClass::EmergencyCouncilFixture,
            GovernanceExecutionClass::OnChainGovernanceUnavailable,
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
            GovernanceExecutionClass::Unknown,
        ] {
            ok &= GovernanceExecutionClassWire::from_class(c).to_class() == c;
        }
        for a in [
            GovernanceAction::AuthoritySigningKeyInitialActivation,
            GovernanceAction::Rotate,
            GovernanceAction::Retire,
            GovernanceAction::Revoke,
            GovernanceAction::EmergencyRevoke,
            GovernanceAction::PolicyChangeRequest,
            GovernanceAction::CustodyPolicyChangeRequest,
            GovernanceAction::RemoteSignerPolicyChangeRequest,
            GovernanceAction::CustodyAttestationPolicyChangeRequest,
            GovernanceAction::ValidatorSetRotationRequest,
            GovernanceAction::Unknown,
        ] {
            ok &= GovernanceExecutionActionWire::from_action(a).to_action() == a;
        }
        t.assert_true("T7.wire-enum-round-trip", ok, "");
    }

    // T8 — explicit MainNet refusal helper is environment-bound.
    {
        t.assert_true(
            "T8.mainnet-refusal-helper",
            mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
                Env::Mainnet,
            ) && !mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
                Env::Devnet,
            ),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — canonical wire forms, sidecars, and digests for the archive.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let env = TrustBundleEnvironment::Devnet;
    let input = rotate_input(env);
    let decision = rotate_decision();

    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let wire_json = serde_json::to_string_pretty(&wire).expect("wire serializes");
    write_file(&dir.join("governance_execution_payload_wire.json"), &format!("{wire_json}\n"));

    // Canonical v2 sidecar carrying the governance_execution sibling.
    let sidecar = make_v2_sidecar_value(env, Some(serde_json::to_value(&wire).unwrap()));
    let sidecar_json = serde_json::to_string_pretty(&sidecar).expect("sidecar serializes");
    write_file(&dir.join("v2_sidecar_with_governance_execution.json"), &format!("{sidecar_json}\n"));

    // Legacy v2 sidecar (no sibling).
    let legacy = make_v2_sidecar_value(env, None);
    let legacy_json = serde_json::to_string_pretty(&legacy).expect("legacy sidecar serializes");
    write_file(&dir.join("v2_sidecar_legacy_no_sibling.json"), &format!("{legacy_json}\n"));

    // Debug rendering of the in-process parts + digests preserved through wire.
    let parts = wire.to_parts().expect("wire converts");
    write_file(&dir.join("governance_execution_input.txt"), &format!("{input:#?}\n"));
    write_file(&dir.join("governance_execution_decision.txt"), &format!("{decision:#?}\n"));
    write_file(
        &dir.join("governance_execution_expectations.txt"),
        &format!("{:#?}\n", rotate_expectations(env)),
    );
    write_file(&dir.join("input_digest.txt"), &format!("{}\n", parts.input_digest()));
    write_file(&dir.join("decision_digest.txt"), &format!("{}\n", parts.decision_digest()));
    write_file(
        &dir.join("transcript_digest.txt"),
        &format!(
            "{}\n",
            governance_execution_transcript_digest(&parts.input_digest(), &parts.decision_digest())
        ),
    );

    // Per-policy / per-class policy digests.
    let mut policy = String::new();
    for (p, c) in [
        (
            GovernanceExecutionPolicy::FixtureGovernanceAllowed,
            GovernanceExecutionClass::FixtureGovernance,
        ),
        (
            GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
            GovernanceExecutionClass::EmergencyCouncilFixture,
        ),
        (
            GovernanceExecutionPolicy::ProductionGovernanceRequired,
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
        ),
        (
            GovernanceExecutionPolicy::MainnetGovernanceRequired,
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
        ),
        (GovernanceExecutionPolicy::Disabled, GovernanceExecutionClass::Disabled),
    ] {
        policy.push_str(&format!(
            "policy\t{}\tclass\t{}\tpolicy_digest\t{}\n",
            p.tag(),
            c.tag(),
            governance_execution_policy_digest(p, c)
        ));
    }
    write_file(&dir.join("policy_digests.txt"), &policy);
}

fn main() {
    let mut args = env::args().skip(1);
    let out_dir = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            eprintln!(
                "usage: run_214_governance_execution_payload_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("reachability", run_reachability_table),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_214_governance_execution_payload_release_binary_helper\n");
    summary.push_str(
        "scope: Run 213 governance-execution payload carrying + production-context call-site wiring (wire conversion, optional governance_execution v2-sidecar sibling, typed load status, seven per-surface routing helpers, Run 211 evaluator) exercised in release mode through the production library symbols\n",
    );
    summary.push_str(
        "note: fixture-only; no real governance execution engine; no real on-chain governance proof verifier; no real KMS/HSM/RemoteSigner backend; no validator-set rotation; no live trust mutation; no marker/sequence write; no P2P socket; production / on-chain / MainNet governance execution fails closed as unavailable; malformed / required-but-absent carriers fail closed before the evaluator; MainNet peer-driven apply remains refused\n\n",
    );
    for (name, f) in tables {
        let (pass, fail) = f(&out_dir);
        total_pass += pass;
        total_fail += fail;
        summary.push_str(&format!("table {name}: pass={pass} fail={fail}\n"));
    }

    run_fixture_dump(&out_dir);

    summary.push_str(&format!("\ntotal_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };
    summary.push_str(&format!("verdict: {verdict}\n"));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if total_fail != 0 {
        std::process::exit(1);
    }
}
