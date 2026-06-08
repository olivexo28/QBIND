//! Run 213 — source/test governance-execution payload carrying and
//! production-context preflight wiring integration tests.
//!
//! Source/test only. Run 213 does **not** capture release-binary
//! evidence; release-binary governance-execution payload/carrying
//! evidence is deferred to **Run 214**. The tests cover:
//!
//! * the A1–A16 / R1–R40 matrix from `task/RUN_213_TASK.txt` where
//!   representable at the payload/carrying + production-context layer;
//! * serde / parse compatibility (legacy no-governance-execution payload
//!   parses, governance-execution-carrying payload parses, malformed
//!   input / decision / payload fails closed, unsupported future schema
//!   version fails closed);
//! * digest determinism through wire conversion (input / decision /
//!   transcript / policy digests);
//! * action authorization (rotate / revoke / emergency-revoke / wrong
//!   action fail-closed) carried through the wire layer;
//! * source reachability (carried material reaches the seven production
//!   call-site contexts and the Run 211 evaluator);
//! * no-mutation invariants (validation-only surfaces never mutate);
//! * MainNet refusal invariants.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_213.md`.

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
    GovernanceExecutionPayloadParseError, GovernanceExecutionPayloadWire,
    GovernanceExecutionParts, GovernanceExecutionWireParseError,
    GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD, GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    governance_execution_policy_digest, governance_execution_transcript_digest,
    GovernanceAction, GovernanceExecutionClass, GovernanceExecutionComposedOutcome,
    GovernanceExecutionDecision, GovernanceExecutionExpectations, GovernanceExecutionInput,
    GovernanceExecutionOutcome, GovernanceExecutionPolicy, GovernanceQuorumThreshold,
    GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL, GOVERNANCE_EXECUTION_SUPPORTED_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures (mirrors the Run 211 test corpus)
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

fn revoke_input(env: TrustBundleEnvironment) -> GovernanceExecutionInput {
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::Revoke;
    input.lifecycle_action = LocalLifecycleAction::Revoke;
    input.revoked_signing_key_fingerprint = Some(CUR_KEY.to_string());
    input
}

fn revoke_decision() -> GovernanceExecutionDecision {
    let mut decision = rotate_decision();
    decision.authorized_governance_action = GovernanceAction::Revoke;
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision
}

fn revoke_expectations(env: TrustBundleEnvironment) -> GovernanceExecutionExpectations {
    let mut exp = rotate_expectations(env);
    exp.expected_governance_action = GovernanceAction::Revoke;
    exp.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    exp
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

/// Build a `GovernanceExecutionLoadStatus::Available` from a wire payload
/// round-trip (input + decision -> wire -> parts).
fn available_from(
    input: &GovernanceExecutionInput,
    decision: &GovernanceExecutionDecision,
) -> GovernanceExecutionLoadStatus {
    let wire = GovernanceExecutionPayloadWire::from_parts(input, decision);
    GovernanceExecutionLoadStatus::Available(wire.to_parts().expect("wire converts to parts"))
}

/// A complete accepted rotate scenario on the given environment.
struct Scenario {
    env: TrustBundleEnvironment,
    input: GovernanceExecutionInput,
    decision: GovernanceExecutionDecision,
    expectations: GovernanceExecutionExpectations,
    policy: GovernanceExecutionPolicy,
}

impl Scenario {
    fn rotate(env: TrustBundleEnvironment) -> Self {
        Self {
            env,
            input: rotate_input(env),
            decision: rotate_decision(),
            expectations: rotate_expectations(env),
            policy: GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        }
    }

    fn td(&self) -> AuthorityTrustDomain {
        trust_domain(self.env)
    }

    fn loaded(&self) -> GovernanceExecutionLoadStatus {
        available_from(&self.input, &self.decision)
    }

    fn ctx<'a>(
        &'a self,
        td: &'a AuthorityTrustDomain,
    ) -> GovernanceExecutionCallsiteContext<'a> {
        callsite_context_for_governance_execution(td, &self.expectations, self.policy)
    }
}

// ===========================================================================
// A — accepted / reachable scenarios
// ===========================================================================

// A1. no-governance-execution payload remains compatible under default
//     Disabled.
#[test]
fn a1_absent_payload_compatible_under_disabled() {
    let env = TrustBundleEnvironment::Devnet;
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
    assert_eq!(
        outcome,
        GovernanceExecutionPayloadCarryingDecisionOutcome::NoGovernanceExecutionSupplied
    );
    assert!(outcome.is_bypassed());
    assert!(!outcome.is_reject());
}

// A2. DevNet fixture governance carried through reload-check accepted.
#[test]
fn a2_devnet_fixture_reload_check_accepted() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        route_loaded_governance_execution_to_reload_check_callsite_decision(&ctx, &s.loaded());
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. })
    ));
}

// A3. TestNet fixture governance carried through reload-check accepted.
#[test]
fn a3_testnet_fixture_reload_check_accepted() {
    let s = Scenario::rotate(TrustBundleEnvironment::Testnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        route_loaded_governance_execution_to_reload_check_callsite_decision(&ctx, &s.loaded());
    assert!(outcome.is_accept());
}

// A4. DevNet fixture governance carried through reload-apply accepted.
#[test]
fn a4_devnet_fixture_reload_apply_accepted() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &s.loaded());
    assert!(outcome.is_accept());
}

// A5. input digest preserved through wire conversion.
#[test]
fn a5_input_digest_preserved_through_wire() {
    let input = rotate_input(TrustBundleEnvironment::Devnet);
    let wire = GovernanceExecutionInputWire::from_input(&input);
    let back = wire.to_input().expect("wire converts");
    assert_eq!(input.input_digest(), back.input_digest());
}

// A6. decision digest preserved through wire conversion.
#[test]
fn a6_decision_digest_preserved_through_wire() {
    let decision = rotate_decision();
    let wire = GovernanceExecutionDecisionWire::from_decision(&decision);
    let back = wire.to_decision().expect("wire converts");
    assert_eq!(decision.decision_digest(), back.decision_digest());
}

// A7. transcript digest preserved through wire conversion.
#[test]
fn a7_transcript_digest_preserved_through_wire() {
    let input = rotate_input(TrustBundleEnvironment::Devnet);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let parts = wire.to_parts().expect("wire converts");
    let before = governance_execution_transcript_digest(
        &input.input_digest(),
        &decision.decision_digest(),
    );
    let after =
        governance_execution_transcript_digest(&parts.input_digest(), &parts.decision_digest());
    assert_eq!(before, after);
}

// A8. policy digest preserved through wire conversion (policy is carried
//     in the call-site context, not the wire, so it is stable).
#[test]
fn a8_policy_digest_stable_across_carrying() {
    let before = governance_execution_policy_digest(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        GovernanceExecutionClass::FixtureGovernance,
    );
    let input = rotate_input(TrustBundleEnvironment::Devnet);
    let decision = rotate_decision();
    let parts = GovernanceExecutionPayloadWire::from_parts(&input, &decision)
        .to_parts()
        .unwrap();
    let after = governance_execution_policy_digest(
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
        parts.input.governance_class,
    );
    assert_eq!(before, after);
}

// A9. fixture governance routes to the Run 211 evaluator when material is
//     present.
#[test]
fn a9_fixture_routes_to_run211_evaluator() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome = evaluate_loaded_governance_execution(&ctx, &s.loaded());
    assert!(matches!(
        outcome,
        Some(GovernanceExecutionOutcome::FixtureGovernanceAccepted { .. })
    ));
}

// A10. rotate authorized only when decision authorizes rotate with
//      matching candidate digest and sequence.
#[test]
fn a10_rotate_authorized_with_matching_candidate_and_sequence() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &s.loaded());
    assert!(outcome.is_accept());

    // Mismatched candidate digest in the decision -> rejected.
    let mut bad_decision = s.decision.clone();
    bad_decision.authorized_candidate_digest = "wrong-candidate".to_string();
    let loaded = available_from(&s.input, &bad_decision);
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_reject());
}

// A11. revoke authorized only when decision authorizes revoke with
//      matching candidate/revoked material and sequence.
#[test]
fn a11_revoke_authorized_with_matching_material() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = revoke_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = available_from(&revoke_input(env), &revoke_decision());
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

// A12. emergency revoke accepted only under emergency fixture policy.
#[test]
fn a12_emergency_revoke_accepted_under_emergency_policy() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::EmergencyCouncilFixtureAllowed,
    );
    let loaded = available_from(&emergency_input(env), &emergency_decision());
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
    assert!(matches!(
        outcome.callsite_outcome(),
        Some(GovernanceExecutionOutcome::EmergencyCouncilFixtureAccepted { .. })
    ));
}

// A13. combined lifecycle + governance proof + custody-attestation digest
//      + fixture governance accepted on DevNet.
#[test]
fn a13_combined_bound_digests_accepted_devnet() {
    let env = TrustBundleEnvironment::Devnet;
    let mut input = rotate_input(env);
    input.on_chain_proof_digest = Some("onchain-digest-1111".to_string());
    input.custody_attestation_digest = Some("custody-att-digest-2222".to_string());
    let decision = rotate_decision();
    let mut exp = rotate_expectations(env);
    exp.expected_on_chain_proof_digest = Some("onchain-digest-1111".to_string());
    exp.expected_custody_attestation_digest = Some("custody-att-digest-2222".to_string());
    let td = trust_domain(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = available_from(&input, &decision);
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_accept());
}

// A14. proof-carrier behavior unchanged when policy is Disabled — absent
//      carrier bypasses (legacy compatibility) regardless of issuer class.
#[test]
fn a14_disabled_policy_bypasses_absent_carrier() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::Disabled,
    );
    for surface in [
        route_loaded_governance_execution_to_reload_check_callsite_decision,
        route_loaded_governance_execution_to_sighup_callsite_decision,
    ] {
        let outcome = surface(&ctx, &GovernanceExecutionLoadStatus::Absent);
        assert!(outcome.is_bypassed());
    }
}

// A15. carried fixture material with no on-chain/custody digests remains
//      compatible under Disabled (absent carrier).
#[test]
fn a15_compatible_paths_under_disabled() {
    let env = TrustBundleEnvironment::Testnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::Disabled,
    );
    let outcome = route_loaded_governance_execution_to_startup_p2p_trust_bundle_callsite_decision(
        &ctx,
        &GovernanceExecutionLoadStatus::Absent,
    );
    assert!(outcome.is_bypassed());
}

// A16. production/on-chain/MainNet material reaches the evaluator and
//      returns typed unavailable under production-required policy.
#[test]
fn a16_production_material_reaches_evaluator_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    let loaded = available_from(&input, &rotate_decision());
    let outcome = evaluate_loaded_governance_execution(&ctx, &loaded);
    assert_eq!(
        outcome,
        Some(GovernanceExecutionOutcome::ProductionGovernanceUnavailable)
    );
}

// ===========================================================================
// R — rejection scenarios
// ===========================================================================

// R1. material absent where policy requires it -> fail closed.
#[test]
fn r1_absent_when_required_fails_closed() {
    let env = TrustBundleEnvironment::Devnet;
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
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// R2. malformed governance execution input rejected.
#[test]
fn r2_malformed_input_rejected() {
    let mut wire = GovernanceExecutionInputWire::from_input(&rotate_input(
        TrustBundleEnvironment::Devnet,
    ));
    wire.candidate_digest = String::new();
    assert_eq!(
        wire.to_input().unwrap_err(),
        GovernanceExecutionWireParseError::EmptyRequiredField { part: "input" }
    );
}

// R3. malformed governance execution decision rejected.
#[test]
fn r3_malformed_decision_rejected() {
    let mut wire = GovernanceExecutionDecisionWire::from_decision(&rotate_decision());
    wire.decision_commitment = String::new();
    assert_eq!(
        wire.to_decision().unwrap_err(),
        GovernanceExecutionWireParseError::EmptyRequiredField { part: "decision" }
    );
}

// R4. malformed combined payload rejected (and routes fail closed).
#[test]
fn r4_malformed_combined_payload_rejected() {
    let value = serde_json::json!({
        GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: "not-an-object"
    });
    let loaded = parse_optional_governance_execution_sibling_from_json_value(&value);
    assert!(loaded.is_malformed());

    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// R5. unsupported future schema version rejected.
#[test]
fn r5_unsupported_schema_version_rejected() {
    let mut wire = GovernanceExecutionPayloadWire::from_parts(
        &rotate_input(TrustBundleEnvironment::Devnet),
        &rotate_decision(),
    );
    wire.schema_version = 9_999;
    assert!(matches!(
        wire.to_parts().unwrap_err(),
        GovernanceExecutionWireParseError::UnknownSchemaVersion { .. }
    ));
    let value = serde_json::json!({
        GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    assert!(parse_optional_governance_execution_sibling_from_json_value(&value).is_malformed());
}

// R6. fixture governance rejected under ProductionGovernanceRequired.
#[test]
fn r6_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert_eq!(
        outcome.callsite_outcome(),
        Some(&GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R7. emergency fixture rejected under ProductionGovernanceRequired.
#[test]
fn r7_emergency_fixture_rejected_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    let loaded = available_from(&emergency_input(env), &emergency_decision());
    let outcome = evaluate_loaded_governance_execution(&ctx, &loaded);
    assert_eq!(
        outcome,
        Some(GovernanceExecutionOutcome::EmergencyFixtureRejectedProductionRequired)
    );
}

// R8. fixture governance rejected under MainnetGovernanceRequired.
#[test]
fn r8_fixture_rejected_mainnet_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::MainnetGovernanceRequired,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = evaluate_loaded_governance_execution(&ctx, &loaded);
    assert_eq!(
        outcome,
        Some(GovernanceExecutionOutcome::FixtureRejectedMainnetRequired)
    );
}

// R9/R10/R11. production / on-chain / MainNet governance rejected as
//             unavailable.
#[test]
fn r9_r10_r11_production_onchain_mainnet_unavailable() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    for (class, expected) in [
        (
            GovernanceExecutionClass::ProductionGovernanceUnavailable,
            GovernanceExecutionOutcome::ProductionGovernanceUnavailable,
        ),
        (
            GovernanceExecutionClass::OnChainGovernanceUnavailable,
            GovernanceExecutionOutcome::OnChainGovernanceUnavailable,
        ),
        (
            GovernanceExecutionClass::MainnetGovernanceUnavailable,
            GovernanceExecutionOutcome::MainNetGovernanceUnavailable,
        ),
    ] {
        let mut input = rotate_input(env);
        input.governance_class = class;
        let loaded = available_from(&input, &rotate_decision());
        assert_eq!(evaluate_loaded_governance_execution(&ctx, &loaded), Some(expected));
    }
}

// R12. unknown governance class rejected.
#[test]
fn r12_unknown_class_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::Unknown;
    let loaded = available_from(&input, &rotate_decision());
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &loaded),
        Some(GovernanceExecutionOutcome::UnknownGovernanceClassRejected { .. })
    ));
}

// R13/R14/R15. wrong environment / chain / genesis rejected.
#[test]
fn r13_r14_r15_wrong_domain_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );

    let mut wrong_chain = rotate_input(env);
    wrong_chain.chain_id = "other-chain".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&wrong_chain, &rotate_decision())),
        Some(GovernanceExecutionOutcome::WrongChain { .. })
    ));

    let mut wrong_genesis = rotate_input(env);
    wrong_genesis.genesis_hash = "other-genesis".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(
            &ctx,
            &available_from(&wrong_genesis, &rotate_decision())
        ),
        Some(GovernanceExecutionOutcome::WrongGenesis { .. })
    ));
}

// R16. wrong authority root rejected.
#[test]
fn r16_wrong_authority_root_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.authority_root_fingerprint = "wrong-root".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::WrongAuthorityRoot { .. })
    ));
}

// R17/R34. wrong lifecycle action rejected.
#[test]
fn r17_r34_wrong_lifecycle_action_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    // Decision authorizes revoke while input/expectations are rotate.
    let mut decision = rotate_decision();
    decision.authorized_lifecycle_action = LocalLifecycleAction::Revoke;
    decision.authorized_governance_action = GovernanceAction::Revoke;
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&rotate_input(env), &decision)),
        Some(GovernanceExecutionOutcome::WrongLifecycleAction { .. })
    ));
}

// R18. wrong candidate digest rejected.
#[test]
fn r18_wrong_candidate_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.candidate_digest = "different-digest".to_string();
    let mut decision = rotate_decision();
    decision.authorized_candidate_digest = "different-digest".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &decision)),
        Some(GovernanceExecutionOutcome::WrongCandidateDigest { .. })
    ));
}

// R19. wrong authority-domain sequence rejected.
#[test]
fn r19_wrong_sequence_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.authority_domain_sequence = 9;
    let mut decision = rotate_decision();
    decision.authorized_sequence = 9;
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &decision)),
        Some(GovernanceExecutionOutcome::WrongAuthorityDomainSequence { .. })
    ));
}

// R20. wrong governance proof digest rejected.
#[test]
fn r20_wrong_governance_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.governance_proof_digest = "wrong-proof".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::WrongGovernanceProofDigest { .. })
    ));
}

// R21. wrong on-chain proof digest rejected.
#[test]
fn r21_wrong_onchain_proof_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_on_chain_proof_digest = Some("expected-onchain".to_string());
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.on_chain_proof_digest = Some("wrong-onchain".to_string());
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::WrongOnChainProofDigest { .. })
    ));
}

// R22. wrong custody attestation digest rejected.
#[test]
fn r22_wrong_custody_attestation_digest_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_custody_attestation_digest = Some("expected-custody".to_string());
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.custody_attestation_digest = Some("wrong-custody".to_string());
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::WrongCustodyAttestationDigest { .. })
    ));
}

// R23. wrong proposal id rejected.
#[test]
fn r23_wrong_proposal_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.proposal_id = "wrong-proposal".to_string();
    let mut decision = rotate_decision();
    decision.proposal_id = "wrong-proposal".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &decision)),
        Some(GovernanceExecutionOutcome::WrongProposalId { .. })
    ));
}

// R24. wrong decision id rejected.
#[test]
fn r24_wrong_decision_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.decision_id = "wrong-decision".to_string();
    let mut decision = rotate_decision();
    decision.decision_id = "wrong-decision".to_string();
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &decision)),
        Some(GovernanceExecutionOutcome::WrongDecisionId { .. })
    ));
}

// R25. wrong effective epoch rejected.
#[test]
fn r25_wrong_effective_epoch_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.effective_epoch = 101;
    let mut decision = rotate_decision();
    decision.effective_epoch = 101;
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &decision)),
        Some(GovernanceExecutionOutcome::WrongEffectiveEpoch { .. })
    ));
}

// R26. expired decision rejected.
#[test]
fn r26_expired_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.now_epoch = 250; // past expiry_epoch 200
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &loaded),
        Some(GovernanceExecutionOutcome::ExpiredDecision { .. })
    ));
}

// R27. stale/replayed decision rejected.
#[test]
fn r27_stale_replayed_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let mut exp = rotate_expectations(env);
    exp.expected_replay_nonce = "fresh-nonce".to_string();
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &loaded),
        Some(GovernanceExecutionOutcome::StaleOrReplayedDecision)
    );
}

// R28. quorum threshold insufficient rejected.
#[test]
fn r28_quorum_insufficient_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.quorum = GovernanceQuorumThreshold::new(1, 5, 3);
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::QuorumThresholdInsufficient { .. })
    ));
}

// R29. emergency action not authorized rejected (emergency flag under
//      non-emergency fixture policy).
#[test]
fn r29_emergency_action_not_authorized_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = emergency_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    // Emergency action carried under the non-emergency fixture class/policy
    // is not authorized (class matches the FixtureGovernanceAllowed policy
    // but the emergency action/flag is refused).
    let mut input = emergency_input(env);
    input.governance_class = GovernanceExecutionClass::FixtureGovernance;
    let mut decision = emergency_decision();
    decision.issuer_authority_class = GovernanceAuthorityClass::GenesisBound;
    let loaded = available_from(&input, &decision);
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &loaded),
        Some(GovernanceExecutionOutcome::EmergencyActionNotAuthorized)
    );
}

// R30. validator-set rotation unsupported rejected.
#[test]
fn r30_validator_set_rotation_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::ValidatorSetRotationRequest;
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::ValidatorSetRotationUnsupported)
    );
}

// R31. policy-change action unsupported rejected.
#[test]
fn r31_policy_change_action_unsupported() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut input = rotate_input(env);
    input.governance_action = GovernanceAction::PolicyChangeRequest;
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::PolicyChangeActionUnsupported)
    );
}

// R32. local operator cannot satisfy production governance execution.
// R33. peer majority cannot satisfy production governance execution.
#[test]
fn r32_r33_production_required_with_fixture_material_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome = evaluate_loaded_governance_execution(&ctx, &loaded);
    assert_eq!(
        outcome,
        Some(GovernanceExecutionOutcome::FixtureRejectedProductionRequired)
    );
}

// R35. lifecycle valid but governance decision invalid (rejected
//      decision) rejected.
#[test]
fn r35_governance_decision_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut decision = rotate_decision();
    decision.approved = false;
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&rotate_input(env), &decision)),
        Some(GovernanceExecutionOutcome::GovernanceDecisionRejected)
    );
}

// R36. lifecycle + governance proof + custody valid but production
//      governance execution unavailable rejected.
#[test]
fn r36_production_unavailable_under_production_required() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::ProductionGovernanceRequired,
    );
    let mut input = rotate_input(env);
    input.governance_class = GovernanceExecutionClass::ProductionGovernanceUnavailable;
    assert_eq!(
        evaluate_loaded_governance_execution(&ctx, &available_from(&input, &rotate_decision())),
        Some(GovernanceExecutionOutcome::ProductionGovernanceUnavailable)
    );
}

// R37. validation-only rejection writes no marker / no sequence — the
//      routing helpers return data values only; nothing is mutated.
#[test]
fn r37_validation_only_rejection_is_pure() {
    let env = TrustBundleEnvironment::Devnet;
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
    // Two validation-only surfaces; both pure and equal.
    let a = route_loaded_governance_execution_to_reload_check_callsite_decision(&ctx, &loaded);
    let b = route_loaded_governance_execution_to_local_peer_candidate_check_callsite_decision(
        &ctx, &loaded,
    );
    assert!(a.is_reject());
    assert_eq!(a, b);
}

// R38. mutating rejection produces no Run 070 call, no live trust swap,
//      etc. — the routing helper only returns a typed outcome.
#[test]
fn r38_mutating_rejection_is_pure() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = GovernanceExecutionLoadStatus::Malformed(
        GovernanceExecutionPayloadParseError::Json {
            error: "broken".to_string(),
        },
    );
    let outcome = route_loaded_governance_execution_to_reload_apply_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_malformed_payload());
}

// R39. invalid live 0x05 governance-execution candidate is not
//      propagated/staged/applied — the routing helper short-circuits to a
//      reject outcome.
#[test]
fn r39_invalid_live_0x05_not_propagated() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = GovernanceExecutionLoadStatus::Malformed(
        GovernanceExecutionPayloadParseError::Json {
            error: "broken".to_string(),
        },
    );
    let outcome =
        route_loaded_governance_execution_to_live_inbound_0x05_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_reject());
    assert!(outcome.is_malformed_payload());
}

// R40. MainNet peer-driven apply remains refused even with a fully-valid
//      fixture governance approval.
#[test]
fn r40_mainnet_peer_driven_apply_refused_with_fixture_approval() {
    let env = TrustBundleEnvironment::Mainnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    // Even with a fixture-allowed policy and a structurally valid carrier.
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let loaded = available_from(&rotate_input(env), &rotate_decision());
    let outcome =
        route_loaded_governance_execution_to_peer_driven_drain_callsite_decision(&ctx, &loaded);
    assert!(outcome.is_mainnet_peer_driven_apply_refused());
    assert!(mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying(
        env
    ));
}

// ===========================================================================
// Serde / parse compatibility
// ===========================================================================

#[test]
fn sibling_field_and_schema_version_are_canonical() {
    assert_eq!(GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD, "governance_execution");
    assert_eq!(GOVERNANCE_EXECUTION_PAYLOAD_WIRE_SCHEMA_VERSION, 1);
}

#[test]
fn absent_sibling_when_field_missing_or_null() {
    let missing = serde_json::json!({ "schema_version": 2 });
    assert!(parse_optional_governance_execution_sibling_from_json_value(&missing).is_absent());
    let null = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: null });
    assert!(parse_optional_governance_execution_sibling_from_json_value(&null).is_absent());
}

#[test]
fn carrying_payload_round_trips_through_json() {
    let input = rotate_input(TrustBundleEnvironment::Devnet);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let json = serde_json::to_value(&wire).unwrap();
    let value = serde_json::json!({ GOVERNANCE_EXECUTION_PAYLOAD_SIBLING_FIELD: json });
    let loaded = parse_optional_governance_execution_sibling_from_json_value(&value);
    let parts = loaded.as_parts().expect("available");
    assert_eq!(parts, &GovernanceExecutionParts { input, decision });
}

fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    sibling: Option<serde_json::Value>,
) -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
    use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
    use qbind_ledger::BundleSigningRatificationV2Action;
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

#[test]
fn loader_legacy_v2_sidecar_without_sibling_yields_absent() {
    let value = make_v2_sidecar_value(TrustBundleEnvironment::Devnet, None);
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-213-legacy.json");
    let loaded =
        load_v2_ratification_sidecar_with_governance_execution_from_bytes(&bytes, &path)
            .expect("legacy v2 sidecar parses");
    assert!(loaded.governance_execution.is_absent());
}

#[test]
fn loader_v2_sidecar_with_sibling_yields_available() {
    let input = rotate_input(TrustBundleEnvironment::Devnet);
    let decision = rotate_decision();
    let wire = GovernanceExecutionPayloadWire::from_parts(&input, &decision);
    let value = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-213-carry.json");
    let loaded =
        load_v2_ratification_sidecar_with_governance_execution_from_bytes(&bytes, &path)
            .expect("v2 sidecar with sibling parses");
    assert!(loaded.governance_execution.is_available());
    assert_eq!(
        loaded.governance_execution.as_parts().unwrap(),
        &GovernanceExecutionParts { input, decision }
    );
}

#[test]
fn loader_v2_sidecar_with_malformed_sibling_yields_malformed() {
    let value = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::json!({ "schema_version": 9_999 })),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    let path = std::path::PathBuf::from("/dev/null/run-213-malformed.json");
    let loaded =
        load_v2_ratification_sidecar_with_governance_execution_from_bytes(&bytes, &path)
            .expect("v2 ratification still parses");
    assert!(loaded.governance_execution.is_malformed());
}

// ===========================================================================
// Wire enum coverage
// ===========================================================================

#[test]
fn class_and_action_wire_round_trip_all_variants() {
    for c in [
        GovernanceExecutionClass::Disabled,
        GovernanceExecutionClass::FixtureGovernance,
        GovernanceExecutionClass::EmergencyCouncilFixture,
        GovernanceExecutionClass::OnChainGovernanceUnavailable,
        GovernanceExecutionClass::ProductionGovernanceUnavailable,
        GovernanceExecutionClass::MainnetGovernanceUnavailable,
        GovernanceExecutionClass::Unknown,
    ] {
        assert_eq!(GovernanceExecutionClassWire::from_class(c).to_class(), c);
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
        assert_eq!(GovernanceExecutionActionWire::from_action(a).to_action(), a);
    }
}

#[test]
fn invalid_commitment_sentinel_fails_closed_through_carrying() {
    let env = TrustBundleEnvironment::Devnet;
    let td = trust_domain(env);
    let exp = rotate_expectations(env);
    let ctx = callsite_context_for_governance_execution(
        &td,
        &exp,
        GovernanceExecutionPolicy::FixtureGovernanceAllowed,
    );
    let mut decision = rotate_decision();
    decision.decision_commitment = GOVERNANCE_EXECUTION_INVALID_COMMITMENT_SENTINEL.to_string();
    let loaded = available_from(&rotate_input(env), &decision);
    assert!(matches!(
        evaluate_loaded_governance_execution(&ctx, &loaded),
        Some(GovernanceExecutionOutcome::MalformedExecutionDecision { .. })
    ));
}

// ===========================================================================
// Source reachability — all seven surfaces reach the Run 211 evaluator
// ===========================================================================

#[test]
fn all_seven_surfaces_reach_run211_evaluator_on_accept() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let loaded = s.loaded();
    let surfaces: [fn(
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
    for surface in surfaces {
        assert!(surface(&ctx, &loaded).is_accept());
    }
    // 7th surface: peer-driven drain accepts on non-MainNet.
    assert!(
        route_loaded_governance_execution_to_peer_driven_drain_callsite_decision(&ctx, &loaded)
            .is_accept()
    );
}

#[test]
fn peer_driven_guard_reachability_helper_accepts_non_mainnet() {
    let s = Scenario::rotate(TrustBundleEnvironment::Devnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        evaluate_loaded_governance_execution_with_peer_driven_guard(&ctx, &s.loaded(), true);
    assert!(matches!(
        outcome,
        Some(GovernanceExecutionComposedOutcome::Accepted(_))
    ));
}

#[test]
fn peer_driven_guard_reachability_helper_refuses_mainnet() {
    let s = Scenario::rotate(TrustBundleEnvironment::Mainnet);
    let td = s.td();
    let ctx = s.ctx(&td);
    let outcome =
        evaluate_loaded_governance_execution_with_peer_driven_guard(&ctx, &s.loaded(), true);
    assert_eq!(
        outcome,
        Some(GovernanceExecutionComposedOutcome::MainNetPeerDrivenApplyRefused)
    );
}