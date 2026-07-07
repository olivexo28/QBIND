//! Run 303 — source/test validator-set rotation / authority-set
//! synchronization intent boundary integration tests.
//!
//! Source/test only. Run 303 does **not** capture release-binary evidence;
//! release-binary evidence for the validator-set rotation boundary is
//! deferred to **Run 304**. The tests cover:
//!
//! * A. accepted / compatible source-test evidence;
//! * B. rejection / fail-closed paths;
//! * C. MainNet / authority policy refusal;
//! * D. replay / recovery / idempotency;
//! * E. non-mutation invariants (the boundary surfaces are pure);
//! * F. C4/C5 taxonomy status.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_303.md`.

use qbind_node::pqc_authority_custody::AuthorityCustodyClass;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_proof::{
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
};
use qbind_node::pqc_production_governance_execution_engine::{
    GovernanceExecutionAttestationBinding, GovernanceExecutionCustodyBinding,
    GovernanceExecutionDurableReplayBinding, GovernanceExecutionRequestedOperation,
    ProductionGovernanceExecutionDecision, ProductionGovernanceExecutionIntent,
    ProductionGovernanceExecutionIntentKind, ProductionGovernanceExecutionOutcome,
};
use qbind_node::pqc_production_validator_set_rotation_intent::*;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

const GENESIS_HASH: &str = "genesis-hash-1";
const ROOT_FP: &str = "authority-root-fp-1";
const GOV_DOMAIN: &str = "gov-domain-1";
const GOV_EPOCH: u64 = 42;
const GOV_HEIGHT: u64 = 1000;
const PROPOSAL_ID: &str = "proposal-1";
const PROPOSAL_DIGEST: &str = "proposal-digest-1";
const CANDIDATE_DIGEST: &str = "candidate-digest-2";
const SEQ: u64 = 7;
const GOV_DECISION_ID: &str = "gov-decision-id-1";
const GOV_REQUEST_ID: &str = "gov-request-id-1";
const GOV_TRANSCRIPT_DIGEST: &str = "gov-transcript-digest-1";
const EXEC_POLICY_ID: &str = "exec-policy-1";
const ROTATION_POLICY_ID: &str = "rotation-policy-1";
const NONCE: u64 = 3;
const CUR_EPOCH: u64 = 10;
const CUR_VERSION: u64 = 5;

fn chain_for(env: TrustBundleEnvironment) -> &'static str {
    match env {
        TrustBundleEnvironment::Devnet => "qbind-devnet",
        TrustBundleEnvironment::Testnet => "qbind-testnet",
        TrustBundleEnvironment::Mainnet => "qbind-mainnet",
    }
}

fn trust_domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
        chain_for(env),
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn quorum() -> OnChainGovernanceQuorum {
    OnChainGovernanceQuorum {
        voters_voted: 8,
        total_voters: 10,
        required_quorum: 6,
    }
}

fn threshold() -> GovernanceThreshold {
    GovernanceThreshold::new(8, 6, 10)
}

fn validator(env: TrustBundleEnvironment, idx: u64, power: u64, act: u64) -> CanonicalValidatorRecord {
    CanonicalValidatorRecord {
        identity: CanonicalValidatorIdentity {
            validator_index: idx,
            consensus_key_fingerprint: format!("cons-{idx}"),
            pqc_transport_fingerprint: format!("pqc-{idx}"),
            authority_key_fingerprint: format!("auth-{idx}"),
        },
        voting_power: power,
        activation_epoch: act,
        retirement_epoch: None,
        environment: env,
        chain_id: chain_for(env).to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
    }
}

fn current_set(env: TrustBundleEnvironment) -> CanonicalValidatorSetSnapshot {
    CanonicalValidatorSetSnapshot::new(
        vec![
            validator(env, 1, 100, 1),
            validator(env, 2, 100, 1),
            validator(env, 3, 100, 1),
        ],
        CUR_EPOCH,
        CUR_VERSION,
    )
}

fn gov_intent(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
) -> ProductionGovernanceExecutionIntent {
    ProductionGovernanceExecutionIntent {
        intent_kind: ProductionGovernanceExecutionIntentKind::AuthorityLifecycleRotationIntent,
        protocol_version: 1,
        execution_policy_id: EXEC_POLICY_ID.to_string(),
        environment: env,
        chain_id: chain_for(env).to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        governance_domain_id: GOV_DOMAIN.to_string(),
        governance_epoch: GOV_EPOCH,
        governance_height: GOV_HEIGHT,
        proposal_id: PROPOSAL_ID.to_string(),
        proposal_digest: PROPOSAL_DIGEST.to_string(),
        proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        quorum: quorum(),
        threshold: threshold(),
        lifecycle_action: lifecycle,
        requested_operation: GovernanceExecutionRequestedOperation::AuthorityLifecycleRotation,
        candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        authority_domain_sequence: SEQ,
        decision_id: GOV_DECISION_ID.to_string(),
        proof_transcript_digest: "run299-transcript".to_string(),
        proof_digest: "run299-proof".to_string(),
        trusted_checkpoint_digest: "run299-checkpoint".to_string(),
        custody_binding: None,
        attestation_binding: None,
        durable_replay_binding: None,
    }
}

fn gov_decision(intent: ProductionGovernanceExecutionIntent) -> ProductionGovernanceExecutionDecision {
    let idig = intent.intent_digest();
    ProductionGovernanceExecutionDecision {
        outcome: ProductionGovernanceExecutionOutcome::AcceptedSourceTestGovernanceExecutionIntent {
            intent_kind: intent.intent_kind,
            environment: intent.environment,
            decision_id: intent.decision_id.clone(),
        },
        decision_id: GOV_DECISION_ID.to_string(),
        request_id: GOV_REQUEST_ID.to_string(),
        intent: Some(intent),
        intent_digest: idig,
        transcript_digest: GOV_TRANSCRIPT_DIGEST.to_string(),
    }
}

fn verified_source(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
) -> (ValidatorSetRotationAuthoritySource, String) {
    let decision = gov_decision(gov_intent(env, lifecycle));
    let idig = decision.intent_digest.clone();
    (
        ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision },
        idig,
    )
}

fn base_inputs(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    intent_digest: String,
    current: &CanonicalValidatorSetSnapshot,
    proposed: &CanonicalValidatorSetSnapshot,
) -> ProductionValidatorSetRotationInputs {
    ProductionValidatorSetRotationInputs {
        trust_domain: trust_domain(env),
        expected_execution_policy_id: EXEC_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        expected_lifecycle_action: lifecycle,
        expected_rotation_action: requested_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_transcript_digest: GOV_TRANSCRIPT_DIGEST.to_string(),
        expected_intent_digest: intent_digest,
        min_governance_epoch: 0,
        min_validator_set_epoch: 0,
        min_validator_set_version: 0,
        persisted_sequence: Some(SEQ - 1),
        expected_current_set_digest: current.set_digest(),
        expected_proposed_set_digest: proposed.set_digest(),
        rotation_policy_id: ROTATION_POLICY_ID.to_string(),
        require_custody_evidence: false,
        expected_custody: None,
        require_attestation_evidence: false,
        expected_attestation: None,
        require_durable_replay_evidence: false,
        expected_durable_replay: None,
    }
}

/// Build a fully-wired case for a given lifecycle / requested action /
/// current set / delta / proposed set.
struct Case {
    boundary: ProductionValidatorSetRotationBoundary,
    request: ProductionValidatorSetRotationRequest,
    inputs: ProductionValidatorSetRotationInputs,
}

fn make_case(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> Case {
    let (source, idig) = verified_source(env, lifecycle);
    let request = ProductionValidatorSetRotationRequest::new(
        source,
        current.clone(),
        delta,
        requested_action,
        proposed.validator_set_epoch,
        proposed.validator_set_version,
        NONCE,
    );
    let inputs = base_inputs(env, lifecycle, requested_action, idig, &current, &proposed);
    Case {
        boundary: ProductionValidatorSetRotationBoundary::source_test(),
        request,
        inputs,
    }
}

fn empty_replay() -> EmptyValidatorSetRotationReplaySet {
    EmptyValidatorSetRotationReplaySet
}

fn eval(case: &Case) -> ProductionValidatorSetRotationDecision {
    case.boundary
        .evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay())
}

// ---- Scenario builders ----------------------------------------------------

/// Add validator 4 (all-Add delta), Rotate lifecycle, ValidatorAdd action.
fn add_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![
            validator(env, 1, 100, 1),
            validator(env, 2, 100, 1),
            validator(env, 3, 100, 1),
            v4,
        ],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorAdd,
        current,
        delta,
        proposed,
    )
}

/// Remove validator 3 (all-Remove delta).
fn remove_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorRemove,
        current,
        delta,
        proposed,
    )
}

/// Update validator 2 voting power (all-Update delta).
fn update_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let updated = validator(env, 2, 250, 1);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(updated.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), updated, validator(env, 3, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorUpdate,
        current,
        delta,
        proposed,
    )
}

/// No-op / already synchronized (empty delta).
fn noop_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let proposed = current_set(env);
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current,
        ValidatorSetDelta::empty(),
        proposed,
    )
}

// ===========================================================================
// A. Accepted / compatible source-test evidence
// ===========================================================================

#[test]
fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_validator_set_rotation_boundary_default_is_disabled());
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::default(),
        ProductionValidatorSetRotationPolicy::default(),
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = b.evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, ProductionValidatorSetRotationOutcome::Disabled);
    assert!(!d.is_accept());
    assert!(d.plan.is_none());
}

#[test]
fn a02_devnet_intent_produces_plan() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.plan.is_some());
}

#[test]
fn a03_testnet_intent_produces_plan() {
    let d = eval(&add_case(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.plan.is_some());
}

#[test]
fn a04_noop_plan_accepted_non_mutating() {
    let d = eval(&noop_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::NoOpAlreadySynchronized
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a05_validator_add_plan_non_mutating() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    let plan = d.plan.unwrap();
    assert_eq!(plan.plan_kind, ProductionValidatorSetRotationPlanKind::ValidatorAdd);
    assert!(plan.is_non_mutating());
}

#[test]
fn a06_validator_remove_plan_non_mutating() {
    let d = eval(&remove_case(TrustBundleEnvironment::Devnet));
    let plan = d.plan.unwrap();
    assert_eq!(plan.plan_kind, ProductionValidatorSetRotationPlanKind::ValidatorRemove);
    assert!(plan.is_non_mutating());
}

#[test]
fn a07_validator_update_plan_non_mutating() {
    let d = eval(&update_case(TrustBundleEnvironment::Devnet));
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::ValidatorMetadataUpdate
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a08_validator_identity_rotation_plan_non_mutating() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    // Update validator 2 with a rotated consensus key.
    let mut rotated = validator(env, 2, 100, 1);
    rotated.identity.consensus_key_fingerprint = "cons-2-rotated".to_string();
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(rotated.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), rotated, validator(env, 3, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorIdentityRotation,
        current,
        delta,
        proposed,
    );
    let d = eval(&case);
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::ValidatorIdentityRotation
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a09_validator_retirement_plan_non_mutating() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let case = make_case(
        env,
        LocalLifecycleAction::Retire,
        ValidatorSetRotationAction::ValidatorRetirement,
        current,
        delta,
        proposed,
    );
    let d = eval(&case);
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::ValidatorRetirement
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a10_emergency_validator_removal_plan_non_mutating() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let case = make_case(
        env,
        LocalLifecycleAction::EmergencyRevoke,
        ValidatorSetRotationAction::EmergencyValidatorRemoval,
        current,
        delta,
        proposed,
    );
    let d = eval(&case);
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::EmergencyValidatorRemoval
    );
    assert!(plan.is_non_mutating());
}

/// A mixed add+remove delta used for authority-set-sync and bulk scenarios.
fn bulk_case(env: TrustBundleEnvironment, action: ValidatorSetRotationAction) -> Case {
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![
        ValidatorSetChange::add(v4.clone()),
        ValidatorSetChange::remove(3),
    ]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), v4],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::Rotate, action, current, delta, proposed)
}

#[test]
fn a11_authority_set_synchronization_plan_non_mutating() {
    let d = eval(&bulk_case(
        TrustBundleEnvironment::Devnet,
        ValidatorSetRotationAction::AuthoritySetSynchronization,
    ));
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::AuthoritySetSynchronization
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a12_bulk_validator_set_rotation_plan_non_mutating() {
    let d = eval(&bulk_case(
        TrustBundleEnvironment::Devnet,
        ValidatorSetRotationAction::BulkValidatorSetRotation,
    ));
    let plan = d.plan.unwrap();
    assert_eq!(
        plan.plan_kind,
        ProductionValidatorSetRotationPlanKind::BulkValidatorSetRotation
    );
    assert!(plan.is_non_mutating());
}

#[test]
fn a13_accepted_plan_binds_environment_chain_genesis_root() {
    let env = TrustBundleEnvironment::Testnet;
    let plan = eval(&add_case(env)).plan.unwrap();
    assert_eq!(plan.environment, env);
    assert_eq!(plan.chain_id, chain_for(env));
    assert_eq!(plan.genesis_hash, GENESIS_HASH);
    assert_eq!(plan.authority_root_fingerprint, ROOT_FP);
    assert_eq!(plan.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

#[test]
fn a14_accepted_plan_binds_governance_tuple() {
    let plan = eval(&add_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    assert_eq!(plan.governance_domain_id, GOV_DOMAIN);
    assert_eq!(plan.governance_epoch, GOV_EPOCH);
    assert_eq!(plan.proposal_id, PROPOSAL_ID);
    assert_eq!(plan.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(plan.authority_domain_sequence, SEQ);
}

#[test]
fn a15_accepted_plan_binds_governance_execution_ids_and_digests() {
    let plan = eval(&add_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    assert_eq!(plan.governance_decision_id, GOV_DECISION_ID);
    assert_eq!(plan.governance_request_id, GOV_REQUEST_ID);
    assert!(!plan.governance_intent_digest.is_empty());
}

#[test]
fn a16_accepted_plan_binds_validator_set_digests_and_versions() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_current = case.inputs.expected_current_set_digest.clone();
    let expected_proposed = case.inputs.expected_proposed_set_digest.clone();
    let plan = eval(&case).plan.unwrap();
    assert_eq!(plan.current_set_digest, expected_current);
    assert_eq!(plan.proposed_set_digest, expected_proposed);
    assert_eq!(plan.validator_set_epoch, CUR_EPOCH + 1);
    assert_eq!(plan.validator_set_version, CUR_VERSION + 1);
    assert_eq!(plan.proposed_validator_count, 4);
}

#[test]
fn a17_accepted_plan_binds_rotation_nonce_and_quorum_threshold() {
    let plan = eval(&add_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    assert_eq!(plan.rotation_nonce, NONCE);
    assert_eq!(plan.quorum, quorum());
    assert_eq!(plan.threshold, threshold());
}

#[test]
fn a18_accepted_plan_binds_custody_attestation_durable_where_represented() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.custody_binding = Some(custody());
    case.request.attestation_binding = Some(attestation());
    case.request.durable_replay_binding = Some(durable());
    let plan = eval(&case).plan.unwrap();
    assert_eq!(plan.custody_binding, Some(custody()));
    assert_eq!(plan.attestation_binding, Some(attestation()));
    assert_eq!(plan.durable_replay_binding, Some(durable()));
}

#[test]
fn a19_request_id_deterministic() {
    let a = production_validator_set_rotation_request_id(1, "d", "i", "p", 3);
    let b = production_validator_set_rotation_request_id(1, "d", "i", "p", 3);
    assert_eq!(a, b);
    let c = production_validator_set_rotation_request_id(1, "d", "i", "p", 4);
    assert_ne!(a, c);
}

#[test]
fn a20_set_and_delta_and_plan_digests_deterministic() {
    let case1 = add_case(TrustBundleEnvironment::Devnet);
    let case2 = add_case(TrustBundleEnvironment::Devnet);
    assert_eq!(
        case1.request.current_set.set_digest(),
        case2.request.current_set.set_digest()
    );
    assert_eq!(
        case1.request.delta.delta_digest(),
        case2.request.delta.delta_digest()
    );
    let p1 = eval(&case1).plan.unwrap();
    let p2 = eval(&case2).plan.unwrap();
    assert_eq!(p1.plan_digest(), p2.plan_digest());
}

#[test]
fn a21_transcript_digest_deterministic() {
    let d1 = eval(&add_case(TrustBundleEnvironment::Devnet));
    let d2 = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
}

#[test]
fn a22_records_sorted_canonically_before_digesting() {
    let env = TrustBundleEnvironment::Devnet;
    let ordered = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    let shuffled = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 3, 100, 1), validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    assert_eq!(ordered.set_digest(), shuffled.set_digest());
}

#[test]
fn a23_different_validator_id_changes_set_digest() {
    let env = TrustBundleEnvironment::Devnet;
    let a = current_set(env);
    let b = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 9, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    assert_ne!(a.set_digest(), b.set_digest());
}

#[test]
fn a24_different_consensus_key_changes_set_digest() {
    let env = TrustBundleEnvironment::Devnet;
    let a = current_set(env);
    let mut v = validator(env, 3, 100, 1);
    v.identity.consensus_key_fingerprint = "cons-3-alt".to_string();
    let b = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), v],
        CUR_EPOCH,
        CUR_VERSION,
    );
    assert_ne!(a.set_digest(), b.set_digest());
}

#[test]
fn a25_different_voting_power_changes_set_digest() {
    let env = TrustBundleEnvironment::Devnet;
    let a = current_set(env);
    let b = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 999, 1), validator(env, 3, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    assert_ne!(a.set_digest(), b.set_digest());
}

#[test]
fn a26_different_activation_epoch_changes_set_digest() {
    let env = TrustBundleEnvironment::Devnet;
    let a = current_set(env);
    let b = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 9), validator(env, 3, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    assert_ne!(a.set_digest(), b.set_digest());
}

#[test]
fn a27_different_rotation_action_changes_plan_digest() {
    let add = eval(&add_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    let remove = eval(&remove_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    assert_ne!(add.plan_digest(), remove.plan_digest());
}

#[test]
fn a28_different_proposed_set_changes_plan_digest() {
    let add = eval(&add_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    let update = eval(&update_case(TrustBundleEnvironment::Devnet)).plan.unwrap();
    assert_ne!(add.proposed_set_digest, update.proposed_set_digest);
    assert_ne!(add.plan_digest(), update.plan_digest());
}

#[test]
fn a29_governance_execution_accept_composes_into_boundary_input() {
    // The Run 301/302 accepted decision carrying an intent is the only
    // authority the boundary accepts.
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.authorizes_future_mutation_only());
}

#[test]
fn a30_accepted_outcome_is_non_mutating_and_future_only() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_non_mutating());
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(!d.outcome.is_reject());
}

// ---- Evidence fixtures ----------------------------------------------------

fn custody() -> GovernanceExecutionCustodyBinding {
    GovernanceExecutionCustodyBinding {
        provider_class: AuthorityCustodyClass::Kms,
        key_handle: "kms-key-1".to_string(),
        signer_fingerprint: "signer-fp-1".to_string(),
        custody_transcript_digest: "custody-transcript-1".to_string(),
    }
}

fn attestation() -> GovernanceExecutionAttestationBinding {
    GovernanceExecutionAttestationBinding {
        attestation_transcript_digest: "attestation-transcript-1".to_string(),
        measurement: "measurement-1".to_string(),
    }
}

fn durable() -> GovernanceExecutionDurableReplayBinding {
    GovernanceExecutionDurableReplayBinding {
        durable_record_id: "durable-1".to_string(),
        durable_record_digest: "durable-digest-1".to_string(),
    }
}

// ===========================================================================
// B. Rejection / fail-closed source-test evidence
// ===========================================================================

use ProductionValidatorSetRotationOutcome as O;

fn assert_reject(d: &ProductionValidatorSetRotationDecision, expected: &O) {
    assert_eq!(&d.outcome, expected);
    assert!(!d.is_accept());
    assert!(d.outcome.is_reject());
    assert!(d.plan.is_none());
    assert!(d.outcome.is_non_mutating());
}

#[test]
fn b01_disabled_rejects_before_plan_construction() {
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::default(),
        ProductionValidatorSetRotationPolicy::Disabled,
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = b.evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, O::Disabled);
    assert!(d.plan.is_none());
}

fn eval_with_source(source: ValidatorSetRotationAuthoritySource) -> ProductionValidatorSetRotationDecision {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.authority_source = source;
    eval(&case)
}

#[test]
fn b02_missing_governance_intent_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::MissingGovernanceIntent);
    assert_reject(&d, &O::VerifiedGovernanceExecutionIntentRequired);
}

#[test]
fn b03_unverified_governance_intent_rejected() {
    let decision = gov_decision(gov_intent(TrustBundleEnvironment::Devnet, LocalLifecycleAction::Rotate));
    let d = eval_with_source(
        ValidatorSetRotationAuthoritySource::UnverifiedGovernanceExecutionDecision { decision },
    );
    assert_reject(&d, &O::UnverifiedGovernanceExecutionIntentRejected);
}

#[test]
fn b04_onchain_proof_alone_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::OnChainProofWithoutExecutionIntent);
    assert_reject(&d, &O::OnChainProofAloneRejected);
}

#[test]
fn b05_fixture_proof_alone_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::FixtureGovernanceIntent);
    assert_reject(&d, &O::FixtureProofRejectedAsProductionAuthority);
}

#[test]
fn b06_local_operator_assertion_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::LocalOperatorAssertion);
    assert_reject(&d, &O::LocalOperatorProofRejected);
}

#[test]
fn b07_peer_majority_assertion_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::PeerMajorityAssertion);
    assert_reject(&d, &O::PeerMajorityProofRejected);
}

#[test]
fn b08_custody_only_evidence_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::CustodyOnlyEvidence);
    assert_reject(&d, &O::CustodyOnlyProofRejected);
}

#[test]
fn b09_remote_signer_only_evidence_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::RemoteSignerOnlyEvidence);
    assert_reject(&d, &O::RemoteSignerOnlyProofRejected);
}

#[test]
fn b10_custody_attestation_only_evidence_rejected() {
    let d = eval_with_source(ValidatorSetRotationAuthoritySource::CustodyAttestationOnlyEvidence);
    assert_reject(&d, &O::CustodyAttestationOnlyProofRejected);
}

#[test]
fn b11_accepted_decision_without_intent_rejected() {
    let mut decision = gov_decision(gov_intent(TrustBundleEnvironment::Devnet, LocalLifecycleAction::Rotate));
    decision.intent = None;
    let d = eval_with_source(
        ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision },
    );
    assert_reject(&d, &O::VerifiedGovernanceExecutionIntentRequired);
}

#[test]
fn b12_wrong_intent_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_intent_digest = "wrong-digest".to_string();
    assert_reject(&eval(&case), &O::WrongGovernanceExecutionIntentDigest);
}

#[test]
fn b13_wrong_transcript_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_transcript_digest = "wrong-transcript".to_string();
    assert_reject(&eval(&case), &O::GovernanceExecutionTranscriptMismatch);
}

#[test]
fn b14_wrong_environment_rejected() {
    // Trust domain says Testnet but the intent is Devnet.
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Testnet);
    assert_reject(&eval(&case), &O::WrongEnvironment);
}

#[test]
fn b15_wrong_chain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain.chain_id = "other-chain".to_string();
    assert_reject(&eval(&case), &O::WrongChain);
}

#[test]
fn b16_wrong_genesis_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain.genesis_hash = "other-genesis".to_string();
    assert_reject(&eval(&case), &O::WrongGenesis);
}

#[test]
fn b17_wrong_authority_root_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain.authority_root_fingerprint = "other-root".to_string();
    assert_reject(&eval(&case), &O::WrongAuthorityRoot);
}

#[test]
fn b18_wrong_governance_domain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_reject(&eval(&case), &O::WrongGovernanceDomain);
}

#[test]
fn b19_wrong_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&eval(&case), &O::WrongGovernanceEpoch);
}

#[test]
fn b20_wrong_governance_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_decision_id = "other-decision".to_string();
    assert_reject(&eval(&case), &O::WrongGovernanceExecutionDecisionId);
}

#[test]
fn b21_wrong_governance_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_request_id = "other-request".to_string();
    assert_reject(&eval(&case), &O::WrongGovernanceExecutionRequestId);
}

#[test]
fn b22_wrong_lifecycle_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_lifecycle_action = LocalLifecycleAction::Retire;
    assert_reject(&eval(&case), &O::WrongLifecycleAction);
}

#[test]
fn b23_wrong_candidate_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_candidate_v2_digest = "other-candidate".to_string();
    assert_reject(&eval(&case), &O::WrongCandidateDigest);
}

#[test]
fn b24_wrong_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_authority_domain_sequence = SEQ + 5;
    assert_reject(&eval(&case), &O::WrongAuthoritySequence);
}

#[test]
fn b25_wrong_quorum_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_quorum = OnChainGovernanceQuorum {
        voters_voted: 9,
        total_voters: 10,
        required_quorum: 6,
    };
    assert_reject(&eval(&case), &O::WrongQuorum);
}

#[test]
fn b26_wrong_threshold_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_threshold = GovernanceThreshold::new(9, 6, 10);
    assert_reject(&eval(&case), &O::WrongThreshold);
}

#[test]
fn b27_current_set_digest_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_current_set_digest = "wrong-current".to_string();
    assert_reject(&eval(&case), &O::CurrentValidatorSetDigestMismatch);
}

#[test]
fn b28_proposed_set_digest_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposed_set_digest = "wrong-proposed".to_string();
    assert_reject(&eval(&case), &O::ProposedValidatorSetDigestMismatch);
}

#[test]
fn b29_validator_set_epoch_mismatch_rejected() {
    // Non-empty delta but proposed epoch unchanged.
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_validator_set_epoch = CUR_EPOCH;
    assert_reject(&eval(&case), &O::ValidatorSetEpochMismatch);
}

#[test]
fn b30_validator_set_version_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Advance epoch (so we pass the epoch gate) but leave version unchanged.
    case.request.proposed_validator_set_version = CUR_VERSION;
    assert_reject(&eval(&case), &O::ValidatorSetVersionMismatch);
}

#[test]
fn b31_non_monotonic_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_validator_set_epoch = CUR_EPOCH - 1;
    assert_reject(&eval(&case), &O::NonMonotonicValidatorSetEpoch);
}

#[test]
fn b32_non_monotonic_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_validator_set_version = CUR_VERSION - 1;
    assert_reject(&eval(&case), &O::NonMonotonicValidatorSetVersion);
}

#[test]
fn b33_empty_proposed_validator_set_rejected() {
    // Remove all validators.
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![
        ValidatorSetChange::remove(1),
        ValidatorSetChange::remove(2),
        ValidatorSetChange::remove(3),
    ]);
    let proposed = CanonicalValidatorSetSnapshot::new(vec![], CUR_EPOCH + 1, CUR_VERSION + 1);
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorRemove,
        current,
        delta,
        proposed,
    );
    assert_reject(&eval(&case), &O::EmptyProposedValidatorSetRejected);
}

#[test]
fn b34_duplicate_validator_id_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let dup = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 1, 100, 1)],
        CUR_EPOCH,
        CUR_VERSION,
    );
    let mut case = add_case(env);
    case.request.current_set = dup.clone();
    case.inputs.expected_current_set_digest = dup.set_digest();
    assert_reject(&eval(&case), &O::DuplicateValidatorId);
}

#[test]
fn b35_duplicate_consensus_key_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut v2 = validator(env, 2, 100, 1);
    v2.identity.consensus_key_fingerprint = "cons-1".to_string();
    let dup = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), v2],
        CUR_EPOCH,
        CUR_VERSION,
    );
    let mut case = add_case(env);
    case.request.current_set = dup.clone();
    case.inputs.expected_current_set_digest = dup.set_digest();
    assert_reject(&eval(&case), &O::DuplicateConsensusKey);
}

#[test]
fn b36_duplicate_pqc_transport_key_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut v2 = validator(env, 2, 100, 1);
    v2.identity.pqc_transport_fingerprint = "pqc-1".to_string();
    let dup = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), v2],
        CUR_EPOCH,
        CUR_VERSION,
    );
    let mut case = add_case(env);
    case.request.current_set = dup.clone();
    case.inputs.expected_current_set_digest = dup.set_digest();
    assert_reject(&eval(&case), &O::DuplicatePqcTransportKey);
}

#[test]
fn b37_duplicate_authority_key_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let mut v2 = validator(env, 2, 100, 1);
    v2.identity.authority_key_fingerprint = "auth-1".to_string();
    let dup = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), v2],
        CUR_EPOCH,
        CUR_VERSION,
    );
    let mut case = add_case(env);
    case.request.current_set = dup.clone();
    case.inputs.expected_current_set_digest = dup.set_digest();
    assert_reject(&eval(&case), &O::DuplicateAuthorityKey);
}

#[test]
fn b38_unknown_validator_removal_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(99)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorRemove,
        current,
        delta,
        proposed,
    );
    assert_reject(&eval(&case), &O::UnknownValidatorRemoval);
}

#[test]
fn b39_unknown_validator_update_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(validator(env, 99, 100, 1))]);
    let proposed = current_set(env);
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorUpdate,
        current,
        delta,
        proposed,
    );
    assert_reject(&eval(&case), &O::UnknownValidatorUpdate);
}

#[test]
fn b40_conflicting_delta_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![
        ValidatorSetChange::add(validator(env, 4, 100, 2)),
        ValidatorSetChange::remove(4),
    ]);
    let proposed = current_set(env);
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::BulkValidatorSetRotation,
        current,
        delta,
        proposed,
    );
    assert_reject(&eval(&case), &O::ConflictingValidatorDelta);
}

#[test]
fn b41_ambiguous_delta_rejected() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![
        ValidatorSetChange::remove(3),
        ValidatorSetChange::remove(3),
    ]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let case = make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorRemove,
        current,
        delta,
        proposed,
    );
    assert_reject(&eval(&case), &O::AmbiguousValidatorSetDelta);
}

#[test]
fn b42_unsupported_validator_set_delta_rejected() {
    // Requested action inconsistent with the derived delta composition:
    // an all-Add delta requested as ValidatorRemove.
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.requested_action = ValidatorSetRotationAction::ValidatorRemove;
    case.inputs.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove;
    // Rotate authorizes ValidatorRemove, so we reach the delta-composition
    // gate.
    assert_reject(&eval(&case), &O::UnsupportedValidatorSetDelta);
}

#[test]
fn b43_unsupported_rotation_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.requested_action = ValidatorSetRotationAction::UnsupportedRotation;
    case.inputs.expected_rotation_action = ValidatorSetRotationAction::UnsupportedRotation;
    assert_reject(&eval(&case), &O::UnsupportedRotationAction);
}

#[test]
fn b44_missing_custody_evidence_rejected_when_required() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    assert_reject(&eval(&case), &O::CustodyBackendEvidenceRequired);
}

#[test]
fn b45_wrong_custody_evidence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    let mut wrong = custody();
    wrong.key_handle = "other".to_string();
    case.request.custody_binding = Some(wrong);
    assert_reject(&eval(&case), &O::CustodyBackendMismatch);
}

#[test]
fn b46_missing_attestation_rejected_when_required() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    assert_reject(&eval(&case), &O::CustodyAttestationRequired);
}

#[test]
fn b47_wrong_attestation_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    let mut wrong = attestation();
    wrong.measurement = "other".to_string();
    case.request.attestation_binding = Some(wrong);
    assert_reject(&eval(&case), &O::CustodyAttestationMismatch);
}

#[test]
fn b48_missing_durable_replay_rejected_when_required() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    assert_reject(&eval(&case), &O::DurableReplayEvidenceRequired);
}

#[test]
fn b49_wrong_durable_replay_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    let mut wrong = durable();
    wrong.durable_record_digest = "other".to_string();
    case.request.durable_replay_binding = Some(wrong);
    assert_reject(&eval(&case), &O::DurableReplayMismatch);
}

#[test]
fn b50_durable_replay_unavailable_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    // Malformed durable binding (empty digest) => unavailable.
    case.request.durable_replay_binding = Some(GovernanceExecutionDurableReplayBinding {
        durable_record_id: "durable-1".to_string(),
        durable_record_digest: String::new(),
    });
    assert_reject(&eval(&case), &O::DurableReplayUnavailable);
}

#[test]
fn b51_replayed_rotation_nonce_rejected() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    // Recompute the exact rotation id the boundary derives.
    let idig = match &case.request.authority_source {
        ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision } => {
            decision.intent_digest.clone()
        }
        _ => unreachable!(),
    };
    let real_id = production_validator_set_rotation_request_id(
        1,
        GOV_DECISION_ID,
        &idig,
        ROTATION_POLICY_ID,
        NONCE,
    );
    let replay = vec![real_id];
    let d = case
        .boundary
        .evaluate_validator_set_rotation(&case.request, &case.inputs, &replay);
    assert!(matches!(d.outcome, O::RotationReplayRejected { .. }));
    assert!(d.plan.is_none());
}

#[test]
fn b52_stale_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&eval(&case), &O::StaleGovernanceEpoch);
}

#[test]
fn b53_stale_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ + 1);
    assert_reject(&eval(&case), &O::StaleAuthoritySequence);
}

#[test]
fn b54_stale_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Require a validator-set epoch higher than the proposed one.
    case.inputs.min_validator_set_epoch = CUR_EPOCH + 5;
    assert_reject(&eval(&case), &O::StaleValidatorSetEpoch);
}

#[test]
fn b55_stale_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_version = CUR_VERSION + 5;
    assert_reject(&eval(&case), &O::StaleValidatorSetVersion);
}

#[test]
fn b56_production_policy_without_prerequisites_fails_closed() {
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::source_test(),
        ProductionValidatorSetRotationPolicy::RequireProductionValidatorSetRotation,
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = b.evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, O::ProductionValidatorSetRotationUnavailable);
    assert!(d.plan.is_none());
}

#[test]
fn b57_ambiguous_input_fails_closed() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.rotation_policy_id = String::new();
    assert_reject(&eval(&case), &O::ValidatorSetRotationBoundaryUnavailable);
}

#[test]
fn b58_missing_current_set_rejected() {
    // A malformed (empty-fingerprint) current record fails closed.
    let env = TrustBundleEnvironment::Devnet;
    let mut bad = validator(env, 1, 100, 1);
    bad.identity.consensus_key_fingerprint = String::new();
    let snap = CanonicalValidatorSetSnapshot::new(vec![bad], CUR_EPOCH, CUR_VERSION);
    let mut case = add_case(env);
    case.request.current_set = snap.clone();
    case.inputs.expected_current_set_digest = snap.set_digest();
    assert_reject(&eval(&case), &O::CurrentValidatorSetRequired);
}

// ===========================================================================
// C. MainNet / authority policy evidence
// ===========================================================================

/// A MainNet case: MainNet trust domain + intent, source/test policy.
fn mainnet_case() -> Case {
    let env = TrustBundleEnvironment::Mainnet;
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![
            validator(env, 1, 100, 1),
            validator(env, 2, 100, 1),
            validator(env, 3, 100, 1),
            v4,
        ],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorAdd,
        current,
        delta,
        proposed,
    )
}

fn mainnet_reject_with(source: ValidatorSetRotationAuthoritySource) -> ProductionValidatorSetRotationDecision {
    let mut case = mainnet_case();
    case.request.authority_source = source;
    eval(&case)
}

#[test]
fn c01_mainnet_not_satisfied_by_fixture() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::FixtureGovernanceIntent);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c02_mainnet_not_satisfied_by_local_operator() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::LocalOperatorAssertion);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c03_mainnet_not_satisfied_by_peer_majority() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::PeerMajorityAssertion);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c04_mainnet_not_satisfied_by_remote_signer_only() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::RemoteSignerOnlyEvidence);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c05_mainnet_not_satisfied_by_custody_alone() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::CustodyOnlyEvidence);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c06_mainnet_not_satisfied_by_custody_attestation_alone() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::CustodyAttestationOnlyEvidence);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c07_mainnet_not_satisfied_by_onchain_proof_alone() {
    let d = mainnet_reject_with(ValidatorSetRotationAuthoritySource::OnChainProofWithoutExecutionIntent);
    assert_eq!(d.outcome, O::MainNetRefused);
}

#[test]
fn c08_mainnet_not_satisfied_by_governance_intent_alone() {
    // A fully valid-looking MainNet governance execution intent is still
    // refused: no production rotation prerequisites are wired.
    let d = eval(&mainnet_case());
    assert_eq!(d.outcome, O::MainNetRefused);
    assert!(d.plan.is_none());
}

#[test]
fn c09_mainnet_production_required_policy_returns_unavailable() {
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::source_test(),
        ProductionValidatorSetRotationPolicy::MainnetProductionValidatorSetRotationRequired,
    );
    let case = mainnet_case();
    let d = b.evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, O::MainNetProductionValidatorSetRotationUnavailable);
    assert!(d.plan.is_none());
}

#[test]
fn c10_mainnet_policy_on_non_mainnet_domain_unavailable() {
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::source_test(),
        ProductionValidatorSetRotationPolicy::MainnetProductionValidatorSetRotationRequired,
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = b.evaluate_validator_set_rotation(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, O::MainNetProductionValidatorSetRotationUnavailable);
}

#[test]
fn c11_valid_devnet_source_test_does_not_enable_mainnet() {
    // A DevNet accept never touches MainNet: the accepted plan environment
    // is DevNet and mainnet is still refused.
    let devnet = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(devnet.is_accept());
    assert_eq!(devnet.plan.unwrap().environment, TrustBundleEnvironment::Devnet);
    assert!(production_validator_set_rotation_boundary_mainnet_refused());
    assert_eq!(eval(&mainnet_case()).outcome, O::MainNetRefused);
}

#[test]
fn c12_mainnet_refused_is_non_mutating() {
    let d = eval(&mainnet_case());
    assert!(d.outcome.is_non_mutating());
    assert!(!d.is_accept());
}

// ===========================================================================
// D. Replay / recovery / idempotency evidence
// ===========================================================================

fn accepted_plan(env: TrustBundleEnvironment) -> ProductionValidatorSetRotationPlan {
    eval(&add_case(env)).plan.unwrap()
}

#[test]
fn d01_no_prior_window_is_clean_no_op() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let outcome = b.recover_validator_set_rotation_window(None, &current);
    assert!(outcome.is_clean());
    assert!(outcome.is_non_mutating());
    assert_eq!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::NoPriorRotationWindow
    );
}

#[test]
fn d02_byte_identical_plan_is_idempotent() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let prior = current.clone();
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    assert!(matches!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
    assert!(outcome.is_non_mutating());
}

#[test]
fn d03_different_proposed_set_same_window_fails_closed() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let mut prior = current.clone();
    prior.proposed_set_digest = "different".to_string();
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    // Non-identical plan in the same window is not treated as idempotent.
    assert!(!matches!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
    assert!(outcome.is_non_mutating());
}

#[test]
fn d04_different_current_set_same_window_fails_closed() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let mut prior = current.clone();
    prior.current_set_digest = "different".to_string();
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    assert!(!matches!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
}

#[test]
fn d05_different_lifecycle_action_same_window_fails_closed() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let mut prior = current.clone();
    prior.lifecycle_action = LocalLifecycleAction::Retire;
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    assert!(!matches!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
}

#[test]
fn d06_different_intent_digest_same_window_fails_closed() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let mut prior = current.clone();
    prior.governance_intent_digest = "different".to_string();
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    assert!(!matches!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
}

#[test]
fn d07_unrelated_window_is_clean() {
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let mut prior = current.clone();
    prior.governance_decision_id = "other-decision".to_string();
    let outcome = b.recover_validator_set_rotation_window(Some(&prior), &current);
    assert_eq!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::NoPriorRotationWindow
    );
}

#[test]
fn d08_recovery_disabled_when_policy_disabled() {
    let b = ProductionValidatorSetRotationBoundary::new(
        ProductionValidatorSetRotationConfig::default(),
        ProductionValidatorSetRotationPolicy::Disabled,
    );
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let outcome = b.recover_validator_set_rotation_window(None, &current);
    assert_eq!(
        outcome,
        ProductionValidatorSetRotationRecoveryOutcome::RecoveryDisabled
    );
}

#[test]
fn d09_stale_governance_epoch_fails_closed_in_eval() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH + 10;
    assert_eq!(eval(&case).outcome, O::StaleGovernanceEpoch);
}

#[test]
fn d10_stale_authority_sequence_fails_closed_in_eval() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ + 3);
    assert_eq!(eval(&case).outcome, O::StaleAuthoritySequence);
}

#[test]
fn d11_stale_validator_set_epoch_fails_closed_in_eval() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_epoch = CUR_EPOCH + 10;
    assert_eq!(eval(&case).outcome, O::StaleValidatorSetEpoch);
}

#[test]
fn d12_stale_validator_set_version_fails_closed_in_eval() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_version = CUR_VERSION + 10;
    assert_eq!(eval(&case).outcome, O::StaleValidatorSetVersion);
}

#[test]
fn d13_no_durable_mutation_is_claimed() {
    // Recovery never claims durable mutation.
    let b = ProductionValidatorSetRotationBoundary::source_test();
    let current = accepted_plan(TrustBundleEnvironment::Devnet);
    let outcome = b.recover_validator_set_rotation_window(None, &current);
    assert!(outcome.is_non_mutating());
}

// ===========================================================================
// E. Non-mutation evidence
// ===========================================================================

#[test]
fn e01_accepted_plan_is_non_mutating() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_non_mutating());
    assert!(d.plan.unwrap().is_non_mutating());
}

#[test]
fn e02_every_reject_is_non_mutating() {
    let rejects = [
        eval_with_source(ValidatorSetRotationAuthoritySource::MissingGovernanceIntent),
        eval_with_source(ValidatorSetRotationAuthoritySource::FixtureGovernanceIntent),
        eval_with_source(ValidatorSetRotationAuthoritySource::LocalOperatorAssertion),
        eval(&mainnet_case()),
    ];
    for d in &rejects {
        assert!(d.outcome.is_non_mutating());
        assert!(d.plan.is_none());
    }
}

#[test]
fn e03_boundary_never_falls_back() {
    assert!(production_validator_set_rotation_boundary_never_falls_back());
}

#[test]
fn e04_boundary_no_default_runtime_wiring() {
    assert!(production_validator_set_rotation_boundary_no_default_runtime_wiring());
}

#[test]
fn e05_boundary_is_non_mutating_invariant() {
    assert!(production_validator_set_rotation_boundary_is_non_mutating());
}

#[test]
fn e06_boundary_requires_verified_governance_intent() {
    assert!(production_validator_set_rotation_boundary_requires_verified_governance_intent());
}

#[test]
fn e07_all_outcomes_report_non_mutating() {
    // Sample a representative set of outcomes.
    let outcomes = [
        O::Disabled,
        O::MainNetRefused,
        O::VerifiedGovernanceExecutionIntentRequired,
        O::ConflictingValidatorDelta,
        O::AcceptedSourceTestValidatorSetRotationPlan {
            plan_kind: ProductionValidatorSetRotationPlanKind::ValidatorAdd,
            environment: TrustBundleEnvironment::Devnet,
            rotation_nonce: NONCE,
        },
    ];
    for o in &outcomes {
        assert!(o.is_non_mutating());
    }
}

#[test]
fn e08_only_accept_authorizes_future_mutation_only() {
    assert!(O::AcceptedSourceTestValidatorSetRotationPlan {
        plan_kind: ProductionValidatorSetRotationPlanKind::ValidatorAdd,
        environment: TrustBundleEnvironment::Devnet,
        rotation_nonce: NONCE,
    }
    .authorizes_future_mutation_only());
    assert!(!O::Disabled.authorizes_future_mutation_only());
    assert!(!O::MainNetRefused.authorizes_future_mutation_only());
}

// ===========================================================================
// F. C4/C5 taxonomy evidence
// ===========================================================================

#[test]
fn f01_run303_is_source_test_not_release_binary_evidence() {
    assert!(
        production_validator_set_rotation_boundary_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn f02_default_disabled_is_fail_closed() {
    assert!(production_validator_set_rotation_boundary_default_is_disabled());
}

#[test]
fn f03_policy_tags_are_stable() {
    assert_eq!(ProductionValidatorSetRotationPolicy::Disabled.tag(), "disabled");
    assert_eq!(
        ProductionValidatorSetRotationPolicy::AllowSourceTestValidatorSetRotationIntent.tag(),
        "allow-source-test-validator-set-rotation-intent"
    );
    assert!(ProductionValidatorSetRotationPolicy::default().is_disabled());
}

#[test]
fn f04_plan_kind_tags_are_stable() {
    assert_eq!(
        ProductionValidatorSetRotationPlanKind::ValidatorAdd.tag(),
        "validator-add-plan"
    );
    assert_eq!(
        ProductionValidatorSetRotationPlanKind::NoOpAlreadySynchronized.tag(),
        "no-op-already-synchronized"
    );
    assert!(ProductionValidatorSetRotationPlanKind::BulkValidatorSetRotation.is_non_mutating());
}

#[test]
fn f05_outcome_tags_are_stable() {
    assert_eq!(
        O::AcceptedSourceTestValidatorSetRotationPlan {
            plan_kind: ProductionValidatorSetRotationPlanKind::ValidatorAdd,
            environment: TrustBundleEnvironment::Devnet,
            rotation_nonce: NONCE,
        }
        .tag(),
        "accepted-source-test-validator-set-rotation-plan"
    );
    assert_eq!(O::MainNetRefused.tag(), "mainnet-refused");
    assert_eq!(O::ConflictingValidatorDelta.tag(), "conflicting-validator-delta");
}

#[test]
fn f06_protocol_version_is_supported() {
    assert_eq!(PRODUCTION_VALIDATOR_SET_ROTATION_PROTOCOL_VERSION, 1);
    assert!(ProductionValidatorSetRotationProtocolVersion::supported().is_supported());
    assert!(ProductionValidatorSetRotationProtocolVersion::default().is_supported());
}

#[test]
fn f07_config_defaults_to_disabled_kind() {
    assert_eq!(
        ProductionValidatorSetRotationConfig::default().kind,
        ProductionValidatorSetRotationKind::Disabled
    );
    assert!(ProductionValidatorSetRotationConfig::source_test().is_well_formed());
    assert!(ProductionValidatorSetRotationConfig::source_test()
        .kind
        .is_source_test());
}

#[test]
fn f08_rotation_action_plan_kind_mapping() {
    assert_eq!(
        ValidatorSetRotationAction::ValidatorAdd.plan_kind(),
        Some(ProductionValidatorSetRotationPlanKind::ValidatorAdd)
    );
    assert_eq!(ValidatorSetRotationAction::UnsupportedRotation.plan_kind(), None);
    assert!(ValidatorSetRotationAction::UnsupportedRotation.is_unsupported());
}

#[test]
fn f09_derived_action_composition() {
    let env = TrustBundleEnvironment::Devnet;
    assert_eq!(
        ValidatorSetDelta::empty().derived_action(),
        ValidatorSetRotationAction::NoOpSynchronization
    );
    let all_add =
        ValidatorSetDelta::new(vec![ValidatorSetChange::add(validator(env, 4, 1, 1))]);
    assert_eq!(all_add.derived_action(), ValidatorSetRotationAction::ValidatorAdd);
    let mixed = ValidatorSetDelta::new(vec![
        ValidatorSetChange::add(validator(env, 4, 1, 1)),
        ValidatorSetChange::remove(1),
    ]);
    assert_eq!(
        mixed.derived_action(),
        ValidatorSetRotationAction::BulkValidatorSetRotation
    );
}

#[test]
fn f10_green_for_scope_rows_not_weakened() {
    // Run 303 does not weaken prior Green-for-scope rows: the boundary only
    // consumes a verified Run 301/302 intent and produces a non-mutating
    // plan. This is asserted structurally by the accept path composing the
    // verified decision and by the boundary never mutating.
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.outcome.is_non_mutating());
    assert!(
        production_validator_set_rotation_boundary_is_source_test_not_release_binary_evidence()
    );
}