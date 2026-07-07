//! Run 305 — source/test validator-set rotation application /
//! epoch-transition executor boundary integration tests.
//!
//! Source/test only. Run 305 does **not** capture release-binary evidence;
//! release-binary evidence for the validator-set rotation application /
//! epoch-transition executor boundary is deferred to **Run 306**. The tests
//! cover:
//!
//! * A. accepted / compatible source-test application decisions;
//! * B. rejection / fail-closed paths (authority sources + wrong fields);
//! * C. MainNet / authority policy refusal;
//! * D. replay / recovery / idempotency;
//! * E. non-mutation invariants (the executor surfaces are pure);
//! * F. C4/C5 taxonomy status.
//!
//! Each accepted case composes the real Run 303 validator-set rotation
//! boundary (`ProductionValidatorSetRotationBoundary`) to produce a verified
//! rotation plan, then feeds the accepted decision into the Run 305
//! executor.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_305.md`.

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
use qbind_node::pqc_production_validator_set_rotation_application_executor::*;
use qbind_node::pqc_production_validator_set_rotation_intent::{
    CanonicalValidatorIdentity, CanonicalValidatorRecord, CanonicalValidatorSetSnapshot,
    EmptyValidatorSetRotationReplaySet, ProductionValidatorSetRotationBoundary,
    ProductionValidatorSetRotationDecision, ValidatorSetChange, ValidatorSetDelta,
    ValidatorSetRotationAction, ValidatorSetRotationAuthoritySource,
    ProductionValidatorSetRotationRequest, ProductionValidatorSetRotationInputs,
};
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
const APP_POLICY_ID: &str = "application-policy-1";
const ROT_NONCE: u64 = 3;
const APP_NONCE: u64 = 11;
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

fn validator(
    env: TrustBundleEnvironment,
    idx: u64,
    power: u64,
    act: u64,
) -> CanonicalValidatorRecord {
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

// ---- Run 301/302 governance execution intent + decision (composed) --------

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

fn gov_decision(
    intent: ProductionGovernanceExecutionIntent,
) -> ProductionGovernanceExecutionDecision {
    let idig = intent.intent_digest();
    ProductionGovernanceExecutionDecision {
        outcome:
            ProductionGovernanceExecutionOutcome::AcceptedSourceTestGovernanceExecutionIntent {
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

// ---- Run 303 rotation decision (composed authority input) -----------------

/// Build a verified Run 303 rotation decision (accept, with plan).
fn rotation_decision(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> ProductionValidatorSetRotationDecision {
    let decision = gov_decision(gov_intent(env, lifecycle));
    let idig = decision.intent_digest.clone();
    let source =
        ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision };
    let request = ProductionValidatorSetRotationRequest::new(
        source,
        current.clone(),
        delta,
        requested_action,
        proposed.validator_set_epoch,
        proposed.validator_set_version,
        ROT_NONCE,
    );
    let inputs = ProductionValidatorSetRotationInputs {
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
        expected_intent_digest: idig,
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
    };
    let boundary = ProductionValidatorSetRotationBoundary::source_test();
    let d = boundary.evaluate_validator_set_rotation(
        &request,
        &inputs,
        &EmptyValidatorSetRotationReplaySet,
    );
    assert!(d.is_accept(), "rotation decision must accept for fixture");
    d
}

// ---- Run 305 application case --------------------------------------------

struct Case {
    executor: ProductionValidatorSetRotationApplicationExecutor,
    request: ProductionValidatorSetRotationApplicationRequest,
    inputs: ProductionValidatorSetRotationApplicationInputs,
}

fn app_inputs(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    decision: &ProductionValidatorSetRotationDecision,
) -> ProductionValidatorSetRotationApplicationInputs {
    let plan = decision.plan.as_ref().unwrap();
    ProductionValidatorSetRotationApplicationInputs {
        trust_domain: trust_domain(env),
        application_policy_id: APP_POLICY_ID.to_string(),
        expected_rotation_policy_id: ROTATION_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: lifecycle,
        expected_rotation_action: requested_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: plan.governance_intent_digest.clone(),
        expected_rotation_decision_id: decision.rotation_id.clone(),
        expected_rotation_request_id: decision.request_id.clone(),
        expected_rotation_transcript_digest: decision.transcript_digest.clone(),
        expected_rotation_plan_digest: decision.plan_digest.clone(),
        expected_current_set_digest: plan.current_set_digest.clone(),
        expected_proposed_set_digest: plan.proposed_set_digest.clone(),
        expected_delta_digest: plan.delta_digest.clone(),
        expected_validator_set_epoch: plan.validator_set_epoch,
        expected_validator_set_version: plan.validator_set_version,
        expected_rotation_nonce: ROT_NONCE,
        expected_epoch_transition_target: plan.validator_set_epoch,
        min_governance_epoch: 0,
        min_validator_set_epoch: 0,
        min_validator_set_version: 0,
        persisted_sequence: Some(SEQ - 1),
        require_custody_evidence: false,
        expected_custody: None,
        require_attestation_evidence: false,
        expected_attestation: None,
        require_durable_replay_evidence: false,
        expected_durable_replay: None,
    }
}

fn make_case(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> Case {
    let decision = rotation_decision(env, lifecycle, requested_action, current, delta, proposed);
    let target = decision.plan.as_ref().unwrap().validator_set_epoch;
    let inputs = app_inputs(env, lifecycle, requested_action, &decision);
    let request = ProductionValidatorSetRotationApplicationRequest::new(
        ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision },
        target,
        APP_NONCE,
    );
    Case {
        executor: ProductionValidatorSetRotationApplicationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay() -> EmptyValidatorSetRotationApplicationReplaySet {
    EmptyValidatorSetRotationApplicationReplaySet
}

fn eval(case: &Case) -> ProductionValidatorSetRotationApplicationDecision {
    case.executor.evaluate_validator_set_rotation_application(
        &case.request,
        &case.inputs,
        &empty_replay(),
    )
}

// ---- Scenario builders ----------------------------------------------------

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

fn identity_rotation_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let mut rotated = validator(env, 2, 100, 1);
    rotated.identity.consensus_key_fingerprint = "cons-2-rotated".to_string();
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(rotated.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), rotated, validator(env, 3, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::ValidatorIdentityRotation,
        current,
        delta,
        proposed,
    )
}

fn retirement_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::Retire,
        ValidatorSetRotationAction::ValidatorRetirement,
        current,
        delta,
        proposed,
    )
}

fn emergency_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(
        env,
        LocalLifecycleAction::EmergencyRevoke,
        ValidatorSetRotationAction::EmergencyValidatorRemoval,
        current,
        delta,
        proposed,
    )
}

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

use ProductionValidatorSetRotationApplicationOutcome as O;
use ValidatorSetRotationApplicationDecisionKind as K;

// ===========================================================================
// A. Accepted / compatible source-test evidence
// ===========================================================================

#[test]
fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_validator_set_rotation_application_executor_default_is_disabled());
    let e = ProductionValidatorSetRotationApplicationExecutor::new(
        ProductionValidatorSetRotationApplicationConfig::default(),
        ProductionValidatorSetRotationApplicationPolicy::default(),
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = e.evaluate_validator_set_rotation_application(
        &case.request,
        &case.inputs,
        &empty_replay(),
    );
    assert_eq!(d.outcome, O::Disabled);
    assert!(!d.is_accept());
    assert!(d.application_intent.is_none());
}

#[test]
fn a02_devnet_plan_produces_application_decision() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.application_intent.is_some());
}

#[test]
fn a03_testnet_plan_produces_application_decision() {
    let d = eval(&add_case(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.application_intent.is_some());
}

#[test]
fn a04_noop_application_accepted_non_mutating() {
    let d = eval(&noop_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    let intent = d.application_intent.unwrap();
    assert_eq!(intent.decision_kind, K::ApplyNoOpAlreadySynchronized);
    assert!(intent.is_non_mutating());
}

#[test]
fn a05_validator_add_application_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorAdd);
    assert!(intent.is_non_mutating());
}

#[test]
fn a06_validator_remove_application_non_mutating() {
    let intent = eval(&remove_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorRemove);
    assert!(intent.is_non_mutating());
}

#[test]
fn a07_validator_update_application_non_mutating() {
    let intent = eval(&update_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorMetadataUpdate);
    assert!(intent.is_non_mutating());
}

#[test]
fn a08_validator_identity_rotation_application_non_mutating() {
    let intent = eval(&identity_rotation_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorIdentityRotation);
    assert!(intent.is_non_mutating());
}

#[test]
fn a09_validator_retirement_application_non_mutating() {
    let intent = eval(&retirement_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorRetirement);
    assert!(intent.is_non_mutating());
}

#[test]
fn a10_emergency_validator_removal_application_non_mutating() {
    let intent = eval(&emergency_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyEmergencyValidatorRemoval);
    assert!(intent.is_non_mutating());
}

#[test]
fn a11_authority_set_synchronization_application_non_mutating() {
    let intent = eval(&bulk_case(
        TrustBundleEnvironment::Devnet,
        ValidatorSetRotationAction::AuthoritySetSynchronization,
    ))
    .application_intent
    .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyAuthoritySetSynchronization);
    assert!(intent.is_non_mutating());
}

#[test]
fn a12_bulk_validator_set_rotation_application_non_mutating() {
    let intent = eval(&bulk_case(
        TrustBundleEnvironment::Devnet,
        ValidatorSetRotationAction::BulkValidatorSetRotation,
    ))
    .application_intent
    .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyBulkValidatorSetRotation);
    assert!(intent.is_non_mutating());
}

#[test]
fn a13_application_binds_environment_chain_genesis_root() {
    let env = TrustBundleEnvironment::Testnet;
    let intent = eval(&add_case(env)).application_intent.unwrap();
    assert_eq!(intent.environment, env);
    assert_eq!(intent.chain_id, chain_for(env));
    assert_eq!(intent.genesis_hash, GENESIS_HASH);
    assert_eq!(intent.authority_root_fingerprint, ROOT_FP);
    assert_eq!(intent.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

#[test]
fn a14_application_binds_governance_tuple() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.governance_domain_id, GOV_DOMAIN);
    assert_eq!(intent.governance_epoch, GOV_EPOCH);
    assert_eq!(intent.proposal_id, PROPOSAL_ID);
    assert_eq!(intent.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(intent.authority_domain_sequence, SEQ);
}

#[test]
fn a15_application_binds_governance_execution_ids_and_digests() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.governance_decision_id, GOV_DECISION_ID);
    assert_eq!(intent.governance_request_id, GOV_REQUEST_ID);
    assert!(!intent.governance_intent_digest.is_empty());
}

#[test]
fn a16_application_binds_rotation_plan_ids_and_digests() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_plan_digest = case.inputs.expected_rotation_plan_digest.clone();
    let expected_transcript = case.inputs.expected_rotation_transcript_digest.clone();
    let intent = eval(&case).application_intent.unwrap();
    assert_eq!(intent.rotation_plan_digest, expected_plan_digest);
    assert_eq!(intent.rotation_transcript_digest, expected_transcript);
    assert!(!intent.rotation_request_id.is_empty());
    assert_eq!(intent.rotation_decision_id, GOV_DECISION_ID);
}

#[test]
fn a17_application_binds_validator_set_digests_and_versions() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_current = case.inputs.expected_current_set_digest.clone();
    let expected_proposed = case.inputs.expected_proposed_set_digest.clone();
    let expected_delta = case.inputs.expected_delta_digest.clone();
    let intent = eval(&case).application_intent.unwrap();
    assert_eq!(intent.current_set_digest, expected_current);
    assert_eq!(intent.proposed_set_digest, expected_proposed);
    assert_eq!(intent.delta_digest, expected_delta);
    assert_eq!(intent.validator_set_epoch, CUR_EPOCH + 1);
    assert_eq!(intent.validator_set_version, CUR_VERSION + 1);
    assert_eq!(intent.proposed_validator_count, 4);
}

#[test]
fn a18_application_binds_epoch_transition_target_and_nonces() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.epoch_transition_target, CUR_EPOCH + 1);
    assert_eq!(intent.epoch_transition_target, intent.validator_set_epoch);
    assert_eq!(intent.application_nonce, APP_NONCE);
    assert_eq!(intent.rotation_nonce, ROT_NONCE);
}

#[test]
fn a19_application_binds_quorum_threshold_policy() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.quorum, quorum());
    assert_eq!(intent.threshold, threshold());
    assert_eq!(intent.application_policy_id, APP_POLICY_ID);
}

#[test]
fn a20_application_binds_custody_attestation_durable_where_represented() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.custody_binding = Some(custody());
    case.request.attestation_binding = Some(attestation());
    case.request.durable_replay_binding = Some(durable());
    let intent = eval(&case).application_intent.unwrap();
    assert_eq!(intent.custody_binding, Some(custody()));
    assert_eq!(intent.attestation_binding, Some(attestation()));
    assert_eq!(intent.durable_replay_binding, Some(durable()));
}

#[test]
fn a21_request_id_deterministic() {
    let a = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 3);
    let b = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 3);
    assert_eq!(a, b);
    let c = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 4);
    assert_ne!(a, c);
}

#[test]
fn a22_intent_digest_deterministic() {
    let i1 = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    let i2 = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(i1.intent_digest(), i2.intent_digest());
    assert_eq!(
        production_validator_set_rotation_application_intent_digest(&i1),
        i1.intent_digest()
    );
}

#[test]
fn a23_transcript_digest_deterministic() {
    let d1 = eval(&add_case(TrustBundleEnvironment::Devnet));
    let d2 = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert_eq!(d1.intent_digest, d2.intent_digest);
}

#[test]
fn a24_different_action_changes_intent_digest() {
    let add = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    let rem = eval(&remove_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_ne!(add.intent_digest(), rem.intent_digest());
}

#[test]
fn a25_different_application_nonce_changes_intent_digest() {
    let base = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&base).application_intent.unwrap();
    let mut other = add_case(TrustBundleEnvironment::Devnet);
    other.request.application_nonce = APP_NONCE + 1;
    let i2 = eval(&other).application_intent.unwrap();
    assert_ne!(i1.intent_digest(), i2.intent_digest());
}

#[test]
fn a26_accept_authorizes_future_mutation_only() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.authorizes_future_mutation_only());
    assert!(d.outcome.authorizes_future_mutation_only());
}

#[test]
fn a27_accept_outcome_carries_kind_env_target_nonce() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    match d.outcome {
        O::AcceptedSourceTestValidatorSetRotationApplicationDecision {
            decision_kind,
            environment,
            epoch_transition_target,
            application_nonce,
        } => {
            assert_eq!(decision_kind, K::ApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(epoch_transition_target, CUR_EPOCH + 1);
            assert_eq!(application_nonce, APP_NONCE);
        }
        other => panic!("expected accept, got {:?}", other),
    }
}

#[test]
fn a28_evidence_required_and_matched_accepts() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.custody_binding = Some(custody());
    case.request.attestation_binding = Some(attestation());
    case.request.durable_replay_binding = Some(durable());
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    assert!(eval(&case).is_accept());
}

#[test]
fn a29_min_governance_epoch_at_boundary_accepts() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH;
    assert!(eval(&case).is_accept());
}

#[test]
fn a30_persisted_sequence_equal_accepts() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ);
    assert!(eval(&case).is_accept());
}

// ===========================================================================
// B. Rejection / fail-closed source-test evidence
// ===========================================================================

fn assert_reject(case: &Case, expected: O) {
    let d = eval(case);
    assert_eq!(d.outcome, expected);
    assert!(!d.is_accept());
    assert!(d.application_intent.is_none());
    assert!(d.outcome.is_reject());
    assert!(d.outcome.is_non_mutating());
}

fn with_source(src: ValidatorSetRotationApplicationAuthoritySource) -> Case {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.authority_source = src;
    case
}

#[test]
fn b01_missing_rotation_plan_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::MissingRotationPlan),
        O::VerifiedRotationPlanRequired,
    );
}

#[test]
fn b02_unverified_rotation_plan_rejected() {
    // A non-accept Run 303 decision presented as verified.
    let bad = ProductionValidatorSetRotationDecision {
        outcome:
            qbind_node::pqc_production_validator_set_rotation_intent::ProductionValidatorSetRotationOutcome::Disabled,
        rotation_id: GOV_DECISION_ID.to_string(),
        request_id: "r".to_string(),
        plan: None,
        plan_digest: String::new(),
        transcript_digest: "t".to_string(),
    };
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision: bad },
        ),
        O::UnverifiedRotationPlanRejected,
    );
}

#[test]
fn b03_unverified_rotation_plan_variant_rejected() {
    let decision = rotation_decision(
        TrustBundleEnvironment::Devnet,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet),
        ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::UnverifiedRotationPlan {
            decision,
        }),
        O::UnverifiedRotationPlanRejected,
    );
}

#[test]
fn b04_accepted_decision_without_plan_rejected() {
    let mut decision = rotation_decision(
        TrustBundleEnvironment::Devnet,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet),
        ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    decision.plan = None;
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan {
            decision,
        }),
        O::VerifiedRotationPlanRequired,
    );
}

#[test]
fn b05_accepted_decision_without_plan_source_rejected() {
    let decision = rotation_decision(
        TrustBundleEnvironment::Devnet,
        LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet),
        ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::AcceptedDecisionWithoutPlan {
                decision,
            },
        ),
        O::VerifiedRotationPlanRequired,
    );
}

#[test]
fn b06_governance_proof_alone_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::GovernanceProofWithoutRotationPlan,
        ),
        O::GovernanceProofAloneRejected,
    );
}

#[test]
fn b07_governance_execution_intent_alone_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::GovernanceExecutionIntentWithoutRotationPlan,
        ),
        O::GovernanceExecutionIntentAloneRejected,
    );
}

#[test]
fn b08_local_operator_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::LocalOperatorAssertion),
        O::LocalOperatorProofRejected,
    );
}

#[test]
fn b09_peer_majority_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::PeerMajorityAssertion),
        O::PeerMajorityProofRejected,
    );
}

#[test]
fn b10_custody_only_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::CustodyOnlyEvidence),
        O::CustodyOnlyProofRejected,
    );
}

#[test]
fn b11_remote_signer_only_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::RemoteSignerOnlyEvidence),
        O::RemoteSignerOnlyProofRejected,
    );
}

#[test]
fn b12_custody_attestation_only_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::CustodyAttestationOnlyEvidence,
        ),
        O::CustodyAttestationOnlyProofRejected,
    );
}

#[test]
fn b13_fixture_only_plan_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::FixtureOnlyPlan),
        O::FixtureRotationPlanRejectedAsProductionAuthority,
    );
}

#[test]
fn b14_arbitrary_validator_set_bytes_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::ArbitraryValidatorSetBytes),
        O::ArbitraryValidatorSetBytesRejected,
    );
}

#[test]
fn b15_wrong_rotation_plan_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_plan_digest = "wrong-plan-digest".to_string();
    assert_reject(&case, O::RotationPlanDigestMismatch);
}

#[test]
fn b16_wrong_rotation_transcript_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_transcript_digest = "wrong-transcript".to_string();
    assert_reject(&case, O::RotationPlanTranscriptMismatch);
}

#[test]
fn b17_wrong_rotation_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_request_id = "wrong-request".to_string();
    assert_reject(&case, O::RotationPlanRequestIdMismatch);
}

#[test]
fn b18_wrong_rotation_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_decision_id = "wrong-decision".to_string();
    assert_reject(&case, O::WrongRotationDecisionId);
}

#[test]
fn b19_tampered_plan_integrity_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Tamper the carried plan so plan_digest() no longer matches the stored
    // decision.plan_digest, while the expected digest still equals the
    // (untampered) stored digest.
    if let ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision } =
        &mut case.request.authority_source
    {
        if let Some(plan) = &mut decision.plan {
            plan.proposed_validator_count += 1;
        }
    }
    assert_reject(&case, O::RotationPlanIntegrityMismatch);
}

#[test]
fn b20_wrong_rotation_policy_id_integrity_mismatch() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_policy_id = "wrong-rotation-policy".to_string();
    assert_reject(&case, O::RotationPlanIntegrityMismatch);
}

#[test]
fn b21_wrong_environment_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Same non-mainnet env class is required for the gate; use Testnet chain
    // domain vs Devnet plan to trip the environment check first.
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet,
        chain_for(TrustBundleEnvironment::Devnet),
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongEnvironment);
}

#[test]
fn b22_wrong_chain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        "other-chain",
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongChain);
}

#[test]
fn b23_wrong_genesis_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        chain_for(TrustBundleEnvironment::Devnet),
        "other-genesis",
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongGenesis);
}

#[test]
fn b24_wrong_authority_root_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        chain_for(TrustBundleEnvironment::Devnet),
        GENESIS_HASH,
        "other-root",
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongAuthorityRoot);
}

#[test]
fn b25_wrong_governance_domain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_reject(&case, O::WrongGovernanceDomain);
}

#[test]
fn b26_wrong_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::WrongGovernanceEpoch);
}

#[test]
fn b27_wrong_proposal_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposal_id = "other-proposal".to_string();
    assert_reject(&case, O::WrongProposalId);
}

#[test]
fn b28_wrong_governance_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_decision_id = "other-gov-decision".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionDecisionId);
}

#[test]
fn b29_wrong_governance_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_request_id = "other-gov-request".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionRequestId);
}

#[test]
fn b30_wrong_governance_intent_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_intent_digest = "other-intent-digest".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionIntentDigest);
}

#[test]
fn b31_wrong_lifecycle_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_lifecycle_action = LocalLifecycleAction::Retire;
    assert_reject(&case, O::WrongLifecycleAction);
}

#[test]
fn b32_wrong_rotation_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove;
    assert_reject(&case, O::WrongRotationAction);
}

#[test]
fn b33_wrong_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_authority_domain_sequence = SEQ + 1;
    assert_reject(&case, O::WrongAuthoritySequence);
}

#[test]
fn b34_wrong_quorum_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_quorum = OnChainGovernanceQuorum {
        voters_voted: 9,
        total_voters: 10,
        required_quorum: 6,
    };
    assert_reject(&case, O::WrongQuorum);
}

#[test]
fn b35_wrong_threshold_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_threshold = GovernanceThreshold::new(9, 6, 10);
    assert_reject(&case, O::WrongThreshold);
}

#[test]
fn b36_wrong_current_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_current_set_digest = "other-current".to_string();
    assert_reject(&case, O::WrongCurrentValidatorSetDigest);
}

#[test]
fn b37_wrong_proposed_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposed_set_digest = "other-proposed".to_string();
    assert_reject(&case, O::WrongProposedValidatorSetDigest);
}

#[test]
fn b38_wrong_delta_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_delta_digest = "other-delta".to_string();
    assert_reject(&case, O::WrongValidatorSetDeltaDigest);
}

#[test]
fn b39_wrong_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongValidatorSetEpoch);
}

#[test]
fn b40_wrong_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::WrongValidatorSetVersion);
}

#[test]
fn b41_wrong_rotation_nonce_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_nonce = ROT_NONCE + 1;
    assert_reject(&case, O::WrongRotationNonce);
}

#[test]
fn b42_wrong_epoch_transition_target_request_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}

#[test]
fn b43_wrong_epoch_transition_target_expected_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Request and expected agree but disagree with the plan's proposed epoch.
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 5;
    case.inputs.expected_epoch_transition_target = CUR_EPOCH + 5;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}

#[test]
fn b44_custody_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    assert_reject(&case, O::CustodyBackendEvidenceRequired);
}

#[test]
fn b45_custody_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    let mut other = custody();
    other.key_handle = "other-key".to_string();
    case.request.custody_binding = Some(other);
    assert_reject(&case, O::CustodyBackendMismatch);
}

#[test]
fn b46_attestation_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    assert_reject(&case, O::CustodyAttestationRequired);
}

#[test]
fn b47_attestation_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    let mut other = attestation();
    other.measurement = "other-measurement".to_string();
    case.request.attestation_binding = Some(other);
    assert_reject(&case, O::CustodyAttestationMismatch);
}

#[test]
fn b48_durable_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    assert_reject(&case, O::DurableReplayEvidenceRequired);
}

#[test]
fn b49_durable_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    let mut other = durable();
    other.durable_record_id = "other-durable".to_string();
    case.request.durable_replay_binding = Some(other);
    assert_reject(&case, O::DurableReplayMismatch);
}

#[test]
fn b50_stale_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::StaleGovernanceEpoch);
}

#[test]
fn b51_stale_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ + 1);
    assert_reject(&case, O::StaleAuthoritySequence);
}

#[test]
fn b52_stale_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::StaleValidatorSetEpoch);
}

#[test]
fn b53_stale_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::StaleValidatorSetVersion);
}

#[test]
fn b54_ill_formed_inputs_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.application_policy_id = String::new();
    assert_reject(&case, O::ValidatorSetRotationApplicationBoundaryUnavailable);
}

#[test]
fn b55_plan_carried_custody_disagreement_rejected() {
    // Plan carries custody binding B; request + expected both carry A. The
    // request matches the expected binding, but the plan's carried binding
    // disagrees, so the composition check fails closed.
    let env = TrustBundleEnvironment::Devnet;
    let mut case = add_case(env);
    let mut plan_custody = custody();
    plan_custody.key_handle = "plan-carried-key".to_string();
    if let ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision } =
        &mut case.request.authority_source
    {
        if let Some(plan) = &mut decision.plan {
            plan.custody_binding = Some(plan_custody);
        }
        let new_digest = decision.plan.as_ref().unwrap().plan_digest();
        decision.plan_digest = new_digest.clone();
        case.inputs.expected_rotation_plan_digest = new_digest;
    }
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    case.request.custody_binding = Some(custody());
    assert_reject(&case, O::CustodyBackendMismatch);
}

// ===========================================================================
// C. MainNet / authority policy refusal
// ===========================================================================

#[test]
fn c01_mainnet_trust_domain_refused() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    // binding_env is the plan env (Devnet); trust-domain env is Mainnet.
    assert_reject(&case, O::MainNetRefused);
}

#[test]
fn c02_mainnet_plan_refused() {
    // A Mainnet rotation decision cannot even be produced by Run 303 (it
    // refuses MainNet), so we assert the Run 305 gate via the trust domain.
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = eval(&case);
    assert_eq!(d.outcome, O::MainNetRefused);
    assert!(d.application_intent.is_none());
}

#[test]
fn c03_production_policy_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::RequireProductionValidatorSetRotationApplication;
    assert_reject(&case, O::ProductionValidatorSetRotationApplicationUnavailable);
}

#[test]
fn c04_mainnet_policy_unavailable_on_non_mainnet() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::MainnetProductionValidatorSetRotationApplicationRequired;
    assert_reject(
        &case,
        O::MainNetProductionValidatorSetRotationApplicationUnavailable,
    );
}

#[test]
fn c05_mainnet_policy_on_mainnet_domain_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::MainnetProductionValidatorSetRotationApplicationRequired;
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    assert_reject(
        &case,
        O::MainNetProductionValidatorSetRotationApplicationUnavailable,
    );
}

#[test]
fn c06_reserved_production_kind_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind =
        ProductionValidatorSetRotationApplicationKind::ProductionValidatorSetRotationApplication;
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication;
    assert_reject(&case, O::ValidatorSetRotationApplicationBoundaryUnavailable);
}

#[test]
fn c07_disabled_kind_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind = ProductionValidatorSetRotationApplicationKind::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}

#[test]
fn c08_disabled_policy_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy = ProductionValidatorSetRotationApplicationPolicy::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}

#[test]
fn c09_mainnet_refused_named_helper() {
    assert!(production_validator_set_rotation_application_executor_mainnet_refused());
}

// ===========================================================================
// D. Replay / recovery / idempotency
// ===========================================================================

#[test]
fn d01_replayed_application_id_rejected() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let accepted = eval(&case);
    let replay = vec![accepted.request_id.clone()];
    let d = case.executor.evaluate_validator_set_rotation_application(
        &case.request,
        &case.inputs,
        &replay,
    );
    match d.outcome {
        O::ApplicationReplayRejected { .. } => {}
        other => panic!("expected replay reject, got {:?}", other),
    }
    assert!(d.application_intent.is_none());
}

#[test]
fn d02_non_replayed_id_accepts() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let replay = vec!["unrelated-id".to_string()];
    let d = case.executor.evaluate_validator_set_rotation_application(
        &case.request,
        &case.inputs,
        &replay,
    );
    assert!(d.is_accept());
}

#[test]
fn d03_recovery_no_prior_window_clean() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).application_intent.unwrap();
    let r = case
        .executor
        .recover_validator_set_rotation_application_window(None, &intent);
    assert!(r.is_clean());
    assert!(r.is_non_mutating());
}

#[test]
fn d04_recovery_idempotent_replay_observed() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).application_intent.unwrap();
    let r = case
        .executor
        .recover_validator_set_rotation_application_window(Some(&intent), &intent);
    match r {
        ProductionValidatorSetRotationApplicationRecoveryOutcome::IdempotentReplayObserved {
            ..
        } => {}
        other => panic!("expected idempotent replay, got {:?}", other),
    }
}

#[test]
fn d05_recovery_unrelated_window_clean() {
    let case_a = add_case(TrustBundleEnvironment::Devnet);
    let case_b = remove_case(TrustBundleEnvironment::Devnet);
    let ia = eval(&case_a).application_intent.unwrap();
    let ib = eval(&case_b).application_intent.unwrap();
    let r = case_a
        .executor
        .recover_validator_set_rotation_application_window(Some(&ib), &ia);
    assert!(r.is_clean());
}

#[test]
fn d06_recovery_disabled_policy() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).application_intent.unwrap();
    let disabled = ProductionValidatorSetRotationApplicationExecutor::new(
        ProductionValidatorSetRotationApplicationConfig::default(),
        ProductionValidatorSetRotationApplicationPolicy::default(),
    );
    let r = disabled.recover_validator_set_rotation_application_window(Some(&intent), &intent);
    assert_eq!(
        r,
        ProductionValidatorSetRotationApplicationRecoveryOutcome::RecoveryDisabled
    );
}

#[test]
fn d07_recovery_same_window_divergent_intent_clean() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).application_intent.unwrap();
    let mut divergent = intent.clone();
    // Same plan digest / nonce / target window, but a different bound field.
    divergent.proposed_validator_count += 1;
    let r = case
        .executor
        .recover_validator_set_rotation_application_window(Some(&intent), &divergent);
    assert!(r.is_clean());
}

#[test]
fn d08_replay_recovery_is_deterministic() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&case).application_intent.unwrap();
    let i2 = eval(&case).application_intent.unwrap();
    assert_eq!(i1, i2);
}

// ===========================================================================
// E. Non-mutation invariants + named helpers
// ===========================================================================

#[test]
fn e01_named_helper_default_disabled() {
    assert!(production_validator_set_rotation_application_executor_default_is_disabled());
}

#[test]
fn e02_named_helper_source_test_not_release_binary() {
    assert!(
        production_validator_set_rotation_application_executor_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn e03_named_helper_non_mutating() {
    assert!(production_validator_set_rotation_application_executor_is_non_mutating());
}

#[test]
fn e04_named_helper_never_falls_back() {
    assert!(production_validator_set_rotation_application_executor_never_falls_back());
}

#[test]
fn e05_named_helper_no_default_runtime_wiring() {
    assert!(production_validator_set_rotation_application_executor_no_default_runtime_wiring());
}

#[test]
fn e06_named_helper_requires_verified_rotation_plan() {
    assert!(
        production_validator_set_rotation_application_executor_requires_verified_rotation_plan()
    );
}

#[test]
fn e07_every_outcome_is_non_mutating() {
    let outcomes = [
        O::Disabled,
        O::MainNetRefused,
        O::ProductionValidatorSetRotationApplicationUnavailable,
        O::VerifiedRotationPlanRequired,
        O::WrongEpochTransitionTarget,
    ];
    for o in outcomes {
        assert!(o.is_non_mutating());
    }
}

#[test]
fn e08_accept_is_only_mutation_authorizer() {
    assert!(O::AcceptedSourceTestValidatorSetRotationApplicationDecision {
        decision_kind: K::ApplyValidatorAdd,
        environment: TrustBundleEnvironment::Devnet,
        epoch_transition_target: 11,
        application_nonce: 1,
    }
    .authorizes_future_mutation_only());
    assert!(!O::Disabled.authorizes_future_mutation_only());
    assert!(!O::MainNetRefused.authorizes_future_mutation_only());
}

#[test]
fn e09_disabled_is_not_reject() {
    assert!(!O::Disabled.is_reject());
    assert!(!O::Disabled.is_accept());
}

#[test]
fn e10_config_source_test_well_formed() {
    assert!(ProductionValidatorSetRotationApplicationConfig::source_test().is_well_formed());
    assert!(ProductionValidatorSetRotationApplicationConfig::default().is_well_formed());
}

#[test]
fn e11_protocol_version_supported() {
    assert!(ProductionValidatorSetRotationApplicationProtocolVersion::supported().is_supported());
    assert!(!ProductionValidatorSetRotationApplicationProtocolVersion(2).is_supported());
}

#[test]
fn e12_decision_kind_from_plan_kind_roundtrip() {
    use qbind_node::pqc_production_validator_set_rotation_intent::ProductionValidatorSetRotationPlanKind as P;
    assert_eq!(
        K::from_plan_kind(P::ValidatorAdd),
        K::ApplyValidatorAdd
    );
    assert_eq!(
        K::from_plan_kind(P::UnsupportedRotationRequest),
        K::UnsupportedApplication
    );
    assert!(K::UnsupportedApplication.is_unsupported());
    assert!(!K::ApplyValidatorAdd.is_unsupported());
}

#[test]
fn e13_intent_marked_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert!(intent.is_non_mutating());
}

#[test]
fn e14_reject_carries_no_intent_but_has_transcript() {
    let case = with_source(ValidatorSetRotationApplicationAuthoritySource::LocalOperatorAssertion);
    let d = eval(&case);
    assert!(d.application_intent.is_none());
    assert!(d.intent_digest.is_empty());
    assert!(!d.transcript_digest.is_empty());
}

// ===========================================================================
// F. C4/C5 taxonomy status
// ===========================================================================

#[test]
fn f01_policy_tags_stable() {
    assert_eq!(
        ProductionValidatorSetRotationApplicationPolicy::Disabled.tag(),
        "disabled"
    );
    assert_eq!(
        ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication.tag(),
        "allow-source-test-validator-set-rotation-application"
    );
}

#[test]
fn f02_kind_tags_stable() {
    assert_eq!(
        ProductionValidatorSetRotationApplicationKind::SourceTestValidatorSetRotationApplication
            .tag(),
        "source-test-validator-set-rotation-application"
    );
    assert!(
        ProductionValidatorSetRotationApplicationKind::SourceTestValidatorSetRotationApplication
            .is_source_test()
    );
}

#[test]
fn f03_decision_kind_tags_stable() {
    assert_eq!(K::ApplyNoOpAlreadySynchronized.tag(), "apply-no-op-already-synchronized");
    assert_eq!(K::ApplyBulkValidatorSetRotation.tag(), "apply-bulk-validator-set-rotation");
    assert_eq!(K::UnsupportedApplication.tag(), "unsupported-application");
}

#[test]
fn f04_outcome_tags_unique_and_stable() {
    assert_eq!(
        O::AcceptedSourceTestValidatorSetRotationApplicationDecision {
            decision_kind: K::ApplyValidatorAdd,
            environment: TrustBundleEnvironment::Devnet,
            epoch_transition_target: 11,
            application_nonce: 1,
        }
        .tag(),
        "accepted-source-test-validator-set-rotation-application-decision"
    );
    assert_eq!(O::MainNetRefused.tag(), "mainnet-refused");
    assert_eq!(O::WrongEpochTransitionTarget.tag(), "wrong-epoch-transition-target");
}

#[test]
fn f05_policy_predicates() {
    use ProductionValidatorSetRotationApplicationPolicy as Pol;
    assert!(Pol::Disabled.is_disabled());
    assert!(Pol::AllowSourceTestValidatorSetRotationApplication.allows_source_test());
    assert!(Pol::RequireProductionValidatorSetRotationApplication.is_production());
    assert!(Pol::MainnetProductionValidatorSetRotationApplicationRequired.is_mainnet());
}

#[test]
fn f06_all_decision_kinds_non_mutating() {
    let kinds = [
        K::ApplyNoOpAlreadySynchronized,
        K::ApplyValidatorAdd,
        K::ApplyValidatorRemove,
        K::ApplyValidatorMetadataUpdate,
        K::ApplyValidatorIdentityRotation,
        K::ApplyValidatorRetirement,
        K::ApplyEmergencyValidatorRemoval,
        K::ApplyAuthoritySetSynchronization,
        K::ApplyBulkValidatorSetRotation,
        K::UnsupportedApplication,
    ];
    for k in kinds {
        assert!(k.is_non_mutating());
    }
}

#[test]
fn f07_source_test_executor_shape() {
    let e = ProductionValidatorSetRotationApplicationExecutor::source_test();
    assert_eq!(
        e.policy,
        ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication
    );
    assert!(e.config.kind.is_source_test());
}

#[test]
fn f08_request_new_has_no_evidence_bindings() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    assert!(case.request.custody_binding.is_none());
    assert!(case.request.attestation_binding.is_none());
    assert!(case.request.durable_replay_binding.is_none());
}

#[test]
fn f09_testnet_and_devnet_have_distinct_intent_digests() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    let t = eval(&add_case(TrustBundleEnvironment::Testnet))
        .application_intent
        .unwrap();
    assert_ne!(d.intent_digest(), t.intent_digest());
}

#[test]
fn f10_accept_across_all_supported_actions() {
    let env = TrustBundleEnvironment::Devnet;
    assert!(eval(&noop_case(env)).is_accept());
    assert!(eval(&add_case(env)).is_accept());
    assert!(eval(&remove_case(env)).is_accept());
    assert!(eval(&update_case(env)).is_accept());
    assert!(eval(&identity_rotation_case(env)).is_accept());
    assert!(eval(&retirement_case(env)).is_accept());
    assert!(eval(&emergency_case(env)).is_accept());
    assert!(eval(&bulk_case(env, ValidatorSetRotationAction::AuthoritySetSynchronization)).is_accept());
    assert!(eval(&bulk_case(env, ValidatorSetRotationAction::BulkValidatorSetRotation)).is_accept());
}
