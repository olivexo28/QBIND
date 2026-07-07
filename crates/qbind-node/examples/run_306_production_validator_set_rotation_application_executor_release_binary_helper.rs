//! Run 306 — release-binary helper for the Run 305 **validator-set rotation
//! application / epoch-transition executor boundary**.
//!
//! Release-binary evidence for the Run 305 source/test validator-set rotation
//! application / epoch-transition executor boundary
//! (`crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 305
//! [`ProductionValidatorSetRotationApplicationExecutor`] and proves, per check
//! with PASS/FAIL, the accepted / rejection-fail-closed / MainNet-refusal /
//! replay-recovery-idempotency / non-mutation / taxonomy behavior of the real
//! executor, including the environment / chain / genesis / authority-root /
//! governance (domain / epoch / proposal / execution-decision-id / request-id /
//! intent-digest) / rotation-decision-id / rotation-request-id /
//! rotation-transcript / rotation-plan-digest binding, the current/proposed
//! validator-set digests + delta digest + validator-set epoch/version + rotation
//! nonce + epoch-transition target (= plan validator-set epoch) + application
//! nonce, composing the real Run 303/304 verified validator-set rotation plan
//! accept decision (itself composing the Run 301/302 verified governance
//! execution accept decision).
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the executor only
//! through the source/test boundary, only for DevNet/TestNet identities on the
//! accept path, and never enables any production runtime path, MainNet
//! enablement, validator-set-rotation-application default wiring, or live
//! validator-set mutation. The executor only ever produces typed non-mutating
//! validator-set rotation application decisions/intents; it never applies a
//! live validator-set change, never calls Run 070, never mutates
//! `LivePqcTrustState`, never mutates a live validator set, consensus state, or
//! epoch counter, never calls `BasicHotStuffEngine::transition_to_epoch`, never
//! writes `meta:current_epoch`, never injects a reconfig block, and never
//! writes trust-bundle sequence or authority marker files. Under a MainNet or
//! production policy it never falls back to fixture / local operator / peer
//! majority / governance-proof-alone / governance-execution-intent-alone /
//! custody-only / remote-signer-only / custody-attestation-only /
//! arbitrary-bytes material.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_306.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

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
fn a02_devnet_plan_produces_application_decision() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.application_intent.is_some());
}
fn a03_testnet_plan_produces_application_decision() {
    let d = eval(&add_case(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.application_intent.is_some());
}
fn a04_noop_application_accepted_non_mutating() {
    let d = eval(&noop_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    let intent = d.application_intent.unwrap();
    assert_eq!(intent.decision_kind, K::ApplyNoOpAlreadySynchronized);
    assert!(intent.is_non_mutating());
}
fn a05_validator_add_application_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorAdd);
    assert!(intent.is_non_mutating());
}
fn a06_validator_remove_application_non_mutating() {
    let intent = eval(&remove_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorRemove);
    assert!(intent.is_non_mutating());
}
fn a07_validator_update_application_non_mutating() {
    let intent = eval(&update_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorMetadataUpdate);
    assert!(intent.is_non_mutating());
}
fn a08_validator_identity_rotation_application_non_mutating() {
    let intent = eval(&identity_rotation_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorIdentityRotation);
    assert!(intent.is_non_mutating());
}
fn a09_validator_retirement_application_non_mutating() {
    let intent = eval(&retirement_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyValidatorRetirement);
    assert!(intent.is_non_mutating());
}
fn a10_emergency_validator_removal_application_non_mutating() {
    let intent = eval(&emergency_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.decision_kind, K::ApplyEmergencyValidatorRemoval);
    assert!(intent.is_non_mutating());
}
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
fn a13_application_binds_environment_chain_genesis_root() {
    let env = TrustBundleEnvironment::Testnet;
    let intent = eval(&add_case(env)).application_intent.unwrap();
    assert_eq!(intent.environment, env);
    assert_eq!(intent.chain_id, chain_for(env));
    assert_eq!(intent.genesis_hash, GENESIS_HASH);
    assert_eq!(intent.authority_root_fingerprint, ROOT_FP);
    assert_eq!(intent.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}
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
fn a15_application_binds_governance_execution_ids_and_digests() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.governance_decision_id, GOV_DECISION_ID);
    assert_eq!(intent.governance_request_id, GOV_REQUEST_ID);
    assert!(!intent.governance_intent_digest.is_empty());
}
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
fn a18_application_binds_epoch_transition_target_and_nonces() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.epoch_transition_target, CUR_EPOCH + 1);
    assert_eq!(intent.epoch_transition_target, intent.validator_set_epoch);
    assert_eq!(intent.application_nonce, APP_NONCE);
    assert_eq!(intent.rotation_nonce, ROT_NONCE);
}
fn a19_application_binds_quorum_threshold_policy() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_eq!(intent.quorum, quorum());
    assert_eq!(intent.threshold, threshold());
    assert_eq!(intent.application_policy_id, APP_POLICY_ID);
}
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
fn a21_request_id_deterministic() {
    let a = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 3);
    let b = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 3);
    assert_eq!(a, b);
    let c = production_validator_set_rotation_application_request_id(1, "pd", "ap", 11, 4);
    assert_ne!(a, c);
}
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
fn a23_transcript_digest_deterministic() {
    let d1 = eval(&add_case(TrustBundleEnvironment::Devnet));
    let d2 = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert_eq!(d1.intent_digest, d2.intent_digest);
}
fn a24_different_action_changes_intent_digest() {
    let add = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    let rem = eval(&remove_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert_ne!(add.intent_digest(), rem.intent_digest());
}
fn a25_different_application_nonce_changes_intent_digest() {
    let base = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&base).application_intent.unwrap();
    let mut other = add_case(TrustBundleEnvironment::Devnet);
    other.request.application_nonce = APP_NONCE + 1;
    let i2 = eval(&other).application_intent.unwrap();
    assert_ne!(i1.intent_digest(), i2.intent_digest());
}
fn a26_accept_authorizes_future_mutation_only() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.authorizes_future_mutation_only());
    assert!(d.outcome.authorizes_future_mutation_only());
}
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
fn a29_min_governance_epoch_at_boundary_accepts() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH;
    assert!(eval(&case).is_accept());
}
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
fn b01_missing_rotation_plan_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::MissingRotationPlan),
        O::VerifiedRotationPlanRequired,
    );
}
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
fn b06_governance_proof_alone_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::GovernanceProofWithoutRotationPlan,
        ),
        O::GovernanceProofAloneRejected,
    );
}
fn b07_governance_execution_intent_alone_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::GovernanceExecutionIntentWithoutRotationPlan,
        ),
        O::GovernanceExecutionIntentAloneRejected,
    );
}
fn b08_local_operator_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::LocalOperatorAssertion),
        O::LocalOperatorProofRejected,
    );
}
fn b09_peer_majority_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::PeerMajorityAssertion),
        O::PeerMajorityProofRejected,
    );
}
fn b10_custody_only_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::CustodyOnlyEvidence),
        O::CustodyOnlyProofRejected,
    );
}
fn b11_remote_signer_only_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::RemoteSignerOnlyEvidence),
        O::RemoteSignerOnlyProofRejected,
    );
}
fn b12_custody_attestation_only_rejected() {
    assert_reject(
        &with_source(
            ValidatorSetRotationApplicationAuthoritySource::CustodyAttestationOnlyEvidence,
        ),
        O::CustodyAttestationOnlyProofRejected,
    );
}
fn b13_fixture_only_plan_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::FixtureOnlyPlan),
        O::FixtureRotationPlanRejectedAsProductionAuthority,
    );
}
fn b14_arbitrary_validator_set_bytes_rejected() {
    assert_reject(
        &with_source(ValidatorSetRotationApplicationAuthoritySource::ArbitraryValidatorSetBytes),
        O::ArbitraryValidatorSetBytesRejected,
    );
}
fn b15_wrong_rotation_plan_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_plan_digest = "wrong-plan-digest".to_string();
    assert_reject(&case, O::RotationPlanDigestMismatch);
}
fn b16_wrong_rotation_transcript_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_transcript_digest = "wrong-transcript".to_string();
    assert_reject(&case, O::RotationPlanTranscriptMismatch);
}
fn b17_wrong_rotation_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_request_id = "wrong-request".to_string();
    assert_reject(&case, O::RotationPlanRequestIdMismatch);
}
fn b18_wrong_rotation_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_decision_id = "wrong-decision".to_string();
    assert_reject(&case, O::WrongRotationDecisionId);
}
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
fn b20_wrong_rotation_policy_id_integrity_mismatch() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_policy_id = "wrong-rotation-policy".to_string();
    assert_reject(&case, O::RotationPlanIntegrityMismatch);
}
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
fn b25_wrong_governance_domain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_reject(&case, O::WrongGovernanceDomain);
}
fn b26_wrong_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::WrongGovernanceEpoch);
}
fn b27_wrong_proposal_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposal_id = "other-proposal".to_string();
    assert_reject(&case, O::WrongProposalId);
}
fn b28_wrong_governance_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_decision_id = "other-gov-decision".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionDecisionId);
}
fn b29_wrong_governance_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_request_id = "other-gov-request".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionRequestId);
}
fn b30_wrong_governance_intent_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_intent_digest = "other-intent-digest".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionIntentDigest);
}
fn b31_wrong_lifecycle_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_lifecycle_action = LocalLifecycleAction::Retire;
    assert_reject(&case, O::WrongLifecycleAction);
}
fn b32_wrong_rotation_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove;
    assert_reject(&case, O::WrongRotationAction);
}
fn b33_wrong_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_authority_domain_sequence = SEQ + 1;
    assert_reject(&case, O::WrongAuthoritySequence);
}
fn b34_wrong_quorum_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_quorum = OnChainGovernanceQuorum {
        voters_voted: 9,
        total_voters: 10,
        required_quorum: 6,
    };
    assert_reject(&case, O::WrongQuorum);
}
fn b35_wrong_threshold_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_threshold = GovernanceThreshold::new(9, 6, 10);
    assert_reject(&case, O::WrongThreshold);
}
fn b36_wrong_current_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_current_set_digest = "other-current".to_string();
    assert_reject(&case, O::WrongCurrentValidatorSetDigest);
}
fn b37_wrong_proposed_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposed_set_digest = "other-proposed".to_string();
    assert_reject(&case, O::WrongProposedValidatorSetDigest);
}
fn b38_wrong_delta_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_delta_digest = "other-delta".to_string();
    assert_reject(&case, O::WrongValidatorSetDeltaDigest);
}
fn b39_wrong_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongValidatorSetEpoch);
}
fn b40_wrong_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::WrongValidatorSetVersion);
}
fn b41_wrong_rotation_nonce_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_nonce = ROT_NONCE + 1;
    assert_reject(&case, O::WrongRotationNonce);
}
fn b42_wrong_epoch_transition_target_request_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}
fn b43_wrong_epoch_transition_target_expected_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    // Request and expected agree but disagree with the plan's proposed epoch.
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 5;
    case.inputs.expected_epoch_transition_target = CUR_EPOCH + 5;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}
fn b44_custody_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    assert_reject(&case, O::CustodyBackendEvidenceRequired);
}
fn b45_custody_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    let mut other = custody();
    other.key_handle = "other-key".to_string();
    case.request.custody_binding = Some(other);
    assert_reject(&case, O::CustodyBackendMismatch);
}
fn b46_attestation_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    assert_reject(&case, O::CustodyAttestationRequired);
}
fn b47_attestation_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    let mut other = attestation();
    other.measurement = "other-measurement".to_string();
    case.request.attestation_binding = Some(other);
    assert_reject(&case, O::CustodyAttestationMismatch);
}
fn b48_durable_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    assert_reject(&case, O::DurableReplayEvidenceRequired);
}
fn b49_durable_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    let mut other = durable();
    other.durable_record_id = "other-durable".to_string();
    case.request.durable_replay_binding = Some(other);
    assert_reject(&case, O::DurableReplayMismatch);
}
fn b50_stale_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::StaleGovernanceEpoch);
}
fn b51_stale_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ + 1);
    assert_reject(&case, O::StaleAuthoritySequence);
}
fn b52_stale_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::StaleValidatorSetEpoch);
}
fn b53_stale_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::StaleValidatorSetVersion);
}
fn b54_ill_formed_inputs_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.application_policy_id = String::new();
    assert_reject(&case, O::ValidatorSetRotationApplicationBoundaryUnavailable);
}
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
fn c01_mainnet_trust_domain_refused() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    // binding_env is the plan env (Devnet); trust-domain env is Mainnet.
    assert_reject(&case, O::MainNetRefused);
}
fn c02_mainnet_plan_refused() {
    // A Mainnet rotation decision cannot even be produced by Run 303 (it
    // refuses MainNet), so we assert the Run 305 gate via the trust domain.
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = eval(&case);
    assert_eq!(d.outcome, O::MainNetRefused);
    assert!(d.application_intent.is_none());
}
fn c03_production_policy_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::RequireProductionValidatorSetRotationApplication;
    assert_reject(&case, O::ProductionValidatorSetRotationApplicationUnavailable);
}
fn c04_mainnet_policy_unavailable_on_non_mainnet() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::MainnetProductionValidatorSetRotationApplicationRequired;
    assert_reject(
        &case,
        O::MainNetProductionValidatorSetRotationApplicationUnavailable,
    );
}
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
fn c06_reserved_production_kind_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind =
        ProductionValidatorSetRotationApplicationKind::ProductionValidatorSetRotationApplication;
    case.executor.policy =
        ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication;
    assert_reject(&case, O::ValidatorSetRotationApplicationBoundaryUnavailable);
}
fn c07_disabled_kind_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind = ProductionValidatorSetRotationApplicationKind::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}
fn c08_disabled_policy_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy = ProductionValidatorSetRotationApplicationPolicy::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}
fn c09_mainnet_refused_named_helper() {
    assert!(production_validator_set_rotation_application_executor_mainnet_refused());
}

// ===========================================================================
// D. Replay / recovery / idempotency
// ===========================================================================
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
fn d03_recovery_no_prior_window_clean() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).application_intent.unwrap();
    let r = case
        .executor
        .recover_validator_set_rotation_application_window(None, &intent);
    assert!(r.is_clean());
    assert!(r.is_non_mutating());
}
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
fn d08_replay_recovery_is_deterministic() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&case).application_intent.unwrap();
    let i2 = eval(&case).application_intent.unwrap();
    assert_eq!(i1, i2);
}

// ===========================================================================
// E. Non-mutation invariants + named helpers
// ===========================================================================
fn e01_named_helper_default_disabled() {
    assert!(production_validator_set_rotation_application_executor_default_is_disabled());
}
fn e02_named_helper_source_test_not_release_binary() {
    assert!(
        production_validator_set_rotation_application_executor_is_source_test_not_release_binary_evidence()
    );
}
fn e03_named_helper_non_mutating() {
    assert!(production_validator_set_rotation_application_executor_is_non_mutating());
}
fn e04_named_helper_never_falls_back() {
    assert!(production_validator_set_rotation_application_executor_never_falls_back());
}
fn e05_named_helper_no_default_runtime_wiring() {
    assert!(production_validator_set_rotation_application_executor_no_default_runtime_wiring());
}
fn e06_named_helper_requires_verified_rotation_plan() {
    assert!(
        production_validator_set_rotation_application_executor_requires_verified_rotation_plan()
    );
}
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
fn e09_disabled_is_not_reject() {
    assert!(!O::Disabled.is_reject());
    assert!(!O::Disabled.is_accept());
}
fn e10_config_source_test_well_formed() {
    assert!(ProductionValidatorSetRotationApplicationConfig::source_test().is_well_formed());
    assert!(ProductionValidatorSetRotationApplicationConfig::default().is_well_formed());
}
fn e11_protocol_version_supported() {
    assert!(ProductionValidatorSetRotationApplicationProtocolVersion::supported().is_supported());
    assert!(!ProductionValidatorSetRotationApplicationProtocolVersion(2).is_supported());
}
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
fn e13_intent_marked_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    assert!(intent.is_non_mutating());
}
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
fn f03_decision_kind_tags_stable() {
    assert_eq!(K::ApplyNoOpAlreadySynchronized.tag(), "apply-no-op-already-synchronized");
    assert_eq!(K::ApplyBulkValidatorSetRotation.tag(), "apply-bulk-validator-set-rotation");
    assert_eq!(K::UnsupportedApplication.tag(), "unsupported-application");
}
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
fn f05_policy_predicates() {
    use ProductionValidatorSetRotationApplicationPolicy as Pol;
    assert!(Pol::Disabled.is_disabled());
    assert!(Pol::AllowSourceTestValidatorSetRotationApplication.allows_source_test());
    assert!(Pol::RequireProductionValidatorSetRotationApplication.is_production());
    assert!(Pol::MainnetProductionValidatorSetRotationApplicationRequired.is_mainnet());
}
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
fn f07_source_test_executor_shape() {
    let e = ProductionValidatorSetRotationApplicationExecutor::source_test();
    assert_eq!(
        e.policy,
        ProductionValidatorSetRotationApplicationPolicy::AllowSourceTestValidatorSetRotationApplication
    );
    assert!(e.config.kind.is_source_test());
}
fn f08_request_new_has_no_evidence_bindings() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    assert!(case.request.custody_binding.is_none());
    assert!(case.request.attestation_binding.is_none());
    assert!(case.request.durable_replay_binding.is_none());
}
fn f09_testnet_and_devnet_have_distinct_intent_digests() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet))
        .application_intent
        .unwrap();
    let t = eval(&add_case(TrustBundleEnvironment::Testnet))
        .application_intent
        .unwrap();
    assert_ne!(d.intent_digest(), t.intent_digest());
}
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
// ===========================================================================
// G. Release-symbol reachability probe
// ===========================================================================

/// Exercises the Run 305 named free-function digest surfaces and named
/// invariant helpers so they are linked and reachable in the release binary.
fn g01_release_symbol_reachability_probe() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = eval(&case);
    assert!(d.is_accept());
    let intent = d.application_intent.clone().expect("accept intent");
    assert!(intent.is_non_mutating());

    // Named free-function digest surfaces are linked and deterministic.
    let intent_digest = production_validator_set_rotation_application_intent_digest(&intent);
    assert_eq!(intent_digest, intent.intent_digest());
    assert_eq!(intent_digest, d.intent_digest);
    let request_id = production_validator_set_rotation_application_request_id(
        PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION,
        &case.inputs.expected_rotation_plan_digest,
        &case.inputs.application_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.application_nonce,
    );
    assert_eq!(request_id, d.request_id);
    let transcript_digest = production_validator_set_rotation_application_transcript_digest(
        PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION,
        &request_id,
        &intent_digest,
        d.outcome.tag(),
    );
    assert_eq!(transcript_digest, d.transcript_digest);

    // Recovery surface is linked and non-mutating.
    let rec = case
        .executor
        .recover_validator_set_rotation_application_window(None, &intent);
    assert!(rec.is_clean());
    assert!(rec.is_non_mutating());

    // Named invariant helpers.
    assert!(production_validator_set_rotation_application_executor_default_is_disabled());
    assert!(production_validator_set_rotation_application_executor_is_source_test_not_release_binary_evidence());
    assert!(production_validator_set_rotation_application_executor_mainnet_refused());
    assert!(production_validator_set_rotation_application_executor_is_non_mutating());
    assert!(production_validator_set_rotation_application_executor_never_falls_back());
    assert!(production_validator_set_rotation_application_executor_no_default_runtime_wiring());
    assert!(production_validator_set_rotation_application_executor_requires_verified_rotation_plan());
}

// ===========================================================================
// Harness
// ===========================================================================

fn run_case(table: &str, name: &str, f: fn(), rows: &mut Vec<(String, String, bool)>) {
    let ok = catch_unwind(AssertUnwindSafe(f)).is_ok();
    println!("case {table} {name} {}", if ok { "PASS" } else { "FAIL" });
    rows.push((table.to_string(), name.to_string(), ok));
}

fn main() {
    let outdir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            "docs/devnet/run_306_production_validator_set_rotation_application_executor_release_binary/helper_evidence/run_306",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_default_policy_is_disabled_and_inert", a01_default_policy_is_disabled_and_inert as fn()),
        ("accepted_compatible", "a02_devnet_plan_produces_application_decision", a02_devnet_plan_produces_application_decision as fn()),
        ("accepted_compatible", "a03_testnet_plan_produces_application_decision", a03_testnet_plan_produces_application_decision as fn()),
        ("accepted_compatible", "a04_noop_application_accepted_non_mutating", a04_noop_application_accepted_non_mutating as fn()),
        ("accepted_compatible", "a05_validator_add_application_non_mutating", a05_validator_add_application_non_mutating as fn()),
        ("accepted_compatible", "a06_validator_remove_application_non_mutating", a06_validator_remove_application_non_mutating as fn()),
        ("accepted_compatible", "a07_validator_update_application_non_mutating", a07_validator_update_application_non_mutating as fn()),
        ("accepted_compatible", "a08_validator_identity_rotation_application_non_mutating", a08_validator_identity_rotation_application_non_mutating as fn()),
        ("accepted_compatible", "a09_validator_retirement_application_non_mutating", a09_validator_retirement_application_non_mutating as fn()),
        ("accepted_compatible", "a10_emergency_validator_removal_application_non_mutating", a10_emergency_validator_removal_application_non_mutating as fn()),
        ("accepted_compatible", "a11_authority_set_synchronization_application_non_mutating", a11_authority_set_synchronization_application_non_mutating as fn()),
        ("accepted_compatible", "a12_bulk_validator_set_rotation_application_non_mutating", a12_bulk_validator_set_rotation_application_non_mutating as fn()),
        ("accepted_compatible", "a13_application_binds_environment_chain_genesis_root", a13_application_binds_environment_chain_genesis_root as fn()),
        ("accepted_compatible", "a14_application_binds_governance_tuple", a14_application_binds_governance_tuple as fn()),
        ("accepted_compatible", "a15_application_binds_governance_execution_ids_and_digests", a15_application_binds_governance_execution_ids_and_digests as fn()),
        ("accepted_compatible", "a16_application_binds_rotation_plan_ids_and_digests", a16_application_binds_rotation_plan_ids_and_digests as fn()),
        ("accepted_compatible", "a17_application_binds_validator_set_digests_and_versions", a17_application_binds_validator_set_digests_and_versions as fn()),
        ("accepted_compatible", "a18_application_binds_epoch_transition_target_and_nonces", a18_application_binds_epoch_transition_target_and_nonces as fn()),
        ("accepted_compatible", "a19_application_binds_quorum_threshold_policy", a19_application_binds_quorum_threshold_policy as fn()),
        ("accepted_compatible", "a20_application_binds_custody_attestation_durable_where_represented", a20_application_binds_custody_attestation_durable_where_represented as fn()),
        ("accepted_compatible", "a21_request_id_deterministic", a21_request_id_deterministic as fn()),
        ("accepted_compatible", "a22_intent_digest_deterministic", a22_intent_digest_deterministic as fn()),
        ("accepted_compatible", "a23_transcript_digest_deterministic", a23_transcript_digest_deterministic as fn()),
        ("accepted_compatible", "a24_different_action_changes_intent_digest", a24_different_action_changes_intent_digest as fn()),
        ("accepted_compatible", "a25_different_application_nonce_changes_intent_digest", a25_different_application_nonce_changes_intent_digest as fn()),
        ("accepted_compatible", "a26_accept_authorizes_future_mutation_only", a26_accept_authorizes_future_mutation_only as fn()),
        ("accepted_compatible", "a27_accept_outcome_carries_kind_env_target_nonce", a27_accept_outcome_carries_kind_env_target_nonce as fn()),
        ("accepted_compatible", "a28_evidence_required_and_matched_accepts", a28_evidence_required_and_matched_accepts as fn()),
        ("accepted_compatible", "a29_min_governance_epoch_at_boundary_accepts", a29_min_governance_epoch_at_boundary_accepts as fn()),
        ("accepted_compatible", "a30_persisted_sequence_equal_accepts", a30_persisted_sequence_equal_accepts as fn()),
        ("rejection_fail_closed", "b01_missing_rotation_plan_rejected", b01_missing_rotation_plan_rejected as fn()),
        ("rejection_fail_closed", "b02_unverified_rotation_plan_rejected", b02_unverified_rotation_plan_rejected as fn()),
        ("rejection_fail_closed", "b03_unverified_rotation_plan_variant_rejected", b03_unverified_rotation_plan_variant_rejected as fn()),
        ("rejection_fail_closed", "b04_accepted_decision_without_plan_rejected", b04_accepted_decision_without_plan_rejected as fn()),
        ("rejection_fail_closed", "b05_accepted_decision_without_plan_source_rejected", b05_accepted_decision_without_plan_source_rejected as fn()),
        ("rejection_fail_closed", "b06_governance_proof_alone_rejected", b06_governance_proof_alone_rejected as fn()),
        ("rejection_fail_closed", "b07_governance_execution_intent_alone_rejected", b07_governance_execution_intent_alone_rejected as fn()),
        ("rejection_fail_closed", "b08_local_operator_rejected", b08_local_operator_rejected as fn()),
        ("rejection_fail_closed", "b09_peer_majority_rejected", b09_peer_majority_rejected as fn()),
        ("rejection_fail_closed", "b10_custody_only_rejected", b10_custody_only_rejected as fn()),
        ("rejection_fail_closed", "b11_remote_signer_only_rejected", b11_remote_signer_only_rejected as fn()),
        ("rejection_fail_closed", "b12_custody_attestation_only_rejected", b12_custody_attestation_only_rejected as fn()),
        ("rejection_fail_closed", "b13_fixture_only_plan_rejected", b13_fixture_only_plan_rejected as fn()),
        ("rejection_fail_closed", "b14_arbitrary_validator_set_bytes_rejected", b14_arbitrary_validator_set_bytes_rejected as fn()),
        ("rejection_fail_closed", "b15_wrong_rotation_plan_digest_rejected", b15_wrong_rotation_plan_digest_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_rotation_transcript_rejected", b16_wrong_rotation_transcript_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_rotation_request_id_rejected", b17_wrong_rotation_request_id_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_rotation_decision_id_rejected", b18_wrong_rotation_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b19_tampered_plan_integrity_mismatch_rejected", b19_tampered_plan_integrity_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b20_wrong_rotation_policy_id_integrity_mismatch", b20_wrong_rotation_policy_id_integrity_mismatch as fn()),
        ("rejection_fail_closed", "b21_wrong_environment_rejected", b21_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b22_wrong_chain_rejected", b22_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b23_wrong_genesis_rejected", b23_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b24_wrong_authority_root_rejected", b24_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b25_wrong_governance_domain_rejected", b25_wrong_governance_domain_rejected as fn()),
        ("rejection_fail_closed", "b26_wrong_governance_epoch_rejected", b26_wrong_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b27_wrong_proposal_id_rejected", b27_wrong_proposal_id_rejected as fn()),
        ("rejection_fail_closed", "b28_wrong_governance_decision_id_rejected", b28_wrong_governance_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b29_wrong_governance_request_id_rejected", b29_wrong_governance_request_id_rejected as fn()),
        ("rejection_fail_closed", "b30_wrong_governance_intent_digest_rejected", b30_wrong_governance_intent_digest_rejected as fn()),
        ("rejection_fail_closed", "b31_wrong_lifecycle_action_rejected", b31_wrong_lifecycle_action_rejected as fn()),
        ("rejection_fail_closed", "b32_wrong_rotation_action_rejected", b32_wrong_rotation_action_rejected as fn()),
        ("rejection_fail_closed", "b33_wrong_authority_sequence_rejected", b33_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b34_wrong_quorum_rejected", b34_wrong_quorum_rejected as fn()),
        ("rejection_fail_closed", "b35_wrong_threshold_rejected", b35_wrong_threshold_rejected as fn()),
        ("rejection_fail_closed", "b36_wrong_current_set_digest_rejected", b36_wrong_current_set_digest_rejected as fn()),
        ("rejection_fail_closed", "b37_wrong_proposed_set_digest_rejected", b37_wrong_proposed_set_digest_rejected as fn()),
        ("rejection_fail_closed", "b38_wrong_delta_digest_rejected", b38_wrong_delta_digest_rejected as fn()),
        ("rejection_fail_closed", "b39_wrong_validator_set_epoch_rejected", b39_wrong_validator_set_epoch_rejected as fn()),
        ("rejection_fail_closed", "b40_wrong_validator_set_version_rejected", b40_wrong_validator_set_version_rejected as fn()),
        ("rejection_fail_closed", "b41_wrong_rotation_nonce_rejected", b41_wrong_rotation_nonce_rejected as fn()),
        ("rejection_fail_closed", "b42_wrong_epoch_transition_target_request_rejected", b42_wrong_epoch_transition_target_request_rejected as fn()),
        ("rejection_fail_closed", "b43_wrong_epoch_transition_target_expected_rejected", b43_wrong_epoch_transition_target_expected_rejected as fn()),
        ("rejection_fail_closed", "b44_custody_required_but_missing_rejected", b44_custody_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b45_custody_mismatch_rejected", b45_custody_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b46_attestation_required_but_missing_rejected", b46_attestation_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b47_attestation_mismatch_rejected", b47_attestation_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b48_durable_required_but_missing_rejected", b48_durable_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b49_durable_mismatch_rejected", b49_durable_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b50_stale_governance_epoch_rejected", b50_stale_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b51_stale_authority_sequence_rejected", b51_stale_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b52_stale_validator_set_epoch_rejected", b52_stale_validator_set_epoch_rejected as fn()),
        ("rejection_fail_closed", "b53_stale_validator_set_version_rejected", b53_stale_validator_set_version_rejected as fn()),
        ("rejection_fail_closed", "b54_ill_formed_inputs_rejected", b54_ill_formed_inputs_rejected as fn()),
        ("rejection_fail_closed", "b55_plan_carried_custody_disagreement_rejected", b55_plan_carried_custody_disagreement_rejected as fn()),
        ("mainnet_authority_policy", "c01_mainnet_trust_domain_refused", c01_mainnet_trust_domain_refused as fn()),
        ("mainnet_authority_policy", "c02_mainnet_plan_refused", c02_mainnet_plan_refused as fn()),
        ("mainnet_authority_policy", "c03_production_policy_unavailable", c03_production_policy_unavailable as fn()),
        ("mainnet_authority_policy", "c04_mainnet_policy_unavailable_on_non_mainnet", c04_mainnet_policy_unavailable_on_non_mainnet as fn()),
        ("mainnet_authority_policy", "c05_mainnet_policy_on_mainnet_domain_unavailable", c05_mainnet_policy_on_mainnet_domain_unavailable as fn()),
        ("mainnet_authority_policy", "c06_reserved_production_kind_unavailable", c06_reserved_production_kind_unavailable as fn()),
        ("mainnet_authority_policy", "c07_disabled_kind_is_disabled", c07_disabled_kind_is_disabled as fn()),
        ("mainnet_authority_policy", "c08_disabled_policy_is_disabled", c08_disabled_policy_is_disabled as fn()),
        ("mainnet_authority_policy", "c09_mainnet_refused_named_helper", c09_mainnet_refused_named_helper as fn()),
        ("replay_recovery_idempotency", "d01_replayed_application_id_rejected", d01_replayed_application_id_rejected as fn()),
        ("replay_recovery_idempotency", "d02_non_replayed_id_accepts", d02_non_replayed_id_accepts as fn()),
        ("replay_recovery_idempotency", "d03_recovery_no_prior_window_clean", d03_recovery_no_prior_window_clean as fn()),
        ("replay_recovery_idempotency", "d04_recovery_idempotent_replay_observed", d04_recovery_idempotent_replay_observed as fn()),
        ("replay_recovery_idempotency", "d05_recovery_unrelated_window_clean", d05_recovery_unrelated_window_clean as fn()),
        ("replay_recovery_idempotency", "d06_recovery_disabled_policy", d06_recovery_disabled_policy as fn()),
        ("replay_recovery_idempotency", "d07_recovery_same_window_divergent_intent_clean", d07_recovery_same_window_divergent_intent_clean as fn()),
        ("replay_recovery_idempotency", "d08_replay_recovery_is_deterministic", d08_replay_recovery_is_deterministic as fn()),
        ("non_mutation", "e01_named_helper_default_disabled", e01_named_helper_default_disabled as fn()),
        ("non_mutation", "e02_named_helper_source_test_not_release_binary", e02_named_helper_source_test_not_release_binary as fn()),
        ("non_mutation", "e03_named_helper_non_mutating", e03_named_helper_non_mutating as fn()),
        ("non_mutation", "e04_named_helper_never_falls_back", e04_named_helper_never_falls_back as fn()),
        ("non_mutation", "e05_named_helper_no_default_runtime_wiring", e05_named_helper_no_default_runtime_wiring as fn()),
        ("non_mutation", "e06_named_helper_requires_verified_rotation_plan", e06_named_helper_requires_verified_rotation_plan as fn()),
        ("non_mutation", "e07_every_outcome_is_non_mutating", e07_every_outcome_is_non_mutating as fn()),
        ("non_mutation", "e08_accept_is_only_mutation_authorizer", e08_accept_is_only_mutation_authorizer as fn()),
        ("non_mutation", "e09_disabled_is_not_reject", e09_disabled_is_not_reject as fn()),
        ("non_mutation", "e10_config_source_test_well_formed", e10_config_source_test_well_formed as fn()),
        ("non_mutation", "e11_protocol_version_supported", e11_protocol_version_supported as fn()),
        ("non_mutation", "e12_decision_kind_from_plan_kind_roundtrip", e12_decision_kind_from_plan_kind_roundtrip as fn()),
        ("non_mutation", "e13_intent_marked_non_mutating", e13_intent_marked_non_mutating as fn()),
        ("non_mutation", "e14_reject_carries_no_intent_but_has_transcript", e14_reject_carries_no_intent_but_has_transcript as fn()),
        ("reachability_taxonomy", "f01_policy_tags_stable", f01_policy_tags_stable as fn()),
        ("reachability_taxonomy", "f02_kind_tags_stable", f02_kind_tags_stable as fn()),
        ("reachability_taxonomy", "f03_decision_kind_tags_stable", f03_decision_kind_tags_stable as fn()),
        ("reachability_taxonomy", "f04_outcome_tags_unique_and_stable", f04_outcome_tags_unique_and_stable as fn()),
        ("reachability_taxonomy", "f05_policy_predicates", f05_policy_predicates as fn()),
        ("reachability_taxonomy", "f06_all_decision_kinds_non_mutating", f06_all_decision_kinds_non_mutating as fn()),
        ("reachability_taxonomy", "f07_source_test_executor_shape", f07_source_test_executor_shape as fn()),
        ("reachability_taxonomy", "f08_request_new_has_no_evidence_bindings", f08_request_new_has_no_evidence_bindings as fn()),
        ("reachability_taxonomy", "f09_testnet_and_devnet_have_distinct_intent_digests", f09_testnet_and_devnet_have_distinct_intent_digests as fn()),
        ("reachability_taxonomy", "f10_accept_across_all_supported_actions", f10_accept_across_all_supported_actions as fn()),
        ("reachability_taxonomy", "g01_release_symbol_reachability_probe", g01_release_symbol_reachability_probe as fn()),
    ];

    let mut rows: Vec<(String, String, bool)> = Vec::new();
    for (table, name, f) in cases {
        run_case(table, name, *f, &mut rows);
    }

    let mut tables = BTreeMap::<String, (usize, usize)>::new();
    for (table, _name, ok) in &rows {
        let entry = tables.entry(table.clone()).or_insert((0, 0));
        if *ok {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    let total_pass: usize = rows.iter().filter(|(_, _, ok)| *ok).count();
    let total_fail = rows.len() - total_pass;

    let mut summary = String::new();
    summary.push_str("Run 306 validator-set rotation application / epoch-transition executor boundary release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "boundary: crates/qbind-node/src/pqc_production_validator_set_rotation_application_executor.rs (Run 305 ProductionValidatorSetRotationApplicationExecutor)\n",
    );
    summary.push_str(
        "mode: real Run 305 validator-set rotation application / epoch-transition executor boundary over the real Run 303/304 verified validator-set rotation plan accept decision (itself composing the Run 301/302 verified governance execution accept decision); DevNet/TestNet source-test accept only; MainNet refused; default Disabled; MainNet/production policy never evaluates and never falls back to fixture / local-operator / peer-majority / governance-proof-alone / governance-execution-intent-alone / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material; consumes verified validator-set rotation plans and produces typed non-mutating application decisions/intents; does not apply a live validator-set change; does not call Run 070; does not mutate LivePqcTrustState; does not mutate a live validator set, consensus state, or epoch counter; does not call BasicHotStuffEngine::transition_to_epoch; does not write meta:current_epoch; does not inject a reconfig block; does not write trust-bundle sequence or authority marker files; every failure is a typed non-mutating outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let case = add_case(env);
    let decision = eval(&case);
    let intent = decision
        .application_intent
        .clone()
        .expect("accept application intent");
    let rotation_plan_digest = case.inputs.expected_rotation_plan_digest.clone();
    let intent_digest = production_validator_set_rotation_application_intent_digest(&intent);
    let request_id = production_validator_set_rotation_application_request_id(
        PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION,
        &rotation_plan_digest,
        &case.inputs.application_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.application_nonce,
    );
    let transcript_digest = production_validator_set_rotation_application_transcript_digest(
        PRODUCTION_VALIDATOR_SET_ROTATION_APPLICATION_PROTOCOL_VERSION,
        &request_id,
        &intent_digest,
        decision.outcome.tag(),
    );
    fs::write(
        outdir.join("fixtures/run_306_deterministic_digests.txt"),
        format!(
            "rotation_plan_digest {rotation_plan_digest}\nintent_digest {intent_digest}\nrequest_id {request_id}\ntranscript_digest {transcript_digest}\noutcome_tag {}\n",
            decision.outcome.tag()
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
