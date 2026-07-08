//! Run 309 — source/test staged live validator-set / epoch-transition
//! **application executor** boundary integration tests.
//!
//! Source/test only. Run 309 does **not** capture release-binary evidence;
//! release-binary evidence for the staged live validator-set / epoch-transition
//! application executor boundary is deferred to **Run 310**. The tests cover:
//!
//! * A. accepted / compatible source-test staged applications;
//! * B. rejection / fail-closed paths (authority sources + wrong fields);
//! * C. MainNet / authority policy refusal;
//! * D. replay / recovery / idempotency;
//! * E. non-mutation invariants (the executor surfaces are pure);
//! * F. C4/C5 taxonomy status.
//!
//! Each accepted case composes the real Run 303 validator-set rotation
//! boundary to produce a verified rotation plan, feeds the accepted decision
//! into the real Run 305 validator-set rotation application executor, feeds the
//! accepted Run 305 application decision into the real Run 307 live-application
//! authorization executor, then feeds the accepted Run 307 authorization
//! decision into the Run 309 staged epoch-transition application executor.
//!
//! Run 309 produces **only** a prepared, non-mutating staged epoch-transition
//! application record. It never applies a live validator-set change, never
//! transitions a consensus epoch, and never mutates any durable trust state.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_309.md`.

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
use qbind_node::pqc_production_live_validator_set_application_authorization::{
    EmptyLiveValidatorSetApplicationAuthorizationReplaySet,
    LiveValidatorSetApplicationAuthorizationAuthoritySource,
    LiveValidatorSetApplicationAuthorizationKind,
    ProductionLiveValidatorSetApplicationAuthorizationDecision,
    ProductionLiveValidatorSetApplicationAuthorizationExecutor,
    ProductionLiveValidatorSetApplicationAuthorizationInputs,
    ProductionLiveValidatorSetApplicationAuthorizationOutcome,
    ProductionLiveValidatorSetApplicationAuthorizationRequest,
};
use qbind_node::pqc_production_staged_live_validator_set_epoch_transition_application_executor::*;
use qbind_node::pqc_production_validator_set_rotation_application_executor::{
    EmptyValidatorSetRotationApplicationReplaySet, ProductionValidatorSetRotationApplicationDecision,
    ProductionValidatorSetRotationApplicationExecutor, ProductionValidatorSetRotationApplicationInputs,
    ProductionValidatorSetRotationApplicationRequest, ValidatorSetRotationApplicationAuthoritySource,
};
use qbind_node::pqc_production_validator_set_rotation_intent::{
    CanonicalValidatorIdentity, CanonicalValidatorRecord, CanonicalValidatorSetSnapshot,
    EmptyValidatorSetRotationReplaySet, ProductionValidatorSetRotationBoundary,
    ProductionValidatorSetRotationDecision, ProductionValidatorSetRotationInputs,
    ProductionValidatorSetRotationRequest, ValidatorSetChange, ValidatorSetDelta,
    ValidatorSetRotationAction, ValidatorSetRotationAuthoritySource,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures (mirrors the Run 307 fixture chain)
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
const AUTH_POLICY_ID: &str = "authorization-policy-1";
const STAGED_POLICY_ID: &str = "staged-application-policy-1";
const ROT_NONCE: u64 = 3;
const APP_NONCE: u64 = 11;
const LIVE_APP_NONCE: u64 = 23;
const STAGED_NONCE: u64 = 29;
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
    AuthorityTrustDomain::new(env, chain_for(env), GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

fn quorum() -> OnChainGovernanceQuorum {
    OnChainGovernanceQuorum { voters_voted: 8, total_voters: 10, required_quorum: 6 }
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
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1)],
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

fn gov_intent(env: TrustBundleEnvironment, lifecycle: LocalLifecycleAction) -> ProductionGovernanceExecutionIntent {
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
    let source = ValidatorSetRotationAuthoritySource::VerifiedGovernanceExecutionIntent { decision };
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
    let d = boundary.evaluate_validator_set_rotation(&request, &inputs, &EmptyValidatorSetRotationReplaySet);
    assert!(d.is_accept(), "rotation decision must accept for fixture");
    d
}

fn app_inputs305(
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

fn app_decision(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> ProductionValidatorSetRotationApplicationDecision {
    let rot = rotation_decision(env, lifecycle, requested_action, current, delta, proposed);
    let target = rot.plan.as_ref().unwrap().validator_set_epoch;
    let inputs = app_inputs305(env, lifecycle, requested_action, &rot);
    let request = ProductionValidatorSetRotationApplicationRequest::new(
        ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision: rot },
        target,
        APP_NONCE,
    );
    let d = ProductionValidatorSetRotationApplicationExecutor::source_test()
        .evaluate_validator_set_rotation_application(
            &request,
            &inputs,
            &EmptyValidatorSetRotationApplicationReplaySet,
        );
    assert!(d.is_accept(), "run 305 application decision must accept for fixture");
    d
}

// ---- Run 307 authorization decision (composed authority input) ------------

fn auth_inputs307(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    decision: &ProductionValidatorSetRotationApplicationDecision,
) -> ProductionLiveValidatorSetApplicationAuthorizationInputs {
    let intent = decision.application_intent.as_ref().unwrap();
    ProductionLiveValidatorSetApplicationAuthorizationInputs {
        trust_domain: trust_domain(env),
        authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
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
        expected_governance_intent_digest: intent.governance_intent_digest.clone(),
        expected_rotation_decision_id: intent.rotation_decision_id.clone(),
        expected_rotation_request_id: intent.rotation_request_id.clone(),
        expected_rotation_transcript_digest: intent.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: intent.rotation_plan_digest.clone(),
        expected_current_set_digest: intent.current_set_digest.clone(),
        expected_proposed_set_digest: intent.proposed_set_digest.clone(),
        expected_delta_digest: intent.delta_digest.clone(),
        expected_validator_set_epoch: intent.validator_set_epoch,
        expected_validator_set_version: intent.validator_set_version,
        expected_proposed_validator_count: intent.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: decision.application_id.clone(),
        expected_application_request_id: decision.request_id.clone(),
        expected_application_intent_digest: decision.intent_digest.clone(),
        expected_application_transcript_digest: decision.transcript_digest.clone(),
        expected_epoch_transition_target: intent.epoch_transition_target,
        expected_application_nonce: intent.application_nonce,
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

/// Build an accepted Run 307 live validator-set application authorization
/// decision — the sole accepted Run 309 authority source.
fn auth_decision(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> ProductionLiveValidatorSetApplicationAuthorizationDecision {
    let app = app_decision(env, lifecycle, requested_action, current, delta, proposed);
    let target = app.application_intent.as_ref().unwrap().epoch_transition_target;
    let inputs = auth_inputs307(env, lifecycle, requested_action, &app);
    let request = ProductionLiveValidatorSetApplicationAuthorizationRequest::new(
        LiveValidatorSetApplicationAuthorizationAuthoritySource::VerifiedApplicationDecision {
            decision: app,
        },
        target,
        LIVE_APP_NONCE,
    );
    let d = ProductionLiveValidatorSetApplicationAuthorizationExecutor::source_test()
        .evaluate_live_validator_set_application_authorization(
            &request,
            &inputs,
            &EmptyLiveValidatorSetApplicationAuthorizationReplaySet,
        );
    assert!(d.is_accept(), "run 307 authorization decision must accept for fixture");
    d
}

// ===========================================================================
// Run 309 staged epoch-transition application case
// ===========================================================================

struct Stg {
    executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor,
    request: ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest,
    inputs: ProductionStagedLiveValidatorSetEpochTransitionApplicationInputs,
}

fn stg_inputs(
    env: TrustBundleEnvironment,
    decision: &ProductionLiveValidatorSetApplicationAuthorizationDecision,
) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationInputs {
    let intent = decision.authorization_intent.as_ref().unwrap();
    ProductionStagedLiveValidatorSetEpochTransitionApplicationInputs {
        trust_domain: trust_domain(env),
        staged_application_policy_id: STAGED_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: intent.lifecycle_action,
        expected_rotation_action: intent.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: intent.governance_intent_digest.clone(),
        expected_rotation_decision_id: intent.rotation_decision_id.clone(),
        expected_rotation_request_id: intent.rotation_request_id.clone(),
        expected_rotation_transcript_digest: intent.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: intent.rotation_plan_digest.clone(),
        expected_current_set_digest: intent.current_set_digest.clone(),
        expected_proposed_set_digest: intent.proposed_set_digest.clone(),
        expected_delta_digest: intent.delta_digest.clone(),
        expected_validator_set_epoch: intent.validator_set_epoch,
        expected_validator_set_version: intent.validator_set_version,
        expected_proposed_validator_count: intent.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: intent.application_decision_id.clone(),
        expected_application_request_id: intent.application_request_id.clone(),
        expected_application_intent_digest: intent.application_intent_digest.clone(),
        expected_application_transcript_digest: intent.application_transcript_digest.clone(),
        expected_authorization_decision_id: decision.authorization_id.clone(),
        expected_authorization_request_id: decision.request_id.clone(),
        expected_authorization_intent_digest: decision.intent_digest.clone(),
        expected_authorization_transcript_digest: decision.transcript_digest.clone(),
        expected_epoch_transition_target: intent.epoch_transition_target,
        expected_application_nonce: intent.application_nonce,
        expected_live_application_nonce: intent.live_application_nonce,
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

#[derive(Clone, Copy)]
enum Sc {
    Add,
    Remove,
    Update,
    NoOp,
    Identity,
    Retire,
    Emergency,
    AuthSync,
    Bulk,
}

const ALL_SC: [Sc; 9] = [
    Sc::Add,
    Sc::Remove,
    Sc::Update,
    Sc::NoOp,
    Sc::Identity,
    Sc::Retire,
    Sc::Emergency,
    Sc::AuthSync,
    Sc::Bulk,
];

fn scenario(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> (
    LocalLifecycleAction,
    ValidatorSetRotationAction,
    CanonicalValidatorSetSnapshot,
    ValidatorSetDelta,
    CanonicalValidatorSetSnapshot,
) {
    let current = current_set(env);
    match sc {
        Sc::Add => {
            let v4 = validator(env, 4, 100, 2);
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone())]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1), v4],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd, current, delta, proposed)
        }
        Sc::Remove => {
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorRemove, current, delta, proposed)
        }
        Sc::Update => {
            let updated = validator(env, 2, 250, 1);
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(updated.clone())]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), updated, validator(env, 3, 100, 1)],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorUpdate, current, delta, proposed)
        }
        Sc::NoOp => {
            let proposed = current_set(env);
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::NoOpSynchronization, current, ValidatorSetDelta::empty(), proposed)
        }
        Sc::Identity => {
            let mut rotated = validator(env, 2, 100, 1);
            rotated.identity.consensus_key_fingerprint = "cons-2-rotated".to_string();
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::update(rotated.clone())]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), rotated, validator(env, 3, 100, 1)],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorIdentityRotation, current, delta, proposed)
        }
        Sc::Retire => {
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Retire, ValidatorSetRotationAction::ValidatorRetirement, current, delta, proposed)
        }
        Sc::Emergency => {
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::EmergencyRevoke, ValidatorSetRotationAction::EmergencyValidatorRemoval, current, delta, proposed)
        }
        Sc::AuthSync => {
            let v4 = validator(env, 4, 100, 2);
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone()), ValidatorSetChange::remove(3)]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), v4],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::AuthoritySetSynchronization, current, delta, proposed)
        }
        Sc::Bulk => {
            let v4 = validator(env, 4, 100, 2);
            let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone()), ValidatorSetChange::remove(3)]);
            let proposed = CanonicalValidatorSetSnapshot::new(
                vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), v4],
                CUR_EPOCH + 1,
                CUR_VERSION + 1,
            );
            (LocalLifecycleAction::Rotate, ValidatorSetRotationAction::BulkValidatorSetRotation, current, delta, proposed)
        }
    }
}

fn expected_staged_kind(sc: Sc) -> StagedLiveValidatorSetEpochTransitionApplicationKind {
    use StagedLiveValidatorSetEpochTransitionApplicationKind as K;
    match sc {
        Sc::Add => K::StageApplyValidatorAdd,
        Sc::Remove => K::StageApplyValidatorRemove,
        Sc::Update => K::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => K::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => K::StageApplyValidatorIdentityRotation,
        Sc::Retire => K::StageApplyValidatorRetirement,
        Sc::Emergency => K::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => K::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => K::StageApplyBulkValidatorSetRotation,
    }
}

/// Build an accepted Run 307 authorization decision for a scenario.
fn auth_decision_for(env: TrustBundleEnvironment, sc: Sc) -> ProductionLiveValidatorSetApplicationAuthorizationDecision {
    let (lifecycle, action, current, delta, proposed) = scenario(env, sc);
    auth_decision(env, lifecycle, action, current, delta, proposed)
}

fn stg_case(env: TrustBundleEnvironment, sc: Sc) -> Stg {
    let decision = auth_decision_for(env, sc);
    let target = decision.authorization_intent.as_ref().unwrap().epoch_transition_target;
    let inputs = stg_inputs(env, &decision);
    let request = ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest::new(
        StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource::VerifiedLiveApplicationAuthorization {
            decision,
        },
        target,
        STAGED_NONCE,
    );
    Stg {
        executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay() -> EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet {
    EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet
}

fn eval(case: &Stg) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    case.executor.evaluate_staged_live_validator_set_epoch_transition_application(
        &case.request,
        &case.inputs,
        &empty_replay(),
    )
}

use ProductionStagedLiveValidatorSetEpochTransitionApplicationOutcome as SO;
use StagedLiveValidatorSetEpochTransitionApplicationKind as SK;

// ===========================================================================
// A. Accepted / compatible source-test staged applications
// ===========================================================================

fn assert_accept(d: &ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision, sc: Sc, env: TrustBundleEnvironment) {
    assert!(d.is_accept(), "expected accept, got {:?}", d.outcome);
    match &d.outcome {
        SO::AcceptedSourceTestStagedLiveValidatorSetEpochTransitionApplication {
            staged_kind,
            environment,
            epoch_transition_target,
            staged_application_nonce,
        } => {
            assert_eq!(*staged_kind, expected_staged_kind(sc));
            assert_eq!(*environment, env);
            assert_eq!(*staged_application_nonce, STAGED_NONCE);
            assert!(*epoch_transition_target >= CUR_EPOCH);
        }
        other => panic!("unexpected accepted outcome: {other:?}"),
    }
    let record = d.staged_application_record.as_ref().expect("record present on accept");
    assert_eq!(record.staged_kind, expected_staged_kind(sc));
    assert_eq!(record.environment, env);
    assert_eq!(record.staged_application_nonce, STAGED_NONCE);
    assert!(d.outcome.is_non_mutating());
    assert!(d.authorizes_future_mutation_only());
}

#[test]
fn accept_add_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Add)), Sc::Add, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_add_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Add)), Sc::Add, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_remove_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Remove)), Sc::Remove, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_remove_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Remove)), Sc::Remove, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_update_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Update)), Sc::Update, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_update_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Update)), Sc::Update, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_noop_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::NoOp)), Sc::NoOp, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_noop_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::NoOp)), Sc::NoOp, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_identity_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Identity)), Sc::Identity, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_identity_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Identity)), Sc::Identity, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_retire_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Retire)), Sc::Retire, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_retire_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Retire)), Sc::Retire, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_emergency_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Emergency)), Sc::Emergency, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_emergency_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Emergency)), Sc::Emergency, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_authsync_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::AuthSync)), Sc::AuthSync, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_authsync_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::AuthSync)), Sc::AuthSync, TrustBundleEnvironment::Testnet); }
#[test]
fn accept_bulk_devnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Bulk)), Sc::Bulk, TrustBundleEnvironment::Devnet); }
#[test]
fn accept_bulk_testnet() { assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Bulk)), Sc::Bulk, TrustBundleEnvironment::Testnet); }

#[test]
fn accepted_all_scenarios_devnet() {
    for sc in ALL_SC {
        assert_accept(&eval(&stg_case(TrustBundleEnvironment::Devnet, sc)), sc, TrustBundleEnvironment::Devnet);
    }
}

#[test]
fn accepted_all_scenarios_testnet() {
    for sc in ALL_SC {
        assert_accept(&eval(&stg_case(TrustBundleEnvironment::Testnet, sc)), sc, TrustBundleEnvironment::Testnet);
    }
}

#[test]
fn accepted_record_binds_run307_authorization_tuple() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.authorization_decision_id, case.inputs.expected_authorization_decision_id);
    assert_eq!(record.authorization_request_id, case.inputs.expected_authorization_request_id);
    assert_eq!(record.authorization_intent_digest, case.inputs.expected_authorization_intent_digest);
    assert_eq!(record.authorization_transcript_digest, case.inputs.expected_authorization_transcript_digest);
}

#[test]
fn accepted_record_binds_run305_application_tuple() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Remove);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.application_decision_id, case.inputs.expected_application_decision_id);
    assert_eq!(record.application_request_id, case.inputs.expected_application_request_id);
    assert_eq!(record.application_intent_digest, case.inputs.expected_application_intent_digest);
    assert_eq!(record.application_transcript_digest, case.inputs.expected_application_transcript_digest);
    assert_eq!(record.application_nonce, case.inputs.expected_application_nonce);
}

#[test]
fn accepted_record_binds_governance_and_rotation_tuple() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Update);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.governance_domain_id, GOV_DOMAIN);
    assert_eq!(record.governance_epoch, GOV_EPOCH);
    assert_eq!(record.proposal_id, PROPOSAL_ID);
    assert_eq!(record.governance_decision_id, GOV_DECISION_ID);
    assert_eq!(record.governance_request_id, GOV_REQUEST_ID);
    assert_eq!(record.rotation_nonce, ROT_NONCE);
    assert_eq!(record.authority_domain_sequence, SEQ);
}

#[test]
fn accepted_record_binds_epoch_transition_target() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = case.request.proposed_epoch_transition_target;
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.epoch_transition_target, target);
    assert_eq!(record.epoch_transition_target, case.inputs.expected_epoch_transition_target);
}

#[test]
fn accepted_record_binds_live_and_staged_nonce() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.live_application_nonce, LIVE_APP_NONCE);
    assert_eq!(record.staged_application_nonce, STAGED_NONCE);
}

#[test]
fn accepted_record_trust_domain_fields() {
    let env = TrustBundleEnvironment::Testnet;
    let case = stg_case(env, Sc::Add);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.environment, env);
    assert_eq!(record.chain_id, chain_for(env));
    assert_eq!(record.genesis_hash, GENESIS_HASH);
    assert_eq!(record.authority_root_fingerprint, ROOT_FP);
    assert_eq!(record.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

#[test]
fn accepted_record_policy_ids() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&case);
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(record.staged_application_policy_id, STAGED_POLICY_ID);
    assert_eq!(record.authorization_policy_id, AUTH_POLICY_ID);
    assert_eq!(record.application_policy_id, APP_POLICY_ID);
}

#[test]
fn accepted_decision_intent_and_transcript_nonempty() {
    let d = eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Add));
    assert!(!d.intent_digest.is_empty());
    assert!(!d.transcript_digest.is_empty());
    assert!(!d.request_id.is_empty());
    assert!(!d.staged_application_id.is_empty());
}

#[test]
fn accepted_decision_intent_digest_matches_record() {
    let d = eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let record = d.staged_application_record.as_ref().unwrap();
    assert_eq!(d.intent_digest, record.intent_digest());
}

#[test]
fn accepted_staged_application_id_matches_authorization_id() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&case);
    assert_eq!(d.staged_application_id, case.inputs.expected_authorization_decision_id);
}

#[test]
fn digest_determinism_repeated_evaluation() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d1 = eval(&case);
    let d2 = eval(&case);
    assert_eq!(d1.intent_digest, d2.intent_digest);
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert_eq!(d1.request_id, d2.request_id);
    assert_eq!(d1.staged_application_id, d2.staged_application_id);
    assert_eq!(d1.outcome, d2.outcome);
}

#[test]
fn digest_determinism_record_intent_digest() {
    let case = stg_case(TrustBundleEnvironment::Devnet, Sc::Bulk);
    let d1 = eval(&case);
    let d2 = eval(&case);
    let r1 = d1.staged_application_record.as_ref().unwrap();
    let r2 = d2.staged_application_record.as_ref().unwrap();
    assert_eq!(r1.intent_digest(), r2.intent_digest());
    assert_eq!(r1, r2);
}

#[test]
fn distinct_scenarios_distinct_intent_digests() {
    let a = eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let b = eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Remove));
    assert_ne!(a.intent_digest, b.intent_digest);
}

#[test]
fn distinct_environments_distinct_intent_digests() {
    let a = eval(&stg_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let b = eval(&stg_case(TrustBundleEnvironment::Testnet, Sc::Add));
    assert_ne!(a.intent_digest, b.intent_digest);
}

// ===========================================================================
// B. Rejection / fail-closed paths
// ===========================================================================

fn stg_case_with_source(
    env: TrustBundleEnvironment,
    source: StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource,
) -> Stg {
    let decision = auth_decision_for(env, Sc::Add);
    let target = decision.authorization_intent.as_ref().unwrap().epoch_transition_target;
    let inputs = stg_inputs(env, &decision);
    let request = ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest::new(
        source,
        target,
        STAGED_NONCE,
    );
    Stg {
        executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor::source_test(),
        request,
        inputs,
    }
}

use StagedLiveValidatorSetEpochTransitionApplicationAuthoritySource as Src;

#[test]
fn reject_missing_authorization() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::MissingLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::VerifiedLiveApplicationAuthorizationRequired);
    assert!(d.outcome.is_reject());
    assert!(d.staged_application_record.is_none());
}

#[test]
fn reject_application_decision_alone() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::ApplicationDecisionWithoutLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::ApplicationDecisionAloneRejected);
}

#[test]
fn reject_rotation_plan_alone() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::RotationPlanWithoutLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::RotationPlanAloneRejected);
}

#[test]
fn reject_governance_execution_intent_alone() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::GovernanceExecutionIntentWithoutLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::GovernanceExecutionIntentAloneRejected);
}

#[test]
fn reject_governance_proof_alone() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::GovernanceProofWithoutLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::GovernanceProofAloneRejected);
}

#[test]
fn reject_local_operator() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::LocalOperatorAssertion));
    assert_eq!(d.outcome, SO::LocalOperatorProofRejected);
}

#[test]
fn reject_peer_majority() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::PeerMajorityAssertion));
    assert_eq!(d.outcome, SO::PeerMajorityProofRejected);
}

#[test]
fn reject_custody_only() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::CustodyOnlyEvidence));
    assert_eq!(d.outcome, SO::CustodyOnlyProofRejected);
}

#[test]
fn reject_remote_signer_only() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::RemoteSignerOnlyEvidence));
    assert_eq!(d.outcome, SO::RemoteSignerOnlyProofRejected);
}

#[test]
fn reject_custody_attestation_only() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::CustodyAttestationOnlyEvidence));
    assert_eq!(d.outcome, SO::CustodyAttestationOnlyProofRejected);
}

#[test]
fn reject_fixture_only_as_production_authority() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::FixtureOnlyLiveApplicationAuthorization));
    assert_eq!(d.outcome, SO::FixtureLiveApplicationAuthorizationRejectedAsProductionAuthority);
}

#[test]
fn reject_arbitrary_bytes() {
    let d = eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::ArbitraryValidatorSetBytes));
    assert_eq!(d.outcome, SO::ArbitraryValidatorSetBytesRejected);
}

#[test]
fn reject_unverified_via_verified_source() {
    let mut decision = auth_decision_for(TrustBundleEnvironment::Devnet, Sc::Add);
    decision.outcome = ProductionLiveValidatorSetApplicationAuthorizationOutcome::MainNetRefused;
    let d = eval(&stg_case_with_source(
        TrustBundleEnvironment::Devnet,
        Src::VerifiedLiveApplicationAuthorization { decision },
    ));
    assert_eq!(d.outcome, SO::UnverifiedLiveApplicationAuthorizationRejected);
}

#[test]
fn reject_unverified_marker_source() {
    let decision = auth_decision_for(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&stg_case_with_source(
        TrustBundleEnvironment::Devnet,
        Src::UnverifiedLiveApplicationAuthorization { decision },
    ));
    assert_eq!(d.outcome, SO::UnverifiedLiveApplicationAuthorizationRejected);
}

#[test]
fn reject_accepted_without_intent_via_verified_source() {
    let mut decision = auth_decision_for(TrustBundleEnvironment::Devnet, Sc::Add);
    decision.authorization_intent = None;
    let d = eval(&stg_case_with_source(
        TrustBundleEnvironment::Devnet,
        Src::VerifiedLiveApplicationAuthorization { decision },
    ));
    assert_eq!(d.outcome, SO::VerifiedLiveApplicationAuthorizationRequired);
}

#[test]
fn reject_accepted_without_intent_marker_source() {
    let decision = auth_decision_for(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = eval(&stg_case_with_source(
        TrustBundleEnvironment::Devnet,
        Src::AcceptedAuthorizationWithoutAuthorizationIntent { decision },
    ));
    assert_eq!(d.outcome, SO::VerifiedLiveApplicationAuthorizationRequired);
}

// ---- Wrong authorization-decision transcript binding ----------------------

#[test]
fn reject_wrong_authorization_decision_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authorization_decision_id = "wrong-auth-id".to_string();
    assert_eq!(eval(&c).outcome, SO::AuthorizationDecisionIdMismatch);
}

#[test]
fn reject_wrong_authorization_request_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authorization_request_id = "wrong-auth-req".to_string();
    assert_eq!(eval(&c).outcome, SO::AuthorizationDecisionRequestIdMismatch);
}

#[test]
fn reject_wrong_authorization_intent_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authorization_intent_digest = "wrong-auth-intent-digest".to_string();
    assert_eq!(eval(&c).outcome, SO::AuthorizationDecisionIntentDigestMismatch);
}

#[test]
fn reject_wrong_authorization_transcript_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authorization_transcript_digest = "wrong-auth-transcript".to_string();
    assert_eq!(eval(&c).outcome, SO::AuthorizationDecisionTranscriptMismatch);
}

#[test]
fn reject_authorization_integrity_mismatch() {
    let env = TrustBundleEnvironment::Devnet;
    let mut decision = auth_decision_for(env, Sc::Add);
    let inputs = stg_inputs(env, &decision);
    let target = inputs.expected_epoch_transition_target;
    // Tamper the carried intent so its recomputed digest diverges from the
    // bound decision.intent_digest (transcript checks still match).
    decision.authorization_intent.as_mut().unwrap().governance_height += 1;
    let request = ProductionStagedLiveValidatorSetEpochTransitionApplicationRequest::new(
        Src::VerifiedLiveApplicationAuthorization { decision },
        target,
        STAGED_NONCE,
    );
    let case = Stg {
        executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor::source_test(),
        request,
        inputs,
    };
    assert_eq!(eval(&case).outcome, SO::AuthorizationDecisionIntegrityMismatch);
}

#[test]
fn reject_wrong_authorization_policy_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authorization_policy_id = "wrong-auth-policy".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongAuthorizationPolicyId);
}

// ---- Wrong application tuple ----------------------------------------------

#[test]
fn reject_wrong_application_decision_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_decision_id = "wrong-app-id".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongApplicationDecisionId);
}

#[test]
fn reject_wrong_application_request_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_request_id = "wrong-app-req".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongApplicationRequestId);
}

#[test]
fn reject_wrong_application_intent_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_intent_digest = "wrong-app-intent".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongApplicationIntentDigest);
}

#[test]
fn reject_wrong_application_transcript_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_transcript_digest = "wrong-app-transcript".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongApplicationTranscriptDigest);
}

#[test]
fn reject_wrong_application_policy_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_policy_id = "wrong-app-policy".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongApplicationPolicyId);
}

// ---- Wrong trust domain ---------------------------------------------------

#[test]
fn reject_wrong_environment() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Testnet);
    assert_eq!(eval(&c).outcome, SO::WrongEnvironment);
}

#[test]
fn reject_wrong_chain() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain.chain_id = "wrong-chain".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongChain);
}

#[test]
fn reject_wrong_genesis() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain.genesis_hash = "wrong-genesis".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongGenesis);
}

#[test]
fn reject_wrong_authority_root() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain.authority_root_fingerprint = "wrong-root".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongAuthorityRoot);
}

// ---- Wrong governance / rotation tuple ------------------------------------

#[test]
fn reject_wrong_governance_domain() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_governance_domain_id = "wrong-domain".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongGovernanceDomain);
}

#[test]
fn reject_wrong_governance_epoch() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_eq!(eval(&c).outcome, SO::WrongGovernanceEpoch);
}

#[test]
fn reject_wrong_proposal_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_proposal_id = "wrong-proposal".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongProposalId);
}

#[test]
fn reject_wrong_governance_execution_decision_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_governance_decision_id = "wrong-gov-decision".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongGovernanceExecutionDecisionId);
}

#[test]
fn reject_wrong_governance_execution_request_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_governance_request_id = "wrong-gov-request".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongGovernanceExecutionRequestId);
}

#[test]
fn reject_wrong_governance_execution_intent_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_governance_intent_digest = "wrong-gov-intent".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongGovernanceExecutionIntentDigest);
}

#[test]
fn reject_wrong_rotation_decision_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_decision_id = "wrong-rot-decision".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongRotationDecisionId);
}

#[test]
fn reject_wrong_rotation_request_id() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_request_id = "wrong-rot-request".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongRotationRequestId);
}

#[test]
fn reject_wrong_rotation_transcript_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_transcript_digest = "wrong-rot-transcript".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongRotationTranscriptDigest);
}

#[test]
fn reject_wrong_rotation_plan_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_plan_digest = "wrong-rot-plan".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongRotationPlanDigest);
}

#[test]
fn reject_wrong_lifecycle_action() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_lifecycle_action = LocalLifecycleAction::Retire;
    assert_eq!(eval(&c).outcome, SO::WrongLifecycleAction);
}

#[test]
fn reject_wrong_rotation_action() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove;
    assert_eq!(eval(&c).outcome, SO::WrongRotationAction);
}

#[test]
fn reject_wrong_authority_sequence() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_authority_domain_sequence = SEQ + 5;
    assert_eq!(eval(&c).outcome, SO::WrongAuthoritySequence);
}

#[test]
fn reject_wrong_quorum() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_quorum = OnChainGovernanceQuorum { voters_voted: 9, total_voters: 10, required_quorum: 6 };
    assert_eq!(eval(&c).outcome, SO::WrongQuorum);
}

#[test]
fn reject_wrong_threshold() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_threshold = GovernanceThreshold::new(7, 6, 10);
    assert_eq!(eval(&c).outcome, SO::WrongThreshold);
}

// ---- Wrong validator-set tuple --------------------------------------------

#[test]
fn reject_wrong_current_set_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_current_set_digest = "wrong-current".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongCurrentValidatorSetDigest);
}

#[test]
fn reject_wrong_proposed_set_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_proposed_set_digest = "wrong-proposed".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongProposedValidatorSetDigest);
}

#[test]
fn reject_wrong_delta_digest() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_delta_digest = "wrong-delta".to_string();
    assert_eq!(eval(&c).outcome, SO::WrongValidatorSetDeltaDigest);
}

#[test]
fn reject_wrong_validator_set_epoch() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_validator_set_epoch += 100;
    assert_eq!(eval(&c).outcome, SO::WrongValidatorSetEpoch);
}

#[test]
fn reject_wrong_validator_set_version() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_validator_set_version += 100;
    assert_eq!(eval(&c).outcome, SO::WrongValidatorSetVersion);
}

#[test]
fn reject_wrong_proposed_validator_count() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_proposed_validator_count += 100;
    assert_eq!(eval(&c).outcome, SO::WrongProposedValidatorCount);
}

#[test]
fn reject_wrong_rotation_nonce() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_rotation_nonce = ROT_NONCE + 1;
    assert_eq!(eval(&c).outcome, SO::WrongRotationNonce);
}

// ---- Wrong epoch-transition target / nonces -------------------------------

#[test]
fn reject_wrong_epoch_transition_target_inputs() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_epoch_transition_target += 7;
    assert_eq!(eval(&c).outcome, SO::WrongEpochTransitionTarget);
}

#[test]
fn reject_wrong_epoch_transition_target_request() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.proposed_epoch_transition_target += 7;
    assert_eq!(eval(&c).outcome, SO::WrongEpochTransitionTarget);
}

#[test]
fn reject_wrong_application_nonce() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_application_nonce = APP_NONCE + 1;
    assert_eq!(eval(&c).outcome, SO::WrongApplicationNonce);
}

#[test]
fn reject_wrong_live_application_nonce() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_live_application_nonce = LIVE_APP_NONCE + 1;
    assert_eq!(eval(&c).outcome, SO::WrongLiveApplicationNonce);
}

// ---- Staleness / freshness ------------------------------------------------

#[test]
fn reject_stale_authority_sequence() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.persisted_sequence = Some(SEQ + 1);
    assert_eq!(eval(&c).outcome, SO::StaleAuthoritySequence);
}

#[test]
fn reject_stale_governance_epoch() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.min_governance_epoch = GOV_EPOCH + 1;
    assert_eq!(eval(&c).outcome, SO::StaleGovernanceEpoch);
}

#[test]
fn reject_stale_validator_set_epoch() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.min_validator_set_epoch = 1_000_000;
    assert_eq!(eval(&c).outcome, SO::StaleValidatorSetEpoch);
}

#[test]
fn reject_stale_validator_set_version() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.min_validator_set_version = 1_000_000;
    assert_eq!(eval(&c).outcome, SO::StaleValidatorSetVersion);
}

// ---- Evidence composition -------------------------------------------------

#[test]
fn reject_custody_evidence_required() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.require_custody_evidence = true;
    c.inputs.expected_custody = Some(custody());
    assert_eq!(eval(&c).outcome, SO::CustodyBackendEvidenceRequired);
}

#[test]
fn reject_custody_evidence_mismatch() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let mut other = custody();
    other.key_handle = "different-key".to_string();
    c.inputs.require_custody_evidence = true;
    c.inputs.expected_custody = Some(custody());
    c.request.custody_binding = Some(other);
    assert_eq!(eval(&c).outcome, SO::CustodyBackendMismatch);
}

#[test]
fn reject_attestation_evidence_required() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.require_attestation_evidence = true;
    c.inputs.expected_attestation = Some(attestation());
    assert_eq!(eval(&c).outcome, SO::CustodyAttestationRequired);
}

#[test]
fn reject_durable_replay_evidence_required() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.require_durable_replay_evidence = true;
    c.inputs.expected_durable_replay = Some(durable());
    assert_eq!(eval(&c).outcome, SO::DurableReplayEvidenceRequired);
}

#[test]
fn accept_with_matching_custody_evidence() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.require_custody_evidence = true;
    c.inputs.expected_custody = Some(custody());
    c.request.custody_binding = Some(custody());
    assert!(eval(&c).is_accept());
}

// ===========================================================================
// C. Policy / kind gate — MainNet refusal & fail-closed unavailability
// ===========================================================================

use ProductionStagedLiveValidatorSetEpochTransitionApplicationPolicy as Pol;
use ProductionStagedLiveValidatorSetEpochTransitionApplicationKind as Knd;
use ProductionStagedLiveValidatorSetEpochTransitionApplicationConfig as Cfg;
use ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor as Exec;

/// A valid Devnet Add case whose executor is replaced.
fn stg_case_with_executor(exec: Exec) -> Stg {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.executor = exec;
    c
}

#[test]
fn reject_mainnet_trust_domain_refused() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    assert_eq!(eval(&c).outcome, SO::MainNetRefused);
}

#[test]
fn reject_disabled_default_executor() {
    let c = stg_case_with_executor(Exec::new(Cfg::default(), Pol::Disabled));
    let d = eval(&c);
    assert_eq!(d.outcome, SO::Disabled);
    assert!(!d.outcome.is_reject(), "Disabled is inert, not a reject");
    assert!(d.staged_application_record.is_none());
}

#[test]
fn reject_disabled_policy_with_source_test_kind() {
    let c = stg_case_with_executor(Exec::new(Cfg::source_test(), Pol::Disabled));
    assert_eq!(eval(&c).outcome, SO::Disabled);
}

#[test]
fn reject_production_policy_unavailable() {
    let c = stg_case_with_executor(Exec::new(
        Cfg::source_test(),
        Pol::RequireProductionStagedLiveValidatorSetEpochTransitionApplication,
    ));
    assert_eq!(
        eval(&c).outcome,
        SO::ProductionStagedLiveValidatorSetEpochTransitionApplicationUnavailable
    );
}

#[test]
fn reject_mainnet_policy_unavailable_on_devnet_domain() {
    let c = stg_case_with_executor(Exec::new(
        Cfg::source_test(),
        Pol::MainnetProductionStagedLiveValidatorSetEpochTransitionApplicationRequired,
    ));
    assert_eq!(
        eval(&c).outcome,
        SO::MainNetProductionStagedLiveValidatorSetEpochTransitionApplicationUnavailable
    );
}

#[test]
fn reject_mainnet_policy_on_mainnet_domain_unavailable() {
    let mut c = stg_case_with_executor(Exec::new(
        Cfg::source_test(),
        Pol::MainnetProductionStagedLiveValidatorSetEpochTransitionApplicationRequired,
    ));
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        eval(&c).outcome,
        SO::MainNetProductionStagedLiveValidatorSetEpochTransitionApplicationUnavailable
    );
}

#[test]
fn reject_reserved_production_kind_unavailable() {
    let c = stg_case_with_executor(Exec::new(
        Cfg::new(Knd::ProductionStagedLiveValidatorSetEpochTransitionApplication),
        Pol::AllowSourceTestStagedLiveValidatorSetEpochTransitionApplication,
    ));
    assert_eq!(
        eval(&c).outcome,
        SO::StagedLiveValidatorSetEpochTransitionApplicationBoundaryUnavailable
    );
}

// ===========================================================================
// D. Replay / idempotency / recovery / equivocation
// ===========================================================================

#[test]
fn reject_replay_of_prior_staged_application() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let first = eval(&c);
    assert!(first.is_accept());
    // The staged-application replay id equals the decision request id; feed
    // it back as a persisted replay id.
    let replay = vec![first.request_id.clone()];
    let d = c.executor.evaluate_staged_live_validator_set_epoch_transition_application(
        &c.request,
        &c.inputs,
        &replay,
    );
    match d.outcome {
        SO::StagedApplicationReplayRejected { staged_application_id } => {
            assert_eq!(staged_application_id, first.request_id);
        }
        other => panic!("expected replay rejection, got {other:?}"),
    }
    assert!(d.staged_application_record.is_none());
}

#[test]
fn accept_is_deterministic_under_reeval() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let a = eval(&c);
    let b = eval(&c);
    assert_eq!(a, b);
    assert_eq!(
        a.staged_application_record.unwrap().intent_digest(),
        b.staged_application_record.unwrap().intent_digest()
    );
}

#[test]
fn recover_clean_when_no_prior_window() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let rec = eval(&c).staged_application_record.unwrap();
    let r = c.executor.recover_staged_live_validator_set_epoch_transition_application_window(None, &rec);
    assert!(r.is_clean());
    assert!(r.is_non_mutating());
}

#[test]
fn recover_idempotent_when_same_window() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let rec = eval(&c).staged_application_record.unwrap();
    let r = c.executor.recover_staged_live_validator_set_epoch_transition_application_window(Some(&rec), &rec);
    match r {
        ProductionStagedLiveValidatorSetEpochTransitionApplicationRecoveryOutcome::IdempotentReplayObserved { ref staged_application_id } => {
            assert_eq!(*staged_application_id, rec.authorization_decision_id);
        }
        other => panic!("expected idempotent replay, got {other:?}"),
    }
    assert!(r.is_non_mutating());
}

#[test]
fn recover_disabled_when_policy_disabled() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let rec = eval(&c).staged_application_record.unwrap();
    let disabled = Exec::new(Cfg::default(), Pol::Disabled);
    let r = disabled.recover_staged_live_validator_set_epoch_transition_application_window(Some(&rec), &rec);
    assert_eq!(
        r,
        ProductionStagedLiveValidatorSetEpochTransitionApplicationRecoveryOutcome::RecoveryDisabled
    );
    assert!(r.is_non_mutating());
}

#[test]
fn recover_independent_window_when_nonce_differs() {
    let c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let rec1 = eval(&c).staged_application_record.unwrap();
    let mut c2 = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c2.request.staged_application_nonce = STAGED_NONCE + 1;
    let rec2 = eval(&c2).staged_application_record.unwrap();
    let r = c.executor.recover_staged_live_validator_set_epoch_transition_application_window(Some(&rec1), &rec2);
    assert!(r.is_clean());
}

// ===========================================================================
// E. Non-mutation invariants
// ===========================================================================

#[test]
fn every_accepted_outcome_is_non_mutating() {
    for sc in ALL_SC {
        for &env in &[TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
            let d = eval(&stg_case(env, sc));
            assert!(d.is_accept());
            assert!(d.outcome.is_non_mutating());
            assert!(d.authorizes_future_mutation_only());
        }
    }
}

#[test]
fn rejection_outcomes_are_non_mutating_and_recordless() {
    let cases = [
        eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::MissingLiveApplicationAuthorization)),
        eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::LocalOperatorAssertion)),
        eval(&stg_case_with_source(TrustBundleEnvironment::Devnet, Src::ArbitraryValidatorSetBytes)),
    ];
    for d in cases {
        assert!(d.outcome.is_reject());
        assert!(d.outcome.is_non_mutating());
        assert!(d.staged_application_record.is_none());
        assert!(!d.authorizes_future_mutation_only());
    }
}

#[test]
fn mainnet_refusal_is_non_mutating() {
    let mut c = stg_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = eval(&c);
    assert_eq!(d.outcome, SO::MainNetRefused);
    assert!(d.outcome.is_non_mutating());
    assert!(d.staged_application_record.is_none());
}

// ===========================================================================
// F. C4 / C5 taxonomy checks
// ===========================================================================

#[test]
fn policy_taxonomy_tags_and_predicates() {
    assert!(Pol::default().is_disabled());
    assert!(Pol::AllowSourceTestStagedLiveValidatorSetEpochTransitionApplication.allows_source_test());
    assert!(Pol::RequireProductionStagedLiveValidatorSetEpochTransitionApplication.is_production());
    assert!(Pol::MainnetProductionStagedLiveValidatorSetEpochTransitionApplicationRequired.is_mainnet());
    assert_eq!(Pol::default().tag(), "disabled");
}

#[test]
fn kind_taxonomy_tags_and_predicates() {
    assert!(!Knd::default().is_source_test());
    assert!(Knd::SourceTestStagedLiveValidatorSetEpochTransitionApplication.is_source_test());
    assert!(!Knd::ProductionStagedLiveValidatorSetEpochTransitionApplication.is_source_test());
    assert_eq!(Knd::default().tag(), "disabled");
}

#[test]
fn config_default_is_disabled_and_source_test_is_well_formed() {
    assert_eq!(Cfg::default().kind, Knd::Disabled);
    assert!(Cfg::source_test().is_well_formed());
}

#[test]
fn staged_kind_from_authorization_kind_mapping() {
    use LiveValidatorSetApplicationAuthorizationKind as AK;
    let pairs = [
        (AK::AuthorizeApplyNoOpAlreadySynchronized, SK::StageApplyNoOpAlreadySynchronized),
        (AK::AuthorizeApplyValidatorAdd, SK::StageApplyValidatorAdd),
        (AK::AuthorizeApplyValidatorRemove, SK::StageApplyValidatorRemove),
        (AK::AuthorizeApplyValidatorMetadataUpdate, SK::StageApplyValidatorMetadataUpdate),
        (AK::AuthorizeApplyValidatorIdentityRotation, SK::StageApplyValidatorIdentityRotation),
        (AK::AuthorizeApplyValidatorRetirement, SK::StageApplyValidatorRetirement),
        (AK::AuthorizeApplyEmergencyValidatorRemoval, SK::StageApplyEmergencyValidatorRemoval),
        (AK::AuthorizeApplyAuthoritySetSynchronization, SK::StageApplyAuthoritySetSynchronization),
        (AK::AuthorizeApplyBulkValidatorSetRotation, SK::StageApplyBulkValidatorSetRotation),
    ];
    for (ak, expected) in pairs {
        assert_eq!(SK::from_authorization_kind(ak), expected);
    }
    assert!(SK::from_authorization_kind(AK::UnsupportedAuthorization).is_unsupported());
}

#[test]
fn standalone_source_test_invariant_helpers() {
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_default_is_disabled());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_is_source_test_not_release_binary_evidence());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_mainnet_refused());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_is_non_mutating());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_never_falls_back());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_no_default_runtime_wiring());
    assert!(production_staged_live_validator_set_epoch_transition_application_executor_requires_verified_application_decision());
}
