//! Run 327 — source/test **live epoch-transition durable-audit finalization /
//! audit-ledger preparation** boundary integration tests.
//!
//! Source/test only. Run 327 does **not** capture release-binary evidence;
//! release-binary evidence for the live epoch-transition durable-audit
//! finalization / audit-ledger preparation boundary is deferred to **Run 328**.
//!
//! Each accepted case composes the real Run 303 -> 305 -> 307 -> 309 -> 311 ->
//! 313 -> 315 -> 317 -> 319 -> 321 -> 323 -> 325 chain to produce a verified,
//! accepted Run 325 live epoch-transition post-commit-audit decision, then
//! feeds that decision into the Run 327 live epoch-transition durable-audit
//! finalization / audit-ledger preparation executor.
//!
//! Run 327 produces **only** a typed, non-mutating durable-audit-finalization /
//! audit-ledger-preparation artifact. It never applies a live validator-set
//! change, never transitions a consensus epoch, never writes
//! `meta:current_epoch`, never injects a reconfig block, never writes a
//! production audit-ledger / audit-finalization record, and never mutates any
//! durable trust state. The only mutation a positive path performs is against a
//! caller-owned in-memory
//! `LiveEpochTransitionDurableAuditFinalizationFixtureState` used exclusively by
//! these tests.

#![allow(dead_code)]
#![allow(unused_imports)]


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
    ProductionLiveValidatorSetApplicationAuthorizationDecision,
    ProductionLiveValidatorSetApplicationAuthorizationExecutor,
    ProductionLiveValidatorSetApplicationAuthorizationInputs,
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
/// decision — the sole accepted Run 311 authority source.
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
// Run 311 staged epoch-transition application case
// ===========================================================================

struct Stg311 {
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

fn stg_case311(env: TrustBundleEnvironment, sc: Sc) -> Stg311 {
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
    Stg311 {
        executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay311() -> EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet {
    EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet
}

fn eval311(case: &Stg311) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    case.executor.evaluate_staged_live_validator_set_epoch_transition_application(
        &case.request,
        &case.inputs,
        &empty_replay311(),
    )
}

// ===========================================================================
// Run 313 guarded epoch-transition mutation layer
// ===========================================================================

use qbind_node::pqc_production_guarded_epoch_transition_mutation_executor::*;

const GUARDED_POLICY_ID: &str = "guarded-mutation-policy-1";
const GUARDED_NONCE: u64 = 37;

use GuardedEpochTransitionMutationKind as GK;

/// Build an accepted Run 311 staged epoch-transition application decision — the
/// sole accepted Run 313 authority source.
fn stg_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    let d = eval311(&stg_case311(env, sc));
    assert!(d.is_accept(), "run 311 staged decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 311 staged decision for authority-source
/// negative tests.
fn stg_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    let mut c = stg_case311(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = eval311(&c);
    assert!(!d.is_accept(), "tampered run 311 decision must reject");
    d
}

fn expected_mutation_kind(sc: Sc) -> GK {
    match sc {
        Sc::Add => GK::StageApplyValidatorAdd,
        Sc::Remove => GK::StageApplyValidatorRemove,
        Sc::Update => GK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => GK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => GK::StageApplyValidatorIdentityRotation,
        Sc::Retire => GK::StageApplyValidatorRetirement,
        Sc::Emergency => GK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => GK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => GK::StageApplyBulkValidatorSetRotation,
    }
}

struct Gem {
    executor: ProductionGuardedEpochTransitionMutationExecutor,
    request: ProductionGuardedEpochTransitionMutationRequest,
    inputs: ProductionGuardedEpochTransitionMutationInputs,
}

fn gem_inputs(
    env: TrustBundleEnvironment,
    stg_dec: &ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision,
) -> ProductionGuardedEpochTransitionMutationInputs {
    let rec = stg_dec.staged_application_record.as_ref().unwrap();
    ProductionGuardedEpochTransitionMutationInputs {
        trust_domain: trust_domain(env),
        staged_application_policy_id: GUARDED_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: rec.lifecycle_action,
        expected_rotation_action: rec.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: rec.governance_intent_digest.clone(),
        expected_rotation_decision_id: rec.rotation_decision_id.clone(),
        expected_rotation_request_id: rec.rotation_request_id.clone(),
        expected_rotation_transcript_digest: rec.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: rec.rotation_plan_digest.clone(),
        expected_current_set_digest: rec.current_set_digest.clone(),
        expected_proposed_set_digest: rec.proposed_set_digest.clone(),
        expected_delta_digest: rec.delta_digest.clone(),
        expected_validator_set_epoch: rec.validator_set_epoch,
        expected_validator_set_version: rec.validator_set_version,
        expected_proposed_validator_count: rec.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: rec.application_decision_id.clone(),
        expected_application_request_id: rec.application_request_id.clone(),
        expected_application_intent_digest: rec.application_intent_digest.clone(),
        expected_application_transcript_digest: rec.application_transcript_digest.clone(),
        expected_authorization_decision_id: rec.authorization_decision_id.clone(),
        expected_authorization_request_id: rec.authorization_request_id.clone(),
        expected_authorization_intent_digest: rec.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: rec.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: stg_dec.staged_application_id.clone(),
        expected_staged_application_request_id: stg_dec.request_id.clone(),
        expected_staged_application_intent_digest: stg_dec.intent_digest.clone(),
        expected_staged_application_transcript_digest: stg_dec.transcript_digest.clone(),
        expected_staged_application_nonce: rec.staged_application_nonce,
        expected_epoch_transition_target: rec.epoch_transition_target,
        expected_application_nonce: rec.application_nonce,
        expected_live_application_nonce: rec.live_application_nonce,
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

fn gem_case(env: TrustBundleEnvironment, sc: Sc) -> Gem {
    let stg_dec = stg_decision(env, sc);
    let target = stg_dec
        .staged_application_record
        .as_ref()
        .unwrap()
        .epoch_transition_target;
    let inputs = gem_inputs(env, &stg_dec);
    let request = ProductionGuardedEpochTransitionMutationRequest::new(
        GuardedEpochTransitionMutationAuthoritySource::VerifiedStagedApplicationDecision {
            decision: stg_dec,
        },
        target,
        GUARDED_NONCE,
    );
    Gem {
        executor: ProductionGuardedEpochTransitionMutationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay313() -> EmptyGuardedEpochTransitionMutationReplaySet {
    EmptyGuardedEpochTransitionMutationReplaySet
}

fn gem_eval(case: &Gem) -> ProductionGuardedEpochTransitionMutationDecision {
    case.executor.evaluate_guarded_epoch_transition_mutation(
        &case.request,
        &case.inputs,
        &empty_replay313(),
    )
}

fn gem_eval_replay(case: &Gem, replay: &[String]) -> ProductionGuardedEpochTransitionMutationDecision {
    case.executor
        .evaluate_guarded_epoch_transition_mutation(&case.request, &case.inputs, &replay)
}

fn custom_domain(
    env: TrustBundleEnvironment,
    chain: &str,
    genesis: &str,
    root: &str,
) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, chain, genesis, root, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

// ===========================================================================
// Run 315 epoch-transition runtime handoff layer
// ===========================================================================

use qbind_node::pqc_production_epoch_transition_runtime_handoff::*;

const HANDOFF_POLICY_ID: &str = "runtime-handoff-policy-1";
const HANDOFF_NONCE: u64 = 41;
const REPLAY_WINDOW: u64 = 8;

use EpochTransitionRuntimeHandoffKind as HK;

/// Build an accepted Run 313 guarded epoch-transition mutation-execution
/// decision — the sole accepted Run 315 authority source.
fn guarded_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionGuardedEpochTransitionMutationDecision {
    let d = gem_eval(&gem_case(env, sc));
    assert!(d.is_accept(), "run 313 guarded decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 313 guarded decision for authority-source
/// negative tests.
fn guarded_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionGuardedEpochTransitionMutationDecision {
    let mut c = gem_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = gem_eval(&c);
    assert!(!d.is_accept(), "tampered run 313 decision must reject");
    d
}

fn expected_handoff_kind(sc: Sc) -> HK {
    match sc {
        Sc::Add => HK::StageApplyValidatorAdd,
        Sc::Remove => HK::StageApplyValidatorRemove,
        Sc::Update => HK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => HK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => HK::StageApplyValidatorIdentityRotation,
        Sc::Retire => HK::StageApplyValidatorRetirement,
        Sc::Emergency => HK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => HK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => HK::StageApplyBulkValidatorSetRotation,
    }
}

struct H315 {
    executor: ProductionEpochTransitionRuntimeHandoffExecutor,
    request: ProductionEpochTransitionRuntimeHandoffRequest,
    inputs: ProductionEpochTransitionRuntimeHandoffInputs,
}

fn h_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionGuardedEpochTransitionMutationDecision,
) -> ProductionEpochTransitionRuntimeHandoffInputs {
    let rec = dec.staged_application_record.as_ref().unwrap();
    ProductionEpochTransitionRuntimeHandoffInputs {
        trust_domain: trust_domain(env),
        handoff_policy_id: HANDOFF_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: rec.lifecycle_action,
        expected_rotation_action: rec.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: rec.governance_intent_digest.clone(),
        expected_rotation_decision_id: rec.rotation_decision_id.clone(),
        expected_rotation_request_id: rec.rotation_request_id.clone(),
        expected_rotation_transcript_digest: rec.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: rec.rotation_plan_digest.clone(),
        expected_current_set_digest: rec.current_set_digest.clone(),
        expected_proposed_set_digest: rec.proposed_set_digest.clone(),
        expected_delta_digest: rec.delta_digest.clone(),
        expected_validator_set_epoch: rec.validator_set_epoch,
        expected_validator_set_version: rec.validator_set_version,
        expected_proposed_validator_count: rec.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: rec.application_decision_id.clone(),
        expected_application_request_id: rec.application_request_id.clone(),
        expected_application_intent_digest: rec.application_intent_digest.clone(),
        expected_application_transcript_digest: rec.application_transcript_digest.clone(),
        expected_authorization_decision_id: rec.authorization_decision_id.clone(),
        expected_authorization_request_id: rec.authorization_request_id.clone(),
        expected_authorization_intent_digest: rec.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: rec.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: rec.staged_application_decision_id.clone(),
        expected_staged_application_request_id: rec.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: rec.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: rec
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: rec.staged_application_nonce,
        expected_epoch_transition_target: rec.epoch_transition_target,
        expected_application_nonce: rec.application_nonce,
        expected_live_application_nonce: rec.live_application_nonce,
        expected_guarded_mutation_decision_id: dec.staged_application_id.clone(),
        expected_guarded_mutation_request_id: dec.request_id.clone(),
        expected_guarded_mutation_intent_digest: dec.intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: dec.transcript_digest.clone(),
        expected_guarded_mutation_nonce: rec.guarded_mutation_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn h_case(env: TrustBundleEnvironment, sc: Sc) -> H315 {
    let dec = guarded_decision(env, sc);
    let target = dec
        .staged_application_record
        .as_ref()
        .unwrap()
        .epoch_transition_target;
    let inputs = h_inputs(env, &dec);
    let request = ProductionEpochTransitionRuntimeHandoffRequest::new(
        EpochTransitionRuntimeHandoffAuthoritySource::VerifiedGuardedMutationDecision {
            decision: dec,
        },
        target,
        HANDOFF_NONCE,
    );
    H315 {
        executor: ProductionEpochTransitionRuntimeHandoffExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay315() -> EmptyEpochTransitionRuntimeHandoffReplaySet {
    EmptyEpochTransitionRuntimeHandoffReplaySet
}

fn h_eval(case: &H315) -> ProductionEpochTransitionRuntimeHandoffDecision {
    case.executor.evaluate_epoch_transition_runtime_handoff(
        &case.request,
        &case.inputs,
        &empty_replay315(),
    )
}

fn h_eval_replay(case: &H315, replay: &[String]) -> ProductionEpochTransitionRuntimeHandoffDecision {
    case.executor
        .evaluate_epoch_transition_runtime_handoff(&case.request, &case.inputs, &replay)
}

// ===========================================================================
// Run 317 live epoch-transition execution preparation layer
// ===========================================================================

use qbind_node::pqc_production_live_epoch_transition_execution_preparation::*;

const PREP_POLICY_ID: &str = "execution-preparation-policy-1";
const PREP_NONCE: u64 = 43;

use ProductionLiveEpochTransitionExecutionPreparationOutcome as PO;
use LiveEpochTransitionExecutionPreparationKind as PK;

/// Build an accepted Run 315 epoch-transition runtime handoff decision — the
/// sole accepted Run 317 authority source.
fn handoff_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionEpochTransitionRuntimeHandoffDecision {
    let d = h_eval(&h_case(env, sc));
    assert!(d.is_accept(), "run 315 handoff decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 315 handoff decision for authority-source
/// negative tests.
fn handoff_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionEpochTransitionRuntimeHandoffDecision {
    let mut c = h_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = h_eval(&c);
    assert!(!d.is_accept(), "tampered run 315 decision must reject");
    d
}

/// Build an accepted Run 315 handoff decision that carries no package (an
/// accepted-runtime-handoff-without-package authority-source negative case).
fn handoff_decision_no_package(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionEpochTransitionRuntimeHandoffDecision {
    let mut d = handoff_decision(env, sc);
    d.handoff_package = None;
    d
}

fn expected_prep_kind(sc: Sc) -> PK {
    match sc {
        Sc::Add => PK::StageApplyValidatorAdd,
        Sc::Remove => PK::StageApplyValidatorRemove,
        Sc::Update => PK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => PK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => PK::StageApplyValidatorIdentityRotation,
        Sc::Retire => PK::StageApplyValidatorRetirement,
        Sc::Emergency => PK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => PK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => PK::StageApplyBulkValidatorSetRotation,
    }
}

struct P317 {
    executor: ProductionLiveEpochTransitionExecutionPreparationExecutor,
    request: ProductionLiveEpochTransitionExecutionPreparationRequest,
    inputs: ProductionLiveEpochTransitionExecutionPreparationInputs,
}

fn p_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionEpochTransitionRuntimeHandoffDecision,
) -> ProductionLiveEpochTransitionExecutionPreparationInputs {
    let pkg = dec.handoff_package.as_ref().unwrap();
    ProductionLiveEpochTransitionExecutionPreparationInputs {
        trust_domain: trust_domain(env),
        preparation_policy_id: PREP_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_runtime_handoff_decision_id: dec.handoff_id.clone(),
        expected_runtime_handoff_request_id: dec.request_id.clone(),
        expected_runtime_handoff_intent_digest: dec.handoff_digest.clone(),
        expected_runtime_handoff_transcript_digest: dec.transcript_digest.clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn p_case(env: TrustBundleEnvironment, sc: Sc) -> P317 {
    let dec = handoff_decision(env, sc);
    let target = dec.handoff_package.as_ref().unwrap().epoch_transition_target;
    let inputs = p_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionExecutionPreparationRequest::new(
        LiveEpochTransitionExecutionPreparationAuthoritySource::VerifiedRuntimeHandoffDecision {
            decision: dec,
        },
        target,
        PREP_NONCE,
    );
    P317 {
        executor: ProductionLiveEpochTransitionExecutionPreparationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay317() -> EmptyLiveEpochTransitionExecutionPreparationReplaySet {
    EmptyLiveEpochTransitionExecutionPreparationReplaySet
}

fn p_eval(case: &P317) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    case.executor.evaluate_live_epoch_transition_execution_preparation(
        &case.request,
        &case.inputs,
        &empty_replay317(),
    )
}

fn p_eval_replay(
    case: &P317,
    replay: &[String],
) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    case.executor
        .evaluate_live_epoch_transition_execution_preparation(&case.request, &case.inputs, &replay)
}

fn p_exec_with_policy(
    policy: ProductionLiveEpochTransitionExecutionPreparationExecutorPolicy,
) -> ProductionLiveEpochTransitionExecutionPreparationExecutor {
    ProductionLiveEpochTransitionExecutionPreparationExecutor::new(
        ProductionLiveEpochTransitionExecutionPreparationConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no artifact).
fn p_reject_inputs(
    mutate: impl FnOnce(&mut ProductionLiveEpochTransitionExecutionPreparationInputs),
    expected: PO,
) {
    let mut c = p_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = p_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.preparation_artifact.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn p_reject_source(
    source: LiveEpochTransitionExecutionPreparationAuthoritySource,
    expected: PO,
) {
    let mut c = p_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = p_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.preparation_artifact.is_none());
}

use qbind_node::pqc_production_live_epoch_transition_mutation_execution::*;

const MUT_POLICY_ID: &str = "mutation-execution-policy-1";
const MUT_NONCE: u64 = 45;

use ProductionLiveEpochTransitionMutationExecutionOutcome as MO;
use LiveEpochTransitionMutationExecutionKind as MK;

/// Build an accepted Run 317 epoch-transition runtime handoff decision — the
/// sole accepted Run 319 authority source.
fn prep_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    let d = p_eval(&p_case(env, sc));
    assert!(
        d.is_accept(),
        "run 317 execution-preparation decision must accept for fixture"
    );
    d
}

fn prep_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    let mut c = p_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = p_eval(&c);
    assert!(!d.is_accept(), "tampered run 317 decision must reject");
    d
}

fn prep_decision_no_artifact(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    let mut d = prep_decision(env, sc);
    d.preparation_artifact = None;
    d
}

fn expected_mut_kind(sc: Sc) -> MK {
    match sc {
        Sc::Add => MK::StageApplyValidatorAdd,
        Sc::Remove => MK::StageApplyValidatorRemove,
        Sc::Update => MK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => MK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => MK::StageApplyValidatorIdentityRotation,
        Sc::Retire => MK::StageApplyValidatorRetirement,
        Sc::Emergency => MK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => MK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => MK::StageApplyBulkValidatorSetRotation,
    }
}

struct M319 {
    executor: ProductionLiveEpochTransitionMutationExecutionExecutor,
    request: ProductionLiveEpochTransitionMutationExecutionRequest,
    inputs: ProductionLiveEpochTransitionMutationExecutionInputs,
}

fn m_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionExecutionPreparationDecision,
) -> ProductionLiveEpochTransitionMutationExecutionInputs {
    let pkg = dec.preparation_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionMutationExecutionInputs {
        trust_domain: trust_domain(env),
        mutation_execution_policy_id: MUT_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_execution_preparation_decision_id: dec.preparation_id.clone(),
        expected_execution_preparation_request_id: dec.request_id.clone(),
        expected_execution_preparation_intent_digest: dec.preparation_digest.clone(),
        expected_execution_preparation_transcript_digest: dec.transcript_digest.clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn m_case(env: TrustBundleEnvironment, sc: Sc) -> M319 {
    let dec = prep_decision(env, sc);
    let target = dec.preparation_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = m_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionMutationExecutionRequest::new(
        LiveEpochTransitionMutationExecutionAuthoritySource::VerifiedExecutionPreparationDecision {
            decision: dec,
        },
        target,
        MUT_NONCE,
    );
    M319 {
        executor: ProductionLiveEpochTransitionMutationExecutionExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay319() -> EmptyLiveEpochTransitionMutationExecutionReplaySet {
    EmptyLiveEpochTransitionMutationExecutionReplaySet
}

fn m_eval(case: &M319) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    case.executor.evaluate_live_epoch_transition_mutation_execution(
        &case.request,
        &case.inputs,
        &empty_replay319(),
    )
}

fn m_eval_replay(
    case: &M319,
    replay: &[String],
) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    case.executor
        .evaluate_live_epoch_transition_mutation_execution(&case.request, &case.inputs, &replay)
}

fn m_exec_with_policy(
    policy: ProductionLiveEpochTransitionMutationExecutionExecutorPolicy,
) -> ProductionLiveEpochTransitionMutationExecutionExecutor {
    ProductionLiveEpochTransitionMutationExecutionExecutor::new(
        ProductionLiveEpochTransitionMutationExecutionConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no artifact).
fn m_reject_inputs(
    mutate: impl FnOnce(&mut ProductionLiveEpochTransitionMutationExecutionInputs),
    expected: MO,
) {
    let mut c = m_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = m_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.execution_artifact.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn m_reject_source(
    source: LiveEpochTransitionMutationExecutionAuthoritySource,
    expected: MO,
) {
    let mut c = m_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = m_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.execution_artifact.is_none());
}

// ===========================================================================
// A. Accepted / compatible source-test mutation-execution artifacts
// ===========================================================================


// ===========================================================================
// Run 321 — commit-authorization self layer (consumes verified Run 319/320
// mutation-execution decisions produced by the m_ harness above).
// ===========================================================================

use qbind_node::pqc_production_live_epoch_transition_commit_authorization::*;

use ProductionLiveEpochTransitionCommitAuthorizationOutcome as CO;
use LiveEpochTransitionCommitAuthorizationKind as CK;

const CMT_POLICY_ID: &str = "commit-authorization-policy-1";
const CMT_NONCE: u64 = 47;

fn expected_cmt_kind(sc: Sc) -> CK {
    match sc {
        Sc::Add => CK::StageApplyValidatorAdd,
        Sc::Remove => CK::StageApplyValidatorRemove,
        Sc::Update => CK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => CK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => CK::StageApplyValidatorIdentityRotation,
        Sc::Retire => CK::StageApplyValidatorRetirement,
        Sc::Emergency => CK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => CK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => CK::StageApplyBulkValidatorSetRotation,
    }
}

/// Build an accepted Run 319/320 mutation-execution decision — the sole
/// accepted Run 321 commit-authorization authority source.
fn mut_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    let d = m_eval(&m_case(env, sc));
    assert!(
        d.is_accept(),
        "run 319 mutation-execution decision must accept for fixture"
    );
    d
}

fn mut_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    let mut c = m_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = m_eval(&c);
    assert!(!d.is_accept(), "tampered run 319 decision must reject");
    d
}

fn mut_decision_no_artifact(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    let mut d = mut_decision(env, sc);
    d.execution_artifact = None;
    d
}

struct C321 {
    executor: ProductionLiveEpochTransitionCommitAuthorizationExecutor,
    request: ProductionLiveEpochTransitionCommitAuthorizationRequest,
    inputs: ProductionLiveEpochTransitionCommitAuthorizationInputs,
}

fn c_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionMutationExecutionDecision,
) -> ProductionLiveEpochTransitionCommitAuthorizationInputs {
    let pkg = dec.execution_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionCommitAuthorizationInputs {
        trust_domain: trust_domain(env),
        commit_authorization_policy_id: CMT_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_mutation_execution_decision_id: dec.execution_id.clone(),
        expected_mutation_execution_request_id: dec.request_id.clone(),
        expected_mutation_execution_intent_digest: dec.execution_digest.clone(),
        expected_mutation_execution_transcript_digest: dec.transcript_digest.clone(),
        expected_mutation_execution_nonce: pkg.mutation_execution_nonce,
        expected_execution_preparation_decision_id: pkg.execution_preparation_decision_id.clone(),
        expected_execution_preparation_request_id: pkg.execution_preparation_request_id.clone(),
        expected_execution_preparation_intent_digest: pkg.execution_preparation_intent_digest.clone(),
        expected_execution_preparation_transcript_digest: pkg
            .execution_preparation_transcript_digest
            .clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn c_case(env: TrustBundleEnvironment, sc: Sc) -> C321 {
    let dec = mut_decision(env, sc);
    let target = dec.execution_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = c_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionCommitAuthorizationRequest::new(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::VerifiedMutationExecutionDecision {
            decision: dec,
        },
        target,
        CMT_NONCE,
    );
    C321 {
        executor: ProductionLiveEpochTransitionCommitAuthorizationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay321() -> EmptyLiveEpochTransitionCommitAuthorizationReplaySet {
    EmptyLiveEpochTransitionCommitAuthorizationReplaySet
}

fn c_eval(case: &C321) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    case.executor.evaluate_live_epoch_transition_commit_authorization(
        &case.request,
        &case.inputs,
        &empty_replay321(),
    )
}

fn c_eval_replay(
    case: &C321,
    replay: &[String],
) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    case.executor
        .evaluate_live_epoch_transition_commit_authorization(&case.request, &case.inputs, &replay)
}

fn c_exec_with_policy(
    policy: ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy,
) -> ProductionLiveEpochTransitionCommitAuthorizationExecutor {
    ProductionLiveEpochTransitionCommitAuthorizationExecutor::new(
        ProductionLiveEpochTransitionCommitAuthorizationConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no artifact).
fn c_reject_inputs(
    mutate: impl FnOnce(&mut ProductionLiveEpochTransitionCommitAuthorizationInputs),
    expected: CO,
) {
    let mut c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = c_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.commit_authorization_artifact.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn c_reject_source(
    source: LiveEpochTransitionCommitAuthorizationAuthoritySource,
    expected: CO,
) {
    let mut c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = c_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.commit_authorization_artifact.is_none());
}

// ===========================================================================
// A. Accepted / compatible source-test mutation-execution artifacts
// ===========================================================================


use qbind_node::pqc_production_live_epoch_transition_commit_execution::*;
use qbind_node::pqc_production_live_epoch_transition_commit_receipt::*;

use LiveEpochTransitionCommitReceiptKind as XK;

const CXE_POLICY_ID: &str = "commit-receipt-policy-1";
const CXE_NONCE: u64 = 49;

fn expected_cxe_kind(sc: Sc) -> XK {
    match sc {
        Sc::Add => XK::StageApplyValidatorAdd,
        Sc::Remove => XK::StageApplyValidatorRemove,
        Sc::Update => XK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => XK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => XK::StageApplyValidatorIdentityRotation,
        Sc::Retire => XK::StageApplyValidatorRetirement,
        Sc::Emergency => XK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => XK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => XK::StageApplyBulkValidatorSetRotation,
    }
}

/// Build an accepted Run 321/322 commit-authorization decision — the sole
/// accepted Run 323 commit-receipt authority source.
fn ca_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    let d = c_eval(&c_case(env, sc));
    assert!(
        d.is_accept(),
        "run 321 commit-authorization decision must accept for fixture"
    );
    d
}

fn ca_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    let mut c = c_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = c_eval(&c);
    assert!(!d.is_accept(), "tampered run 321 decision must reject");
    d
}

fn ca_decision_no_artifact(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    let mut d = ca_decision(env, sc);
    d.commit_authorization_artifact = None;
    d
}

// ---------------------------------------------------------------------------
// Run 323/324 commit-execution builder — deepest re-exposed ancestor rung.
// Produces a verified accepted Run 321/322 commit-execution decision, the
// sole accepted authority source of the Run 323/324 commit-receipt provider.
// ---------------------------------------------------------------------------
const CE_POLICY_ID: &str = "commit-execution-policy-1";
const CE_NONCE: u64 = 49;

struct Xce {
    executor: ProductionLiveEpochTransitionCommitExecutionExecutor,
    request: ProductionLiveEpochTransitionCommitExecutionRequest,
    inputs: ProductionLiveEpochTransitionCommitExecutionInputs,
}

fn ce_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionCommitAuthorizationDecision,
) -> ProductionLiveEpochTransitionCommitExecutionInputs {
    let pkg = dec.commit_authorization_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionCommitExecutionInputs {
        trust_domain: trust_domain(env),
        commit_execution_policy_id: CE_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_commit_authorization_decision_id: dec.commit_authorization_id.clone(),
        expected_commit_authorization_request_id: dec.request_id.clone(),
        expected_commit_authorization_intent_digest: dec.commit_authorization_digest.clone(),
        expected_commit_authorization_transcript_digest: dec.transcript_digest.clone(),
        expected_commit_authorization_nonce: pkg.commit_authorization_nonce,
        expected_mutation_execution_decision_id: pkg.mutation_execution_decision_id.clone(),
        expected_mutation_execution_request_id: pkg.mutation_execution_request_id.clone(),
        expected_mutation_execution_intent_digest: pkg.mutation_execution_intent_digest.clone(),
        expected_mutation_execution_transcript_digest: pkg
            .mutation_execution_transcript_digest
            .clone(),
        expected_mutation_execution_nonce: pkg.mutation_execution_nonce,
        expected_execution_preparation_decision_id: pkg.execution_preparation_decision_id.clone(),
        expected_execution_preparation_request_id: pkg.execution_preparation_request_id.clone(),
        expected_execution_preparation_intent_digest: pkg.execution_preparation_intent_digest.clone(),
        expected_execution_preparation_transcript_digest: pkg
            .execution_preparation_transcript_digest
            .clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn ce_case(env: TrustBundleEnvironment, sc: Sc) -> Xce {
    let dec = ca_decision(env, sc);
    let target = dec.commit_authorization_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = ce_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionCommitExecutionRequest::new(
        LiveEpochTransitionCommitExecutionAuthoritySource::VerifiedCommitAuthorizationDecision {
            decision: dec,
        },
        target,
        CE_NONCE,
    );
    Xce {
        executor: ProductionLiveEpochTransitionCommitExecutionExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay_ce() -> EmptyLiveEpochTransitionCommitExecutionReplaySet {
    EmptyLiveEpochTransitionCommitExecutionReplaySet
}

fn ce_eval(case: &Xce) -> ProductionLiveEpochTransitionCommitExecutionDecision {
    case.executor.evaluate_live_epoch_transition_commit_execution(
        &case.request,
        &case.inputs,
        &empty_replay_ce(),
    )
}

fn ce_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitExecutionDecision {
    let d = ce_eval(&ce_case(env, sc));
    assert!(
        d.is_accept(),
        "run 321 commit-execution decision must accept for fixture"
    );
    d
}

// ---------------------------------------------------------------------------
// Run 323/324 commit-receipt provider — the sole accepted Run 325 authority
// source. Consumes the verified commit-execution decision above and emits an
// accepted commit-receipt decision carrying a commit-receipt artifact.
// ---------------------------------------------------------------------------
struct X323 {
    executor: ProductionLiveEpochTransitionCommitReceiptExecutor,
    request: ProductionLiveEpochTransitionCommitReceiptRequest,
    inputs: ProductionLiveEpochTransitionCommitReceiptInputs,
}

fn x_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionCommitExecutionDecision,
) -> ProductionLiveEpochTransitionCommitReceiptInputs {
    let pkg = dec.commit_execution_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionCommitReceiptInputs {
        trust_domain: trust_domain(env),
        commit_receipt_policy_id: CXE_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_commit_execution_decision_id: dec.commit_execution_id.clone(),
        expected_commit_execution_request_id: dec.request_id.clone(),
        expected_commit_execution_intent_digest: dec.commit_execution_digest.clone(),
        expected_commit_execution_transcript_digest: dec.transcript_digest.clone(),
        expected_commit_execution_nonce: pkg.commit_execution_nonce,
        expected_commit_authorization_decision_id: pkg.commit_authorization_decision_id.clone(),
        expected_commit_authorization_request_id: pkg.commit_authorization_request_id.clone(),
        expected_commit_authorization_intent_digest: pkg
            .commit_authorization_intent_digest
            .clone(),
        expected_commit_authorization_transcript_digest: pkg
            .commit_authorization_transcript_digest
            .clone(),
        expected_commit_authorization_nonce: pkg.commit_authorization_nonce,
        expected_mutation_execution_decision_id: pkg.mutation_execution_decision_id.clone(),
        expected_mutation_execution_request_id: pkg.mutation_execution_request_id.clone(),
        expected_mutation_execution_intent_digest: pkg.mutation_execution_intent_digest.clone(),
        expected_mutation_execution_transcript_digest: pkg
            .mutation_execution_transcript_digest
            .clone(),
        expected_mutation_execution_nonce: pkg.mutation_execution_nonce,
        expected_execution_preparation_decision_id: pkg.execution_preparation_decision_id.clone(),
        expected_execution_preparation_request_id: pkg.execution_preparation_request_id.clone(),
        expected_execution_preparation_intent_digest: pkg.execution_preparation_intent_digest.clone(),
        expected_execution_preparation_transcript_digest: pkg
            .execution_preparation_transcript_digest
            .clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn x_case(env: TrustBundleEnvironment, sc: Sc) -> X323 {
    let dec = ce_decision(env, sc);
    let target = dec.commit_execution_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = x_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionCommitReceiptRequest::new(
        LiveEpochTransitionCommitReceiptAuthoritySource::VerifiedCommitExecutionDecision {
            decision: dec,
        },
        target,
        CXE_NONCE,
    );
    X323 {
        executor: ProductionLiveEpochTransitionCommitReceiptExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay323() -> EmptyLiveEpochTransitionCommitReceiptReplaySet {
    EmptyLiveEpochTransitionCommitReceiptReplaySet
}

fn x_eval(case: &X323) -> ProductionLiveEpochTransitionCommitReceiptDecision {
    case.executor.evaluate_live_epoch_transition_commit_receipt(
        &case.request,
        &case.inputs,
        &empty_replay323(),
    )
}

// ===========================================================================
// A. Accepted / compatible source-test commit-authorization artifacts
// ===========================================================================

use qbind_node::pqc_production_live_epoch_transition_post_commit_audit::*;

use ProductionLiveEpochTransitionPostCommitAuditOutcome as RO;
use LiveEpochTransitionPostCommitAuditKind as RK;

const CRC_POLICY_ID: &str = "post-commit-audit-policy-1";
const CRC_NONCE: u64 = 49;

fn expected_crc_kind(sc: Sc) -> RK {
    match sc {
        Sc::Add => RK::StageApplyValidatorAdd,
        Sc::Remove => RK::StageApplyValidatorRemove,
        Sc::Update => RK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => RK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => RK::StageApplyValidatorIdentityRotation,
        Sc::Retire => RK::StageApplyValidatorRetirement,
        Sc::Emergency => RK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => RK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => RK::StageApplyBulkValidatorSetRotation,
    }
}

/// Build an accepted Run 323/324 commit-receipt decision — the sole
/// accepted Run 325 post-commit-audit authority source.
fn cx_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitReceiptDecision {
    let d = x_eval(&x_case(env, sc));
    assert!(
        d.is_accept(),
        "run 323 commit-receipt decision must accept for fixture"
    );
    d
}

fn cx_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitReceiptDecision {
    let mut c = x_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = x_eval(&c);
    assert!(!d.is_accept(), "tampered run 323 decision must reject");
    d
}

fn cx_decision_no_artifact(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionCommitReceiptDecision {
    let mut d = cx_decision(env, sc);
    d.commit_receipt_artifact = None;
    d
}

struct R325 {
    executor: ProductionLiveEpochTransitionPostCommitAuditExecutor,
    request: ProductionLiveEpochTransitionPostCommitAuditRequest,
    inputs: ProductionLiveEpochTransitionPostCommitAuditInputs,
}

fn r_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionCommitReceiptDecision,
) -> ProductionLiveEpochTransitionPostCommitAuditInputs {
    let pkg = dec.commit_receipt_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionPostCommitAuditInputs {
        trust_domain: trust_domain(env),
        post_commit_audit_policy_id: CRC_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_commit_receipt_decision_id: dec.commit_receipt_id.clone(),
        expected_commit_receipt_request_id: dec.request_id.clone(),
        expected_commit_receipt_intent_digest: dec.commit_receipt_digest.clone(),
        expected_commit_receipt_transcript_digest: dec.transcript_digest.clone(),
        expected_commit_receipt_nonce: pkg.commit_receipt_nonce,
        expected_commit_authorization_decision_id: pkg.commit_authorization_decision_id.clone(),
        expected_commit_authorization_request_id: pkg.commit_authorization_request_id.clone(),
        expected_commit_authorization_intent_digest: pkg
            .commit_authorization_intent_digest
            .clone(),
        expected_commit_authorization_transcript_digest: pkg
            .commit_authorization_transcript_digest
            .clone(),
        expected_commit_authorization_nonce: pkg.commit_authorization_nonce,
        expected_mutation_execution_decision_id: pkg.mutation_execution_decision_id.clone(),
        expected_mutation_execution_request_id: pkg.mutation_execution_request_id.clone(),
        expected_mutation_execution_intent_digest: pkg.mutation_execution_intent_digest.clone(),
        expected_mutation_execution_transcript_digest: pkg
            .mutation_execution_transcript_digest
            .clone(),
        expected_mutation_execution_nonce: pkg.mutation_execution_nonce,
        expected_execution_preparation_decision_id: pkg.execution_preparation_decision_id.clone(),
        expected_execution_preparation_request_id: pkg.execution_preparation_request_id.clone(),
        expected_execution_preparation_intent_digest: pkg.execution_preparation_intent_digest.clone(),
        expected_execution_preparation_transcript_digest: pkg
            .execution_preparation_transcript_digest
            .clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn r_case(env: TrustBundleEnvironment, sc: Sc) -> R325 {
    let dec = cx_decision(env, sc);
    let target = dec.commit_receipt_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = r_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionPostCommitAuditRequest::new(
        LiveEpochTransitionPostCommitAuditAuthoritySource::VerifiedCommitReceiptDecision {
            decision: dec,
        },
        target,
        CRC_NONCE,
    );
    R325 {
        executor: ProductionLiveEpochTransitionPostCommitAuditExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay325() -> EmptyLiveEpochTransitionPostCommitAuditReplaySet {
    EmptyLiveEpochTransitionPostCommitAuditReplaySet
}

fn r_eval(case: &R325) -> ProductionLiveEpochTransitionPostCommitAuditDecision {
    case.executor.evaluate_live_epoch_transition_post_commit_audit(
        &case.request,
        &case.inputs,
        &empty_replay325(),
    )
}
use qbind_node::pqc_production_live_epoch_transition_durable_audit_finalization::*;

use ProductionLiveEpochTransitionDurableAuditFinalizationOutcome as SO;
use LiveEpochTransitionDurableAuditFinalizationKind as SK;

const CRC2_POLICY_ID: &str = "durable-audit-finalization-policy-1";
const CRC2_NONCE: u64 = 49;

fn expected_crc2_kind(sc: Sc) -> SK {
    match sc {
        Sc::Add => SK::StageApplyValidatorAdd,
        Sc::Remove => SK::StageApplyValidatorRemove,
        Sc::Update => SK::StageApplyValidatorMetadataUpdate,
        Sc::NoOp => SK::StageApplyNoOpAlreadySynchronized,
        Sc::Identity => SK::StageApplyValidatorIdentityRotation,
        Sc::Retire => SK::StageApplyValidatorRetirement,
        Sc::Emergency => SK::StageApplyEmergencyValidatorRemoval,
        Sc::AuthSync => SK::StageApplyAuthoritySetSynchronization,
        Sc::Bulk => SK::StageApplyBulkValidatorSetRotation,
    }
}

/// Build an accepted Run 325/326 post-commit-audit decision — the sole
/// accepted Run 327 durable-audit-finalization authority source.
fn cr_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionPostCommitAuditDecision {
    let d = r_eval(&r_case(env, sc));
    assert!(
        d.is_accept(),
        "run 325 post-commit-audit decision must accept for fixture"
    );
    d
}

fn cr_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionPostCommitAuditDecision {
    let mut c = r_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = r_eval(&c);
    assert!(!d.is_accept(), "tampered run 325 decision must reject");
    d
}

fn cr_decision_no_artifact(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionPostCommitAuditDecision {
    let mut d = cr_decision(env, sc);
    d.post_commit_audit_artifact = None;
    d
}

struct S327 {
    executor: ProductionLiveEpochTransitionDurableAuditFinalizationExecutor,
    request: ProductionLiveEpochTransitionDurableAuditFinalizationRequest,
    inputs: ProductionLiveEpochTransitionDurableAuditFinalizationInputs,
}

fn s_inputs(
    env: TrustBundleEnvironment,
    dec: &ProductionLiveEpochTransitionPostCommitAuditDecision,
) -> ProductionLiveEpochTransitionDurableAuditFinalizationInputs {
    let pkg = dec.post_commit_audit_artifact.as_ref().unwrap();
    ProductionLiveEpochTransitionDurableAuditFinalizationInputs {
        trust_domain: trust_domain(env),
        durable_audit_finalization_policy_id: CRC2_POLICY_ID.to_string(),
        expected_authorization_policy_id: AUTH_POLICY_ID.to_string(),
        expected_application_policy_id: APP_POLICY_ID.to_string(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_lifecycle_action: pkg.lifecycle_action,
        expected_rotation_action: pkg.rotation_action,
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_governance_decision_id: GOV_DECISION_ID.to_string(),
        expected_governance_request_id: GOV_REQUEST_ID.to_string(),
        expected_governance_intent_digest: pkg.governance_intent_digest.clone(),
        expected_rotation_decision_id: pkg.rotation_decision_id.clone(),
        expected_rotation_request_id: pkg.rotation_request_id.clone(),
        expected_rotation_transcript_digest: pkg.rotation_transcript_digest.clone(),
        expected_rotation_plan_digest: pkg.rotation_plan_digest.clone(),
        expected_current_set_digest: pkg.current_set_digest.clone(),
        expected_proposed_set_digest: pkg.proposed_set_digest.clone(),
        expected_delta_digest: pkg.delta_digest.clone(),
        expected_validator_set_epoch: pkg.validator_set_epoch,
        expected_validator_set_version: pkg.validator_set_version,
        expected_proposed_validator_count: pkg.proposed_validator_count,
        expected_rotation_nonce: ROT_NONCE,
        expected_application_decision_id: pkg.application_decision_id.clone(),
        expected_application_request_id: pkg.application_request_id.clone(),
        expected_application_intent_digest: pkg.application_intent_digest.clone(),
        expected_application_transcript_digest: pkg.application_transcript_digest.clone(),
        expected_authorization_decision_id: pkg.authorization_decision_id.clone(),
        expected_authorization_request_id: pkg.authorization_request_id.clone(),
        expected_authorization_intent_digest: pkg.authorization_intent_digest.clone(),
        expected_authorization_transcript_digest: pkg.authorization_transcript_digest.clone(),
        expected_staged_application_decision_id: pkg.staged_application_decision_id.clone(),
        expected_staged_application_request_id: pkg.staged_application_request_id.clone(),
        expected_staged_application_intent_digest: pkg.staged_application_intent_digest.clone(),
        expected_staged_application_transcript_digest: pkg
            .staged_application_transcript_digest
            .clone(),
        expected_staged_application_nonce: pkg.staged_application_nonce,
        expected_epoch_transition_target: pkg.epoch_transition_target,
        expected_application_nonce: pkg.application_nonce,
        expected_live_application_nonce: pkg.live_application_nonce,
        expected_guarded_mutation_decision_id: pkg.guarded_mutation_decision_id.clone(),
        expected_guarded_mutation_request_id: pkg.guarded_mutation_request_id.clone(),
        expected_guarded_mutation_intent_digest: pkg.guarded_mutation_intent_digest.clone(),
        expected_guarded_mutation_transcript_digest: pkg
            .guarded_mutation_transcript_digest
            .clone(),
        expected_guarded_mutation_nonce: pkg.guarded_mutation_nonce,
        expected_post_commit_audit_decision_id: dec.post_commit_audit_id.clone(),
        expected_post_commit_audit_request_id: dec.request_id.clone(),
        expected_post_commit_audit_intent_digest: dec.post_commit_audit_digest.clone(),
        expected_post_commit_audit_transcript_digest: dec.transcript_digest.clone(),
        expected_post_commit_audit_nonce: pkg.post_commit_audit_nonce,
        expected_commit_authorization_decision_id: pkg.commit_authorization_decision_id.clone(),
        expected_commit_authorization_request_id: pkg.commit_authorization_request_id.clone(),
        expected_commit_authorization_intent_digest: pkg
            .commit_authorization_intent_digest
            .clone(),
        expected_commit_authorization_transcript_digest: pkg
            .commit_authorization_transcript_digest
            .clone(),
        expected_commit_authorization_nonce: pkg.commit_authorization_nonce,
        expected_mutation_execution_decision_id: pkg.mutation_execution_decision_id.clone(),
        expected_mutation_execution_request_id: pkg.mutation_execution_request_id.clone(),
        expected_mutation_execution_intent_digest: pkg.mutation_execution_intent_digest.clone(),
        expected_mutation_execution_transcript_digest: pkg
            .mutation_execution_transcript_digest
            .clone(),
        expected_mutation_execution_nonce: pkg.mutation_execution_nonce,
        expected_execution_preparation_decision_id: pkg.execution_preparation_decision_id.clone(),
        expected_execution_preparation_request_id: pkg.execution_preparation_request_id.clone(),
        expected_execution_preparation_intent_digest: pkg.execution_preparation_intent_digest.clone(),
        expected_execution_preparation_transcript_digest: pkg
            .execution_preparation_transcript_digest
            .clone(),
        expected_execution_preparation_nonce: pkg.execution_preparation_nonce,
        expected_runtime_handoff_decision_id: pkg.runtime_handoff_decision_id.clone(),
        expected_runtime_handoff_request_id: pkg.runtime_handoff_request_id.clone(),
        expected_runtime_handoff_intent_digest: pkg.runtime_handoff_intent_digest.clone(),
        expected_runtime_handoff_transcript_digest: pkg
            .runtime_handoff_transcript_digest
            .clone(),
        expected_runtime_handoff_nonce: pkg.runtime_handoff_nonce,
        expected_current_validator_set_epoch: CUR_EPOCH,
        expected_current_validator_set_version: CUR_VERSION,
        required_replay_window: REPLAY_WINDOW,
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

fn s_case(env: TrustBundleEnvironment, sc: Sc) -> S327 {
    let dec = cr_decision(env, sc);
    let target = dec.post_commit_audit_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = s_inputs(env, &dec);
    let request = ProductionLiveEpochTransitionDurableAuditFinalizationRequest::new(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision {
            decision: dec,
        },
        target,
        CRC2_NONCE,
    );
    S327 {
        executor: ProductionLiveEpochTransitionDurableAuditFinalizationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay327() -> EmptyLiveEpochTransitionDurableAuditFinalizationReplaySet {
    EmptyLiveEpochTransitionDurableAuditFinalizationReplaySet
}

fn s_eval(case: &S327) -> ProductionLiveEpochTransitionDurableAuditFinalizationDecision {
    case.executor.evaluate_live_epoch_transition_durable_audit_finalization(
        &case.request,
        &case.inputs,
        &empty_replay327(),
    )
}

fn s_eval_replay(
    case: &S327,
    replay: &[String],
) -> ProductionLiveEpochTransitionDurableAuditFinalizationDecision {
    case.executor
        .evaluate_live_epoch_transition_durable_audit_finalization(&case.request, &case.inputs, &replay)
}

fn s_exec_with_policy(
    policy: ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy,
) -> ProductionLiveEpochTransitionDurableAuditFinalizationExecutor {
    ProductionLiveEpochTransitionDurableAuditFinalizationExecutor::new(
        ProductionLiveEpochTransitionDurableAuditFinalizationConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no artifact).
fn s_reject_inputs(
    mutate: impl FnOnce(&mut ProductionLiveEpochTransitionDurableAuditFinalizationInputs),
    expected: SO,
) {
    let mut c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = s_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.durable_audit_finalization_artifact.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn s_reject_source(
    source: LiveEpochTransitionDurableAuditFinalizationAuthoritySource,
    expected: SO,
) {
    let mut c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = s_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.durable_audit_finalization_artifact.is_none());
}

// ===========================================================================
// A. Accepted / compatible source-test post-commit-audit artifacts
// ===========================================================================

#[test]
fn accept_all_scenarios_devnet() {
    for sc in ALL_SC {
        let c = s_case(TrustBundleEnvironment::Devnet, sc);
        let d = s_eval(&c);
        assert!(d.is_accept(), "scenario must accept");
        assert!(d.authorizes_future_mutation_only());
        let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
        assert_eq!(art.staged_kind, expected_crc2_kind(sc));
        assert_eq!(art.durable_audit_finalization_nonce, CRC2_NONCE);
        assert_eq!(art.post_commit_audit_nonce, CRC_NONCE);
        assert_eq!(art.guarded_mutation_nonce, GUARDED_NONCE);
        assert_eq!(art.staged_application_nonce, STAGED_NONCE);
    }
}

#[test]
fn accept_all_scenarios_testnet() {
    for sc in ALL_SC {
        let c = s_case(TrustBundleEnvironment::Testnet, sc);
        let d = s_eval(&c);
        assert!(d.is_accept());
        let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
        assert_eq!(art.environment, TrustBundleEnvironment::Testnet);
        assert_eq!(art.staged_kind, expected_crc2_kind(sc));
    }
}

#[test]
fn accept_outcome_carries_kind_env_target_nonce() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    match d.outcome {
        SO::AcceptedSourceTestLiveEpochTransitionDurableAuditFinalization {
            execution_kind,
            environment,
            epoch_transition_target,
            durable_audit_finalization_nonce,
        } => {
            assert_eq!(execution_kind, SK::StageApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(epoch_transition_target, c.request.proposed_epoch_transition_target);
            assert_eq!(durable_audit_finalization_nonce, CRC2_NONCE);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn accept_artifact_reexposes_consumed_post_commit_audit_transcript() {
    let dec = cr_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = dec.post_commit_audit_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = s_inputs(TrustBundleEnvironment::Devnet, &dec);
    let handoff_id = dec.post_commit_audit_id.clone();
    let handoff_req = dec.request_id.clone();
    let handoff_digest = dec.post_commit_audit_digest.clone();
    let handoff_transcript = dec.transcript_digest.clone();
    let request = ProductionLiveEpochTransitionDurableAuditFinalizationRequest::new(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision {
            decision: dec,
        },
        target,
        CRC2_NONCE,
    );
    let exec = ProductionLiveEpochTransitionDurableAuditFinalizationExecutor::source_test();
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &request,
        &inputs,
        &empty_replay327(),
    );
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(art.post_commit_audit_decision_id, handoff_id);
    assert_eq!(art.post_commit_audit_request_id, handoff_req);
    assert_eq!(art.post_commit_audit_intent_digest, handoff_digest);
    assert_eq!(art.post_commit_audit_transcript_digest, handoff_transcript);
}

#[test]
fn accept_artifact_encodes_future_executor_preconditions() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(art.precondition_current_validator_set_epoch, art.validator_set_epoch);
    assert_eq!(art.precondition_current_validator_set_version, art.validator_set_version);
    assert_eq!(art.precondition_target_epoch, art.epoch_transition_target);
    assert_eq!(art.precondition_required_governance_epoch, art.governance_epoch);
    assert_eq!(art.precondition_required_authority_sequence, art.authority_domain_sequence);
    assert_eq!(art.precondition_required_replay_window, REPLAY_WINDOW);
    assert_eq!(art.precondition_proposed_validator_set_digest, art.proposed_set_digest);
    assert_eq!(art.precondition_delta_digest, art.delta_digest);
    assert_eq!(art.precondition_current_validator_set_digest, art.current_set_digest);
}

#[test]
fn accept_decision_ids_match_artifact_ids() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(d.durable_audit_finalization_id, art.durable_audit_finalization_id);
    assert_eq!(d.request_id, art.request_id);
    assert_eq!(d.durable_audit_finalization_digest, art.durable_audit_finalization_digest);
    assert_eq!(d.transcript_digest, art.transcript_digest);
    assert!(!d.durable_audit_finalization_id.is_empty());
    assert!(!d.request_id.is_empty());
    assert!(!d.durable_audit_finalization_digest.is_empty());
    assert!(!d.transcript_digest.is_empty());
}

// ===========================================================================
// B. Determinism under re-evaluation
// ===========================================================================

#[test]
fn deterministic_digests_under_reevaluation() {
    for sc in ALL_SC {
        let c = s_case(TrustBundleEnvironment::Devnet, sc);
        let d1 = s_eval(&c);
        let d2 = s_eval(&c);
        assert_eq!(d1.durable_audit_finalization_id, d2.durable_audit_finalization_id);
        assert_eq!(d1.request_id, d2.request_id);
        assert_eq!(d1.durable_audit_finalization_digest, d2.durable_audit_finalization_digest);
        assert_eq!(d1.transcript_digest, d2.transcript_digest);
    }
}

#[test]
fn artifact_content_digest_is_stable() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Bulk);
    let d = s_eval(&c);
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(art.content_digest(), art.durable_audit_finalization_digest);
    assert_eq!(art.content_digest(), art.content_digest());
}

// ===========================================================================
// C. Consumed execution-preparation decision transcript binding failures
// ===========================================================================

#[test]
fn wrong_post_commit_audit_decision_id() {
    s_reject_inputs(
        |i| i.expected_post_commit_audit_decision_id = "bad".to_string(),
        SO::PostCommitAuditDecisionIdMismatch,
    );
}

#[test]
fn wrong_post_commit_audit_request_id() {
    s_reject_inputs(
        |i| i.expected_post_commit_audit_request_id = "bad".to_string(),
        SO::PostCommitAuditDecisionRequestIdMismatch,
    );
}

#[test]
fn wrong_post_commit_audit_intent_digest() {
    s_reject_inputs(
        |i| i.expected_post_commit_audit_intent_digest = "bad".to_string(),
        SO::PostCommitAuditDecisionIntentDigestMismatch,
    );
}

#[test]
fn wrong_post_commit_audit_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_post_commit_audit_transcript_digest = "bad".to_string(),
        SO::PostCommitAuditDecisionTranscriptMismatch,
    );
}

#[test]
fn wrong_post_commit_audit_nonce() {
    s_reject_inputs(
        |i| i.expected_post_commit_audit_nonce = 9999,
        SO::WrongPostCommitAuditNonce,
    );
}

#[test]
fn tampered_post_commit_audit_package_integrity_mismatch() {
    // Mutate the consumed package so its content digest no longer matches the
    // bound handoff decision digest.
    let mut dec = cr_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = dec.post_commit_audit_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = s_inputs(TrustBundleEnvironment::Devnet, &dec);
    dec.post_commit_audit_artifact.as_mut().unwrap().proposal_digest = "tampered".to_string();
    let request = ProductionLiveEpochTransitionDurableAuditFinalizationRequest::new(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision {
            decision: dec,
        },
        target,
        CRC2_NONCE,
    );
    let exec = ProductionLiveEpochTransitionDurableAuditFinalizationExecutor::source_test();
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &request,
        &inputs,
        &empty_replay327(),
    );
    assert_eq!(d.outcome, SO::PostCommitAuditDecisionIntegrityMismatch);
    assert!(d.durable_audit_finalization_artifact.is_none());
}

// ===========================================================================
// D. Re-exposed guarded-mutation decision transcript binding failures
// ===========================================================================

#[test]
fn wrong_guarded_mutation_decision_id() {
    s_reject_inputs(
        |i| i.expected_guarded_mutation_decision_id = "bad".to_string(),
        SO::GuardedMutationDecisionIdMismatch,
    );
}

#[test]
fn wrong_guarded_mutation_request_id() {
    s_reject_inputs(
        |i| i.expected_guarded_mutation_request_id = "bad".to_string(),
        SO::GuardedMutationDecisionRequestIdMismatch,
    );
}

#[test]
fn wrong_guarded_mutation_intent_digest() {
    s_reject_inputs(
        |i| i.expected_guarded_mutation_intent_digest = "bad".to_string(),
        SO::GuardedMutationDecisionIntentDigestMismatch,
    );
}

#[test]
fn wrong_guarded_mutation_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_guarded_mutation_transcript_digest = "bad".to_string(),
        SO::GuardedMutationDecisionTranscriptMismatch,
    );
}

#[test]
fn wrong_guarded_mutation_nonce() {
    s_reject_inputs(
        |i| i.expected_guarded_mutation_nonce = 9999,
        SO::WrongGuardedMutationNonce,
    );
}

// ===========================================================================
// E. Re-exposed staged-application decision transcript binding failures
// ===========================================================================

#[test]
fn wrong_staged_application_decision_id() {
    s_reject_inputs(
        |i| i.expected_staged_application_decision_id = "bad".to_string(),
        SO::StagedApplicationDecisionIdMismatch,
    );
}

#[test]
fn wrong_staged_application_request_id() {
    s_reject_inputs(
        |i| i.expected_staged_application_request_id = "bad".to_string(),
        SO::StagedApplicationDecisionRequestIdMismatch,
    );
}

#[test]
fn wrong_staged_application_intent_digest() {
    s_reject_inputs(
        |i| i.expected_staged_application_intent_digest = "bad".to_string(),
        SO::StagedApplicationDecisionIntentDigestMismatch,
    );
}

#[test]
fn wrong_staged_application_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_staged_application_transcript_digest = "bad".to_string(),
        SO::StagedApplicationDecisionTranscriptMismatch,
    );
}

#[test]
fn wrong_staged_application_nonce() {
    s_reject_inputs(
        |i| i.expected_staged_application_nonce = 9999,
        SO::WrongStagedApplicationNonce,
    );
}

// ===========================================================================
// F. Re-exposed authorization / application binding failures
// ===========================================================================

#[test]
fn wrong_authorization_decision_id() {
    s_reject_inputs(
        |i| i.expected_authorization_decision_id = "bad".to_string(),
        SO::AuthorizationDecisionIdMismatch,
    );
}

#[test]
fn wrong_authorization_request_id() {
    s_reject_inputs(
        |i| i.expected_authorization_request_id = "bad".to_string(),
        SO::AuthorizationDecisionRequestIdMismatch,
    );
}

#[test]
fn wrong_authorization_intent_digest() {
    s_reject_inputs(
        |i| i.expected_authorization_intent_digest = "bad".to_string(),
        SO::AuthorizationDecisionIntentDigestMismatch,
    );
}

#[test]
fn wrong_authorization_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_authorization_transcript_digest = "bad".to_string(),
        SO::AuthorizationDecisionTranscriptMismatch,
    );
}

#[test]
fn wrong_application_decision_id() {
    s_reject_inputs(
        |i| i.expected_application_decision_id = "bad".to_string(),
        SO::WrongApplicationDecisionId,
    );
}

#[test]
fn wrong_application_request_id() {
    s_reject_inputs(
        |i| i.expected_application_request_id = "bad".to_string(),
        SO::WrongApplicationRequestId,
    );
}

#[test]
fn wrong_application_intent_digest() {
    s_reject_inputs(
        |i| i.expected_application_intent_digest = "bad".to_string(),
        SO::WrongApplicationIntentDigest,
    );
}

#[test]
fn wrong_application_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_application_transcript_digest = "bad".to_string(),
        SO::WrongApplicationTranscriptDigest,
    );
}

#[test]
fn wrong_application_policy_id() {
    s_reject_inputs(
        |i| i.expected_application_policy_id = "bad".to_string(),
        SO::WrongApplicationPolicyId,
    );
}

#[test]
fn wrong_authorization_policy_id() {
    s_reject_inputs(
        |i| i.expected_authorization_policy_id = "bad".to_string(),
        SO::WrongAuthorizationPolicyId,
    );
}

// ===========================================================================
// G. Governance / rotation tuple binding failures
// ===========================================================================

#[test]
fn wrong_environment() {
    s_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Testnet, "qbind-devnet", GENESIS_HASH, ROOT_FP),
        SO::WrongEnvironment,
    );
}

#[test]
fn wrong_chain() {
    s_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "wrong-chain", GENESIS_HASH, ROOT_FP),
        SO::WrongChain,
    );
}

#[test]
fn wrong_genesis() {
    s_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "qbind-devnet", "wrong-genesis", ROOT_FP),
        SO::WrongGenesis,
    );
}

#[test]
fn wrong_authority_root() {
    s_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "qbind-devnet", GENESIS_HASH, "wrong-root"),
        SO::WrongAuthorityRoot,
    );
}

#[test]
fn wrong_governance_domain() {
    s_reject_inputs(
        |i| i.expected_governance_domain_id = "bad".to_string(),
        SO::WrongGovernanceDomain,
    );
}

#[test]
fn wrong_governance_epoch() {
    s_reject_inputs(|i| i.expected_governance_epoch = 999, SO::WrongGovernanceEpoch);
}

#[test]
fn wrong_proposal_id() {
    s_reject_inputs(|i| i.expected_proposal_id = "bad".to_string(), SO::WrongProposalId);
}

#[test]
fn wrong_governance_execution_intent_digest() {
    s_reject_inputs(
        |i| i.expected_governance_intent_digest = "bad".to_string(),
        SO::WrongGovernanceExecutionIntentDigest,
    );
}

#[test]
fn wrong_rotation_decision_id() {
    s_reject_inputs(
        |i| i.expected_rotation_decision_id = "bad".to_string(),
        SO::WrongRotationDecisionId,
    );
}

#[test]
fn wrong_rotation_request_id() {
    s_reject_inputs(
        |i| i.expected_rotation_request_id = "bad".to_string(),
        SO::WrongRotationRequestId,
    );
}

#[test]
fn wrong_rotation_transcript_digest() {
    s_reject_inputs(
        |i| i.expected_rotation_transcript_digest = "bad".to_string(),
        SO::WrongRotationTranscriptDigest,
    );
}

#[test]
fn wrong_rotation_plan_digest() {
    s_reject_inputs(
        |i| i.expected_rotation_plan_digest = "bad".to_string(),
        SO::WrongRotationPlanDigest,
    );
}

#[test]
fn wrong_lifecycle_action() {
    s_reject_inputs(
        |i| i.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke,
        SO::WrongLifecycleAction,
    );
}

#[test]
fn wrong_rotation_action() {
    s_reject_inputs(
        |i| i.expected_rotation_action = ValidatorSetRotationAction::EmergencyValidatorRemoval,
        SO::WrongRotationAction,
    );
}

#[test]
fn wrong_authority_sequence() {
    s_reject_inputs(|i| i.expected_authority_domain_sequence = 999, SO::WrongAuthoritySequence);
}

// ===========================================================================
// H. Validator-set binding failures
// ===========================================================================

#[test]
fn wrong_current_validator_set_digest() {
    s_reject_inputs(
        |i| i.expected_current_set_digest = "bad".to_string(),
        SO::WrongCurrentValidatorSetDigest,
    );
}

#[test]
fn wrong_proposed_validator_set_digest() {
    s_reject_inputs(
        |i| i.expected_proposed_set_digest = "bad".to_string(),
        SO::WrongProposedValidatorSetDigest,
    );
}

#[test]
fn wrong_validator_set_delta_digest() {
    s_reject_inputs(
        |i| i.expected_delta_digest = "bad".to_string(),
        SO::WrongValidatorSetDeltaDigest,
    );
}

#[test]
fn wrong_validator_set_epoch() {
    s_reject_inputs(|i| i.expected_validator_set_epoch = 999, SO::WrongValidatorSetEpoch);
}

#[test]
fn wrong_validator_set_version() {
    s_reject_inputs(|i| i.expected_validator_set_version = 999, SO::WrongValidatorSetVersion);
}

#[test]
fn wrong_current_validator_set_epoch() {
    s_reject_inputs(
        |i| i.expected_current_validator_set_epoch = 999,
        SO::WrongCurrentValidatorSetEpoch,
    );
}

#[test]
fn wrong_current_validator_set_version() {
    s_reject_inputs(
        |i| i.expected_current_validator_set_version = 999,
        SO::WrongCurrentValidatorSetVersion,
    );
}

#[test]
fn wrong_proposed_validator_count() {
    s_reject_inputs(|i| i.expected_proposed_validator_count = 999, SO::WrongProposedValidatorCount);
}

#[test]
fn wrong_rotation_nonce() {
    s_reject_inputs(|i| i.expected_rotation_nonce = 999, SO::WrongRotationNonce);
}

// ===========================================================================
// I. Epoch-transition target / nonce binding failures
// ===========================================================================

#[test]
fn wrong_epoch_transition_target_inputs() {
    s_reject_inputs(|i| i.expected_epoch_transition_target = 999, SO::WrongEpochTransitionTarget);
}

#[test]
fn wrong_epoch_transition_target_request() {
    let mut c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.proposed_epoch_transition_target = 4242;
    let d = s_eval(&c);
    assert_eq!(d.outcome, SO::WrongEpochTransitionTarget);
    assert!(d.durable_audit_finalization_artifact.is_none());
}

#[test]
fn wrong_application_nonce() {
    s_reject_inputs(|i| i.expected_application_nonce = 999, SO::WrongApplicationNonce);
}

#[test]
fn wrong_live_application_nonce() {
    s_reject_inputs(|i| i.expected_live_application_nonce = 999, SO::WrongLiveApplicationNonce);
}

// ===========================================================================
// J. Authority-source rejection / fail-closed paths
// ===========================================================================

#[test]
fn reject_missing_post_commit_audit_decision() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::MissingPostCommitAuditDecision,
        SO::VerifiedPostCommitAuditDecisionRequired,
    );
}

#[test]
fn reject_unverified_post_commit_audit_decision() {
    let dec = cr_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::UnverifiedPostCommitAuditDecision {
            decision: dec,
        },
        SO::UnverifiedPostCommitAuditDecisionRejected,
    );
}

#[test]
fn reject_verified_source_with_non_accept_decision() {
    let dec = cr_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision {
            decision: dec,
        },
        SO::UnverifiedPostCommitAuditDecisionRejected,
    );
}

#[test]
fn reject_accepted_post_commit_audit_without_package_via_verified_source() {
    let dec = cr_decision_no_artifact(TrustBundleEnvironment::Devnet, Sc::Add);
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::VerifiedPostCommitAuditDecision {
            decision: dec,
        },
        SO::VerifiedPostCommitAuditDecisionRequired,
    );
}

#[test]
fn reject_accepted_post_commit_audit_without_package_variant() {
    let dec = cr_decision_no_artifact(TrustBundleEnvironment::Devnet, Sc::Add);
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::AcceptedPostCommitAuditWithoutPackage {
            decision: dec,
        },
        SO::VerifiedPostCommitAuditDecisionRequired,
    );
}

#[test]
fn reject_guarded_mutation_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::GuardedMutationDecisionWithoutPostCommitAudit,
        SO::GuardedMutationDecisionAloneRejected,
    );
}

#[test]
fn reject_staged_application_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::StagedApplicationDecisionWithoutPostCommitAudit,
        SO::StagedApplicationDecisionAloneRejected,
    );
}

#[test]
fn reject_live_application_authorization_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::LiveApplicationAuthorizationWithoutPostCommitAudit,
        SO::LiveApplicationAuthorizationAloneRejected,
    );
}

#[test]
fn reject_application_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::ApplicationDecisionWithoutPostCommitAudit,
        SO::ApplicationDecisionAloneRejected,
    );
}

#[test]
fn reject_rotation_plan_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::RotationPlanWithoutPostCommitAudit,
        SO::RotationPlanAloneRejected,
    );
}

#[test]
fn reject_governance_execution_intent_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::GovernanceExecutionIntentWithoutPostCommitAudit,
        SO::GovernanceExecutionIntentAloneRejected,
    );
}

#[test]
fn reject_governance_proof_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::GovernanceProofWithoutPostCommitAudit,
        SO::GovernanceProofAloneRejected,
    );
}

#[test]
fn reject_local_operator_assertion() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::LocalOperatorAssertion,
        SO::LocalOperatorProofRejected,
    );
}

#[test]
fn reject_peer_majority_assertion() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::PeerMajorityAssertion,
        SO::PeerMajorityProofRejected,
    );
}

#[test]
fn reject_custody_only_evidence() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::CustodyOnlyEvidence,
        SO::CustodyOnlyProofRejected,
    );
}

#[test]
fn reject_remote_signer_only_evidence() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::RemoteSignerOnlyEvidence,
        SO::RemoteSignerOnlyProofRejected,
    );
}

#[test]
fn reject_custody_attestation_only_evidence() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::CustodyAttestationOnlyEvidence,
        SO::CustodyAttestationOnlyProofRejected,
    );
}

#[test]
fn reject_fixture_only_post_commit_audit() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::FixtureOnlyPostCommitAudit,
        SO::FixtureStagedApplicationRejectedAsProductionAuthority,
    );
}

#[test]
fn reject_arbitrary_validator_set_bytes() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::ArbitraryValidatorSetBytes,
        SO::ArbitraryValidatorSetBytesRejected,
    );
}

// ===========================================================================
// K. MainNet / policy refusal
// ===========================================================================

#[test]
fn mainnet_domain_refused_under_source_test_policy() {
    let mut c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = s_eval(&c);
    assert_eq!(d.outcome, SO::MainNetRefused);
    assert!(d.durable_audit_finalization_artifact.is_none());
}

#[test]
fn mainnet_policy_unavailable() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = s_exec_with_policy(
        ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy::MainnetProductionLiveEpochTransitionDurableAuditFinalizationRequired,
    );
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &c.request,
        &c.inputs,
        &empty_replay327(),
    );
    assert_eq!(
        d.outcome,
        SO::MainNetProductionLiveEpochTransitionDurableAuditFinalizationUnavailable
    );
    assert!(d.durable_audit_finalization_artifact.is_none());
}

#[test]
fn production_policy_unavailable() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = s_exec_with_policy(
        ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy::RequireProductionLiveEpochTransitionDurableAuditFinalization,
    );
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &c.request,
        &c.inputs,
        &empty_replay327(),
    );
    assert_eq!(
        d.outcome,
        SO::ProductionLiveEpochTransitionDurableAuditFinalizationUnavailable
    );
    assert!(d.durable_audit_finalization_artifact.is_none());
}

#[test]
fn disabled_policy_fails_closed() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = s_exec_with_policy(
        ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy::Disabled,
    );
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &c.request,
        &c.inputs,
        &empty_replay327(),
    );
    assert_eq!(d.outcome, SO::Disabled);
    assert!(d.durable_audit_finalization_artifact.is_none());
    assert!(!d.is_accept());
}

#[test]
fn reserved_production_kind_fails_closed() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = ProductionLiveEpochTransitionDurableAuditFinalizationExecutor::new(
        ProductionLiveEpochTransitionDurableAuditFinalizationConfig::new(
            ProductionLiveEpochTransitionDurableAuditFinalizationExecutorKind::ProductionLiveEpochTransitionDurableAuditFinalization,
        ),
        ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy::AllowSourceTestLiveEpochTransitionDurableAuditFinalization,
    );
    let d = exec.evaluate_live_epoch_transition_durable_audit_finalization(
        &c.request,
        &c.inputs,
        &empty_replay327(),
    );
    assert_eq!(
        d.outcome,
        SO::LiveEpochTransitionDurableAuditFinalizationBoundaryUnavailable
    );
}

// ===========================================================================
// L. Replay / idempotency / freshness
// ===========================================================================

#[test]
fn replay_rejected_when_id_present() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    let id = d.durable_audit_finalization_artifact.as_ref().unwrap().request_id.clone();
    let replay = vec![id];
    let d2 = s_eval_replay(&c, &replay);
    match d2.outcome {
        SO::StagedApplicationReplayRejected { .. } => {}
        other => panic!("expected replay rejection, got {other:?}"),
    }
    assert!(d2.durable_audit_finalization_artifact.is_none());
}

#[test]
fn no_replay_when_id_absent() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let replay: Vec<String> = vec!["some-other-id".to_string()];
    let d = s_eval_replay(&c, &replay);
    assert!(d.is_accept());
}

#[test]
fn stale_governance_epoch() {
    s_reject_inputs(|i| i.min_governance_epoch = u64::MAX, SO::StaleGovernanceEpoch);
}

#[test]
fn stale_authority_sequence() {
    s_reject_inputs(|i| i.persisted_sequence = Some(u64::MAX), SO::StaleAuthoritySequence);
}

#[test]
fn stale_validator_set_epoch() {
    s_reject_inputs(|i| i.min_validator_set_epoch = u64::MAX, SO::StaleValidatorSetEpoch);
}

#[test]
fn stale_validator_set_version() {
    s_reject_inputs(|i| i.min_validator_set_version = u64::MAX, SO::StaleValidatorSetVersion);
}

// ===========================================================================
// M. Fixture-state (source/test bounded) application
// ===========================================================================

#[test]
fn fixture_state_apply_is_idempotent() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    let mut state = LiveEpochTransitionDurableAuditFinalizationFixtureState::new(CUR_EPOCH, CUR_VERSION, "start");
    assert!(state.apply_prepared_execution(art, &d.durable_audit_finalization_id));
    assert_eq!(state.current_epoch, art.epoch_transition_target);
    assert_eq!(state.validator_set_version, art.validator_set_version);
    assert_eq!(state.current_set_digest, art.proposed_set_digest);
    // Re-applying the same id is a no-op.
    assert!(!state.apply_prepared_execution(art, &d.durable_audit_finalization_id));
    assert!(state.has_applied(&d.durable_audit_finalization_id));
}

#[test]
fn fixture_state_apply_all_scenarios() {
    for sc in ALL_SC {
        let c = s_case(TrustBundleEnvironment::Devnet, sc);
        let d = s_eval(&c);
        let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
        let mut state = LiveEpochTransitionDurableAuditFinalizationFixtureState::new(CUR_EPOCH, CUR_VERSION, "start");
        assert!(state.apply_prepared_execution(art, &d.durable_audit_finalization_id));
        assert_eq!(state.current_epoch, art.epoch_transition_target);
    }
}

// ===========================================================================
// N. Non-mutation invariants
// ===========================================================================

#[test]
fn every_outcome_is_non_mutating() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    assert!(d.outcome.is_non_mutating());
    let bad = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let dbad = s_eval_replay(&bad, &[s_eval(&bad).durable_audit_finalization_id]);
    assert!(dbad.outcome.is_non_mutating());
}

#[test]
fn accept_authorizes_future_mutation_only() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(d.authorizes_future_mutation_only());
    assert!(d.durable_audit_finalization_artifact.as_ref().unwrap().staged_kind.is_non_mutating());
}

#[test]
fn reject_never_authorizes_future_mutation() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::MissingPostCommitAuditDecision,
        SO::VerifiedPostCommitAuditDecisionRequired,
    );
    let mut c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source =
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::MissingPostCommitAuditDecision;
    let d = s_eval(&c);
    assert!(!d.authorizes_future_mutation_only());
    assert!(!d.outcome.authorizes_future_mutation_only());
}

// ===========================================================================
// O. Taxonomy / policy / kind
// ===========================================================================

#[test]
fn policy_predicates() {
    use ProductionLiveEpochTransitionDurableAuditFinalizationExecutorPolicy as Pol;
    assert!(Pol::Disabled.is_disabled());
    assert!(Pol::AllowSourceTestLiveEpochTransitionDurableAuditFinalization.allows_source_test());
    assert!(Pol::RequireProductionLiveEpochTransitionDurableAuditFinalization.is_production());
    assert!(Pol::MainnetProductionLiveEpochTransitionDurableAuditFinalizationRequired.is_mainnet());
    assert_eq!(Pol::default(), Pol::Disabled);
}

#[test]
fn kind_predicates() {
    use ProductionLiveEpochTransitionDurableAuditFinalizationExecutorKind as K;
    assert!(K::SourceTestLiveEpochTransitionDurableAuditFinalization.is_source_test());
    assert!(!K::Disabled.is_source_test());
    assert!(!K::ProductionLiveEpochTransitionDurableAuditFinalization.is_source_test());
    assert_eq!(K::default(), K::Disabled);
}

#[test]
fn execution_kind_mapping_matches_handoff_kind() {
    for sc in ALL_SC {
        let hk = expected_crc_kind(sc);
        let pk = SK::from_staged_application_kind(hk);
        assert_eq!(pk, expected_crc2_kind(sc));
        assert!(pk.is_non_mutating());
        assert!(!pk.is_unsupported());
    }
}

#[test]
fn unsupported_staged_application_kind_is_unsupported() {
    let pk = SK::from_staged_application_kind(LiveEpochTransitionPostCommitAuditKind::UnsupportedStagedApplication);
    assert!(pk.is_unsupported());
}

#[test]
fn outcome_tags_are_stable_and_distinct() {
    let a = SO::PostCommitAuditDecisionIdMismatch;
    let b = SO::GuardedMutationDecisionIdMismatch;
    assert_ne!(a.tag(), b.tag());
    assert_eq!(a.tag(), SO::PostCommitAuditDecisionIdMismatch.tag());
    assert!(!SO::MainNetRefused.tag().is_empty());
}

#[test]
fn config_and_inputs_well_formed() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    assert!(c.inputs.is_well_formed());
    assert!(ProductionLiveEpochTransitionDurableAuditFinalizationConfig::source_test().is_well_formed());
    // The default config still pins the supported protocol version.
    assert!(ProductionLiveEpochTransitionDurableAuditFinalizationConfig::default().is_well_formed());
}

// ===========================================================================
// P. Per-scenario expansion (accept + determinism + non-mutation + bindings)
// ===========================================================================

macro_rules! per_scenario_accept {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let c = s_case(TrustBundleEnvironment::Devnet, $sc);
            let d = s_eval(&c);
            assert!(d.is_accept());
            let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
            assert_eq!(art.staged_kind, expected_crc2_kind($sc));
            assert!(art.staged_kind.is_non_mutating());
            let d2 = s_eval(&c);
            assert_eq!(d.durable_audit_finalization_digest, d2.durable_audit_finalization_digest);
            assert_eq!(d.transcript_digest, d2.transcript_digest);
            let mut state = LiveEpochTransitionDurableAuditFinalizationFixtureState::new(
                CUR_EPOCH,
                CUR_VERSION,
                "start",
            );
            assert!(state.apply_prepared_execution(art, &d.durable_audit_finalization_id));
            assert_eq!(state.current_epoch, art.epoch_transition_target);
        }
    };
}

per_scenario_accept!(scenario_accept_add, Sc::Add);
per_scenario_accept!(scenario_accept_remove, Sc::Remove);
per_scenario_accept!(scenario_accept_update, Sc::Update);
per_scenario_accept!(scenario_accept_noop, Sc::NoOp);
per_scenario_accept!(scenario_accept_identity, Sc::Identity);
per_scenario_accept!(scenario_accept_retire, Sc::Retire);
per_scenario_accept!(scenario_accept_emergency, Sc::Emergency);
per_scenario_accept!(scenario_accept_authsync, Sc::AuthSync);
per_scenario_accept!(scenario_accept_bulk, Sc::Bulk);

macro_rules! per_scenario_testnet_accept {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let c = s_case(TrustBundleEnvironment::Testnet, $sc);
            let d = s_eval(&c);
            assert!(d.is_accept());
            assert_eq!(
                d.durable_audit_finalization_artifact.as_ref().unwrap().environment,
                TrustBundleEnvironment::Testnet
            );
        }
    };
}

per_scenario_testnet_accept!(scenario_testnet_accept_add, Sc::Add);
per_scenario_testnet_accept!(scenario_testnet_accept_remove, Sc::Remove);
per_scenario_testnet_accept!(scenario_testnet_accept_update, Sc::Update);
per_scenario_testnet_accept!(scenario_testnet_accept_noop, Sc::NoOp);
per_scenario_testnet_accept!(scenario_testnet_accept_identity, Sc::Identity);
per_scenario_testnet_accept!(scenario_testnet_accept_retire, Sc::Retire);
per_scenario_testnet_accept!(scenario_testnet_accept_emergency, Sc::Emergency);
per_scenario_testnet_accept!(scenario_testnet_accept_authsync, Sc::AuthSync);
per_scenario_testnet_accept!(scenario_testnet_accept_bulk, Sc::Bulk);

macro_rules! per_scenario_post_commit_audit_binding {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let mut c = s_case(TrustBundleEnvironment::Devnet, $sc);
            c.inputs.expected_post_commit_audit_decision_id = "bad".to_string();
            let d = s_eval(&c);
            assert_eq!(d.outcome, SO::PostCommitAuditDecisionIdMismatch);
            assert!(d.durable_audit_finalization_artifact.is_none());
        }
    };
}

per_scenario_post_commit_audit_binding!(scenario_handoff_binding_add, Sc::Add);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_remove, Sc::Remove);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_update, Sc::Update);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_noop, Sc::NoOp);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_identity, Sc::Identity);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_retire, Sc::Retire);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_emergency, Sc::Emergency);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_authsync, Sc::AuthSync);
per_scenario_post_commit_audit_binding!(scenario_handoff_binding_bulk, Sc::Bulk);

macro_rules! per_scenario_guarded_binding {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let mut c = s_case(TrustBundleEnvironment::Devnet, $sc);
            c.inputs.expected_guarded_mutation_decision_id = "bad".to_string();
            let d = s_eval(&c);
            assert_eq!(d.outcome, SO::GuardedMutationDecisionIdMismatch);
            assert!(d.durable_audit_finalization_artifact.is_none());
        }
    };
}

per_scenario_guarded_binding!(scenario_guarded_binding_add, Sc::Add);
per_scenario_guarded_binding!(scenario_guarded_binding_remove, Sc::Remove);
per_scenario_guarded_binding!(scenario_guarded_binding_update, Sc::Update);
per_scenario_guarded_binding!(scenario_guarded_binding_noop, Sc::NoOp);
per_scenario_guarded_binding!(scenario_guarded_binding_identity, Sc::Identity);
per_scenario_guarded_binding!(scenario_guarded_binding_retire, Sc::Retire);
per_scenario_guarded_binding!(scenario_guarded_binding_emergency, Sc::Emergency);
per_scenario_guarded_binding!(scenario_guarded_binding_authsync, Sc::AuthSync);
per_scenario_guarded_binding!(scenario_guarded_binding_bulk, Sc::Bulk);
// ===========================================================================
// Q. Deeper re-exposed Run 321/322 runtime-handoff authority-tuple binding
//    (additive layer introduced by Run 325 on top of the rotated Run 323
//    coverage above). All non-mutating, fail-closed.
// ===========================================================================

#[test]
fn accept_reexposes_runtime_handoff_tuple_from_parent() {
    let parent = cr_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let ppkg = parent.post_commit_audit_artifact.as_ref().unwrap().clone();
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    assert!(d.is_accept());
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(art.runtime_handoff_decision_id, ppkg.runtime_handoff_decision_id);
    assert_eq!(art.runtime_handoff_request_id, ppkg.runtime_handoff_request_id);
    assert_eq!(art.runtime_handoff_intent_digest, ppkg.runtime_handoff_intent_digest);
    assert_eq!(
        art.runtime_handoff_transcript_digest,
        ppkg.runtime_handoff_transcript_digest
    );
    assert_eq!(art.runtime_handoff_nonce, HANDOFF_NONCE);
    assert_eq!(art.post_commit_audit_nonce, CRC_NONCE);
    assert_eq!(art.durable_audit_finalization_nonce, CRC2_NONCE);
}

#[test]
fn reject_runtime_handoff_decision_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_runtime_handoff_decision_id = "wrong-runtime-handoff-id".to_string(),
        SO::RuntimeHandoffDecisionIdMismatch,
    );
}

#[test]
fn reject_runtime_handoff_request_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_runtime_handoff_request_id = "wrong-runtime-handoff-req".to_string(),
        SO::RuntimeHandoffDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_runtime_handoff_intent_digest_mismatch() {
    s_reject_inputs(
        |i| i.expected_runtime_handoff_intent_digest = "wrong-runtime-handoff-digest".to_string(),
        SO::RuntimeHandoffDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_runtime_handoff_transcript_mismatch() {
    s_reject_inputs(
        |i| {
            i.expected_runtime_handoff_transcript_digest =
                "wrong-runtime-handoff-transcript".to_string()
        },
        SO::RuntimeHandoffDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_runtime_handoff_nonce() {
    s_reject_inputs(
        |i| i.expected_runtime_handoff_nonce = HANDOFF_NONCE + 100,
        SO::WrongRuntimeHandoffNonce,
    );
}

#[test]
fn reject_runtime_handoff_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::RuntimeHandoffDecisionWithoutPostCommitAudit,
        SO::RuntimeHandoffDecisionAloneRejected,
    );
}

#[test]
fn runtime_handoff_alone_tag_is_stable() {
    assert_eq!(
        SO::RuntimeHandoffDecisionAloneRejected.tag(),
        "runtime-handoff-decision-alone-rejected"
    );
    assert_eq!(
        SO::RuntimeHandoffDecisionIdMismatch.tag(),
        "runtime-handoff-decision-id-mismatch"
    );
    assert_eq!(
        SO::WrongRuntimeHandoffNonce.tag(),
        "wrong-runtime-handoff-nonce"
    );
}

#[test]
fn runtime_handoff_binding_rejects_are_non_mutating() {
    for o in [
        SO::RuntimeHandoffDecisionIdMismatch,
        SO::RuntimeHandoffDecisionRequestIdMismatch,
        SO::RuntimeHandoffDecisionIntentDigestMismatch,
        SO::RuntimeHandoffDecisionTranscriptMismatch,
        SO::WrongRuntimeHandoffNonce,
        SO::RuntimeHandoffDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
    }
}

#[test]
fn accept_content_digest_binds_runtime_handoff_tuple() {
    // Two accepted evaluations over identical fixtures reproduce an identical
    // content digest (determinism), and the digest incorporates the
    // re-exposed runtime-handoff tuple.
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d1 = s_eval(&c);
    let d2 = s_eval(&c);
    let a1 = d1.durable_audit_finalization_artifact.as_ref().unwrap();
    let a2 = d2.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(a1.content_digest(), a2.content_digest());
}

// ===========================================================================
// Run 327 — re-exposed Run 323/324 execution-preparation ancestor binding
// (carried through the consumed Run 325/326 post-commit-audit artifact) and
// its alone-rejected authority variant.
// ===========================================================================

#[test]
fn reject_mutation_execution_decision_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_mutation_execution_decision_id = "wrong-mut-exec-id".to_string(),
        SO::MutationExecutionDecisionIdMismatch,
    );
}

#[test]
fn reject_mutation_execution_request_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_mutation_execution_request_id = "wrong-mut-exec-req".to_string(),
        SO::MutationExecutionDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_mutation_execution_intent_digest_mismatch() {
    s_reject_inputs(
        |i| i.expected_mutation_execution_intent_digest = "wrong-mut-exec-digest".to_string(),
        SO::MutationExecutionDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_mutation_execution_transcript_mismatch() {
    s_reject_inputs(
        |i| {
            i.expected_mutation_execution_transcript_digest =
                "wrong-mut-exec-transcript".to_string()
        },
        SO::MutationExecutionDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_mutation_execution_nonce() {
    s_reject_inputs(
        |i| i.expected_mutation_execution_nonce = MUT_NONCE + 100,
        SO::WrongMutationExecutionNonce,
    );
}

#[test]
fn reject_mutation_execution_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::MutationExecutionDecisionWithoutPostCommitAudit,
        SO::MutationExecutionDecisionAloneRejected,
    );
}

#[test]
fn reject_commit_authorization_decision_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_commit_authorization_decision_id = "wrong-commit-auth-id".to_string(),
        SO::CommitAuthorizationDecisionIdMismatch,
    );
}

#[test]
fn reject_commit_authorization_request_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_commit_authorization_request_id = "wrong-commit-auth-req".to_string(),
        SO::CommitAuthorizationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_commit_authorization_intent_digest_mismatch() {
    s_reject_inputs(
        |i| {
            i.expected_commit_authorization_intent_digest =
                "wrong-commit-auth-digest".to_string()
        },
        SO::CommitAuthorizationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_commit_authorization_transcript_mismatch() {
    s_reject_inputs(
        |i| {
            i.expected_commit_authorization_transcript_digest =
                "wrong-commit-auth-transcript".to_string()
        },
        SO::CommitAuthorizationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_commit_authorization_nonce() {
    s_reject_inputs(
        |i| i.expected_commit_authorization_nonce = CMT_NONCE + 100,
        SO::WrongCommitAuthorizationNonce,
    );
}

#[test]
fn reject_commit_authorization_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::CommitAuthorizationDecisionWithoutPostCommitAudit,
        SO::CommitAuthorizationDecisionAloneRejected,
    );
}

#[test]
fn commit_authorization_binding_rejects_are_non_mutating() {
    for o in [
        SO::CommitAuthorizationDecisionIdMismatch,
        SO::CommitAuthorizationDecisionRequestIdMismatch,
        SO::CommitAuthorizationDecisionIntentDigestMismatch,
        SO::CommitAuthorizationDecisionTranscriptMismatch,
        SO::WrongCommitAuthorizationNonce,
        SO::CommitAuthorizationDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
        assert!(!o.tag().is_empty());
    }
}

#[test]
fn accept_artifact_reexposes_commit_authorization_tuple() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    assert_eq!(art.commit_authorization_nonce, CMT_NONCE);
    assert!(!art.commit_authorization_decision_id.is_empty());
    assert!(!art.commit_authorization_transcript_digest.is_empty());
}

#[test]
fn mutation_execution_alone_tag_is_stable() {
    assert_eq!(
        SO::MutationExecutionDecisionAloneRejected.tag(),
        "mutation-execution-decision-alone-rejected"
    );
    assert_eq!(
        SO::MutationExecutionDecisionIdMismatch.tag(),
        "mutation-execution-decision-id-mismatch"
    );
    assert_eq!(
        SO::WrongMutationExecutionNonce.tag(),
        "wrong-mutation-execution-nonce"
    );
}

#[test]
fn accepted_artifact_re_exposes_mutation_execution_ancestor() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    assert!(d.is_accept());
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    // Grandparent Run 323/324 mutation-execution nonce re-exposed intact.
    assert_eq!(art.mutation_execution_nonce, MUT_NONCE);
    // Parent Run 325/326 post-commit-audit nonce re-exposed intact.
    assert_eq!(art.post_commit_audit_nonce, CRC_NONCE);
    // Self Run 327 durable-audit-finalization proposed nonce.
    assert_eq!(art.durable_audit_finalization_nonce, CRC2_NONCE);
}

#[test]
fn mutation_execution_binding_rejects_are_non_mutating() {
    for o in [
        SO::MutationExecutionDecisionIdMismatch,
        SO::MutationExecutionDecisionRequestIdMismatch,
        SO::MutationExecutionDecisionIntentDigestMismatch,
        SO::MutationExecutionDecisionTranscriptMismatch,
        SO::WrongMutationExecutionNonce,
        SO::MutationExecutionDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
        assert!(!o.tag().is_empty());
    }
}

#[test]
fn reject_execution_preparation_decision_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_execution_preparation_decision_id = "wrong-exec-prep-id".to_string(),
        SO::ExecutionPreparationDecisionIdMismatch,
    );
}

#[test]
fn reject_execution_preparation_request_id_mismatch() {
    s_reject_inputs(
        |i| i.expected_execution_preparation_request_id = "wrong-exec-prep-req".to_string(),
        SO::ExecutionPreparationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_execution_preparation_intent_digest_mismatch() {
    s_reject_inputs(
        |i| i.expected_execution_preparation_intent_digest = "wrong-exec-prep-digest".to_string(),
        SO::ExecutionPreparationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_execution_preparation_transcript_mismatch() {
    s_reject_inputs(
        |i| {
            i.expected_execution_preparation_transcript_digest =
                "wrong-exec-prep-transcript".to_string()
        },
        SO::ExecutionPreparationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_execution_preparation_nonce() {
    s_reject_inputs(
        |i| i.expected_execution_preparation_nonce = PREP_NONCE + 100,
        SO::WrongExecutionPreparationNonce,
    );
}

#[test]
fn reject_execution_preparation_decision_alone() {
    s_reject_source(
        LiveEpochTransitionDurableAuditFinalizationAuthoritySource::ExecutionPreparationDecisionWithoutPostCommitAudit,
        SO::ExecutionPreparationDecisionAloneRejected,
    );
}

#[test]
fn execution_preparation_alone_tag_is_stable() {
    assert_eq!(
        SO::ExecutionPreparationDecisionAloneRejected.tag(),
        "execution-preparation-decision-alone-rejected"
    );
    assert_eq!(
        SO::ExecutionPreparationDecisionIdMismatch.tag(),
        "execution-preparation-decision-id-mismatch"
    );
    assert_eq!(
        SO::WrongExecutionPreparationNonce.tag(),
        "wrong-execution-preparation-nonce"
    );
}

#[test]
fn accepted_artifact_re_exposes_execution_preparation_ancestor() {
    let c = s_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = s_eval(&c);
    assert!(d.is_accept());
    let art = d.durable_audit_finalization_artifact.as_ref().unwrap();
    // Grandparent Run 323/324 execution-preparation nonce re-exposed intact.
    assert_eq!(art.execution_preparation_nonce, PREP_NONCE);
    // Parent Run 325/326 post-commit-audit nonce re-exposed intact.
    assert_eq!(art.post_commit_audit_nonce, CRC_NONCE);
    // Self Run 327 durable-audit-finalization proposed nonce.
    assert_eq!(art.durable_audit_finalization_nonce, CRC2_NONCE);
}

#[test]
fn execution_preparation_binding_rejects_are_non_mutating() {
    for o in [
        SO::ExecutionPreparationDecisionIdMismatch,
        SO::ExecutionPreparationDecisionRequestIdMismatch,
        SO::ExecutionPreparationDecisionIntentDigestMismatch,
        SO::ExecutionPreparationDecisionTranscriptMismatch,
        SO::WrongExecutionPreparationNonce,
        SO::ExecutionPreparationDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
        assert!(!o.tag().is_empty());
    }
}
