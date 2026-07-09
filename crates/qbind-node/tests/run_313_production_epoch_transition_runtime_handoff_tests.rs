//! Run 313 — source/test epoch-transition **runtime handoff** boundary
//! integration tests.
//!
//! Source/test only. Run 313 does **not** capture release-binary evidence;
//! release-binary evidence for the epoch-transition runtime handoff boundary
//! is deferred to **Run 314**. The tests cover:
//!
//! * A. accepted / compatible source-test runtime handoff packages;
//! * B. guarded-mutation / staged-application / authorization / application /
//!      governance / rotation / validator-set / nonce binding failures;
//! * C. authority-source rejection / fail-closed paths;
//! * D. MainNet / policy refusal (production + mainnet fail closed);
//! * E. replay / idempotency / recovery / freshness;
//! * F. source/test-bounded in-memory fixture-state application;
//! * G. non-mutation invariants;
//! * H. taxonomy / C4/C5 status.
//!
//! Each accepted case composes the real Run 303 → 305 → 307 → 309 → 311 chain
//! to produce a verified, accepted Run 311 guarded epoch-transition
//! mutation-execution decision, then feeds that decision into the Run 313
//! epoch-transition runtime handoff executor.
//!
//! Run 313 produces **only** a prepared, non-mutating runtime handoff /
//! live-mutation preflight package. It never applies a live validator-set
//! change, never transitions a consensus epoch, never writes
//! `meta:current_epoch`, never injects a reconfig block, and never mutates any
//! durable trust state. The only mutation a positive path performs is against
//! a caller-owned in-memory `EpochTransitionRuntimeHandoffFixtureState` used
//! exclusively by these tests.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_313.md`.

#![allow(dead_code)]

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

struct Stg309 {
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

fn stg_case309(env: TrustBundleEnvironment, sc: Sc) -> Stg309 {
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
    Stg309 {
        executor: ProductionStagedLiveValidatorSetEpochTransitionApplicationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay309() -> EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet {
    EmptyStagedLiveValidatorSetEpochTransitionApplicationReplaySet
}

fn eval309(case: &Stg309) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    case.executor.evaluate_staged_live_validator_set_epoch_transition_application(
        &case.request,
        &case.inputs,
        &empty_replay309(),
    )
}

// ===========================================================================
// Run 311 guarded epoch-transition mutation layer
// ===========================================================================

use qbind_node::pqc_production_guarded_epoch_transition_mutation_executor::*;

const GUARDED_POLICY_ID: &str = "guarded-mutation-policy-1";
const GUARDED_NONCE: u64 = 37;

use ProductionGuardedEpochTransitionMutationOutcome as GO;
use GuardedEpochTransitionMutationKind as GK;

/// Build an accepted Run 309 staged epoch-transition application decision — the
/// sole accepted Run 311 authority source.
fn stg_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    let d = eval309(&stg_case309(env, sc));
    assert!(d.is_accept(), "run 309 staged decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 309 staged decision for authority-source
/// negative tests.
fn stg_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionStagedLiveValidatorSetEpochTransitionApplicationDecision {
    let mut c = stg_case309(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = eval309(&c);
    assert!(!d.is_accept(), "tampered run 309 decision must reject");
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

fn empty_replay311() -> EmptyGuardedEpochTransitionMutationReplaySet {
    EmptyGuardedEpochTransitionMutationReplaySet
}

fn gem_eval(case: &Gem) -> ProductionGuardedEpochTransitionMutationDecision {
    case.executor.evaluate_guarded_epoch_transition_mutation(
        &case.request,
        &case.inputs,
        &empty_replay311(),
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
// Run 313 epoch-transition runtime handoff layer
// ===========================================================================

use qbind_node::pqc_production_epoch_transition_runtime_handoff::*;

const HANDOFF_POLICY_ID: &str = "runtime-handoff-policy-1";
const HANDOFF_NONCE: u64 = 41;
const REPLAY_WINDOW: u64 = 8;

use ProductionEpochTransitionRuntimeHandoffOutcome as HO;
use EpochTransitionRuntimeHandoffKind as HK;

/// Build an accepted Run 311 guarded epoch-transition mutation-execution
/// decision — the sole accepted Run 313 authority source.
fn guarded_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionGuardedEpochTransitionMutationDecision {
    let d = gem_eval(&gem_case(env, sc));
    assert!(d.is_accept(), "run 311 guarded decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 311 guarded decision for authority-source
/// negative tests.
fn guarded_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionGuardedEpochTransitionMutationDecision {
    let mut c = gem_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = gem_eval(&c);
    assert!(!d.is_accept(), "tampered run 311 decision must reject");
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

struct H313 {
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

fn h_case(env: TrustBundleEnvironment, sc: Sc) -> H313 {
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
    H313 {
        executor: ProductionEpochTransitionRuntimeHandoffExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay313() -> EmptyEpochTransitionRuntimeHandoffReplaySet {
    EmptyEpochTransitionRuntimeHandoffReplaySet
}

fn h_eval(case: &H313) -> ProductionEpochTransitionRuntimeHandoffDecision {
    case.executor.evaluate_epoch_transition_runtime_handoff(
        &case.request,
        &case.inputs,
        &empty_replay313(),
    )
}

fn h_eval_replay(case: &H313, replay: &[String]) -> ProductionEpochTransitionRuntimeHandoffDecision {
    case.executor
        .evaluate_epoch_transition_runtime_handoff(&case.request, &case.inputs, &replay)
}

fn h_exec_with_policy(
    policy: ProductionEpochTransitionRuntimeHandoffExecutorPolicy,
) -> ProductionEpochTransitionRuntimeHandoffExecutor {
    ProductionEpochTransitionRuntimeHandoffExecutor::new(
        ProductionEpochTransitionRuntimeHandoffConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no package).
fn h_reject_inputs(
    mutate: impl FnOnce(&mut ProductionEpochTransitionRuntimeHandoffInputs),
    expected: HO,
) {
    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = h_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.handoff_package.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn h_reject_source(source: EpochTransitionRuntimeHandoffAuthoritySource, expected: HO) {
    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = h_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.handoff_package.is_none());
}

// ===========================================================================
// A. Accepted / compatible source-test runtime handoff packages
// ===========================================================================

#[test]
fn accept_all_scenarios_devnet() {
    for sc in ALL_SC {
        let c = h_case(TrustBundleEnvironment::Devnet, sc);
        let d = h_eval(&c);
        assert!(d.is_accept(), "scenario must accept");
        assert!(d.authorizes_future_mutation_only());
        let pkg = d.handoff_package.as_ref().unwrap();
        assert_eq!(pkg.staged_kind, expected_handoff_kind(sc));
        assert_eq!(pkg.runtime_handoff_nonce, HANDOFF_NONCE);
        assert_eq!(pkg.guarded_mutation_nonce, GUARDED_NONCE);
        assert_eq!(pkg.staged_application_nonce, STAGED_NONCE);
    }
}

#[test]
fn accept_all_scenarios_testnet() {
    for sc in ALL_SC {
        let c = h_case(TrustBundleEnvironment::Testnet, sc);
        let d = h_eval(&c);
        assert!(d.is_accept());
        let pkg = d.handoff_package.as_ref().unwrap();
        assert_eq!(pkg.environment, TrustBundleEnvironment::Testnet);
        assert_eq!(pkg.staged_kind, expected_handoff_kind(sc));
    }
}

#[test]
fn accept_outcome_carries_kind_env_target_nonce() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    match d.outcome {
        HO::AcceptedSourceTestEpochTransitionRuntimeHandoff {
            handoff_kind,
            environment,
            epoch_transition_target,
            runtime_handoff_nonce,
        } => {
            assert_eq!(handoff_kind, HK::StageApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(epoch_transition_target, c.request.proposed_epoch_transition_target);
            assert_eq!(runtime_handoff_nonce, HANDOFF_NONCE);
        }
        other => panic!("expected accept, got {}", other.tag()),
    }
}

#[test]
fn accept_binds_guarded_mutation_decision_transcript() {
    let dec = guarded_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let did = dec.staged_application_id.clone();
    let rid = dec.request_id.clone();
    let idig = dec.intent_digest.clone();
    let tdig = dec.transcript_digest.clone();
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert_eq!(pkg.guarded_mutation_decision_id, did);
    assert_eq!(pkg.guarded_mutation_request_id, rid);
    assert_eq!(pkg.guarded_mutation_intent_digest, idig);
    assert_eq!(pkg.guarded_mutation_transcript_digest, tdig);
}

#[test]
fn accept_reexposes_staged_application_tuple() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert!(!pkg.staged_application_decision_id.is_empty());
    assert!(!pkg.staged_application_request_id.is_empty());
    assert!(!pkg.staged_application_intent_digest.is_empty());
    assert!(!pkg.staged_application_transcript_digest.is_empty());
}

#[test]
fn accept_reexposes_live_authorization_tuple() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert!(!pkg.authorization_decision_id.is_empty());
    assert!(!pkg.authorization_request_id.is_empty());
    assert!(!pkg.authorization_intent_digest.is_empty());
    assert!(!pkg.authorization_transcript_digest.is_empty());
}

#[test]
fn accept_reexposes_application_and_governance_tuple() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert!(!pkg.application_decision_id.is_empty());
    assert_eq!(pkg.governance_domain_id, GOV_DOMAIN);
    assert_eq!(pkg.governance_epoch, GOV_EPOCH);
    assert_eq!(pkg.proposal_id, PROPOSAL_ID);
}

#[test]
fn accept_package_carries_future_executor_preconditions() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert_eq!(pkg.precondition_current_validator_set_digest, pkg.current_set_digest);
    assert_eq!(pkg.precondition_current_validator_set_epoch, pkg.validator_set_epoch);
    assert_eq!(pkg.precondition_current_validator_set_version, pkg.validator_set_version);
    assert_eq!(pkg.precondition_proposed_validator_set_digest, pkg.proposed_set_digest);
    assert_eq!(pkg.precondition_delta_digest, pkg.delta_digest);
    assert_eq!(pkg.precondition_target_epoch, pkg.epoch_transition_target);
    assert_eq!(pkg.precondition_required_governance_epoch, pkg.governance_epoch);
    assert_eq!(pkg.precondition_required_authority_sequence, pkg.authority_domain_sequence);
    assert_eq!(pkg.precondition_required_replay_window, REPLAY_WINDOW);
}

#[test]
fn accept_deterministic_digests_under_reevaluation() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Bulk);
    let d1 = h_eval(&c);
    let d2 = h_eval(&c);
    assert_eq!(d1.handoff_id, d2.handoff_id);
    assert_eq!(d1.request_id, d2.request_id);
    assert_eq!(d1.handoff_digest, d2.handoff_digest);
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
}

#[test]
fn accept_package_digest_matches_named_helper() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert_eq!(
        pkg.content_digest(),
        production_epoch_transition_runtime_handoff_content_digest(pkg)
    );
    assert_eq!(pkg.handoff_digest, d.handoff_digest);
}

#[test]
fn accept_decision_and_package_identifiers_agree() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert_eq!(pkg.handoff_id, d.handoff_id);
    assert_eq!(pkg.request_id, d.request_id);
    assert_eq!(pkg.handoff_digest, d.handoff_digest);
    assert_eq!(pkg.transcript_digest, d.transcript_digest);
}

#[test]
fn accept_distinct_scenarios_have_distinct_digests() {
    let a = h_eval(&h_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let b = h_eval(&h_case(TrustBundleEnvironment::Devnet, Sc::Remove));
    assert_ne!(a.handoff_digest, b.handoff_digest);
}

#[test]
fn accept_target_matches_package_epoch_transition_target() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = c.request.proposed_epoch_transition_target;
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    assert_eq!(pkg.epoch_transition_target, target);
}

// ===========================================================================
// B0. Guarded-mutation-decision transcript binding failures
// ===========================================================================

#[test]
fn reject_wrong_guarded_mutation_decision_id() {
    h_reject_inputs(
        |i| i.expected_guarded_mutation_decision_id = "bad".to_string(),
        HO::GuardedMutationDecisionIdMismatch,
    );
}

#[test]
fn reject_wrong_guarded_mutation_request_id() {
    h_reject_inputs(
        |i| i.expected_guarded_mutation_request_id = "bad".to_string(),
        HO::GuardedMutationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_wrong_guarded_mutation_intent_digest() {
    h_reject_inputs(
        |i| i.expected_guarded_mutation_intent_digest = "bad".to_string(),
        HO::GuardedMutationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_wrong_guarded_mutation_transcript_digest() {
    h_reject_inputs(
        |i| i.expected_guarded_mutation_transcript_digest = "bad".to_string(),
        HO::GuardedMutationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_guarded_mutation_nonce() {
    h_reject_inputs(
        |i| i.expected_guarded_mutation_nonce = GUARDED_NONCE + 999,
        HO::WrongGuardedMutationNonce,
    );
}

#[test]
fn reject_guarded_mutation_integrity_mismatch() {
    // Tamper the consumed guarded-mutation decision's transcript-bound intent
    // digest so the prepared record no longer reproduces it. We keep the
    // inputs' expected intent digest aligned with the tampered value so the
    // transcript checks pass but the record-integrity check fails.
    let dec = guarded_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let mut tampered = dec.clone();
    // Break the record's own bound fields so its recomputed intent digest
    // diverges from the decision's stored intent digest.
    if let Some(rec) = tampered.staged_application_record.as_mut() {
        rec.governance_height = rec.governance_height.wrapping_add(1);
    }
    let target = tampered
        .staged_application_record
        .as_ref()
        .unwrap()
        .epoch_transition_target;
    let mut inputs = h_inputs(TrustBundleEnvironment::Devnet, &tampered);
    // Realign the guarded-mutation transcript expectations to the (unchanged)
    // decision identifiers so the earlier transcript checks pass.
    inputs.expected_guarded_mutation_decision_id = tampered.staged_application_id.clone();
    inputs.expected_guarded_mutation_request_id = tampered.request_id.clone();
    inputs.expected_guarded_mutation_intent_digest = tampered.intent_digest.clone();
    inputs.expected_guarded_mutation_transcript_digest = tampered.transcript_digest.clone();
    let request = ProductionEpochTransitionRuntimeHandoffRequest::new(
        EpochTransitionRuntimeHandoffAuthoritySource::VerifiedGuardedMutationDecision {
            decision: tampered,
        },
        target,
        HANDOFF_NONCE,
    );
    let d = ProductionEpochTransitionRuntimeHandoffExecutor::source_test()
        .evaluate_epoch_transition_runtime_handoff(&request, &inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::GuardedMutationDecisionIntegrityMismatch);
    assert!(d.handoff_package.is_none());
}

// ===========================================================================
// B. Staged-application-decision transcript binding failures
// ===========================================================================

#[test]
fn reject_wrong_staged_application_decision_id() {
    h_reject_inputs(
        |i| i.expected_staged_application_decision_id = "bad".to_string(),
        HO::StagedApplicationDecisionIdMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_request_id() {
    h_reject_inputs(
        |i| i.expected_staged_application_request_id = "bad".to_string(),
        HO::StagedApplicationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_intent_digest() {
    h_reject_inputs(
        |i| i.expected_staged_application_intent_digest = "bad".to_string(),
        HO::StagedApplicationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_transcript_digest() {
    h_reject_inputs(
        |i| i.expected_staged_application_transcript_digest = "bad".to_string(),
        HO::StagedApplicationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_nonce() {
    h_reject_inputs(
        |i| i.expected_staged_application_nonce = STAGED_NONCE + 999,
        HO::WrongStagedApplicationNonce,
    );
}

// ---- Re-exposed live-authorization tuple binding failures -----------------

#[test]
fn reject_wrong_authorization_decision_id() {
    h_reject_inputs(
        |i| i.expected_authorization_decision_id = "bad".to_string(),
        HO::AuthorizationDecisionIdMismatch,
    );
}

#[test]
fn reject_wrong_authorization_request_id() {
    h_reject_inputs(
        |i| i.expected_authorization_request_id = "bad".to_string(),
        HO::AuthorizationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_wrong_authorization_intent_digest() {
    h_reject_inputs(
        |i| i.expected_authorization_intent_digest = "bad".to_string(),
        HO::AuthorizationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_wrong_authorization_transcript_digest() {
    h_reject_inputs(
        |i| i.expected_authorization_transcript_digest = "bad".to_string(),
        HO::AuthorizationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_authorization_policy_id() {
    h_reject_inputs(
        |i| i.expected_authorization_policy_id = "bad".to_string(),
        HO::WrongAuthorizationPolicyId,
    );
}

// ---- Re-exposed application-decision tuple binding failures ---------------

#[test]
fn reject_wrong_application_decision_id() {
    h_reject_inputs(
        |i| i.expected_application_decision_id = "bad".to_string(),
        HO::WrongApplicationDecisionId,
    );
}

#[test]
fn reject_wrong_application_request_id() {
    h_reject_inputs(
        |i| i.expected_application_request_id = "bad".to_string(),
        HO::WrongApplicationRequestId,
    );
}

#[test]
fn reject_wrong_application_intent_digest() {
    h_reject_inputs(
        |i| i.expected_application_intent_digest = "bad".to_string(),
        HO::WrongApplicationIntentDigest,
    );
}

#[test]
fn reject_wrong_application_transcript_digest() {
    h_reject_inputs(
        |i| i.expected_application_transcript_digest = "bad".to_string(),
        HO::WrongApplicationTranscriptDigest,
    );
}

#[test]
fn reject_wrong_application_policy_id() {
    h_reject_inputs(
        |i| i.expected_application_policy_id = "bad".to_string(),
        HO::WrongApplicationPolicyId,
    );
}

// ---- Trust-domain binding failures ----------------------------------------

#[test]
fn reject_wrong_environment() {
    h_reject_inputs(
        |i| i.trust_domain = trust_domain(TrustBundleEnvironment::Testnet),
        HO::WrongEnvironment,
    );
}

#[test]
fn reject_wrong_chain() {
    h_reject_inputs(
        |i| {
            i.trust_domain =
                custom_domain(TrustBundleEnvironment::Devnet, "bad-chain", GENESIS_HASH, ROOT_FP)
        },
        HO::WrongChain,
    );
}

#[test]
fn reject_wrong_genesis() {
    h_reject_inputs(
        |i| {
            i.trust_domain = custom_domain(
                TrustBundleEnvironment::Devnet,
                chain_for(TrustBundleEnvironment::Devnet),
                "bad-genesis",
                ROOT_FP,
            )
        },
        HO::WrongGenesis,
    );
}

#[test]
fn reject_wrong_authority_root() {
    h_reject_inputs(
        |i| {
            i.trust_domain = custom_domain(
                TrustBundleEnvironment::Devnet,
                chain_for(TrustBundleEnvironment::Devnet),
                GENESIS_HASH,
                "bad-root",
            )
        },
        HO::WrongAuthorityRoot,
    );
}

// ---- Governance / rotation tuple binding failures -------------------------

#[test]
fn reject_wrong_governance_domain() {
    h_reject_inputs(|i| i.expected_governance_domain_id = "bad".to_string(), HO::WrongGovernanceDomain);
}

#[test]
fn reject_wrong_governance_epoch() {
    h_reject_inputs(|i| i.expected_governance_epoch = GOV_EPOCH + 1, HO::WrongGovernanceEpoch);
}

#[test]
fn reject_wrong_proposal_id() {
    h_reject_inputs(|i| i.expected_proposal_id = "bad".to_string(), HO::WrongProposalId);
}

#[test]
fn reject_wrong_governance_execution_decision_id() {
    h_reject_inputs(
        |i| i.expected_governance_decision_id = "bad".to_string(),
        HO::WrongGovernanceExecutionDecisionId,
    );
}

#[test]
fn reject_wrong_governance_execution_request_id() {
    h_reject_inputs(
        |i| i.expected_governance_request_id = "bad".to_string(),
        HO::WrongGovernanceExecutionRequestId,
    );
}

#[test]
fn reject_wrong_governance_execution_intent_digest() {
    h_reject_inputs(
        |i| i.expected_governance_intent_digest = "bad".to_string(),
        HO::WrongGovernanceExecutionIntentDigest,
    );
}

#[test]
fn reject_wrong_rotation_decision_id() {
    h_reject_inputs(|i| i.expected_rotation_decision_id = "bad".to_string(), HO::WrongRotationDecisionId);
}

#[test]
fn reject_wrong_rotation_request_id() {
    h_reject_inputs(|i| i.expected_rotation_request_id = "bad".to_string(), HO::WrongRotationRequestId);
}

#[test]
fn reject_wrong_rotation_transcript_digest() {
    h_reject_inputs(
        |i| i.expected_rotation_transcript_digest = "bad".to_string(),
        HO::WrongRotationTranscriptDigest,
    );
}

#[test]
fn reject_wrong_rotation_plan_digest() {
    h_reject_inputs(|i| i.expected_rotation_plan_digest = "bad".to_string(), HO::WrongRotationPlanDigest);
}

#[test]
fn reject_wrong_lifecycle_action() {
    h_reject_inputs(|i| i.expected_lifecycle_action = LocalLifecycleAction::Retire, HO::WrongLifecycleAction);
}

#[test]
fn reject_wrong_rotation_action() {
    h_reject_inputs(
        |i| i.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove,
        HO::WrongRotationAction,
    );
}

#[test]
fn reject_wrong_authority_sequence() {
    h_reject_inputs(|i| i.expected_authority_domain_sequence = SEQ + 5, HO::WrongAuthoritySequence);
}

#[test]
fn reject_wrong_quorum() {
    h_reject_inputs(
        |i| i.expected_quorum = OnChainGovernanceQuorum { voters_voted: 1, total_voters: 10, required_quorum: 6 },
        HO::WrongQuorum,
    );
}

#[test]
fn reject_wrong_threshold() {
    h_reject_inputs(|i| i.expected_threshold = GovernanceThreshold::new(9, 6, 10), HO::WrongThreshold);
}

// ---- Validator-set tuple binding failures ---------------------------------

#[test]
fn reject_wrong_current_validator_set_digest() {
    h_reject_inputs(|i| i.expected_current_set_digest = "bad".to_string(), HO::WrongCurrentValidatorSetDigest);
}

#[test]
fn reject_wrong_proposed_validator_set_digest() {
    h_reject_inputs(|i| i.expected_proposed_set_digest = "bad".to_string(), HO::WrongProposedValidatorSetDigest);
}

#[test]
fn reject_wrong_validator_set_delta_digest() {
    h_reject_inputs(|i| i.expected_delta_digest = "bad".to_string(), HO::WrongValidatorSetDeltaDigest);
}

#[test]
fn reject_wrong_validator_set_epoch() {
    h_reject_inputs(|i| i.expected_validator_set_epoch = 9999, HO::WrongValidatorSetEpoch);
}

#[test]
fn reject_wrong_validator_set_version() {
    h_reject_inputs(|i| i.expected_validator_set_version = 9999, HO::WrongValidatorSetVersion);
}

#[test]
fn reject_wrong_proposed_validator_count() {
    h_reject_inputs(|i| i.expected_proposed_validator_count = 9999, HO::WrongProposedValidatorCount);
}

#[test]
fn reject_wrong_rotation_nonce() {
    h_reject_inputs(|i| i.expected_rotation_nonce = ROT_NONCE + 1, HO::WrongRotationNonce);
}

// ---- Current-validator-set epoch/version fail-closed preconditions --------

#[test]
fn reject_current_validator_set_epoch_leads_record() {
    h_reject_inputs(
        |i| i.expected_current_validator_set_epoch = 100_000,
        HO::WrongCurrentValidatorSetEpoch,
    );
}

#[test]
fn reject_current_validator_set_version_leads_record() {
    h_reject_inputs(
        |i| i.expected_current_validator_set_version = 100_000,
        HO::WrongCurrentValidatorSetVersion,
    );
}

// ---- Epoch-transition / nonce binding failures ----------------------------

#[test]
fn reject_wrong_epoch_transition_target_inputs() {
    h_reject_inputs(|i| i.expected_epoch_transition_target = 9999, HO::WrongEpochTransitionTarget);
}

#[test]
fn reject_wrong_epoch_transition_target_request() {
    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.proposed_epoch_transition_target = 9999;
    c.inputs.expected_epoch_transition_target = 9999;
    let d = h_eval(&c);
    assert_eq!(d.outcome, HO::WrongEpochTransitionTarget);
    assert!(d.handoff_package.is_none());
}

#[test]
fn reject_wrong_application_nonce() {
    h_reject_inputs(|i| i.expected_application_nonce = APP_NONCE + 1, HO::WrongApplicationNonce);
}

#[test]
fn reject_wrong_live_application_nonce() {
    h_reject_inputs(|i| i.expected_live_application_nonce = LIVE_APP_NONCE + 1, HO::WrongLiveApplicationNonce);
}

// ===========================================================================
// C. Authority-source rejection / fail-closed paths
// ===========================================================================

#[test]
fn reject_missing_guarded_mutation_decision() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::MissingGuardedMutationDecision,
        HO::VerifiedGuardedMutationDecisionRequired,
    );
}

#[test]
fn reject_unverified_guarded_mutation_decision() {
    let dec = guarded_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::UnverifiedGuardedMutationDecision { decision: dec },
        HO::UnverifiedGuardedMutationDecisionRejected,
    );
}

#[test]
fn reject_unverified_guarded_mutation_decision_via_verified_variant() {
    // A non-accept decision presented through the verified variant must also
    // be rejected as unverified.
    let dec = guarded_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::VerifiedGuardedMutationDecision { decision: dec },
        HO::UnverifiedGuardedMutationDecisionRejected,
    );
}

#[test]
fn reject_accepted_guarded_mutation_without_record() {
    let dec = guarded_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::AcceptedGuardedMutationWithoutRecord { decision: dec },
        HO::VerifiedGuardedMutationDecisionRequired,
    );
}

#[test]
fn reject_staged_application_decision_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::StagedApplicationDecisionWithoutGuardedMutation,
        HO::StagedApplicationDecisionAloneRejected,
    );
}

#[test]
fn reject_live_application_authorization_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::LiveApplicationAuthorizationWithoutGuardedMutation,
        HO::LiveApplicationAuthorizationAloneRejected,
    );
}

#[test]
fn reject_application_decision_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::ApplicationDecisionWithoutGuardedMutation,
        HO::ApplicationDecisionAloneRejected,
    );
}

#[test]
fn reject_rotation_plan_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::RotationPlanWithoutGuardedMutation,
        HO::RotationPlanAloneRejected,
    );
}

#[test]
fn reject_governance_execution_intent_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::GovernanceExecutionIntentWithoutGuardedMutation,
        HO::GovernanceExecutionIntentAloneRejected,
    );
}

#[test]
fn reject_governance_proof_alone() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::GovernanceProofWithoutGuardedMutation,
        HO::GovernanceProofAloneRejected,
    );
}

#[test]
fn reject_local_operator_assertion() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::LocalOperatorAssertion,
        HO::LocalOperatorProofRejected,
    );
}

#[test]
fn reject_peer_majority_assertion() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::PeerMajorityAssertion,
        HO::PeerMajorityProofRejected,
    );
}

#[test]
fn reject_custody_only_evidence() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::CustodyOnlyEvidence,
        HO::CustodyOnlyProofRejected,
    );
}

#[test]
fn reject_remote_signer_only_evidence() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::RemoteSignerOnlyEvidence,
        HO::RemoteSignerOnlyProofRejected,
    );
}

#[test]
fn reject_custody_attestation_only_evidence() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::CustodyAttestationOnlyEvidence,
        HO::CustodyAttestationOnlyProofRejected,
    );
}

#[test]
fn reject_fixture_only_guarded_mutation() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::FixtureOnlyGuardedMutation,
        HO::FixtureStagedApplicationRejectedAsProductionAuthority,
    );
}

#[test]
fn reject_arbitrary_validator_set_bytes() {
    h_reject_source(
        EpochTransitionRuntimeHandoffAuthoritySource::ArbitraryValidatorSetBytes,
        HO::ArbitraryValidatorSetBytesRejected,
    );
}

// ===========================================================================
// D. MainNet / policy refusal
// ===========================================================================

#[test]
fn reject_mainnet_trust_domain() {
    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = h_eval(&c);
    assert_eq!(d.outcome, HO::MainNetRefused);
    assert!(d.handoff_package.is_none());
}

#[test]
fn reject_mainnet_policy_unavailable() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = h_exec_with_policy(
        ProductionEpochTransitionRuntimeHandoffExecutorPolicy::MainnetProductionEpochTransitionRuntimeHandoffRequired,
    );
    let d = exec.evaluate_epoch_transition_runtime_handoff(&c.request, &c.inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::MainNetProductionEpochTransitionRuntimeHandoffUnavailable);
}

#[test]
fn reject_mainnet_policy_on_mainnet_domain_unavailable() {
    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let exec = h_exec_with_policy(
        ProductionEpochTransitionRuntimeHandoffExecutorPolicy::MainnetProductionEpochTransitionRuntimeHandoffRequired,
    );
    let d = exec.evaluate_epoch_transition_runtime_handoff(&c.request, &c.inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::MainNetProductionEpochTransitionRuntimeHandoffUnavailable);
}

#[test]
fn reject_production_policy_unavailable() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = h_exec_with_policy(
        ProductionEpochTransitionRuntimeHandoffExecutorPolicy::RequireProductionEpochTransitionRuntimeHandoff,
    );
    let d = exec.evaluate_epoch_transition_runtime_handoff(&c.request, &c.inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::ProductionEpochTransitionRuntimeHandoffUnavailable);
}

#[test]
fn reject_disabled_policy() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = h_exec_with_policy(ProductionEpochTransitionRuntimeHandoffExecutorPolicy::Disabled);
    let d = exec.evaluate_epoch_transition_runtime_handoff(&c.request, &c.inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::Disabled);
}

#[test]
fn reject_production_boundary_kind_unavailable() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = ProductionEpochTransitionRuntimeHandoffExecutor::new(
        ProductionEpochTransitionRuntimeHandoffConfig::new(
            ProductionEpochTransitionRuntimeHandoffExecutorKind::ProductionEpochTransitionRuntimeHandoff,
        ),
        ProductionEpochTransitionRuntimeHandoffExecutorPolicy::AllowSourceTestEpochTransitionRuntimeHandoff,
    );
    let d = exec.evaluate_epoch_transition_runtime_handoff(&c.request, &c.inputs, &empty_replay313());
    assert_eq!(d.outcome, HO::EpochTransitionRuntimeHandoffBoundaryUnavailable);
}

// ===========================================================================
// E. Replay / idempotency / recovery / freshness
// ===========================================================================

#[test]
fn reject_replayed_handoff() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    assert!(d.is_accept());
    let replay = vec![d.request_id.clone()];
    let d2 = h_eval_replay(&c, &replay);
    assert_eq!(
        d2.outcome,
        HO::StagedApplicationReplayRejected { staged_application_id: d.request_id.clone() }
    );
    assert!(d2.handoff_package.is_none());
}

#[test]
fn accept_when_replay_set_has_unrelated_id() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let replay = vec!["unrelated-id".to_string()];
    let d = h_eval_replay(&c, &replay);
    assert!(d.is_accept());
}

#[test]
fn recovery_clean_when_no_prior_window() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    let r = c
        .executor
        .recover_epoch_transition_runtime_handoff_window(None, pkg);
    assert!(r.is_clean());
}

#[test]
fn recovery_idempotent_replay_observed() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap().clone();
    let r = c
        .executor
        .recover_epoch_transition_runtime_handoff_window(Some(&pkg), &pkg);
    assert!(matches!(
        r,
        ProductionEpochTransitionRuntimeHandoffRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
    assert!(r.is_non_mutating());
}

#[test]
fn recovery_disabled_under_disabled_policy() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap().clone();
    let exec = h_exec_with_policy(ProductionEpochTransitionRuntimeHandoffExecutorPolicy::Disabled);
    let r = exec.recover_epoch_transition_runtime_handoff_window(Some(&pkg), &pkg);
    assert!(matches!(
        r,
        ProductionEpochTransitionRuntimeHandoffRecoveryOutcome::RecoveryDisabled
    ));
}

#[test]
fn recovery_independent_window_for_different_nonce() {
    let c1 = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d1 = h_eval(&c1);
    let pkg1 = d1.handoff_package.as_ref().unwrap().clone();
    let mut pkg2 = pkg1.clone();
    pkg2.staged_application_nonce = pkg1.staged_application_nonce + 1;
    let r = c1
        .executor
        .recover_epoch_transition_runtime_handoff_window(Some(&pkg1), &pkg2);
    assert!(r.is_clean());
}

#[test]
fn reject_stale_governance_epoch() {
    h_reject_inputs(|i| i.min_governance_epoch = GOV_EPOCH + 1, HO::StaleGovernanceEpoch);
}

#[test]
fn reject_stale_authority_sequence() {
    h_reject_inputs(|i| i.persisted_sequence = Some(SEQ + 1), HO::StaleAuthoritySequence);
}

#[test]
fn reject_stale_validator_set_epoch() {
    h_reject_inputs(|i| i.min_validator_set_epoch = 100_000, HO::StaleValidatorSetEpoch);
}

#[test]
fn reject_stale_validator_set_version() {
    h_reject_inputs(|i| i.min_validator_set_version = 100_000, HO::StaleValidatorSetVersion);
}

// ===========================================================================
// F. Source/test-bounded fixture state application
// ===========================================================================

#[test]
fn fixture_state_apply_advances_state() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    let mut state = EpochTransitionRuntimeHandoffFixtureState::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    let applied = state.apply_prepared_execution(pkg, &d.handoff_id);
    assert!(applied);
    assert_eq!(state.current_epoch, pkg.epoch_transition_target);
    assert_eq!(state.validator_set_version, pkg.validator_set_version);
    assert_eq!(state.current_set_digest, pkg.proposed_set_digest);
    assert!(state.has_applied(&d.handoff_id));
}

#[test]
fn fixture_state_apply_is_idempotent() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = h_eval(&c);
    let pkg = d.handoff_package.as_ref().unwrap();
    let mut state = EpochTransitionRuntimeHandoffFixtureState::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    assert!(state.apply_prepared_execution(pkg, &d.handoff_id));
    // Re-applying the same execution id is a no-op.
    assert!(!state.apply_prepared_execution(pkg, &d.handoff_id));
    assert_eq!(state.applied_execution_ids.len(), 1);
}

#[test]
fn fixture_state_starts_unapplied() {
    let state = EpochTransitionRuntimeHandoffFixtureState::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    assert!(!state.has_applied("anything"));
    assert!(state.applied_execution_ids.is_empty());
}

// ===========================================================================
// G. Non-mutation invariants
// ===========================================================================

#[test]
fn invariant_all_outcomes_non_mutating() {
    for sc in ALL_SC {
        let d = h_eval(&h_case(TrustBundleEnvironment::Devnet, sc));
        assert!(d.outcome.is_non_mutating());
        if let Some(pkg) = &d.handoff_package {
            assert!(pkg.is_non_mutating());
        }
    }
}

#[test]
fn invariant_default_is_disabled() {
    assert!(production_epoch_transition_runtime_handoff_executor_default_is_disabled());
}

#[test]
fn invariant_source_test_not_release_binary() {
    assert!(
        production_epoch_transition_runtime_handoff_executor_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn invariant_mainnet_refused() {
    assert!(production_epoch_transition_runtime_handoff_executor_mainnet_refused());
}

#[test]
fn invariant_is_non_mutating() {
    assert!(production_epoch_transition_runtime_handoff_executor_is_non_mutating());
}

#[test]
fn invariant_never_falls_back() {
    assert!(production_epoch_transition_runtime_handoff_executor_never_falls_back());
}

#[test]
fn invariant_no_default_runtime_wiring() {
    assert!(production_epoch_transition_runtime_handoff_executor_no_default_runtime_wiring());
}

#[test]
fn invariant_requires_verified_application_decision() {
    assert!(
        production_epoch_transition_runtime_handoff_executor_requires_verified_application_decision()
    );
}

#[test]
fn invariant_accept_authorizes_future_mutation_only() {
    let d = h_eval(&h_case(TrustBundleEnvironment::Devnet, Sc::Add));
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(d.outcome.is_non_mutating());
}

// ===========================================================================
// H. Taxonomy / C4/C5 status
// ===========================================================================

#[test]
fn policy_default_is_disabled() {
    assert!(ProductionEpochTransitionRuntimeHandoffExecutorPolicy::default().is_disabled());
}

#[test]
fn policy_tags_are_distinct() {
    use ProductionEpochTransitionRuntimeHandoffExecutorPolicy as P;
    let tags = [
        P::Disabled.tag(),
        P::AllowSourceTestEpochTransitionRuntimeHandoff.tag(),
        P::RequireProductionEpochTransitionRuntimeHandoff.tag(),
        P::MainnetProductionEpochTransitionRuntimeHandoffRequired.tag(),
    ];
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j]);
        }
    }
}

#[test]
fn kind_source_test_flag() {
    use ProductionEpochTransitionRuntimeHandoffExecutorKind as K;
    assert!(K::SourceTestEpochTransitionRuntimeHandoff.is_source_test());
    assert!(!K::Disabled.is_source_test());
    assert!(!K::ProductionEpochTransitionRuntimeHandoff.is_source_test());
}

#[test]
fn handoff_kind_tags_are_distinct() {
    let kinds = [
        HK::StageApplyNoOpAlreadySynchronized,
        HK::StageApplyValidatorAdd,
        HK::StageApplyValidatorRemove,
        HK::StageApplyValidatorMetadataUpdate,
        HK::StageApplyValidatorIdentityRotation,
        HK::StageApplyValidatorRetirement,
        HK::StageApplyEmergencyValidatorRemoval,
        HK::StageApplyAuthoritySetSynchronization,
        HK::StageApplyBulkValidatorSetRotation,
        HK::UnsupportedStagedApplication,
    ];
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert_ne!(kinds[i].tag(), kinds[j].tag());
        }
    }
}

#[test]
fn handoff_kind_from_guarded_kind_is_identity() {
    assert_eq!(
        HK::from_staged_application_kind(GK::StageApplyValidatorAdd),
        HK::StageApplyValidatorAdd
    );
    assert_eq!(
        HK::from_staged_application_kind(GK::UnsupportedStagedApplication),
        HK::UnsupportedStagedApplication
    );
    assert!(HK::UnsupportedStagedApplication.is_unsupported());
}

#[test]
fn accept_and_reject_classification() {
    let accept = h_eval(&h_case(TrustBundleEnvironment::Devnet, Sc::Add));
    assert!(accept.outcome.is_accept());
    assert!(!accept.outcome.is_reject());

    let mut c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_proposal_id = "bad".to_string();
    let reject = h_eval(&c);
    assert!(reject.outcome.is_reject());
    assert!(!reject.outcome.is_accept());
}

#[test]
fn config_and_inputs_well_formed() {
    let c = h_case(TrustBundleEnvironment::Devnet, Sc::Add);
    assert!(c.inputs.is_well_formed());
    assert!(ProductionEpochTransitionRuntimeHandoffConfig::source_test().is_well_formed());
}

#[test]
fn every_handoff_kind_is_non_mutating() {
    assert!(HK::StageApplyValidatorAdd.is_non_mutating());
    assert!(HK::UnsupportedStagedApplication.is_non_mutating());
}

#[test]
fn distinct_nonce_yields_distinct_request_id() {
    let a = production_epoch_transition_runtime_handoff_request_id(1, "idig", "pol", 5, 1);
    let b = production_epoch_transition_runtime_handoff_request_id(1, "idig", "pol", 5, 2);
    assert_ne!(a, b);
}

#[test]
fn handoff_id_and_request_id_are_domain_separated() {
    let id = production_epoch_transition_runtime_handoff_id(1, "idig", "pol", 5, 1);
    let rid = production_epoch_transition_runtime_handoff_request_id(1, "idig", "pol", 5, 1);
    assert_ne!(id, rid);
}

#[test]
fn transcript_digest_binds_outcome_tag() {
    let a = production_epoch_transition_runtime_handoff_transcript_digest(1, "rid", "idig", "accepted");
    let b = production_epoch_transition_runtime_handoff_transcript_digest(1, "rid", "idig", "rejected");
    assert_ne!(a, b);
}

#[test]
fn distinct_environments_yield_distinct_digests() {
    let dev = h_eval(&h_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let test = h_eval(&h_case(TrustBundleEnvironment::Testnet, Sc::Add));
    assert_ne!(dev.handoff_digest, test.handoff_digest);
}

#[test]
fn reject_all_scenarios_wrong_proposal() {
    for sc in ALL_SC {
        let mut c = h_case(TrustBundleEnvironment::Devnet, sc);
        c.inputs.expected_proposal_id = "bad".to_string();
        let d = h_eval(&c);
        assert_eq!(d.outcome, HO::WrongProposalId);
    }
}

// ===========================================================================
// I. Per-scenario expansion (accept + determinism + non-mutation)
// ===========================================================================

macro_rules! per_scenario_accept {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let c = h_case(TrustBundleEnvironment::Devnet, $sc);
            let d = h_eval(&c);
            assert!(d.is_accept());
            let pkg = d.handoff_package.as_ref().unwrap();
            assert_eq!(pkg.staged_kind, expected_handoff_kind($sc));
            assert!(pkg.is_non_mutating());
            // Deterministic re-evaluation.
            let d2 = h_eval(&c);
            assert_eq!(d.handoff_digest, d2.handoff_digest);
            assert_eq!(d.transcript_digest, d2.transcript_digest);
            // Fixture-state application is source/test bounded.
            let mut state =
                EpochTransitionRuntimeHandoffFixtureState::new(CUR_EPOCH, CUR_VERSION, "start");
            assert!(state.apply_prepared_execution(pkg, &d.handoff_id));
            assert_eq!(state.current_epoch, pkg.epoch_transition_target);
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
            let c = h_case(TrustBundleEnvironment::Testnet, $sc);
            let d = h_eval(&c);
            assert!(d.is_accept());
            assert_eq!(
                d.handoff_package.as_ref().unwrap().environment,
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

macro_rules! per_scenario_guarded_binding {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            // The consumed guarded-mutation decision transcript must bind for
            // every scenario.
            let mut c = h_case(TrustBundleEnvironment::Devnet, $sc);
            c.inputs.expected_guarded_mutation_decision_id = "bad".to_string();
            let d = h_eval(&c);
            assert_eq!(d.outcome, HO::GuardedMutationDecisionIdMismatch);
            assert!(d.handoff_package.is_none());
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
