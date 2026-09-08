//! Run 311 — source/test guarded epoch-transition **mutation executor**
//! boundary integration tests.
//!
//! Source/test only. Run 311 does **not** capture release-binary evidence;
//! release-binary evidence for the guarded epoch-transition mutation executor
//! boundary is deferred to **Run 312**. The tests cover:
//!
//! * A. accepted / compatible source-test guarded mutation decisions;
//! * B. staged-application / authorization / application / governance /
//!      rotation / validator-set / nonce binding failures;
//! * C. authority-source rejection / fail-closed paths;
//! * D. MainNet / policy refusal (production + mainnet fail closed);
//! * E. replay / idempotency / recovery / freshness;
//! * F. source/test-bounded in-memory fixture-ledger application;
//! * G. non-mutation invariants;
//! * H. taxonomy / C4/C5 status.
//!
//! Each accepted case composes the real Run 303 → 305 → 307 → 309 chain to
//! produce a verified, accepted Run 309 staged epoch-transition application
//! decision, then feeds that decision into the Run 311 guarded epoch-transition
//! mutation executor.
//!
//! Run 311 produces **only** a prepared, non-mutating guarded mutation-execution
//! record. It never applies a live validator-set change, never transitions a
//! consensus epoch, never writes `meta:current_epoch`, never injects a reconfig
//! block, and never mutates any durable trust state. The only mutation a
//! positive path performs is against a caller-owned in-memory
//! `GuardedEpochTransitionFixtureLedger` used exclusively by these tests.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_311.md`.

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

fn exec_with_policy(
    policy: ProductionGuardedEpochTransitionMutationExecutorPolicy,
) -> ProductionGuardedEpochTransitionMutationExecutor {
    ProductionGuardedEpochTransitionMutationExecutor::new(
        ProductionGuardedEpochTransitionMutationConfig::source_test(),
        policy,
    )
}

/// Common helper: build a Devnet/Add case, apply a mutation to the inputs, and
/// assert the resulting outcome (fail-closed, no record).
fn reject_inputs(mutate: impl FnOnce(&mut ProductionGuardedEpochTransitionMutationInputs), expected: GO) {
    let mut c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    mutate(&mut c.inputs);
    let d = gem_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.staged_application_record.is_none());
    assert!(!d.is_accept());
    assert!(d.outcome.is_non_mutating());
}

/// Common helper: build a Devnet/Add case, replace its authority source, and
/// assert the resulting outcome.
fn reject_source(source: GuardedEpochTransitionMutationAuthoritySource, expected: GO) {
    let mut c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source = source;
    let d = gem_eval(&c);
    assert_eq!(d.outcome, expected, "outcome tag: {}", d.outcome.tag());
    assert!(d.staged_application_record.is_none());
}

// ===========================================================================
// A. Accepted / compatible source-test guarded mutations
// ===========================================================================

#[test]
fn accept_all_scenarios_devnet() {
    for sc in ALL_SC {
        let c = gem_case(TrustBundleEnvironment::Devnet, sc);
        let d = gem_eval(&c);
        assert!(d.is_accept(), "scenario must accept");
        assert!(d.authorizes_future_mutation_only());
        let rec = d.staged_application_record.as_ref().unwrap();
        assert_eq!(rec.staged_kind, expected_mutation_kind(sc));
        assert_eq!(rec.guarded_mutation_nonce, GUARDED_NONCE);
        assert_eq!(rec.staged_application_nonce, STAGED_NONCE);
    }
}

#[test]
fn accept_all_scenarios_testnet() {
    for sc in ALL_SC {
        let c = gem_case(TrustBundleEnvironment::Testnet, sc);
        let d = gem_eval(&c);
        assert!(d.is_accept());
        let rec = d.staged_application_record.as_ref().unwrap();
        assert_eq!(rec.environment, TrustBundleEnvironment::Testnet);
        assert_eq!(rec.staged_kind, expected_mutation_kind(sc));
    }
}

#[test]
fn accept_outcome_carries_kind_env_target_nonce() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    match d.outcome {
        GO::AcceptedSourceTestGuardedEpochTransitionMutation {
            staged_kind,
            environment,
            staged_application_nonce,
            ..
        } => {
            assert_eq!(staged_kind, GK::StageApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(staged_application_nonce, GUARDED_NONCE);
        }
        other => panic!("expected accept, got {}", other.tag()),
    }
}

#[test]
fn accept_binds_staged_decision_transcript() {
    let stg_dec = stg_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let sid = stg_dec.staged_application_id.clone();
    let rid = stg_dec.request_id.clone();
    let idig = stg_dec.intent_digest.clone();
    let tdig = stg_dec.transcript_digest.clone();
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    assert_eq!(rec.staged_application_decision_id, sid);
    assert_eq!(rec.staged_application_request_id, rid);
    assert_eq!(rec.staged_application_intent_digest, idig);
    assert_eq!(rec.staged_application_transcript_digest, tdig);
}

#[test]
fn accept_reexposes_live_authorization_tuple() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    assert!(!rec.authorization_decision_id.is_empty());
    assert!(!rec.authorization_request_id.is_empty());
    assert!(!rec.authorization_intent_digest.is_empty());
    assert!(!rec.authorization_transcript_digest.is_empty());
}

#[test]
fn accept_reexposes_application_and_governance_tuple() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    assert!(!rec.application_decision_id.is_empty());
    assert_eq!(rec.governance_domain_id, GOV_DOMAIN);
    assert_eq!(rec.governance_epoch, GOV_EPOCH);
    assert_eq!(rec.proposal_id, PROPOSAL_ID);
}

#[test]
fn accept_deterministic_digests_under_reevaluation() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Bulk);
    let d1 = gem_eval(&c);
    let d2 = gem_eval(&c);
    assert_eq!(d1.staged_application_id, d2.staged_application_id);
    assert_eq!(d1.request_id, d2.request_id);
    assert_eq!(d1.intent_digest, d2.intent_digest);
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
}

#[test]
fn accept_record_intent_digest_matches_named_helper() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    assert_eq!(
        rec.intent_digest(),
        production_guarded_epoch_transition_mutation_intent_digest(rec)
    );
    assert_eq!(rec.intent_digest(), d.intent_digest);
}

#[test]
fn accept_distinct_scenarios_have_distinct_digests() {
    let a = gem_eval(&gem_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let b = gem_eval(&gem_case(TrustBundleEnvironment::Devnet, Sc::Remove));
    assert_ne!(a.intent_digest, b.intent_digest);
}

#[test]
fn accept_target_matches_record_epoch_transition_target() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = c.request.proposed_epoch_transition_target;
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    assert_eq!(rec.epoch_transition_target, target);
}

// ===========================================================================
// B. Staged-application-decision transcript binding failures
// ===========================================================================

#[test]
fn reject_wrong_staged_application_decision_id() {
    reject_inputs(
        |i| i.expected_staged_application_decision_id = "bad".to_string(),
        GO::StagedApplicationDecisionIdMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_request_id() {
    reject_inputs(
        |i| i.expected_staged_application_request_id = "bad".to_string(),
        GO::StagedApplicationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_intent_digest() {
    reject_inputs(
        |i| i.expected_staged_application_intent_digest = "bad".to_string(),
        GO::StagedApplicationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_transcript_digest() {
    reject_inputs(
        |i| i.expected_staged_application_transcript_digest = "bad".to_string(),
        GO::StagedApplicationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_staged_application_nonce() {
    reject_inputs(
        |i| i.expected_staged_application_nonce = STAGED_NONCE + 999,
        GO::WrongStagedApplicationNonce,
    );
}

// ---- Re-exposed live-authorization tuple binding failures -----------------

#[test]
fn reject_wrong_authorization_decision_id() {
    reject_inputs(
        |i| i.expected_authorization_decision_id = "bad".to_string(),
        GO::AuthorizationDecisionIdMismatch,
    );
}

#[test]
fn reject_wrong_authorization_request_id() {
    reject_inputs(
        |i| i.expected_authorization_request_id = "bad".to_string(),
        GO::AuthorizationDecisionRequestIdMismatch,
    );
}

#[test]
fn reject_wrong_authorization_intent_digest() {
    reject_inputs(
        |i| i.expected_authorization_intent_digest = "bad".to_string(),
        GO::AuthorizationDecisionIntentDigestMismatch,
    );
}

#[test]
fn reject_wrong_authorization_transcript_digest() {
    reject_inputs(
        |i| i.expected_authorization_transcript_digest = "bad".to_string(),
        GO::AuthorizationDecisionTranscriptMismatch,
    );
}

#[test]
fn reject_wrong_authorization_policy_id() {
    reject_inputs(
        |i| i.expected_authorization_policy_id = "bad".to_string(),
        GO::WrongAuthorizationPolicyId,
    );
}

// ---- Re-exposed application-decision tuple binding failures ---------------

#[test]
fn reject_wrong_application_decision_id() {
    reject_inputs(
        |i| i.expected_application_decision_id = "bad".to_string(),
        GO::WrongApplicationDecisionId,
    );
}

#[test]
fn reject_wrong_application_request_id() {
    reject_inputs(
        |i| i.expected_application_request_id = "bad".to_string(),
        GO::WrongApplicationRequestId,
    );
}

#[test]
fn reject_wrong_application_intent_digest() {
    reject_inputs(
        |i| i.expected_application_intent_digest = "bad".to_string(),
        GO::WrongApplicationIntentDigest,
    );
}

#[test]
fn reject_wrong_application_transcript_digest() {
    reject_inputs(
        |i| i.expected_application_transcript_digest = "bad".to_string(),
        GO::WrongApplicationTranscriptDigest,
    );
}

#[test]
fn reject_wrong_application_policy_id() {
    reject_inputs(
        |i| i.expected_application_policy_id = "bad".to_string(),
        GO::WrongApplicationPolicyId,
    );
}

// ---- Trust-domain binding failures ----------------------------------------

#[test]
fn reject_wrong_environment() {
    reject_inputs(
        |i| i.trust_domain = trust_domain(TrustBundleEnvironment::Testnet),
        GO::WrongEnvironment,
    );
}

#[test]
fn reject_wrong_chain() {
    reject_inputs(
        |i| {
            i.trust_domain =
                custom_domain(TrustBundleEnvironment::Devnet, "bad-chain", GENESIS_HASH, ROOT_FP)
        },
        GO::WrongChain,
    );
}

#[test]
fn reject_wrong_genesis() {
    reject_inputs(
        |i| {
            i.trust_domain = custom_domain(
                TrustBundleEnvironment::Devnet,
                chain_for(TrustBundleEnvironment::Devnet),
                "bad-genesis",
                ROOT_FP,
            )
        },
        GO::WrongGenesis,
    );
}

#[test]
fn reject_wrong_authority_root() {
    reject_inputs(
        |i| {
            i.trust_domain = custom_domain(
                TrustBundleEnvironment::Devnet,
                chain_for(TrustBundleEnvironment::Devnet),
                GENESIS_HASH,
                "bad-root",
            )
        },
        GO::WrongAuthorityRoot,
    );
}

// ---- Governance / rotation tuple binding failures -------------------------

#[test]
fn reject_wrong_governance_domain() {
    reject_inputs(|i| i.expected_governance_domain_id = "bad".to_string(), GO::WrongGovernanceDomain);
}

#[test]
fn reject_wrong_governance_epoch() {
    reject_inputs(|i| i.expected_governance_epoch = GOV_EPOCH + 1, GO::WrongGovernanceEpoch);
}

#[test]
fn reject_wrong_proposal_id() {
    reject_inputs(|i| i.expected_proposal_id = "bad".to_string(), GO::WrongProposalId);
}

#[test]
fn reject_wrong_governance_execution_decision_id() {
    reject_inputs(
        |i| i.expected_governance_decision_id = "bad".to_string(),
        GO::WrongGovernanceExecutionDecisionId,
    );
}

#[test]
fn reject_wrong_governance_execution_request_id() {
    reject_inputs(
        |i| i.expected_governance_request_id = "bad".to_string(),
        GO::WrongGovernanceExecutionRequestId,
    );
}

#[test]
fn reject_wrong_governance_execution_intent_digest() {
    reject_inputs(
        |i| i.expected_governance_intent_digest = "bad".to_string(),
        GO::WrongGovernanceExecutionIntentDigest,
    );
}

#[test]
fn reject_wrong_rotation_decision_id() {
    reject_inputs(|i| i.expected_rotation_decision_id = "bad".to_string(), GO::WrongRotationDecisionId);
}

#[test]
fn reject_wrong_rotation_request_id() {
    reject_inputs(|i| i.expected_rotation_request_id = "bad".to_string(), GO::WrongRotationRequestId);
}

#[test]
fn reject_wrong_rotation_transcript_digest() {
    reject_inputs(
        |i| i.expected_rotation_transcript_digest = "bad".to_string(),
        GO::WrongRotationTranscriptDigest,
    );
}

#[test]
fn reject_wrong_rotation_plan_digest() {
    reject_inputs(|i| i.expected_rotation_plan_digest = "bad".to_string(), GO::WrongRotationPlanDigest);
}

#[test]
fn reject_wrong_lifecycle_action() {
    reject_inputs(|i| i.expected_lifecycle_action = LocalLifecycleAction::Retire, GO::WrongLifecycleAction);
}

#[test]
fn reject_wrong_rotation_action() {
    reject_inputs(
        |i| i.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove,
        GO::WrongRotationAction,
    );
}

#[test]
fn reject_wrong_authority_sequence() {
    reject_inputs(|i| i.expected_authority_domain_sequence = SEQ + 5, GO::WrongAuthoritySequence);
}

#[test]
fn reject_wrong_quorum() {
    reject_inputs(
        |i| i.expected_quorum = OnChainGovernanceQuorum { voters_voted: 1, total_voters: 10, required_quorum: 6 },
        GO::WrongQuorum,
    );
}

#[test]
fn reject_wrong_threshold() {
    reject_inputs(|i| i.expected_threshold = GovernanceThreshold::new(9, 6, 10), GO::WrongThreshold);
}

// ---- Validator-set tuple binding failures ---------------------------------

#[test]
fn reject_wrong_current_validator_set_digest() {
    reject_inputs(|i| i.expected_current_set_digest = "bad".to_string(), GO::WrongCurrentValidatorSetDigest);
}

#[test]
fn reject_wrong_proposed_validator_set_digest() {
    reject_inputs(|i| i.expected_proposed_set_digest = "bad".to_string(), GO::WrongProposedValidatorSetDigest);
}

#[test]
fn reject_wrong_validator_set_delta_digest() {
    reject_inputs(|i| i.expected_delta_digest = "bad".to_string(), GO::WrongValidatorSetDeltaDigest);
}

#[test]
fn reject_wrong_validator_set_epoch() {
    reject_inputs(|i| i.expected_validator_set_epoch = 9999, GO::WrongValidatorSetEpoch);
}

#[test]
fn reject_wrong_validator_set_version() {
    reject_inputs(|i| i.expected_validator_set_version = 9999, GO::WrongValidatorSetVersion);
}

#[test]
fn reject_wrong_proposed_validator_count() {
    reject_inputs(|i| i.expected_proposed_validator_count = 9999, GO::WrongProposedValidatorCount);
}

#[test]
fn reject_wrong_rotation_nonce() {
    reject_inputs(|i| i.expected_rotation_nonce = ROT_NONCE + 1, GO::WrongRotationNonce);
}

// ---- Epoch-transition / nonce binding failures ----------------------------

#[test]
fn reject_wrong_epoch_transition_target() {
    reject_inputs(|i| i.expected_epoch_transition_target = 9999, GO::WrongEpochTransitionTarget);
}

#[test]
fn reject_wrong_application_nonce() {
    reject_inputs(|i| i.expected_application_nonce = APP_NONCE + 1, GO::WrongApplicationNonce);
}

#[test]
fn reject_wrong_live_application_nonce() {
    reject_inputs(|i| i.expected_live_application_nonce = LIVE_APP_NONCE + 1, GO::WrongLiveApplicationNonce);
}

// ===========================================================================
// C. Authority-source rejection / fail-closed paths
// ===========================================================================

#[test]
fn reject_missing_staged_application_decision() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::MissingStagedApplicationDecision,
        GO::VerifiedStagedApplicationDecisionRequired,
    );
}

#[test]
fn reject_unverified_staged_application_decision() {
    let dec = stg_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::UnverifiedStagedApplicationDecision { decision: dec },
        GO::UnverifiedStagedApplicationDecisionRejected,
    );
}

#[test]
fn reject_accepted_staged_application_without_record() {
    let dec = stg_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::AcceptedStagedApplicationWithoutRecord { decision: dec },
        GO::VerifiedStagedApplicationDecisionRequired,
    );
}

#[test]
fn reject_application_decision_alone() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::ApplicationDecisionWithoutStagedApplication,
        GO::ApplicationDecisionAloneRejected,
    );
}

#[test]
fn reject_rotation_plan_alone() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::RotationPlanWithoutStagedApplication,
        GO::RotationPlanAloneRejected,
    );
}

#[test]
fn reject_governance_execution_intent_alone() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::GovernanceExecutionIntentWithoutStagedApplication,
        GO::GovernanceExecutionIntentAloneRejected,
    );
}

#[test]
fn reject_governance_proof_alone() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::GovernanceProofWithoutStagedApplication,
        GO::GovernanceProofAloneRejected,
    );
}

#[test]
fn reject_local_operator_assertion() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::LocalOperatorAssertion,
        GO::LocalOperatorProofRejected,
    );
}

#[test]
fn reject_peer_majority_assertion() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::PeerMajorityAssertion,
        GO::PeerMajorityProofRejected,
    );
}

#[test]
fn reject_custody_only_evidence() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::CustodyOnlyEvidence,
        GO::CustodyOnlyProofRejected,
    );
}

#[test]
fn reject_remote_signer_only_evidence() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::RemoteSignerOnlyEvidence,
        GO::RemoteSignerOnlyProofRejected,
    );
}

#[test]
fn reject_custody_attestation_only_evidence() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::CustodyAttestationOnlyEvidence,
        GO::CustodyAttestationOnlyProofRejected,
    );
}

#[test]
fn reject_fixture_only_staged_application() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::FixtureOnlyStagedApplication,
        GO::FixtureStagedApplicationRejectedAsProductionAuthority,
    );
}

#[test]
fn reject_arbitrary_validator_set_bytes() {
    reject_source(
        GuardedEpochTransitionMutationAuthoritySource::ArbitraryValidatorSetBytes,
        GO::ArbitraryValidatorSetBytesRejected,
    );
}

// ===========================================================================
// D. MainNet / policy refusal
// ===========================================================================

#[test]
fn reject_mainnet_trust_domain() {
    let mut c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = gem_eval(&c);
    assert_eq!(d.outcome, GO::MainNetRefused);
    assert!(d.staged_application_record.is_none());
}

#[test]
fn reject_mainnet_policy_unavailable() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = exec_with_policy(
        ProductionGuardedEpochTransitionMutationExecutorPolicy::MainnetProductionGuardedEpochTransitionMutationRequired,
    );
    let d = exec.evaluate_guarded_epoch_transition_mutation(&c.request, &c.inputs, &empty_replay311());
    assert_eq!(d.outcome, GO::MainNetProductionGuardedEpochTransitionMutationUnavailable);
}

#[test]
fn reject_mainnet_policy_on_mainnet_domain_unavailable() {
    let mut c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let exec = exec_with_policy(
        ProductionGuardedEpochTransitionMutationExecutorPolicy::MainnetProductionGuardedEpochTransitionMutationRequired,
    );
    let d = exec.evaluate_guarded_epoch_transition_mutation(&c.request, &c.inputs, &empty_replay311());
    assert_eq!(d.outcome, GO::MainNetProductionGuardedEpochTransitionMutationUnavailable);
}

#[test]
fn reject_production_policy_unavailable() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = exec_with_policy(
        ProductionGuardedEpochTransitionMutationExecutorPolicy::RequireProductionGuardedEpochTransitionMutation,
    );
    let d = exec.evaluate_guarded_epoch_transition_mutation(&c.request, &c.inputs, &empty_replay311());
    assert_eq!(d.outcome, GO::ProductionGuardedEpochTransitionMutationUnavailable);
}

#[test]
fn reject_disabled_policy() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = exec_with_policy(ProductionGuardedEpochTransitionMutationExecutorPolicy::Disabled);
    let d = exec.evaluate_guarded_epoch_transition_mutation(&c.request, &c.inputs, &empty_replay311());
    assert_eq!(d.outcome, GO::Disabled);
}

#[test]
fn reject_production_boundary_kind_unavailable() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = ProductionGuardedEpochTransitionMutationExecutor::new(
        ProductionGuardedEpochTransitionMutationConfig::new(
            ProductionGuardedEpochTransitionMutationExecutorKind::ProductionGuardedEpochTransitionMutation,
        ),
        ProductionGuardedEpochTransitionMutationExecutorPolicy::AllowSourceTestGuardedEpochTransitionMutation,
    );
    let d = exec.evaluate_guarded_epoch_transition_mutation(&c.request, &c.inputs, &empty_replay311());
    assert_eq!(d.outcome, GO::GuardedEpochTransitionMutationBoundaryUnavailable);
}

// ===========================================================================
// E. Replay / idempotency / recovery / freshness
// ===========================================================================

#[test]
fn reject_replayed_staged_application() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    assert!(d.is_accept());
    let replay = vec![d.request_id.clone()];
    let d2 = gem_eval_replay(&c, &replay);
    assert_eq!(
        d2.outcome,
        GO::StagedApplicationReplayRejected { staged_application_id: d.request_id.clone() }
    );
    assert!(d2.staged_application_record.is_none());
}

#[test]
fn accept_when_replay_set_has_unrelated_id() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let replay = vec!["unrelated-id".to_string()];
    let d = gem_eval_replay(&c, &replay);
    assert!(d.is_accept());
}

#[test]
fn recovery_clean_when_no_prior_window() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    let r = c
        .executor
        .recover_guarded_epoch_transition_mutation_window(None, rec);
    assert!(r.is_clean());
}

#[test]
fn recovery_idempotent_replay_observed() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap().clone();
    let r = c
        .executor
        .recover_guarded_epoch_transition_mutation_window(Some(&rec), &rec);
    assert!(matches!(
        r,
        ProductionGuardedEpochTransitionMutationRecoveryOutcome::IdempotentReplayObserved { .. }
    ));
    assert!(r.is_non_mutating());
}

#[test]
fn recovery_disabled_under_disabled_policy() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap().clone();
    let exec = exec_with_policy(ProductionGuardedEpochTransitionMutationExecutorPolicy::Disabled);
    let r = exec.recover_guarded_epoch_transition_mutation_window(Some(&rec), &rec);
    assert!(matches!(
        r,
        ProductionGuardedEpochTransitionMutationRecoveryOutcome::RecoveryDisabled
    ));
}

#[test]
fn reject_stale_governance_epoch() {
    reject_inputs(|i| i.min_governance_epoch = GOV_EPOCH + 1, GO::StaleGovernanceEpoch);
}

#[test]
fn reject_stale_authority_sequence() {
    reject_inputs(|i| i.persisted_sequence = Some(SEQ + 1), GO::StaleAuthoritySequence);
}

#[test]
fn reject_stale_validator_set_epoch() {
    reject_inputs(|i| i.min_validator_set_epoch = 100_000, GO::StaleValidatorSetEpoch);
}

#[test]
fn reject_stale_validator_set_version() {
    reject_inputs(|i| i.min_validator_set_version = 100_000, GO::StaleValidatorSetVersion);
}

// ===========================================================================
// F. Source/test-bounded fixture ledger application
// ===========================================================================

#[test]
fn fixture_ledger_apply_advances_state() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    let mut ledger = GuardedEpochTransitionFixtureLedger::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    let applied = ledger.apply_prepared_execution(rec, &d.staged_application_id);
    assert!(applied);
    assert_eq!(ledger.current_epoch, rec.epoch_transition_target);
    assert_eq!(ledger.validator_set_version, rec.validator_set_version);
    assert_eq!(ledger.current_set_digest, rec.proposed_set_digest);
    assert!(ledger.has_applied(&d.staged_application_id));
}

#[test]
fn fixture_ledger_apply_is_idempotent() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = gem_eval(&c);
    let rec = d.staged_application_record.as_ref().unwrap();
    let mut ledger = GuardedEpochTransitionFixtureLedger::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    assert!(ledger.apply_prepared_execution(rec, &d.staged_application_id));
    // Re-applying the same execution id is a no-op.
    assert!(!ledger.apply_prepared_execution(rec, &d.staged_application_id));
    assert_eq!(ledger.applied_execution_ids.len(), 1);
}

#[test]
fn fixture_ledger_starts_unapplied() {
    let ledger = GuardedEpochTransitionFixtureLedger::new(CUR_EPOCH, CUR_VERSION, "start-digest");
    assert!(!ledger.has_applied("anything"));
    assert!(ledger.applied_execution_ids.is_empty());
}

// ===========================================================================
// G. Non-mutation invariants
// ===========================================================================

#[test]
fn invariant_all_outcomes_non_mutating() {
    for sc in ALL_SC {
        let d = gem_eval(&gem_case(TrustBundleEnvironment::Devnet, sc));
        assert!(d.outcome.is_non_mutating());
        if let Some(rec) = &d.staged_application_record {
            assert!(rec.is_non_mutating());
        }
    }
}

#[test]
fn invariant_source_test_not_release_binary() {
    assert!(
        production_guarded_epoch_transition_mutation_executor_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn invariant_mainnet_refused() {
    assert!(production_guarded_epoch_transition_mutation_executor_mainnet_refused());
}

#[test]
fn invariant_is_non_mutating() {
    assert!(production_guarded_epoch_transition_mutation_executor_is_non_mutating());
}

#[test]
fn invariant_never_falls_back() {
    assert!(production_guarded_epoch_transition_mutation_executor_never_falls_back());
}

#[test]
fn invariant_no_default_runtime_wiring() {
    assert!(production_guarded_epoch_transition_mutation_executor_no_default_runtime_wiring());
}

#[test]
fn invariant_requires_verified_application_decision() {
    assert!(
        production_guarded_epoch_transition_mutation_executor_requires_verified_application_decision()
    );
}

// ===========================================================================
// H. Taxonomy / C4/C5 status
// ===========================================================================

#[test]
fn policy_default_is_disabled() {
    assert!(ProductionGuardedEpochTransitionMutationExecutorPolicy::default().is_disabled());
}

#[test]
fn policy_tags_are_distinct() {
    use ProductionGuardedEpochTransitionMutationExecutorPolicy as P;
    let tags = [
        P::Disabled.tag(),
        P::AllowSourceTestGuardedEpochTransitionMutation.tag(),
        P::RequireProductionGuardedEpochTransitionMutation.tag(),
        P::MainnetProductionGuardedEpochTransitionMutationRequired.tag(),
    ];
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j]);
        }
    }
}

#[test]
fn kind_source_test_flag() {
    use ProductionGuardedEpochTransitionMutationExecutorKind as K;
    assert!(K::SourceTestGuardedEpochTransitionMutation.is_source_test());
    assert!(!K::Disabled.is_source_test());
    assert!(!K::ProductionGuardedEpochTransitionMutation.is_source_test());
}

#[test]
fn mutation_kind_tags_are_distinct() {
    let kinds = [
        GK::StageApplyNoOpAlreadySynchronized,
        GK::StageApplyValidatorAdd,
        GK::StageApplyValidatorRemove,
        GK::StageApplyValidatorMetadataUpdate,
        GK::StageApplyValidatorIdentityRotation,
        GK::StageApplyValidatorRetirement,
        GK::StageApplyEmergencyValidatorRemoval,
        GK::StageApplyAuthoritySetSynchronization,
        GK::StageApplyBulkValidatorSetRotation,
        GK::UnsupportedStagedApplication,
    ];
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert_ne!(kinds[i].tag(), kinds[j].tag());
        }
    }
}

#[test]
fn mutation_kind_from_staged_kind_is_identity() {
    use StagedLiveValidatorSetEpochTransitionApplicationKind as SK2;
    assert_eq!(
        GK::from_staged_application_kind(SK2::StageApplyValidatorAdd),
        GK::StageApplyValidatorAdd
    );
    assert_eq!(
        GK::from_staged_application_kind(SK2::UnsupportedStagedApplication),
        GK::UnsupportedStagedApplication
    );
    assert!(GK::UnsupportedStagedApplication.is_unsupported());
}

#[test]
fn accept_and_reject_classification() {
    let accept = gem_eval(&gem_case(TrustBundleEnvironment::Devnet, Sc::Add));
    assert!(accept.outcome.is_accept());
    assert!(!accept.outcome.is_reject());

    let mut c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.expected_proposal_id = "bad".to_string();
    let reject = gem_eval(&c);
    assert!(reject.outcome.is_reject());
    assert!(!reject.outcome.is_accept());
}

#[test]
fn config_and_inputs_well_formed() {
    let c = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    assert!(c.inputs.is_well_formed());
    assert!(ProductionGuardedEpochTransitionMutationConfig::source_test().is_well_formed());
}

#[test]
fn every_mutation_kind_is_non_mutating() {
    assert!(GK::StageApplyValidatorAdd.is_non_mutating());
    assert!(GK::UnsupportedStagedApplication.is_non_mutating());
}

// ===========================================================================
// I. Per-scenario expansion (accept + determinism + non-mutation)
// ===========================================================================

macro_rules! per_scenario_accept {
    ($name:ident, $sc:expr) => {
        #[test]
        fn $name() {
            let c = gem_case(TrustBundleEnvironment::Devnet, $sc);
            let d = gem_eval(&c);
            assert!(d.is_accept());
            let rec = d.staged_application_record.as_ref().unwrap();
            assert_eq!(rec.staged_kind, expected_mutation_kind($sc));
            assert!(rec.is_non_mutating());
            // Deterministic re-evaluation.
            let d2 = gem_eval(&c);
            assert_eq!(d.intent_digest, d2.intent_digest);
            assert_eq!(d.transcript_digest, d2.transcript_digest);
            // Fixture-ledger application is source/test bounded.
            let mut ledger =
                GuardedEpochTransitionFixtureLedger::new(CUR_EPOCH, CUR_VERSION, "start");
            assert!(ledger.apply_prepared_execution(rec, &d.staged_application_id));
            assert_eq!(ledger.current_epoch, rec.epoch_transition_target);
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
            let c = gem_case(TrustBundleEnvironment::Testnet, $sc);
            let d = gem_eval(&c);
            assert!(d.is_accept());
            assert_eq!(
                d.staged_application_record.as_ref().unwrap().environment,
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

#[test]
fn distinct_environments_yield_distinct_digests() {
    let dev = gem_eval(&gem_case(TrustBundleEnvironment::Devnet, Sc::Add));
    let test = gem_eval(&gem_case(TrustBundleEnvironment::Testnet, Sc::Add));
    assert_ne!(dev.intent_digest, test.intent_digest);
}

#[test]
fn distinct_nonce_yields_distinct_request_id() {
    let a = production_guarded_epoch_transition_mutation_request_id(1, "idig", "pol", 5, 1);
    let b = production_guarded_epoch_transition_mutation_request_id(1, "idig", "pol", 5, 2);
    assert_ne!(a, b);
}

#[test]
fn transcript_digest_binds_outcome_tag() {
    let a = production_guarded_epoch_transition_mutation_transcript_digest(1, "rid", "idig", "accepted");
    let b = production_guarded_epoch_transition_mutation_transcript_digest(1, "rid", "idig", "rejected");
    assert_ne!(a, b);
}

#[test]
fn recovery_independent_window_for_different_nonce() {
    let c1 = gem_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d1 = gem_eval(&c1);
    let rec1 = d1.staged_application_record.as_ref().unwrap().clone();
    let mut rec2 = rec1.clone();
    rec2.staged_application_nonce = rec1.staged_application_nonce + 1;
    let r = c1
        .executor
        .recover_guarded_epoch_transition_mutation_window(Some(&rec1), &rec2);
    assert!(r.is_clean());
}

#[test]
fn reject_all_scenarios_wrong_proposal() {
    for sc in ALL_SC {
        let mut c = gem_case(TrustBundleEnvironment::Devnet, sc);
        c.inputs.expected_proposal_id = "bad".to_string();
        let d = gem_eval(&c);
        assert_eq!(d.outcome, GO::WrongProposalId);
    }
}