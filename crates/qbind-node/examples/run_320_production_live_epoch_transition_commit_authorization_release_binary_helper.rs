//! Run 320 — release-binary helper for the Run 319 **live epoch-transition
//! commit authorization boundary**.
//!
//! Release-binary evidence for the Run 319 live epoch-transition commit
//! authorization boundary
//! (`crates/qbind-node/src/pqc_production_live_epoch_transition_commit_authorization.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 319
//! `ProductionLiveEpochTransitionCommitAuthorizationExecutor` and proves, per
//! check with PASS/FAIL, the accepted / rejection-fail-closed / MainNet-refusal
//! / replay-recovery-idempotency / non-mutation / taxonomy behavior of the real
//! executor. Each accepted case composes the real Run 303 -> 305 -> 307 -> 309
//! -> 311 -> 313 -> 315 -> 317 chain to produce a verified, accepted Run
//! 317/318 live epoch-transition mutation-execution decision (`is_accept()`
//! with `Some(execution_artifact)`), then feeds that decision into the Run 319
//! live epoch-transition commit-authorization executor, which emits only a
//! typed, deterministic, non-mutating live commit-authorization artifact.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the executor only
//! through the source/test boundary, only for DevNet/TestNet identities on the
//! accept path, and never enables any production runtime path, MainNet
//! enablement, commit-authorization default wiring, or live validator-set
//! mutation. The executor only ever produces typed non-mutating live
//! commit-authorization artifacts; it never applies a live validator-set
//! change, never transitions a consensus epoch, never calls Run 070, never
//! mutates `LivePqcTrustState`, never mutates a live validator set, consensus
//! state, or epoch counter, never calls `BasicHotStuffEngine::transition_to_epoch`,
//! never writes `meta:current_epoch`, never injects a `PAYLOAD_KIND_RECONFIG`
//! block, and never writes trust-bundle sequence or authority marker files. The
//! only mutation any positive path performs is against a caller-owned in-memory
//! `LiveEpochTransitionCommitAuthorizationFixtureState` used exclusively as
//! source/test evidence and clearly distinct from production runtime state.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_320.md`.
#![allow(dead_code)]

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

#[derive(Clone, Copy, Debug)]
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

// ===========================================================================
// Run 315 live epoch-transition execution preparation layer
// ===========================================================================

use qbind_node::pqc_production_live_epoch_transition_execution_preparation::*;

const PREP_POLICY_ID: &str = "execution-preparation-policy-1";
const PREP_NONCE: u64 = 43;

use ProductionLiveEpochTransitionExecutionPreparationOutcome as PO;
use LiveEpochTransitionExecutionPreparationKind as PK;

/// Build an accepted Run 313 epoch-transition runtime handoff decision — the
/// sole accepted Run 315 authority source.
fn handoff_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionEpochTransitionRuntimeHandoffDecision {
    let d = h_eval(&h_case(env, sc));
    assert!(d.is_accept(), "run 313 handoff decision must accept for fixture");
    d
}

/// Build a rejected (non-accept) Run 313 handoff decision for authority-source
/// negative tests.
fn handoff_decision_rejected(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionEpochTransitionRuntimeHandoffDecision {
    let mut c = h_case(env, sc);
    c.inputs.expected_proposal_id = "tampered-proposal".to_string();
    let d = h_eval(&c);
    assert!(!d.is_accept(), "tampered run 313 decision must reject");
    d
}

/// Build an accepted Run 313 handoff decision that carries no package (an
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

struct P315 {
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

fn p_case(env: TrustBundleEnvironment, sc: Sc) -> P315 {
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
    P315 {
        executor: ProductionLiveEpochTransitionExecutionPreparationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay315() -> EmptyLiveEpochTransitionExecutionPreparationReplaySet {
    EmptyLiveEpochTransitionExecutionPreparationReplaySet
}

fn p_eval(case: &P315) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    case.executor.evaluate_live_epoch_transition_execution_preparation(
        &case.request,
        &case.inputs,
        &empty_replay315(),
    )
}

fn p_eval_replay(
    case: &P315,
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

/// Build an accepted Run 315 epoch-transition runtime handoff decision — the
/// sole accepted Run 317 authority source.
fn prep_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionExecutionPreparationDecision {
    let d = p_eval(&p_case(env, sc));
    assert!(
        d.is_accept(),
        "run 315 execution-preparation decision must accept for fixture"
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
    assert!(!d.is_accept(), "tampered run 315 decision must reject");
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

struct M317 {
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

fn m_case(env: TrustBundleEnvironment, sc: Sc) -> M317 {
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
    M317 {
        executor: ProductionLiveEpochTransitionMutationExecutionExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay317() -> EmptyLiveEpochTransitionMutationExecutionReplaySet {
    EmptyLiveEpochTransitionMutationExecutionReplaySet
}

fn m_eval(case: &M317) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    case.executor.evaluate_live_epoch_transition_mutation_execution(
        &case.request,
        &case.inputs,
        &empty_replay317(),
    )
}

fn m_eval_replay(
    case: &M317,
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
// Run 319 — commit-authorization self layer (consumes verified Run 317/318
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

/// Build an accepted Run 317/318 mutation-execution decision — the sole
/// accepted Run 319 commit-authorization authority source.
fn mut_decision(
    env: TrustBundleEnvironment,
    sc: Sc,
) -> ProductionLiveEpochTransitionMutationExecutionDecision {
    let d = m_eval(&m_case(env, sc));
    assert!(
        d.is_accept(),
        "run 317 mutation-execution decision must accept for fixture"
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
    assert!(!d.is_accept(), "tampered run 317 decision must reject");
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

struct C319 {
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

fn c_case(env: TrustBundleEnvironment, sc: Sc) -> C319 {
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
    C319 {
        executor: ProductionLiveEpochTransitionCommitAuthorizationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay319() -> EmptyLiveEpochTransitionCommitAuthorizationReplaySet {
    EmptyLiveEpochTransitionCommitAuthorizationReplaySet
}

fn c_eval(case: &C319) -> ProductionLiveEpochTransitionCommitAuthorizationDecision {
    case.executor.evaluate_live_epoch_transition_commit_authorization(
        &case.request,
        &case.inputs,
        &empty_replay319(),
    )
}

fn c_eval_replay(
    case: &C319,
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

fn accept_all_scenarios_devnet() {
    for sc in ALL_SC {
        let c = c_case(TrustBundleEnvironment::Devnet, sc);
        let d = c_eval(&c);
        assert!(d.is_accept(), "scenario must accept");
        assert!(d.authorizes_future_mutation_only());
        let art = d.commit_authorization_artifact.as_ref().unwrap();
        assert_eq!(art.staged_kind, expected_cmt_kind(sc));
        assert_eq!(art.commit_authorization_nonce, CMT_NONCE);
        assert_eq!(art.mutation_execution_nonce, MUT_NONCE);
        assert_eq!(art.guarded_mutation_nonce, GUARDED_NONCE);
        assert_eq!(art.staged_application_nonce, STAGED_NONCE);
    }
}

fn accept_all_scenarios_testnet() {
    for sc in ALL_SC {
        let c = c_case(TrustBundleEnvironment::Testnet, sc);
        let d = c_eval(&c);
        assert!(d.is_accept());
        let art = d.commit_authorization_artifact.as_ref().unwrap();
        assert_eq!(art.environment, TrustBundleEnvironment::Testnet);
        assert_eq!(art.staged_kind, expected_cmt_kind(sc));
    }
}

fn accept_outcome_carries_kind_env_target_nonce() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    match d.outcome {
        CO::AcceptedSourceTestLiveEpochTransitionCommitAuthorization {
            execution_kind,
            environment,
            epoch_transition_target,
            commit_authorization_nonce,
        } => {
            assert_eq!(execution_kind, CK::StageApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(epoch_transition_target, c.request.proposed_epoch_transition_target);
            assert_eq!(commit_authorization_nonce, CMT_NONCE);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

fn accept_artifact_reexposes_consumed_mutation_execution_transcript() {
    let dec = mut_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = dec.execution_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = c_inputs(TrustBundleEnvironment::Devnet, &dec);
    let handoff_id = dec.execution_id.clone();
    let handoff_req = dec.request_id.clone();
    let handoff_digest = dec.execution_digest.clone();
    let handoff_transcript = dec.transcript_digest.clone();
    let request = ProductionLiveEpochTransitionCommitAuthorizationRequest::new(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::VerifiedMutationExecutionDecision {
            decision: dec,
        },
        target,
        CMT_NONCE,
    );
    let exec = ProductionLiveEpochTransitionCommitAuthorizationExecutor::source_test();
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &request,
        &inputs,
        &empty_replay319(),
    );
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    assert_eq!(art.mutation_execution_decision_id, handoff_id);
    assert_eq!(art.mutation_execution_request_id, handoff_req);
    assert_eq!(art.mutation_execution_intent_digest, handoff_digest);
    assert_eq!(art.mutation_execution_transcript_digest, handoff_transcript);
}

fn accept_artifact_encodes_future_executor_preconditions() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    let art = d.commit_authorization_artifact.as_ref().unwrap();
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

fn accept_decision_ids_match_artifact_ids() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    assert_eq!(d.commit_authorization_id, art.commit_authorization_id);
    assert_eq!(d.request_id, art.request_id);
    assert_eq!(d.commit_authorization_digest, art.commit_authorization_digest);
    assert_eq!(d.transcript_digest, art.transcript_digest);
    assert!(!d.commit_authorization_id.is_empty());
    assert!(!d.request_id.is_empty());
    assert!(!d.commit_authorization_digest.is_empty());
    assert!(!d.transcript_digest.is_empty());
}

// ===========================================================================
// B. Determinism under re-evaluation
// ===========================================================================

fn deterministic_digests_under_reevaluation() {
    for sc in ALL_SC {
        let c = c_case(TrustBundleEnvironment::Devnet, sc);
        let d1 = c_eval(&c);
        let d2 = c_eval(&c);
        assert_eq!(d1.commit_authorization_id, d2.commit_authorization_id);
        assert_eq!(d1.request_id, d2.request_id);
        assert_eq!(d1.commit_authorization_digest, d2.commit_authorization_digest);
        assert_eq!(d1.transcript_digest, d2.transcript_digest);
    }
}

fn artifact_content_digest_is_stable() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Bulk);
    let d = c_eval(&c);
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    assert_eq!(art.content_digest(), art.commit_authorization_digest);
    assert_eq!(art.content_digest(), art.content_digest());
}

// ===========================================================================
// C. Consumed execution-preparation decision transcript binding failures
// ===========================================================================

fn wrong_mutation_execution_decision_id() {
    c_reject_inputs(
        |i| i.expected_mutation_execution_decision_id = "bad".to_string(),
        CO::MutationExecutionDecisionIdMismatch,
    );
}

fn wrong_mutation_execution_request_id() {
    c_reject_inputs(
        |i| i.expected_mutation_execution_request_id = "bad".to_string(),
        CO::MutationExecutionDecisionRequestIdMismatch,
    );
}

fn wrong_mutation_execution_intent_digest() {
    c_reject_inputs(
        |i| i.expected_mutation_execution_intent_digest = "bad".to_string(),
        CO::MutationExecutionDecisionIntentDigestMismatch,
    );
}

fn wrong_mutation_execution_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_mutation_execution_transcript_digest = "bad".to_string(),
        CO::MutationExecutionDecisionTranscriptMismatch,
    );
}

fn wrong_mutation_execution_nonce() {
    c_reject_inputs(
        |i| i.expected_mutation_execution_nonce = 9999,
        CO::WrongMutationExecutionNonce,
    );
}

fn tampered_mutation_execution_package_integrity_mismatch() {
    // Mutate the consumed package so its content digest no longer matches the
    // bound handoff decision digest.
    let mut dec = mut_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let target = dec.execution_artifact.as_ref().unwrap().epoch_transition_target;
    let inputs = c_inputs(TrustBundleEnvironment::Devnet, &dec);
    dec.execution_artifact.as_mut().unwrap().proposal_digest = "tampered".to_string();
    let request = ProductionLiveEpochTransitionCommitAuthorizationRequest::new(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::VerifiedMutationExecutionDecision {
            decision: dec,
        },
        target,
        CMT_NONCE,
    );
    let exec = ProductionLiveEpochTransitionCommitAuthorizationExecutor::source_test();
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &request,
        &inputs,
        &empty_replay319(),
    );
    assert_eq!(d.outcome, CO::MutationExecutionDecisionIntegrityMismatch);
    assert!(d.commit_authorization_artifact.is_none());
}

// ===========================================================================
// D. Re-exposed guarded-mutation decision transcript binding failures
// ===========================================================================

fn wrong_guarded_mutation_decision_id() {
    c_reject_inputs(
        |i| i.expected_guarded_mutation_decision_id = "bad".to_string(),
        CO::GuardedMutationDecisionIdMismatch,
    );
}

fn wrong_guarded_mutation_request_id() {
    c_reject_inputs(
        |i| i.expected_guarded_mutation_request_id = "bad".to_string(),
        CO::GuardedMutationDecisionRequestIdMismatch,
    );
}

fn wrong_guarded_mutation_intent_digest() {
    c_reject_inputs(
        |i| i.expected_guarded_mutation_intent_digest = "bad".to_string(),
        CO::GuardedMutationDecisionIntentDigestMismatch,
    );
}

fn wrong_guarded_mutation_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_guarded_mutation_transcript_digest = "bad".to_string(),
        CO::GuardedMutationDecisionTranscriptMismatch,
    );
}

fn wrong_guarded_mutation_nonce() {
    c_reject_inputs(
        |i| i.expected_guarded_mutation_nonce = 9999,
        CO::WrongGuardedMutationNonce,
    );
}

// ===========================================================================
// E. Re-exposed staged-application decision transcript binding failures
// ===========================================================================

fn wrong_staged_application_decision_id() {
    c_reject_inputs(
        |i| i.expected_staged_application_decision_id = "bad".to_string(),
        CO::StagedApplicationDecisionIdMismatch,
    );
}

fn wrong_staged_application_request_id() {
    c_reject_inputs(
        |i| i.expected_staged_application_request_id = "bad".to_string(),
        CO::StagedApplicationDecisionRequestIdMismatch,
    );
}

fn wrong_staged_application_intent_digest() {
    c_reject_inputs(
        |i| i.expected_staged_application_intent_digest = "bad".to_string(),
        CO::StagedApplicationDecisionIntentDigestMismatch,
    );
}

fn wrong_staged_application_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_staged_application_transcript_digest = "bad".to_string(),
        CO::StagedApplicationDecisionTranscriptMismatch,
    );
}

fn wrong_staged_application_nonce() {
    c_reject_inputs(
        |i| i.expected_staged_application_nonce = 9999,
        CO::WrongStagedApplicationNonce,
    );
}

// ===========================================================================
// F. Re-exposed authorization / application binding failures
// ===========================================================================

fn wrong_authorization_decision_id() {
    c_reject_inputs(
        |i| i.expected_authorization_decision_id = "bad".to_string(),
        CO::AuthorizationDecisionIdMismatch,
    );
}

fn wrong_authorization_request_id() {
    c_reject_inputs(
        |i| i.expected_authorization_request_id = "bad".to_string(),
        CO::AuthorizationDecisionRequestIdMismatch,
    );
}

fn wrong_authorization_intent_digest() {
    c_reject_inputs(
        |i| i.expected_authorization_intent_digest = "bad".to_string(),
        CO::AuthorizationDecisionIntentDigestMismatch,
    );
}

fn wrong_authorization_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_authorization_transcript_digest = "bad".to_string(),
        CO::AuthorizationDecisionTranscriptMismatch,
    );
}

fn wrong_application_decision_id() {
    c_reject_inputs(
        |i| i.expected_application_decision_id = "bad".to_string(),
        CO::WrongApplicationDecisionId,
    );
}

fn wrong_application_request_id() {
    c_reject_inputs(
        |i| i.expected_application_request_id = "bad".to_string(),
        CO::WrongApplicationRequestId,
    );
}

fn wrong_application_intent_digest() {
    c_reject_inputs(
        |i| i.expected_application_intent_digest = "bad".to_string(),
        CO::WrongApplicationIntentDigest,
    );
}

fn wrong_application_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_application_transcript_digest = "bad".to_string(),
        CO::WrongApplicationTranscriptDigest,
    );
}

fn wrong_application_policy_id() {
    c_reject_inputs(
        |i| i.expected_application_policy_id = "bad".to_string(),
        CO::WrongApplicationPolicyId,
    );
}

fn wrong_authorization_policy_id() {
    c_reject_inputs(
        |i| i.expected_authorization_policy_id = "bad".to_string(),
        CO::WrongAuthorizationPolicyId,
    );
}

// ===========================================================================
// G. Governance / rotation tuple binding failures
// ===========================================================================

fn wrong_environment() {
    c_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Testnet, "qbind-devnet", GENESIS_HASH, ROOT_FP),
        CO::WrongEnvironment,
    );
}

fn wrong_chain() {
    c_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "wrong-chain", GENESIS_HASH, ROOT_FP),
        CO::WrongChain,
    );
}

fn wrong_genesis() {
    c_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "qbind-devnet", "wrong-genesis", ROOT_FP),
        CO::WrongGenesis,
    );
}

fn wrong_authority_root() {
    c_reject_inputs(
        |i| i.trust_domain = custom_domain(TrustBundleEnvironment::Devnet, "qbind-devnet", GENESIS_HASH, "wrong-root"),
        CO::WrongAuthorityRoot,
    );
}

fn wrong_governance_domain() {
    c_reject_inputs(
        |i| i.expected_governance_domain_id = "bad".to_string(),
        CO::WrongGovernanceDomain,
    );
}

fn wrong_governance_epoch() {
    c_reject_inputs(|i| i.expected_governance_epoch = 999, CO::WrongGovernanceEpoch);
}

fn wrong_proposal_id() {
    c_reject_inputs(|i| i.expected_proposal_id = "bad".to_string(), CO::WrongProposalId);
}

fn wrong_governance_execution_intent_digest() {
    c_reject_inputs(
        |i| i.expected_governance_intent_digest = "bad".to_string(),
        CO::WrongGovernanceExecutionIntentDigest,
    );
}

fn wrong_rotation_decision_id() {
    c_reject_inputs(
        |i| i.expected_rotation_decision_id = "bad".to_string(),
        CO::WrongRotationDecisionId,
    );
}

fn wrong_rotation_request_id() {
    c_reject_inputs(
        |i| i.expected_rotation_request_id = "bad".to_string(),
        CO::WrongRotationRequestId,
    );
}

fn wrong_rotation_transcript_digest() {
    c_reject_inputs(
        |i| i.expected_rotation_transcript_digest = "bad".to_string(),
        CO::WrongRotationTranscriptDigest,
    );
}

fn wrong_rotation_plan_digest() {
    c_reject_inputs(
        |i| i.expected_rotation_plan_digest = "bad".to_string(),
        CO::WrongRotationPlanDigest,
    );
}

fn wrong_lifecycle_action() {
    c_reject_inputs(
        |i| i.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke,
        CO::WrongLifecycleAction,
    );
}

fn wrong_rotation_action() {
    c_reject_inputs(
        |i| i.expected_rotation_action = ValidatorSetRotationAction::EmergencyValidatorRemoval,
        CO::WrongRotationAction,
    );
}

fn wrong_authority_sequence() {
    c_reject_inputs(|i| i.expected_authority_domain_sequence = 999, CO::WrongAuthoritySequence);
}

// ===========================================================================
// H. Validator-set binding failures
// ===========================================================================

fn wrong_current_validator_set_digest() {
    c_reject_inputs(
        |i| i.expected_current_set_digest = "bad".to_string(),
        CO::WrongCurrentValidatorSetDigest,
    );
}

fn wrong_proposed_validator_set_digest() {
    c_reject_inputs(
        |i| i.expected_proposed_set_digest = "bad".to_string(),
        CO::WrongProposedValidatorSetDigest,
    );
}

fn wrong_validator_set_delta_digest() {
    c_reject_inputs(
        |i| i.expected_delta_digest = "bad".to_string(),
        CO::WrongValidatorSetDeltaDigest,
    );
}

fn wrong_validator_set_epoch() {
    c_reject_inputs(|i| i.expected_validator_set_epoch = 999, CO::WrongValidatorSetEpoch);
}

fn wrong_validator_set_version() {
    c_reject_inputs(|i| i.expected_validator_set_version = 999, CO::WrongValidatorSetVersion);
}

fn wrong_current_validator_set_epoch() {
    c_reject_inputs(
        |i| i.expected_current_validator_set_epoch = 999,
        CO::WrongCurrentValidatorSetEpoch,
    );
}

fn wrong_current_validator_set_version() {
    c_reject_inputs(
        |i| i.expected_current_validator_set_version = 999,
        CO::WrongCurrentValidatorSetVersion,
    );
}

fn wrong_proposed_validator_count() {
    c_reject_inputs(|i| i.expected_proposed_validator_count = 999, CO::WrongProposedValidatorCount);
}

fn wrong_rotation_nonce() {
    c_reject_inputs(|i| i.expected_rotation_nonce = 999, CO::WrongRotationNonce);
}

// ===========================================================================
// I. Epoch-transition target / nonce binding failures
// ===========================================================================

fn wrong_epoch_transition_target_inputs() {
    c_reject_inputs(|i| i.expected_epoch_transition_target = 999, CO::WrongEpochTransitionTarget);
}

fn wrong_epoch_transition_target_request() {
    let mut c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.proposed_epoch_transition_target = 4242;
    let d = c_eval(&c);
    assert_eq!(d.outcome, CO::WrongEpochTransitionTarget);
    assert!(d.commit_authorization_artifact.is_none());
}

fn wrong_application_nonce() {
    c_reject_inputs(|i| i.expected_application_nonce = 999, CO::WrongApplicationNonce);
}

fn wrong_live_application_nonce() {
    c_reject_inputs(|i| i.expected_live_application_nonce = 999, CO::WrongLiveApplicationNonce);
}

// ===========================================================================
// J. Authority-source rejection / fail-closed paths
// ===========================================================================

fn reject_missing_mutation_execution_decision() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::MissingMutationExecutionDecision,
        CO::VerifiedMutationExecutionDecisionRequired,
    );
}

fn reject_unverified_mutation_execution_decision() {
    let dec = mut_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::UnverifiedMutationExecutionDecision {
            decision: dec,
        },
        CO::UnverifiedMutationExecutionDecisionRejected,
    );
}

fn reject_verified_source_with_non_accept_decision() {
    let dec = mut_decision_rejected(TrustBundleEnvironment::Devnet, Sc::Add);
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::VerifiedMutationExecutionDecision {
            decision: dec,
        },
        CO::UnverifiedMutationExecutionDecisionRejected,
    );
}

fn reject_accepted_mutation_execution_without_package_via_verified_source() {
    let dec = mut_decision_no_artifact(TrustBundleEnvironment::Devnet, Sc::Add);
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::VerifiedMutationExecutionDecision {
            decision: dec,
        },
        CO::VerifiedMutationExecutionDecisionRequired,
    );
}

fn reject_accepted_mutation_execution_without_package_variant() {
    let dec = mut_decision_no_artifact(TrustBundleEnvironment::Devnet, Sc::Add);
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::AcceptedMutationExecutionWithoutPackage {
            decision: dec,
        },
        CO::VerifiedMutationExecutionDecisionRequired,
    );
}

fn reject_guarded_mutation_decision_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::GuardedMutationDecisionWithoutMutationExecution,
        CO::GuardedMutationDecisionAloneRejected,
    );
}

fn reject_staged_application_decision_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::StagedApplicationDecisionWithoutMutationExecution,
        CO::StagedApplicationDecisionAloneRejected,
    );
}

fn reject_live_application_authorization_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::LiveApplicationAuthorizationWithoutMutationExecution,
        CO::LiveApplicationAuthorizationAloneRejected,
    );
}

fn reject_application_decision_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::ApplicationDecisionWithoutMutationExecution,
        CO::ApplicationDecisionAloneRejected,
    );
}

fn reject_rotation_plan_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::RotationPlanWithoutMutationExecution,
        CO::RotationPlanAloneRejected,
    );
}

fn reject_governance_execution_intent_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::GovernanceExecutionIntentWithoutMutationExecution,
        CO::GovernanceExecutionIntentAloneRejected,
    );
}

fn reject_governance_proof_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::GovernanceProofWithoutMutationExecution,
        CO::GovernanceProofAloneRejected,
    );
}

fn reject_local_operator_assertion() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::LocalOperatorAssertion,
        CO::LocalOperatorProofRejected,
    );
}

fn reject_peer_majority_assertion() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::PeerMajorityAssertion,
        CO::PeerMajorityProofRejected,
    );
}

fn reject_custody_only_evidence() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::CustodyOnlyEvidence,
        CO::CustodyOnlyProofRejected,
    );
}

fn reject_remote_signer_only_evidence() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::RemoteSignerOnlyEvidence,
        CO::RemoteSignerOnlyProofRejected,
    );
}

fn reject_custody_attestation_only_evidence() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::CustodyAttestationOnlyEvidence,
        CO::CustodyAttestationOnlyProofRejected,
    );
}

fn reject_fixture_only_mutation_execution() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::FixtureOnlyMutationExecution,
        CO::FixtureStagedApplicationRejectedAsProductionAuthority,
    );
}

fn reject_arbitrary_validator_set_bytes() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::ArbitraryValidatorSetBytes,
        CO::ArbitraryValidatorSetBytesRejected,
    );
}

// ===========================================================================
// K. MainNet / policy refusal
// ===========================================================================

fn mainnet_domain_refused_under_source_test_policy() {
    let mut c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = c_eval(&c);
    assert_eq!(d.outcome, CO::MainNetRefused);
    assert!(d.commit_authorization_artifact.is_none());
}

fn mainnet_policy_unavailable() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = c_exec_with_policy(
        ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy::MainnetProductionLiveEpochTransitionCommitAuthorizationRequired,
    );
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &c.request,
        &c.inputs,
        &empty_replay319(),
    );
    assert_eq!(
        d.outcome,
        CO::MainNetProductionLiveEpochTransitionCommitAuthorizationUnavailable
    );
    assert!(d.commit_authorization_artifact.is_none());
}

fn production_policy_unavailable() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = c_exec_with_policy(
        ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy::RequireProductionLiveEpochTransitionCommitAuthorization,
    );
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &c.request,
        &c.inputs,
        &empty_replay319(),
    );
    assert_eq!(
        d.outcome,
        CO::ProductionLiveEpochTransitionCommitAuthorizationUnavailable
    );
    assert!(d.commit_authorization_artifact.is_none());
}

fn disabled_policy_fails_closed() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = c_exec_with_policy(
        ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy::Disabled,
    );
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &c.request,
        &c.inputs,
        &empty_replay319(),
    );
    assert_eq!(d.outcome, CO::Disabled);
    assert!(d.commit_authorization_artifact.is_none());
    assert!(!d.is_accept());
}

fn reserved_production_kind_fails_closed() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let exec = ProductionLiveEpochTransitionCommitAuthorizationExecutor::new(
        ProductionLiveEpochTransitionCommitAuthorizationConfig::new(
            ProductionLiveEpochTransitionCommitAuthorizationExecutorKind::ProductionLiveEpochTransitionCommitAuthorization,
        ),
        ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy::AllowSourceTestLiveEpochTransitionCommitAuthorization,
    );
    let d = exec.evaluate_live_epoch_transition_commit_authorization(
        &c.request,
        &c.inputs,
        &empty_replay319(),
    );
    assert_eq!(
        d.outcome,
        CO::LiveEpochTransitionCommitAuthorizationBoundaryUnavailable
    );
}

// ===========================================================================
// L. Replay / idempotency / freshness
// ===========================================================================

fn replay_rejected_when_id_present() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    let id = d.commit_authorization_artifact.as_ref().unwrap().request_id.clone();
    let replay = vec![id];
    let d2 = c_eval_replay(&c, &replay);
    match d2.outcome {
        CO::StagedApplicationReplayRejected { .. } => {}
        other => panic!("expected replay rejection, got {other:?}"),
    }
    assert!(d2.commit_authorization_artifact.is_none());
}

fn no_replay_when_id_absent() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let replay: Vec<String> = vec!["some-other-id".to_string()];
    let d = c_eval_replay(&c, &replay);
    assert!(d.is_accept());
}

fn stale_governance_epoch() {
    c_reject_inputs(|i| i.min_governance_epoch = u64::MAX, CO::StaleGovernanceEpoch);
}

fn stale_authority_sequence() {
    c_reject_inputs(|i| i.persisted_sequence = Some(u64::MAX), CO::StaleAuthoritySequence);
}

fn stale_validator_set_epoch() {
    c_reject_inputs(|i| i.min_validator_set_epoch = u64::MAX, CO::StaleValidatorSetEpoch);
}

fn stale_validator_set_version() {
    c_reject_inputs(|i| i.min_validator_set_version = u64::MAX, CO::StaleValidatorSetVersion);
}

// ===========================================================================
// M. Fixture-state (source/test bounded) application
// ===========================================================================

fn fixture_state_apply_is_idempotent() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    let mut state = LiveEpochTransitionCommitAuthorizationFixtureState::new(CUR_EPOCH, CUR_VERSION, "start");
    assert!(state.apply_prepared_execution(art, &d.commit_authorization_id));
    assert_eq!(state.current_epoch, art.epoch_transition_target);
    assert_eq!(state.validator_set_version, art.validator_set_version);
    assert_eq!(state.current_set_digest, art.proposed_set_digest);
    // Re-applying the same id is a no-op.
    assert!(!state.apply_prepared_execution(art, &d.commit_authorization_id));
    assert!(state.has_applied(&d.commit_authorization_id));
}

fn fixture_state_apply_all_scenarios() {
    for sc in ALL_SC {
        let c = c_case(TrustBundleEnvironment::Devnet, sc);
        let d = c_eval(&c);
        let art = d.commit_authorization_artifact.as_ref().unwrap();
        let mut state = LiveEpochTransitionCommitAuthorizationFixtureState::new(CUR_EPOCH, CUR_VERSION, "start");
        assert!(state.apply_prepared_execution(art, &d.commit_authorization_id));
        assert_eq!(state.current_epoch, art.epoch_transition_target);
    }
}

// ===========================================================================
// N. Non-mutation invariants
// ===========================================================================

fn every_outcome_is_non_mutating() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    assert!(d.outcome.is_non_mutating());
    let bad = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let dbad = c_eval_replay(&bad, &[c_eval(&bad).commit_authorization_id]);
    assert!(dbad.outcome.is_non_mutating());
}

fn accept_authorizes_future_mutation_only() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(d.authorizes_future_mutation_only());
    assert!(d.commit_authorization_artifact.as_ref().unwrap().staged_kind.is_non_mutating());
}

fn reject_never_authorizes_future_mutation() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::MissingMutationExecutionDecision,
        CO::VerifiedMutationExecutionDecisionRequired,
    );
    let mut c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    c.request.authority_source =
        LiveEpochTransitionCommitAuthorizationAuthoritySource::MissingMutationExecutionDecision;
    let d = c_eval(&c);
    assert!(!d.authorizes_future_mutation_only());
    assert!(!d.outcome.authorizes_future_mutation_only());
}

// ===========================================================================
// O. Taxonomy / policy / kind
// ===========================================================================

fn policy_predicates() {
    use ProductionLiveEpochTransitionCommitAuthorizationExecutorPolicy as Pol;
    assert!(Pol::Disabled.is_disabled());
    assert!(Pol::AllowSourceTestLiveEpochTransitionCommitAuthorization.allows_source_test());
    assert!(Pol::RequireProductionLiveEpochTransitionCommitAuthorization.is_production());
    assert!(Pol::MainnetProductionLiveEpochTransitionCommitAuthorizationRequired.is_mainnet());
    assert_eq!(Pol::default(), Pol::Disabled);
}

fn kind_predicates() {
    use ProductionLiveEpochTransitionCommitAuthorizationExecutorKind as K;
    assert!(K::SourceTestLiveEpochTransitionCommitAuthorization.is_source_test());
    assert!(!K::Disabled.is_source_test());
    assert!(!K::ProductionLiveEpochTransitionCommitAuthorization.is_source_test());
    assert_eq!(K::default(), K::Disabled);
}

fn execution_kind_mapping_matches_handoff_kind() {
    for sc in ALL_SC {
        let hk = expected_mut_kind(sc);
        let pk = CK::from_staged_application_kind(hk);
        assert_eq!(pk, expected_cmt_kind(sc));
        assert!(pk.is_non_mutating());
        assert!(!pk.is_unsupported());
    }
}

fn unsupported_staged_application_kind_is_unsupported() {
    let pk = CK::from_staged_application_kind(LiveEpochTransitionMutationExecutionKind::UnsupportedStagedApplication);
    assert!(pk.is_unsupported());
}

fn outcome_tags_are_stable_and_distinct() {
    let a = CO::MutationExecutionDecisionIdMismatch;
    let b = CO::GuardedMutationDecisionIdMismatch;
    assert_ne!(a.tag(), b.tag());
    assert_eq!(a.tag(), CO::MutationExecutionDecisionIdMismatch.tag());
    assert!(!CO::MainNetRefused.tag().is_empty());
}

fn config_and_inputs_well_formed() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    assert!(c.inputs.is_well_formed());
    assert!(ProductionLiveEpochTransitionCommitAuthorizationConfig::source_test().is_well_formed());
    // The default config still pins the supported protocol version.
    assert!(ProductionLiveEpochTransitionCommitAuthorizationConfig::default().is_well_formed());
}

// ===========================================================================
// P. Per-scenario expansion (accept + determinism + non-mutation + bindings)
// ===========================================================================

macro_rules! per_scenario_accept {
    ($name:ident, $sc:expr) => {
        fn $name() {
            let c = c_case(TrustBundleEnvironment::Devnet, $sc);
            let d = c_eval(&c);
            assert!(d.is_accept());
            let art = d.commit_authorization_artifact.as_ref().unwrap();
            assert_eq!(art.staged_kind, expected_cmt_kind($sc));
            assert!(art.staged_kind.is_non_mutating());
            let d2 = c_eval(&c);
            assert_eq!(d.commit_authorization_digest, d2.commit_authorization_digest);
            assert_eq!(d.transcript_digest, d2.transcript_digest);
            let mut state = LiveEpochTransitionCommitAuthorizationFixtureState::new(
                CUR_EPOCH,
                CUR_VERSION,
                "start",
            );
            assert!(state.apply_prepared_execution(art, &d.commit_authorization_id));
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
        fn $name() {
            let c = c_case(TrustBundleEnvironment::Testnet, $sc);
            let d = c_eval(&c);
            assert!(d.is_accept());
            assert_eq!(
                d.commit_authorization_artifact.as_ref().unwrap().environment,
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

macro_rules! per_scenario_mutation_execution_binding {
    ($name:ident, $sc:expr) => {
        fn $name() {
            let mut c = c_case(TrustBundleEnvironment::Devnet, $sc);
            c.inputs.expected_mutation_execution_decision_id = "bad".to_string();
            let d = c_eval(&c);
            assert_eq!(d.outcome, CO::MutationExecutionDecisionIdMismatch);
            assert!(d.commit_authorization_artifact.is_none());
        }
    };
}

per_scenario_mutation_execution_binding!(scenario_handoff_binding_add, Sc::Add);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_remove, Sc::Remove);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_update, Sc::Update);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_noop, Sc::NoOp);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_identity, Sc::Identity);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_retire, Sc::Retire);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_emergency, Sc::Emergency);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_authsync, Sc::AuthSync);
per_scenario_mutation_execution_binding!(scenario_handoff_binding_bulk, Sc::Bulk);

macro_rules! per_scenario_guarded_binding {
    ($name:ident, $sc:expr) => {
        fn $name() {
            let mut c = c_case(TrustBundleEnvironment::Devnet, $sc);
            c.inputs.expected_guarded_mutation_decision_id = "bad".to_string();
            let d = c_eval(&c);
            assert_eq!(d.outcome, CO::GuardedMutationDecisionIdMismatch);
            assert!(d.commit_authorization_artifact.is_none());
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
// Q. Deeper re-exposed Run 313/314 runtime-handoff authority-tuple binding
//    (additive layer introduced by Run 317 on top of the rotated Run 315
//    coverage above). All non-mutating, fail-closed.
// ===========================================================================

fn accept_reexposes_runtime_handoff_tuple_from_parent() {
    let parent = mut_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let ppkg = parent.execution_artifact.as_ref().unwrap().clone();
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    assert!(d.is_accept());
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    assert_eq!(art.runtime_handoff_decision_id, ppkg.runtime_handoff_decision_id);
    assert_eq!(art.runtime_handoff_request_id, ppkg.runtime_handoff_request_id);
    assert_eq!(art.runtime_handoff_intent_digest, ppkg.runtime_handoff_intent_digest);
    assert_eq!(
        art.runtime_handoff_transcript_digest,
        ppkg.runtime_handoff_transcript_digest
    );
    assert_eq!(art.runtime_handoff_nonce, HANDOFF_NONCE);
    assert_eq!(art.mutation_execution_nonce, MUT_NONCE);
    assert_eq!(art.commit_authorization_nonce, CMT_NONCE);
}

fn reject_runtime_handoff_decision_id_mismatch() {
    c_reject_inputs(
        |i| i.expected_runtime_handoff_decision_id = "wrong-runtime-handoff-id".to_string(),
        CO::RuntimeHandoffDecisionIdMismatch,
    );
}

fn reject_runtime_handoff_request_id_mismatch() {
    c_reject_inputs(
        |i| i.expected_runtime_handoff_request_id = "wrong-runtime-handoff-req".to_string(),
        CO::RuntimeHandoffDecisionRequestIdMismatch,
    );
}

fn reject_runtime_handoff_intent_digest_mismatch() {
    c_reject_inputs(
        |i| i.expected_runtime_handoff_intent_digest = "wrong-runtime-handoff-digest".to_string(),
        CO::RuntimeHandoffDecisionIntentDigestMismatch,
    );
}

fn reject_runtime_handoff_transcript_mismatch() {
    c_reject_inputs(
        |i| {
            i.expected_runtime_handoff_transcript_digest =
                "wrong-runtime-handoff-transcript".to_string()
        },
        CO::RuntimeHandoffDecisionTranscriptMismatch,
    );
}

fn reject_wrong_runtime_handoff_nonce() {
    c_reject_inputs(
        |i| i.expected_runtime_handoff_nonce = HANDOFF_NONCE + 100,
        CO::WrongRuntimeHandoffNonce,
    );
}

fn reject_runtime_handoff_decision_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::RuntimeHandoffDecisionWithoutMutationExecution,
        CO::RuntimeHandoffDecisionAloneRejected,
    );
}

fn runtime_handoff_alone_tag_is_stable() {
    assert_eq!(
        CO::RuntimeHandoffDecisionAloneRejected.tag(),
        "runtime-handoff-decision-alone-rejected"
    );
    assert_eq!(
        CO::RuntimeHandoffDecisionIdMismatch.tag(),
        "runtime-handoff-decision-id-mismatch"
    );
    assert_eq!(
        CO::WrongRuntimeHandoffNonce.tag(),
        "wrong-runtime-handoff-nonce"
    );
}

fn runtime_handoff_binding_rejects_are_non_mutating() {
    for o in [
        CO::RuntimeHandoffDecisionIdMismatch,
        CO::RuntimeHandoffDecisionRequestIdMismatch,
        CO::RuntimeHandoffDecisionIntentDigestMismatch,
        CO::RuntimeHandoffDecisionTranscriptMismatch,
        CO::WrongRuntimeHandoffNonce,
        CO::RuntimeHandoffDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
    }
}

fn accept_content_digest_binds_runtime_handoff_tuple() {
    // Two accepted evaluations over identical fixtures reproduce an identical
    // content digest (determinism), and the digest incorporates the
    // re-exposed runtime-handoff tuple.
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d1 = c_eval(&c);
    let d2 = c_eval(&c);
    let a1 = d1.commit_authorization_artifact.as_ref().unwrap();
    let a2 = d2.commit_authorization_artifact.as_ref().unwrap();
    assert_eq!(a1.content_digest(), a2.content_digest());
}

// ===========================================================================
// Run 319 — re-exposed Run 315/316 execution-preparation ancestor binding
// (carried through the consumed Run 317/318 mutation-execution artifact) and
// its alone-rejected authority variant.
// ===========================================================================

fn reject_execution_preparation_decision_id_mismatch() {
    c_reject_inputs(
        |i| i.expected_execution_preparation_decision_id = "wrong-exec-prep-id".to_string(),
        CO::ExecutionPreparationDecisionIdMismatch,
    );
}

fn reject_execution_preparation_request_id_mismatch() {
    c_reject_inputs(
        |i| i.expected_execution_preparation_request_id = "wrong-exec-prep-req".to_string(),
        CO::ExecutionPreparationDecisionRequestIdMismatch,
    );
}

fn reject_execution_preparation_intent_digest_mismatch() {
    c_reject_inputs(
        |i| i.expected_execution_preparation_intent_digest = "wrong-exec-prep-digest".to_string(),
        CO::ExecutionPreparationDecisionIntentDigestMismatch,
    );
}

fn reject_execution_preparation_transcript_mismatch() {
    c_reject_inputs(
        |i| {
            i.expected_execution_preparation_transcript_digest =
                "wrong-exec-prep-transcript".to_string()
        },
        CO::ExecutionPreparationDecisionTranscriptMismatch,
    );
}

fn reject_wrong_execution_preparation_nonce() {
    c_reject_inputs(
        |i| i.expected_execution_preparation_nonce = PREP_NONCE + 100,
        CO::WrongExecutionPreparationNonce,
    );
}

fn reject_execution_preparation_decision_alone() {
    c_reject_source(
        LiveEpochTransitionCommitAuthorizationAuthoritySource::ExecutionPreparationDecisionWithoutMutationExecution,
        CO::ExecutionPreparationDecisionAloneRejected,
    );
}

fn execution_preparation_alone_tag_is_stable() {
    assert_eq!(
        CO::ExecutionPreparationDecisionAloneRejected.tag(),
        "execution-preparation-decision-alone-rejected"
    );
    assert_eq!(
        CO::ExecutionPreparationDecisionIdMismatch.tag(),
        "execution-preparation-decision-id-mismatch"
    );
    assert_eq!(
        CO::WrongExecutionPreparationNonce.tag(),
        "wrong-execution-preparation-nonce"
    );
}

fn accepted_artifact_re_exposes_execution_preparation_ancestor() {
    let c = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let d = c_eval(&c);
    assert!(d.is_accept());
    let art = d.commit_authorization_artifact.as_ref().unwrap();
    // Grandparent Run 315/316 execution-preparation nonce re-exposed intact.
    assert_eq!(art.execution_preparation_nonce, PREP_NONCE);
    // Parent Run 317/318 mutation-execution nonce re-exposed intact.
    assert_eq!(art.mutation_execution_nonce, MUT_NONCE);
    // Self Run 319 commit-authorization proposed nonce.
    assert_eq!(art.commit_authorization_nonce, CMT_NONCE);
}

fn execution_preparation_binding_rejects_are_non_mutating() {
    for o in [
        CO::ExecutionPreparationDecisionIdMismatch,
        CO::ExecutionPreparationDecisionRequestIdMismatch,
        CO::ExecutionPreparationDecisionIntentDigestMismatch,
        CO::ExecutionPreparationDecisionTranscriptMismatch,
        CO::WrongExecutionPreparationNonce,
        CO::ExecutionPreparationDecisionAloneRejected,
    ] {
        assert!(o.is_non_mutating());
        assert!(!o.tag().is_empty());
    }
}
// ===========================================================================
// Release-binary harness
// ===========================================================================

fn run_case(table: &str, name: &str, f: fn(), rows: &mut Vec<(String, String, bool)>) {
    let ok = catch_unwind(AssertUnwindSafe(f)).is_ok();
    println!("case {table} {name} {}", if ok { "PASS" } else { "FAIL" });
    rows.push((table.to_string(), name.to_string(), ok));
}

fn main() {
    let outdir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            "docs/devnet/run_320_production_live_epoch_transition_commit_authorization_release_binary/helper_evidence/run_320",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "accept_all_scenarios_devnet", accept_all_scenarios_devnet as fn()),
        ("accepted_compatible", "accept_all_scenarios_testnet", accept_all_scenarios_testnet as fn()),
        ("accepted_compatible", "accept_outcome_carries_kind_env_target_nonce", accept_outcome_carries_kind_env_target_nonce as fn()),
        ("accepted_compatible", "accept_artifact_reexposes_consumed_mutation_execution_transcript", accept_artifact_reexposes_consumed_mutation_execution_transcript as fn()),
        ("accepted_compatible", "accept_artifact_encodes_future_executor_preconditions", accept_artifact_encodes_future_executor_preconditions as fn()),
        ("accepted_compatible", "accept_decision_ids_match_artifact_ids", accept_decision_ids_match_artifact_ids as fn()),
        ("accepted_compatible", "deterministic_digests_under_reevaluation", deterministic_digests_under_reevaluation as fn()),
        ("accepted_compatible", "artifact_content_digest_is_stable", artifact_content_digest_is_stable as fn()),
        ("rejection_fail_closed", "wrong_mutation_execution_decision_id", wrong_mutation_execution_decision_id as fn()),
        ("rejection_fail_closed", "wrong_mutation_execution_request_id", wrong_mutation_execution_request_id as fn()),
        ("rejection_fail_closed", "wrong_mutation_execution_intent_digest", wrong_mutation_execution_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_mutation_execution_transcript_digest", wrong_mutation_execution_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_mutation_execution_nonce", wrong_mutation_execution_nonce as fn()),
        ("rejection_fail_closed", "tampered_mutation_execution_package_integrity_mismatch", tampered_mutation_execution_package_integrity_mismatch as fn()),
        ("rejection_fail_closed", "wrong_guarded_mutation_decision_id", wrong_guarded_mutation_decision_id as fn()),
        ("rejection_fail_closed", "wrong_guarded_mutation_request_id", wrong_guarded_mutation_request_id as fn()),
        ("rejection_fail_closed", "wrong_guarded_mutation_intent_digest", wrong_guarded_mutation_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_guarded_mutation_transcript_digest", wrong_guarded_mutation_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_guarded_mutation_nonce", wrong_guarded_mutation_nonce as fn()),
        ("rejection_fail_closed", "wrong_staged_application_decision_id", wrong_staged_application_decision_id as fn()),
        ("rejection_fail_closed", "wrong_staged_application_request_id", wrong_staged_application_request_id as fn()),
        ("rejection_fail_closed", "wrong_staged_application_intent_digest", wrong_staged_application_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_staged_application_transcript_digest", wrong_staged_application_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_staged_application_nonce", wrong_staged_application_nonce as fn()),
        ("rejection_fail_closed", "wrong_authorization_decision_id", wrong_authorization_decision_id as fn()),
        ("rejection_fail_closed", "wrong_authorization_request_id", wrong_authorization_request_id as fn()),
        ("rejection_fail_closed", "wrong_authorization_intent_digest", wrong_authorization_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_authorization_transcript_digest", wrong_authorization_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_application_decision_id", wrong_application_decision_id as fn()),
        ("rejection_fail_closed", "wrong_application_request_id", wrong_application_request_id as fn()),
        ("rejection_fail_closed", "wrong_application_intent_digest", wrong_application_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_application_transcript_digest", wrong_application_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_application_policy_id", wrong_application_policy_id as fn()),
        ("rejection_fail_closed", "wrong_authorization_policy_id", wrong_authorization_policy_id as fn()),
        ("rejection_fail_closed", "wrong_environment", wrong_environment as fn()),
        ("rejection_fail_closed", "wrong_chain", wrong_chain as fn()),
        ("rejection_fail_closed", "wrong_genesis", wrong_genesis as fn()),
        ("rejection_fail_closed", "wrong_authority_root", wrong_authority_root as fn()),
        ("rejection_fail_closed", "wrong_governance_domain", wrong_governance_domain as fn()),
        ("rejection_fail_closed", "wrong_governance_epoch", wrong_governance_epoch as fn()),
        ("rejection_fail_closed", "wrong_proposal_id", wrong_proposal_id as fn()),
        ("rejection_fail_closed", "wrong_governance_execution_intent_digest", wrong_governance_execution_intent_digest as fn()),
        ("rejection_fail_closed", "wrong_rotation_decision_id", wrong_rotation_decision_id as fn()),
        ("rejection_fail_closed", "wrong_rotation_request_id", wrong_rotation_request_id as fn()),
        ("rejection_fail_closed", "wrong_rotation_transcript_digest", wrong_rotation_transcript_digest as fn()),
        ("rejection_fail_closed", "wrong_rotation_plan_digest", wrong_rotation_plan_digest as fn()),
        ("rejection_fail_closed", "wrong_lifecycle_action", wrong_lifecycle_action as fn()),
        ("rejection_fail_closed", "wrong_rotation_action", wrong_rotation_action as fn()),
        ("rejection_fail_closed", "wrong_authority_sequence", wrong_authority_sequence as fn()),
        ("rejection_fail_closed", "wrong_current_validator_set_digest", wrong_current_validator_set_digest as fn()),
        ("rejection_fail_closed", "wrong_proposed_validator_set_digest", wrong_proposed_validator_set_digest as fn()),
        ("rejection_fail_closed", "wrong_validator_set_delta_digest", wrong_validator_set_delta_digest as fn()),
        ("rejection_fail_closed", "wrong_validator_set_epoch", wrong_validator_set_epoch as fn()),
        ("rejection_fail_closed", "wrong_validator_set_version", wrong_validator_set_version as fn()),
        ("rejection_fail_closed", "wrong_current_validator_set_epoch", wrong_current_validator_set_epoch as fn()),
        ("rejection_fail_closed", "wrong_current_validator_set_version", wrong_current_validator_set_version as fn()),
        ("rejection_fail_closed", "wrong_proposed_validator_count", wrong_proposed_validator_count as fn()),
        ("rejection_fail_closed", "wrong_rotation_nonce", wrong_rotation_nonce as fn()),
        ("rejection_fail_closed", "wrong_epoch_transition_target_inputs", wrong_epoch_transition_target_inputs as fn()),
        ("rejection_fail_closed", "wrong_epoch_transition_target_request", wrong_epoch_transition_target_request as fn()),
        ("rejection_fail_closed", "wrong_application_nonce", wrong_application_nonce as fn()),
        ("rejection_fail_closed", "wrong_live_application_nonce", wrong_live_application_nonce as fn()),
        ("rejection_fail_closed", "reject_missing_mutation_execution_decision", reject_missing_mutation_execution_decision as fn()),
        ("rejection_fail_closed", "reject_unverified_mutation_execution_decision", reject_unverified_mutation_execution_decision as fn()),
        ("rejection_fail_closed", "reject_verified_source_with_non_accept_decision", reject_verified_source_with_non_accept_decision as fn()),
        ("rejection_fail_closed", "reject_accepted_mutation_execution_without_package_via_verified_source", reject_accepted_mutation_execution_without_package_via_verified_source as fn()),
        ("rejection_fail_closed", "reject_accepted_mutation_execution_without_package_variant", reject_accepted_mutation_execution_without_package_variant as fn()),
        ("rejection_fail_closed", "reject_guarded_mutation_decision_alone", reject_guarded_mutation_decision_alone as fn()),
        ("rejection_fail_closed", "reject_staged_application_decision_alone", reject_staged_application_decision_alone as fn()),
        ("rejection_fail_closed", "reject_live_application_authorization_alone", reject_live_application_authorization_alone as fn()),
        ("rejection_fail_closed", "reject_application_decision_alone", reject_application_decision_alone as fn()),
        ("rejection_fail_closed", "reject_rotation_plan_alone", reject_rotation_plan_alone as fn()),
        ("rejection_fail_closed", "reject_governance_execution_intent_alone", reject_governance_execution_intent_alone as fn()),
        ("rejection_fail_closed", "reject_governance_proof_alone", reject_governance_proof_alone as fn()),
        ("rejection_fail_closed", "reject_local_operator_assertion", reject_local_operator_assertion as fn()),
        ("rejection_fail_closed", "reject_peer_majority_assertion", reject_peer_majority_assertion as fn()),
        ("rejection_fail_closed", "reject_custody_only_evidence", reject_custody_only_evidence as fn()),
        ("rejection_fail_closed", "reject_remote_signer_only_evidence", reject_remote_signer_only_evidence as fn()),
        ("rejection_fail_closed", "reject_custody_attestation_only_evidence", reject_custody_attestation_only_evidence as fn()),
        ("rejection_fail_closed", "reject_fixture_only_mutation_execution", reject_fixture_only_mutation_execution as fn()),
        ("rejection_fail_closed", "reject_arbitrary_validator_set_bytes", reject_arbitrary_validator_set_bytes as fn()),
        ("mainnet_authority_policy", "mainnet_domain_refused_under_source_test_policy", mainnet_domain_refused_under_source_test_policy as fn()),
        ("mainnet_authority_policy", "mainnet_policy_unavailable", mainnet_policy_unavailable as fn()),
        ("mainnet_authority_policy", "production_policy_unavailable", production_policy_unavailable as fn()),
        ("mainnet_authority_policy", "disabled_policy_fails_closed", disabled_policy_fails_closed as fn()),
        ("mainnet_authority_policy", "reserved_production_kind_fails_closed", reserved_production_kind_fails_closed as fn()),
        ("replay_recovery_idempotency", "replay_rejected_when_id_present", replay_rejected_when_id_present as fn()),
        ("replay_recovery_idempotency", "no_replay_when_id_absent", no_replay_when_id_absent as fn()),
        ("replay_recovery_idempotency", "stale_governance_epoch", stale_governance_epoch as fn()),
        ("replay_recovery_idempotency", "stale_authority_sequence", stale_authority_sequence as fn()),
        ("replay_recovery_idempotency", "stale_validator_set_epoch", stale_validator_set_epoch as fn()),
        ("replay_recovery_idempotency", "stale_validator_set_version", stale_validator_set_version as fn()),
        ("fixture_state", "fixture_state_apply_is_idempotent", fixture_state_apply_is_idempotent as fn()),
        ("fixture_state", "fixture_state_apply_all_scenarios", fixture_state_apply_all_scenarios as fn()),
        ("non_mutation", "every_outcome_is_non_mutating", every_outcome_is_non_mutating as fn()),
        ("accepted_compatible", "accept_authorizes_future_mutation_only", accept_authorizes_future_mutation_only as fn()),
        ("non_mutation", "reject_never_authorizes_future_mutation", reject_never_authorizes_future_mutation as fn()),
        ("reachability_taxonomy", "policy_predicates", policy_predicates as fn()),
        ("reachability_taxonomy", "kind_predicates", kind_predicates as fn()),
        ("reachability_taxonomy", "execution_kind_mapping_matches_handoff_kind", execution_kind_mapping_matches_handoff_kind as fn()),
        ("reachability_taxonomy", "unsupported_staged_application_kind_is_unsupported", unsupported_staged_application_kind_is_unsupported as fn()),
        ("reachability_taxonomy", "outcome_tags_are_stable_and_distinct", outcome_tags_are_stable_and_distinct as fn()),
        ("reachability_taxonomy", "config_and_inputs_well_formed", config_and_inputs_well_formed as fn()),
        ("accepted_compatible", "scenario_accept_add", scenario_accept_add as fn()),
        ("accepted_compatible", "scenario_accept_remove", scenario_accept_remove as fn()),
        ("accepted_compatible", "scenario_accept_update", scenario_accept_update as fn()),
        ("accepted_compatible", "scenario_accept_noop", scenario_accept_noop as fn()),
        ("accepted_compatible", "scenario_accept_identity", scenario_accept_identity as fn()),
        ("accepted_compatible", "scenario_accept_retire", scenario_accept_retire as fn()),
        ("accepted_compatible", "scenario_accept_emergency", scenario_accept_emergency as fn()),
        ("accepted_compatible", "scenario_accept_authsync", scenario_accept_authsync as fn()),
        ("accepted_compatible", "scenario_accept_bulk", scenario_accept_bulk as fn()),
        ("accepted_compatible", "scenario_testnet_accept_add", scenario_testnet_accept_add as fn()),
        ("accepted_compatible", "scenario_testnet_accept_remove", scenario_testnet_accept_remove as fn()),
        ("accepted_compatible", "scenario_testnet_accept_update", scenario_testnet_accept_update as fn()),
        ("accepted_compatible", "scenario_testnet_accept_noop", scenario_testnet_accept_noop as fn()),
        ("accepted_compatible", "scenario_testnet_accept_identity", scenario_testnet_accept_identity as fn()),
        ("accepted_compatible", "scenario_testnet_accept_retire", scenario_testnet_accept_retire as fn()),
        ("accepted_compatible", "scenario_testnet_accept_emergency", scenario_testnet_accept_emergency as fn()),
        ("accepted_compatible", "scenario_testnet_accept_authsync", scenario_testnet_accept_authsync as fn()),
        ("accepted_compatible", "scenario_testnet_accept_bulk", scenario_testnet_accept_bulk as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_add", scenario_handoff_binding_add as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_remove", scenario_handoff_binding_remove as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_update", scenario_handoff_binding_update as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_noop", scenario_handoff_binding_noop as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_identity", scenario_handoff_binding_identity as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_retire", scenario_handoff_binding_retire as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_emergency", scenario_handoff_binding_emergency as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_authsync", scenario_handoff_binding_authsync as fn()),
        ("rejection_fail_closed", "scenario_handoff_binding_bulk", scenario_handoff_binding_bulk as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_add", scenario_guarded_binding_add as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_remove", scenario_guarded_binding_remove as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_update", scenario_guarded_binding_update as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_noop", scenario_guarded_binding_noop as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_identity", scenario_guarded_binding_identity as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_retire", scenario_guarded_binding_retire as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_emergency", scenario_guarded_binding_emergency as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_authsync", scenario_guarded_binding_authsync as fn()),
        ("rejection_fail_closed", "scenario_guarded_binding_bulk", scenario_guarded_binding_bulk as fn()),
        ("accepted_compatible", "accept_reexposes_runtime_handoff_tuple_from_parent", accept_reexposes_runtime_handoff_tuple_from_parent as fn()),
        ("rejection_fail_closed", "reject_runtime_handoff_decision_id_mismatch", reject_runtime_handoff_decision_id_mismatch as fn()),
        ("rejection_fail_closed", "reject_runtime_handoff_request_id_mismatch", reject_runtime_handoff_request_id_mismatch as fn()),
        ("rejection_fail_closed", "reject_runtime_handoff_intent_digest_mismatch", reject_runtime_handoff_intent_digest_mismatch as fn()),
        ("rejection_fail_closed", "reject_runtime_handoff_transcript_mismatch", reject_runtime_handoff_transcript_mismatch as fn()),
        ("rejection_fail_closed", "reject_wrong_runtime_handoff_nonce", reject_wrong_runtime_handoff_nonce as fn()),
        ("rejection_fail_closed", "reject_runtime_handoff_decision_alone", reject_runtime_handoff_decision_alone as fn()),
        ("reachability_taxonomy", "runtime_handoff_alone_tag_is_stable", runtime_handoff_alone_tag_is_stable as fn()),
        ("non_mutation", "runtime_handoff_binding_rejects_are_non_mutating", runtime_handoff_binding_rejects_are_non_mutating as fn()),
        ("accepted_compatible", "accept_content_digest_binds_runtime_handoff_tuple", accept_content_digest_binds_runtime_handoff_tuple as fn()),
        ("rejection_fail_closed", "reject_execution_preparation_decision_id_mismatch", reject_execution_preparation_decision_id_mismatch as fn()),
        ("rejection_fail_closed", "reject_execution_preparation_request_id_mismatch", reject_execution_preparation_request_id_mismatch as fn()),
        ("rejection_fail_closed", "reject_execution_preparation_intent_digest_mismatch", reject_execution_preparation_intent_digest_mismatch as fn()),
        ("rejection_fail_closed", "reject_execution_preparation_transcript_mismatch", reject_execution_preparation_transcript_mismatch as fn()),
        ("rejection_fail_closed", "reject_wrong_execution_preparation_nonce", reject_wrong_execution_preparation_nonce as fn()),
        ("rejection_fail_closed", "reject_execution_preparation_decision_alone", reject_execution_preparation_decision_alone as fn()),
        ("reachability_taxonomy", "execution_preparation_alone_tag_is_stable", execution_preparation_alone_tag_is_stable as fn()),
        ("accepted_compatible", "accepted_artifact_re_exposes_execution_preparation_ancestor", accepted_artifact_re_exposes_execution_preparation_ancestor as fn()),
        ("non_mutation", "execution_preparation_binding_rejects_are_non_mutating", execution_preparation_binding_rejects_are_non_mutating as fn()),
    ];

    let mut rows: Vec<(String, String, bool)> = Vec::new();
    for (table, name, f) in cases {
        run_case(table, name, *f, &mut rows);
    }

    // Deterministic-digest fixture — also forces release-symbol linkage of the
    // Run 319 domain-separated digest free functions.
    let case = c_case(TrustBundleEnvironment::Devnet, Sc::Add);
    let decision = c_eval(&case);
    let artifact = decision
        .commit_authorization_artifact
        .as_ref()
        .expect("accepted Devnet Add case must carry a live commit-authorization artifact");
    // On accept, the executor derives the identifiers from the consumed Run 317
    // mutation-execution decision's execution (content) digest.
    let mut_dec = mut_decision(TrustBundleEnvironment::Devnet, Sc::Add);
    let mutation_execution_intent_digest = mut_dec.execution_digest.clone();
    let content_digest =
        production_live_epoch_transition_commit_authorization_content_digest(artifact);
    let commit_authorization_id = production_live_epoch_transition_commit_authorization_id(
        PRODUCTION_LIVE_EPOCH_TRANSITION_COMMIT_AUTHORIZATION_PROTOCOL_VERSION,
        &mutation_execution_intent_digest,
        &case.inputs.commit_authorization_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.commit_authorization_nonce,
    );
    let request_id = production_live_epoch_transition_commit_authorization_request_id(
        PRODUCTION_LIVE_EPOCH_TRANSITION_COMMIT_AUTHORIZATION_PROTOCOL_VERSION,
        &mutation_execution_intent_digest,
        &case.inputs.commit_authorization_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.commit_authorization_nonce,
    );
    let outcome_tag = decision.outcome.tag();
    let transcript_digest =
        production_live_epoch_transition_commit_authorization_transcript_digest(
            PRODUCTION_LIVE_EPOCH_TRANSITION_COMMIT_AUTHORIZATION_PROTOCOL_VERSION,
            &request_id,
            &content_digest,
            outcome_tag,
        );

    let mut digest_body = String::new();
    digest_body.push_str(&format!(
        "mutation_execution_intent_digest={mutation_execution_intent_digest}\n"
    ));
    for sc in ALL_SC {
        let case = c_case(TrustBundleEnvironment::Devnet, sc);
        let decision = c_eval(&case);
        digest_body.push_str(&format!("scenario={:?}\n", sc));
        digest_body.push_str(&format!("commit_authorization_id={}\n", decision.commit_authorization_id));
        digest_body.push_str(&format!("request_id={}\n", decision.request_id));
        digest_body.push_str(&format!("commit_authorization_digest={}\n", decision.commit_authorization_digest));
        digest_body.push_str(&format!(
            "content_digest={}\n",
            decision
                .commit_authorization_artifact
                .as_ref()
                .expect("accepted scenario must carry artifact")
                .content_digest()
        ));
        digest_body.push_str(&format!("transcript_digest={}\n", decision.transcript_digest));
    }
    digest_body.push_str(&format!("named_commit_authorization_id={commit_authorization_id}\n"));
    digest_body.push_str(&format!("named_request_id={request_id}\n"));
    digest_body.push_str(&format!("named_content_digest={content_digest}\n"));
    digest_body.push_str(&format!("named_transcript_digest={transcript_digest}\n"));
    digest_body.push_str(&format!("outcome_tag={outcome_tag}\n"));
    fs::write(
        outdir.join("fixtures/run_320_deterministic_digests.txt"),
        &digest_body,
    )
    .expect("write deterministic-digest fixture");

    // Recovery / idempotency fixture — forces release-symbol linkage of the
    // Run 319 non-mutating recovery window over the typed
    // `ProductionLiveEpochTransitionCommitAuthorizationArtifact` and its
    // `ProductionLiveEpochTransitionCommitAuthorizationRecoveryOutcome`.
    let recover_exec = ProductionLiveEpochTransitionCommitAuthorizationExecutor::source_test();
    let current_artifact: &ProductionLiveEpochTransitionCommitAuthorizationArtifact = artifact;
    let clean: ProductionLiveEpochTransitionCommitAuthorizationRecoveryOutcome =
        recover_exec.recover_live_epoch_transition_commit_authorization_window(
            None,
            current_artifact,
        );
    let idempotent: ProductionLiveEpochTransitionCommitAuthorizationRecoveryOutcome =
        recover_exec.recover_live_epoch_transition_commit_authorization_window(
            Some(current_artifact),
            current_artifact,
        );
    assert!(clean.is_clean(), "no-prior window must be clean");
    assert!(clean.is_non_mutating() && idempotent.is_non_mutating());
    assert!(
        matches!(
            idempotent,
            ProductionLiveEpochTransitionCommitAuthorizationRecoveryOutcome::IdempotentReplayObserved { .. }
        ),
        "byte-identical prior window must be idempotent replay"
    );
    let mut recovery_body = String::new();
    recovery_body.push_str(&format!("no_prior_window_clean={}\n", clean.is_clean()));
    recovery_body.push_str(&format!(
        "idempotent_replay_observed={}\n",
        matches!(
            idempotent,
            ProductionLiveEpochTransitionCommitAuthorizationRecoveryOutcome::IdempotentReplayObserved { .. }
        )
    ));
    recovery_body.push_str("recovery_is_non_mutating=true\n");
    fs::write(
        outdir.join("fixtures/run_320_recovery_window.txt"),
        &recovery_body,
    )
    .expect("write recovery-window fixture");

    // Per-table tallies preserving first-seen order.
    let mut table_order: Vec<String> = Vec::new();
    let mut pass: BTreeMap<String, usize> = BTreeMap::new();
    let mut fail: BTreeMap<String, usize> = BTreeMap::new();
    for (table, _name, ok) in &rows {
        if !table_order.iter().any(|t| t == table) {
            table_order.push(table.clone());
        }
        if *ok {
            *pass.entry(table.clone()).or_insert(0) += 1;
        } else {
            *fail.entry(table.clone()).or_insert(0) += 1;
        }
    }
    let total_pass = rows.iter().filter(|r| r.2).count();
    let total_fail = rows.len() - total_pass;

    let mut summary = String::new();
    summary.push_str("run_320_production_live_epoch_transition_commit_authorization_release_binary_helper\n");
    summary.push_str("boundary=crates/qbind-node/src/pqc_production_live_epoch_transition_commit_authorization.rs :: ProductionLiveEpochTransitionCommitAuthorizationExecutor (Run 319 source/test boundary)\n");
    summary.push_str("mode=release-binary example linked against release-built production library symbols; source/test executor constructor only; DevNet/TestNet accept identities only; no production/MainNet enablement; no live validator-set mutation; no epoch transition\n");
    for table in &table_order {
        let p = pass.get(table).copied().unwrap_or(0);
        let fl = fail.get(table).copied().unwrap_or(0);
        summary.push_str(&format!("table {table} pass={p} fail={fl}\n"));
    }
    summary.push_str(&format!("total_pass={total_pass}\n"));
    summary.push_str(&format!("total_fail={total_fail}\n"));
    summary.push_str(&format!("verdict={}\n", if total_fail == 0 { "PASS" } else { "FAIL" }));
    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    print!("{summary}");

    if total_fail != 0 {
        std::process::exit(1);
    }
}
