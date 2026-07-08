//! Run 308 — release-binary helper for the Run 307 **live validator-set
//! application / epoch-transition authorization boundary**.
//!
//! Release-binary evidence for the Run 307 source/test live validator-set
//! application / epoch-transition authorization boundary
//! (`crates/qbind-node/src/pqc_production_live_validator_set_application_authorization.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 307
//! [`ProductionLiveValidatorSetApplicationAuthorizationExecutor`] and proves,
//! per check with PASS/FAIL, the accepted / rejection-fail-closed /
//! MainNet-refusal / replay-recovery-idempotency / non-mutation / taxonomy
//! behavior of the real executor, including the environment / chain / genesis /
//! authority-root / governance (domain / epoch / proposal / execution-decision-id
//! / request-id / intent-digest) / rotation-decision-id / rotation-request-id /
//! rotation-transcript / rotation-plan-digest binding, the current/proposed
//! validator-set digests + delta digest + validator-set epoch/version + rotation
//! nonce + epoch-transition target + application nonce + application-decision
//! id/request-id/intent-digest/transcript-digest + live-application nonce, and
//! the application-decision-integrity check, composing the real Run 305/306
//! verified validator-set rotation *application* accept decision (itself
//! composing the Run 303/304 verified validator-set rotation plan accept
//! decision, itself composing the Run 301/302 verified governance execution
//! accept decision).
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the executor only
//! through the source/test boundary, only for DevNet/TestNet identities on the
//! accept path, and never enables any production runtime path, MainNet
//! enablement, live-validator-set-application-authorization default wiring, or
//! live validator-set mutation. The executor only ever produces typed
//! non-mutating live validator-set application authorization intents; it never
//! applies a live validator-set change, never calls Run 070, never mutates
//! `LivePqcTrustState`, never mutates a live validator set, consensus state, or
//! epoch counter, never calls `BasicHotStuffEngine::transition_to_epoch`, never
//! writes `meta:current_epoch`, never injects a `PAYLOAD_KIND_RECONFIG` block,
//! and never writes trust-bundle sequence or authority marker files. Under a
//! MainNet or production policy it never falls back to fixture / local operator
//! / peer majority / governance-proof-alone / governance-execution-intent-alone
//! / rotation-plan-alone / custody-only / remote-signer-only /
//! custody-attestation-only / arbitrary-bytes material.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_308.md`.

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
use qbind_node::pqc_production_live_validator_set_application_authorization::*;
use qbind_node::pqc_production_validator_set_rotation_application_executor::{
    EmptyValidatorSetRotationApplicationReplaySet, ProductionValidatorSetRotationApplicationDecision,
    ProductionValidatorSetRotationApplicationExecutor, ProductionValidatorSetRotationApplicationInputs,
    ProductionValidatorSetRotationApplicationRequest, ValidatorSetRotationApplicationAuthoritySource,
    ValidatorSetRotationApplicationDecisionKind,
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
const AUTH_POLICY_ID: &str = "authorization-policy-1";
const ROT_NONCE: u64 = 3;
const APP_NONCE: u64 = 11;
const LIVE_APP_NONCE: u64 = 23;
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

// ---- Run 305 application decision (composed authority input) --------------

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

/// Build an accepted Run 305 application decision (optionally carrying
/// represented custody / attestation / durable-replay evidence bindings).
fn app_decision_ev(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
    cust: Option<GovernanceExecutionCustodyBinding>,
    att: Option<GovernanceExecutionAttestationBinding>,
    dur: Option<GovernanceExecutionDurableReplayBinding>,
) -> ProductionValidatorSetRotationApplicationDecision {
    let rot = rotation_decision(env, lifecycle, requested_action, current, delta, proposed);
    let target = rot.plan.as_ref().unwrap().validator_set_epoch;
    let inputs = app_inputs305(env, lifecycle, requested_action, &rot);
    let mut request = ProductionValidatorSetRotationApplicationRequest::new(
        ValidatorSetRotationApplicationAuthoritySource::VerifiedRotationPlan { decision: rot },
        target,
        APP_NONCE,
    );
    request.custody_binding = cust;
    request.attestation_binding = att;
    request.durable_replay_binding = dur;
    let d = ProductionValidatorSetRotationApplicationExecutor::source_test()
        .evaluate_validator_set_rotation_application(
            &request,
            &inputs,
            &EmptyValidatorSetRotationApplicationReplaySet,
        );
    assert!(d.is_accept(), "run 305 application decision must accept for fixture");
    d
}

fn app_decision(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> ProductionValidatorSetRotationApplicationDecision {
    app_decision_ev(env, lifecycle, requested_action, current, delta, proposed, None, None, None)
}

// ---- Run 307 authorization case -------------------------------------------

struct Case {
    executor: ProductionLiveValidatorSetApplicationAuthorizationExecutor,
    request: ProductionLiveValidatorSetApplicationAuthorizationRequest,
    inputs: ProductionLiveValidatorSetApplicationAuthorizationInputs,
}

fn auth_inputs(
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

fn make_case(
    env: TrustBundleEnvironment,
    lifecycle: LocalLifecycleAction,
    requested_action: ValidatorSetRotationAction,
    current: CanonicalValidatorSetSnapshot,
    delta: ValidatorSetDelta,
    proposed: CanonicalValidatorSetSnapshot,
) -> Case {
    let decision = app_decision(env, lifecycle, requested_action, current, delta, proposed);
    let target = decision.application_intent.as_ref().unwrap().epoch_transition_target;
    let inputs = auth_inputs(env, lifecycle, requested_action, &decision);
    let request = ProductionLiveValidatorSetApplicationAuthorizationRequest::new(
        LiveValidatorSetApplicationAuthorizationAuthoritySource::VerifiedApplicationDecision {
            decision,
        },
        target,
        LIVE_APP_NONCE,
    );
    Case {
        executor: ProductionLiveValidatorSetApplicationAuthorizationExecutor::source_test(),
        request,
        inputs,
    }
}

fn empty_replay() -> EmptyLiveValidatorSetApplicationAuthorizationReplaySet {
    EmptyLiveValidatorSetApplicationAuthorizationReplaySet
}

fn eval(case: &Case) -> ProductionLiveValidatorSetApplicationAuthorizationDecision {
    case.executor.evaluate_live_validator_set_application_authorization(
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
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1), v4],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd, current, delta, proposed)
}

fn remove_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorRemove, current, delta, proposed)
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
    make_case(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorUpdate, current, delta, proposed)
}

fn noop_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let proposed = current_set(env);
    make_case(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::NoOpSynchronization, current, ValidatorSetDelta::empty(), proposed)
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
    make_case(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorIdentityRotation, current, delta, proposed)
}

fn retirement_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::Retire, ValidatorSetRotationAction::ValidatorRetirement, current, delta, proposed)
}

fn emergency_case(env: TrustBundleEnvironment) -> Case {
    let current = current_set(env);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1)],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::EmergencyRevoke, ValidatorSetRotationAction::EmergencyValidatorRemoval, current, delta, proposed)
}

fn bulk_case(env: TrustBundleEnvironment, action: ValidatorSetRotationAction) -> Case {
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone()), ValidatorSetChange::remove(3)]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), v4],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    make_case(env, LocalLifecycleAction::Rotate, action, current, delta, proposed)
}

use LiveValidatorSetApplicationAuthorizationKind as AK;
use ProductionLiveValidatorSetApplicationAuthorizationOutcome as O;

// ===========================================================================
// A. Accepted / compatible source-test evidence
// ===========================================================================

fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_live_validator_set_application_authorization_executor_default_is_disabled());
    let e = ProductionLiveValidatorSetApplicationAuthorizationExecutor::new(
        ProductionLiveValidatorSetApplicationAuthorizationConfig::default(),
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::default(),
    );
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = e.evaluate_live_validator_set_application_authorization(&case.request, &case.inputs, &empty_replay());
    assert_eq!(d.outcome, O::Disabled);
    assert!(!d.is_accept());
    assert!(d.authorization_intent.is_none());
}

fn a02_devnet_decision_produces_authorization() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.authorization_intent.is_some());
}

fn a03_testnet_decision_produces_authorization() {
    let d = eval(&add_case(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.authorization_intent.is_some());
}

fn a04_noop_authorization_accepted_non_mutating() {
    let d = eval(&noop_case(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    let intent = d.authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyNoOpAlreadySynchronized);
    assert!(intent.is_non_mutating());
}

fn a05_validator_add_authorization_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyValidatorAdd);
    assert!(intent.is_non_mutating());
}

fn a06_validator_remove_authorization_non_mutating() {
    let intent = eval(&remove_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyValidatorRemove);
}

fn a07_validator_update_authorization_non_mutating() {
    let intent = eval(&update_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyValidatorMetadataUpdate);
}

fn a08_validator_identity_rotation_authorization_non_mutating() {
    let intent = eval(&identity_rotation_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyValidatorIdentityRotation);
}

fn a09_validator_retirement_authorization_non_mutating() {
    let intent = eval(&retirement_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyValidatorRetirement);
}

fn a10_emergency_validator_removal_authorization_non_mutating() {
    let intent = eval(&emergency_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyEmergencyValidatorRemoval);
}

fn a11_authority_set_synchronization_authorization_non_mutating() {
    let intent = eval(&bulk_case(TrustBundleEnvironment::Devnet, ValidatorSetRotationAction::AuthoritySetSynchronization))
        .authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyAuthoritySetSynchronization);
}

fn a12_bulk_validator_set_rotation_authorization_non_mutating() {
    let intent = eval(&bulk_case(TrustBundleEnvironment::Devnet, ValidatorSetRotationAction::BulkValidatorSetRotation))
        .authorization_intent.unwrap();
    assert_eq!(intent.authorization_kind, AK::AuthorizeApplyBulkValidatorSetRotation);
}

fn a13_authorization_binds_environment_chain_genesis_root() {
    let env = TrustBundleEnvironment::Testnet;
    let intent = eval(&add_case(env)).authorization_intent.unwrap();
    assert_eq!(intent.environment, env);
    assert_eq!(intent.chain_id, chain_for(env));
    assert_eq!(intent.genesis_hash, GENESIS_HASH);
    assert_eq!(intent.authority_root_fingerprint, ROOT_FP);
    assert_eq!(intent.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

fn a14_authorization_binds_governance_tuple() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.governance_domain_id, GOV_DOMAIN);
    assert_eq!(intent.governance_epoch, GOV_EPOCH);
    assert_eq!(intent.proposal_id, PROPOSAL_ID);
    assert_eq!(intent.lifecycle_action, LocalLifecycleAction::Rotate);
    assert_eq!(intent.authority_domain_sequence, SEQ);
}

fn a15_authorization_binds_governance_execution_ids_and_digests() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.governance_decision_id, GOV_DECISION_ID);
    assert_eq!(intent.governance_request_id, GOV_REQUEST_ID);
    assert!(!intent.governance_intent_digest.is_empty());
}

fn a16_authorization_binds_rotation_ids_and_digests() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_plan_digest = case.inputs.expected_rotation_plan_digest.clone();
    let expected_transcript = case.inputs.expected_rotation_transcript_digest.clone();
    let intent = eval(&case).authorization_intent.unwrap();
    assert_eq!(intent.rotation_plan_digest, expected_plan_digest);
    assert_eq!(intent.rotation_transcript_digest, expected_transcript);
    assert!(!intent.rotation_request_id.is_empty());
    assert_eq!(intent.rotation_decision_id, GOV_DECISION_ID);
}

fn a17_authorization_binds_application_decision_tuple() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_id = case.inputs.expected_application_decision_id.clone();
    let expected_req = case.inputs.expected_application_request_id.clone();
    let expected_idig = case.inputs.expected_application_intent_digest.clone();
    let expected_tx = case.inputs.expected_application_transcript_digest.clone();
    let intent = eval(&case).authorization_intent.unwrap();
    assert_eq!(intent.application_decision_id, expected_id);
    assert_eq!(intent.application_request_id, expected_req);
    assert_eq!(intent.application_intent_digest, expected_idig);
    assert_eq!(intent.application_transcript_digest, expected_tx);
}

fn a18_authorization_binds_validator_set_digests_and_versions() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let expected_current = case.inputs.expected_current_set_digest.clone();
    let expected_proposed = case.inputs.expected_proposed_set_digest.clone();
    let expected_delta = case.inputs.expected_delta_digest.clone();
    let intent = eval(&case).authorization_intent.unwrap();
    assert_eq!(intent.current_set_digest, expected_current);
    assert_eq!(intent.proposed_set_digest, expected_proposed);
    assert_eq!(intent.delta_digest, expected_delta);
    assert_eq!(intent.validator_set_epoch, CUR_EPOCH + 1);
    assert_eq!(intent.validator_set_version, CUR_VERSION + 1);
    assert_eq!(intent.proposed_validator_count, 4);
}

fn a19_authorization_binds_epoch_transition_target_and_nonces() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.epoch_transition_target, CUR_EPOCH + 1);
    assert_eq!(intent.epoch_transition_target, intent.validator_set_epoch);
    assert_eq!(intent.application_nonce, APP_NONCE);
    assert_eq!(intent.live_application_nonce, LIVE_APP_NONCE);
    assert_eq!(intent.rotation_nonce, ROT_NONCE);
}

fn a20_authorization_binds_quorum_threshold_policies() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.quorum, quorum());
    assert_eq!(intent.threshold, threshold());
    assert_eq!(intent.application_policy_id, APP_POLICY_ID);
    assert_eq!(intent.authorization_policy_id, AUTH_POLICY_ID);
}

fn a21_authorization_binds_custody_attestation_durable_where_represented() {
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1), v4],
        CUR_EPOCH + 1,
        CUR_VERSION + 1,
    );
    let decision = app_decision_ev(
        env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd,
        current, delta, proposed, Some(custody()), Some(attestation()), Some(durable()),
    );
    let target = decision.application_intent.as_ref().unwrap().epoch_transition_target;
    let inputs = auth_inputs(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd, &decision);
    let mut request = ProductionLiveValidatorSetApplicationAuthorizationRequest::new(
        LiveValidatorSetApplicationAuthorizationAuthoritySource::VerifiedApplicationDecision { decision },
        target, LIVE_APP_NONCE,
    );
    request.custody_binding = Some(custody());
    request.attestation_binding = Some(attestation());
    request.durable_replay_binding = Some(durable());
    let case = Case { executor: ProductionLiveValidatorSetApplicationAuthorizationExecutor::source_test(), request, inputs };
    let intent = eval(&case).authorization_intent.unwrap();
    assert_eq!(intent.custody_binding, Some(custody()));
    assert_eq!(intent.attestation_binding, Some(attestation()));
    assert_eq!(intent.durable_replay_binding, Some(durable()));
}

fn a22_request_id_deterministic() {
    let a = production_live_validator_set_application_authorization_request_id(1, "idig", "ap", 11, 23);
    let b = production_live_validator_set_application_authorization_request_id(1, "idig", "ap", 11, 23);
    assert_eq!(a, b);
    let c = production_live_validator_set_application_authorization_request_id(1, "idig", "ap", 11, 24);
    assert_ne!(a, c);
}

fn a23_intent_digest_deterministic() {
    let i1 = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    let i2 = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(i1.intent_digest(), i2.intent_digest());
    assert_eq!(
        production_live_validator_set_application_authorization_intent_digest(&i1),
        i1.intent_digest()
    );
}

fn a24_transcript_digest_deterministic() {
    let d1 = eval(&add_case(TrustBundleEnvironment::Devnet));
    let d2 = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert_eq!(d1.intent_digest, d2.intent_digest);
}

fn a25_different_action_changes_intent_digest() {
    let add = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    let rem = eval(&remove_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_ne!(add.intent_digest(), rem.intent_digest());
}

fn a26_different_live_application_nonce_changes_intent_digest() {
    let base = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&base).authorization_intent.unwrap();
    let mut other = add_case(TrustBundleEnvironment::Devnet);
    other.request.live_application_nonce = LIVE_APP_NONCE + 1;
    let i2 = eval(&other).authorization_intent.unwrap();
    assert_ne!(i1.intent_digest(), i2.intent_digest());
}

fn a27_accept_authorizes_future_mutation_only() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    assert!(d.authorizes_future_mutation_only());
    assert!(d.outcome.authorizes_future_mutation_only());
}

fn a28_accept_outcome_carries_kind_env_target_nonce() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet));
    match d.outcome {
        O::AcceptedSourceTestLiveValidatorSetApplicationAuthorization {
            authorization_kind, environment, epoch_transition_target, live_application_nonce,
        } => {
            assert_eq!(authorization_kind, AK::AuthorizeApplyValidatorAdd);
            assert_eq!(environment, TrustBundleEnvironment::Devnet);
            assert_eq!(epoch_transition_target, CUR_EPOCH + 1);
            assert_eq!(live_application_nonce, LIVE_APP_NONCE);
        }
        other => panic!("expected accept, got {:?}", other),
    }
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

fn a31_application_nonce_bound_into_intent() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert_eq!(intent.application_nonce, APP_NONCE);
}

// ===========================================================================
// B. Rejection / fail-closed source-test evidence
// ===========================================================================

type Src = LiveValidatorSetApplicationAuthorizationAuthoritySource;

fn assert_reject(case: &Case, expected: O) {
    let d = eval(case);
    assert_eq!(d.outcome, expected);
    assert!(!d.is_accept());
    assert!(d.authorization_intent.is_none());
    assert!(d.outcome.is_reject());
    assert!(d.outcome.is_non_mutating());
}

fn with_source(src: Src) -> Case {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.authority_source = src;
    case
}

fn b01_missing_application_decision_rejected() {
    assert_reject(&with_source(Src::MissingApplicationDecision), O::VerifiedApplicationDecisionRequired);
}

fn b02_unverified_application_decision_rejected() {
    let bad = ProductionValidatorSetRotationApplicationDecision {
        outcome: qbind_node::pqc_production_validator_set_rotation_application_executor::ProductionValidatorSetRotationApplicationOutcome::Disabled,
        application_id: GOV_DECISION_ID.to_string(),
        request_id: "r".to_string(),
        application_intent: None,
        intent_digest: String::new(),
        transcript_digest: "t".to_string(),
    };
    assert_reject(
        &with_source(Src::VerifiedApplicationDecision { decision: bad }),
        O::UnverifiedApplicationDecisionRejected,
    );
}

fn b03_unverified_application_decision_variant_rejected() {
    let decision = app_decision(
        TrustBundleEnvironment::Devnet, LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet), ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    assert_reject(
        &with_source(Src::UnverifiedApplicationDecision { decision }),
        O::UnverifiedApplicationDecisionRejected,
    );
}

fn b04_accepted_decision_without_intent_rejected() {
    let mut decision = app_decision(
        TrustBundleEnvironment::Devnet, LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet), ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    decision.application_intent = None;
    assert_reject(
        &with_source(Src::VerifiedApplicationDecision { decision }),
        O::VerifiedApplicationDecisionRequired,
    );
}

fn b05_accepted_decision_without_intent_source_rejected() {
    let decision = app_decision(
        TrustBundleEnvironment::Devnet, LocalLifecycleAction::Rotate,
        ValidatorSetRotationAction::NoOpSynchronization,
        current_set(TrustBundleEnvironment::Devnet), ValidatorSetDelta::empty(),
        current_set(TrustBundleEnvironment::Devnet),
    );
    assert_reject(
        &with_source(Src::AcceptedDecisionWithoutApplicationIntent { decision }),
        O::VerifiedApplicationDecisionRequired,
    );
}

fn b06_rotation_plan_alone_rejected() {
    assert_reject(&with_source(Src::RotationPlanWithoutApplicationDecision), O::RotationPlanAloneRejected);
}

fn b07_governance_execution_intent_alone_rejected() {
    assert_reject(
        &with_source(Src::GovernanceExecutionIntentWithoutApplicationDecision),
        O::GovernanceExecutionIntentAloneRejected,
    );
}

fn b08_governance_proof_alone_rejected() {
    assert_reject(&with_source(Src::GovernanceProofWithoutApplicationDecision), O::GovernanceProofAloneRejected);
}

fn b09_local_operator_rejected() {
    assert_reject(&with_source(Src::LocalOperatorAssertion), O::LocalOperatorProofRejected);
}

fn b10_peer_majority_rejected() {
    assert_reject(&with_source(Src::PeerMajorityAssertion), O::PeerMajorityProofRejected);
}

fn b11_custody_only_rejected() {
    assert_reject(&with_source(Src::CustodyOnlyEvidence), O::CustodyOnlyProofRejected);
}

fn b12_remote_signer_only_rejected() {
    assert_reject(&with_source(Src::RemoteSignerOnlyEvidence), O::RemoteSignerOnlyProofRejected);
}

fn b13_custody_attestation_only_rejected() {
    assert_reject(&with_source(Src::CustodyAttestationOnlyEvidence), O::CustodyAttestationOnlyProofRejected);
}

fn b14_fixture_only_application_decision_rejected() {
    assert_reject(
        &with_source(Src::FixtureOnlyApplicationDecision),
        O::FixtureApplicationDecisionRejectedAsProductionAuthority,
    );
}

fn b15_arbitrary_validator_set_bytes_rejected() {
    assert_reject(&with_source(Src::ArbitraryValidatorSetBytes), O::ArbitraryValidatorSetBytesRejected);
}

fn b16_wrong_application_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_decision_id = "wrong-app-decision".to_string();
    assert_reject(&case, O::ApplicationDecisionIdMismatch);
}

fn b17_wrong_application_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_request_id = "wrong-app-request".to_string();
    assert_reject(&case, O::ApplicationDecisionRequestIdMismatch);
}

fn b18_wrong_application_intent_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_intent_digest = "wrong-intent-digest".to_string();
    assert_reject(&case, O::ApplicationDecisionIntentDigestMismatch);
}

fn b19_wrong_application_transcript_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_transcript_digest = "wrong-transcript".to_string();
    assert_reject(&case, O::ApplicationDecisionTranscriptMismatch);
}

fn b20_tampered_application_intent_integrity_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    if let Src::VerifiedApplicationDecision { decision } = &mut case.request.authority_source {
        if let Some(intent) = &mut decision.application_intent {
            intent.proposed_validator_count += 1;
        }
    }
    assert_reject(&case, O::ApplicationDecisionIntegrityMismatch);
}

fn b21_wrong_application_policy_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_policy_id = "wrong-app-policy".to_string();
    assert_reject(&case, O::WrongApplicationPolicyId);
}

fn b22_wrong_environment_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet, chain_for(TrustBundleEnvironment::Devnet),
        GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongEnvironment);
}

fn b23_wrong_chain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet, "other-chain", GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongChain);
}

fn b24_wrong_genesis_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet, chain_for(TrustBundleEnvironment::Devnet),
        "other-genesis", ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongGenesis);
}

fn b25_wrong_authority_root_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet, chain_for(TrustBundleEnvironment::Devnet),
        GENESIS_HASH, "other-root", PQC_LIFECYCLE_SUITE_ML_DSA_44,
    );
    assert_reject(&case, O::WrongAuthorityRoot);
}

fn b26_wrong_governance_domain_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_reject(&case, O::WrongGovernanceDomain);
}

fn b27_wrong_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::WrongGovernanceEpoch);
}

fn b28_wrong_proposal_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposal_id = "other-proposal".to_string();
    assert_reject(&case, O::WrongProposalId);
}

fn b29_wrong_governance_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_decision_id = "other-gov-decision".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionDecisionId);
}

fn b30_wrong_governance_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_request_id = "other-gov-request".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionRequestId);
}

fn b31_wrong_governance_intent_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_governance_intent_digest = "other-intent-digest".to_string();
    assert_reject(&case, O::WrongGovernanceExecutionIntentDigest);
}

fn b32_wrong_rotation_decision_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_decision_id = "other-rotation-decision".to_string();
    assert_reject(&case, O::WrongRotationDecisionId);
}

fn b33_wrong_rotation_request_id_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_request_id = "other-rotation-request".to_string();
    assert_reject(&case, O::WrongRotationRequestId);
}

fn b34_wrong_rotation_transcript_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_transcript_digest = "other-rotation-transcript".to_string();
    assert_reject(&case, O::WrongRotationTranscriptDigest);
}

fn b35_wrong_rotation_plan_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_plan_digest = "other-rotation-plan".to_string();
    assert_reject(&case, O::WrongRotationPlanDigest);
}

fn b36_wrong_lifecycle_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_lifecycle_action = LocalLifecycleAction::Retire;
    assert_reject(&case, O::WrongLifecycleAction);
}

fn b37_wrong_rotation_action_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_action = ValidatorSetRotationAction::ValidatorRemove;
    assert_reject(&case, O::WrongRotationAction);
}

fn b38_wrong_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_authority_domain_sequence = SEQ + 1;
    assert_reject(&case, O::WrongAuthoritySequence);
}

fn b39_wrong_quorum_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_quorum = OnChainGovernanceQuorum { voters_voted: 9, total_voters: 10, required_quorum: 6 };
    assert_reject(&case, O::WrongQuorum);
}

fn b40_wrong_threshold_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_threshold = GovernanceThreshold::new(9, 6, 10);
    assert_reject(&case, O::WrongThreshold);
}

fn b41_wrong_current_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_current_set_digest = "other-current".to_string();
    assert_reject(&case, O::WrongCurrentValidatorSetDigest);
}

fn b42_wrong_proposed_set_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposed_set_digest = "other-proposed".to_string();
    assert_reject(&case, O::WrongProposedValidatorSetDigest);
}

fn b43_wrong_delta_digest_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_delta_digest = "other-delta".to_string();
    assert_reject(&case, O::WrongValidatorSetDeltaDigest);
}

fn b44_wrong_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongValidatorSetEpoch);
}

fn b45_wrong_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::WrongValidatorSetVersion);
}

fn b46_wrong_proposed_validator_count_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_proposed_validator_count = 99;
    assert_reject(&case, O::WrongProposedValidatorCount);
}

fn b47_wrong_rotation_nonce_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_rotation_nonce = ROT_NONCE + 1;
    assert_reject(&case, O::WrongRotationNonce);
}

fn b48_wrong_epoch_transition_target_request_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 99;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}

fn b49_wrong_epoch_transition_target_expected_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.request.proposed_epoch_transition_target = CUR_EPOCH + 5;
    case.inputs.expected_epoch_transition_target = CUR_EPOCH + 5;
    assert_reject(&case, O::WrongEpochTransitionTarget);
}

fn b50_wrong_application_nonce_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.expected_application_nonce = APP_NONCE + 1;
    assert_reject(&case, O::WrongApplicationNonce);
}

fn b51_custody_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    assert_reject(&case, O::CustodyBackendEvidenceRequired);
}

fn b52_custody_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_custody_evidence = true;
    case.inputs.expected_custody = Some(custody());
    let mut other = custody();
    other.key_handle = "other-key".to_string();
    case.request.custody_binding = Some(other);
    assert_reject(&case, O::CustodyBackendMismatch);
}

fn b53_attestation_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    assert_reject(&case, O::CustodyAttestationRequired);
}

fn b54_attestation_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_attestation_evidence = true;
    case.inputs.expected_attestation = Some(attestation());
    let mut other = attestation();
    other.measurement = "other-measurement".to_string();
    case.request.attestation_binding = Some(other);
    assert_reject(&case, O::CustodyAttestationMismatch);
}

fn b55_durable_required_but_missing_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    assert_reject(&case, O::DurableReplayEvidenceRequired);
}

fn b56_durable_mismatch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.require_durable_replay_evidence = true;
    case.inputs.expected_durable_replay = Some(durable());
    let mut other = durable();
    other.durable_record_id = "other-durable".to_string();
    case.request.durable_replay_binding = Some(other);
    assert_reject(&case, O::DurableReplayMismatch);
}

fn b57_stale_governance_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_governance_epoch = GOV_EPOCH + 1;
    assert_reject(&case, O::StaleGovernanceEpoch);
}

fn b58_stale_authority_sequence_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.persisted_sequence = Some(SEQ + 1);
    assert_reject(&case, O::StaleAuthoritySequence);
}

fn b59_stale_validator_set_epoch_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_epoch = CUR_EPOCH + 99;
    assert_reject(&case, O::StaleValidatorSetEpoch);
}

fn b60_stale_validator_set_version_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.min_validator_set_version = CUR_VERSION + 99;
    assert_reject(&case, O::StaleValidatorSetVersion);
}

fn b61_ill_formed_inputs_rejected() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.authorization_policy_id = String::new();
    assert_reject(&case, O::LiveValidatorSetApplicationAuthorizationBoundaryUnavailable);
}

fn b62_application_carried_custody_disagreement_rejected() {
    // Run 305 decision's intent carries custody A; request + expected carry a
    // custody with a different key handle, so the composition check fails.
    let env = TrustBundleEnvironment::Devnet;
    let current = current_set(env);
    let v4 = validator(env, 4, 100, 2);
    let delta = ValidatorSetDelta::new(vec![ValidatorSetChange::add(v4.clone())]);
    let proposed = CanonicalValidatorSetSnapshot::new(
        vec![validator(env, 1, 100, 1), validator(env, 2, 100, 1), validator(env, 3, 100, 1), v4],
        CUR_EPOCH + 1, CUR_VERSION + 1,
    );
    let mut intent_custody = custody();
    intent_custody.key_handle = "intent-carried-key".to_string();
    let decision = app_decision_ev(
        env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd,
        current, delta, proposed, Some(intent_custody), None, None,
    );
    let target = decision.application_intent.as_ref().unwrap().epoch_transition_target;
    let mut inputs = auth_inputs(env, LocalLifecycleAction::Rotate, ValidatorSetRotationAction::ValidatorAdd, &decision);
    inputs.require_custody_evidence = true;
    inputs.expected_custody = Some(custody());
    let mut request = ProductionLiveValidatorSetApplicationAuthorizationRequest::new(
        Src::VerifiedApplicationDecision { decision }, target, LIVE_APP_NONCE,
    );
    request.custody_binding = Some(custody());
    let case = Case { executor: ProductionLiveValidatorSetApplicationAuthorizationExecutor::source_test(), request, inputs };
    assert_reject(&case, O::CustodyBackendMismatch);
}

// ===========================================================================
// C. MainNet / authority policy refusal
// ===========================================================================

fn c01_mainnet_trust_domain_refused() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    assert_reject(&case, O::MainNetRefused);
}

fn c02_mainnet_trust_domain_no_intent() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    let d = eval(&case);
    assert_eq!(d.outcome, O::MainNetRefused);
    assert!(d.authorization_intent.is_none());
}

fn c03_production_policy_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::RequireProductionLiveValidatorSetApplicationAuthorization;
    assert_reject(&case, O::ProductionLiveValidatorSetApplicationAuthorizationUnavailable);
}

fn c04_mainnet_policy_unavailable_on_non_mainnet() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired;
    assert_reject(&case, O::MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable);
}

fn c05_mainnet_policy_on_mainnet_domain_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy =
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired;
    case.inputs.trust_domain = trust_domain(TrustBundleEnvironment::Mainnet);
    assert_reject(&case, O::MainNetProductionLiveValidatorSetApplicationAuthorizationUnavailable);
}

fn c06_reserved_production_kind_unavailable() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind =
        ProductionLiveValidatorSetApplicationAuthorizationKind::ProductionLiveValidatorSetApplicationAuthorization;
    case.executor.policy =
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::AllowSourceTestLiveValidatorSetApplicationAuthorization;
    assert_reject(&case, O::LiveValidatorSetApplicationAuthorizationBoundaryUnavailable);
}

fn c07_disabled_kind_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.config.kind = ProductionLiveValidatorSetApplicationAuthorizationKind::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}

fn c08_disabled_policy_is_disabled() {
    let mut case = add_case(TrustBundleEnvironment::Devnet);
    case.executor.policy = ProductionLiveValidatorSetApplicationAuthorizationPolicy::Disabled;
    assert_eq!(eval(&case).outcome, O::Disabled);
}

fn c09_mainnet_refused_named_helper() {
    assert!(production_live_validator_set_application_authorization_executor_mainnet_refused());
}

// ===========================================================================
// D. Replay / recovery / idempotency
// ===========================================================================

fn d01_replayed_authorization_id_rejected() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let accepted = eval(&case);
    let replay = vec![accepted.request_id.clone()];
    let d = case.executor.evaluate_live_validator_set_application_authorization(&case.request, &case.inputs, &replay);
    match d.outcome {
        O::LiveApplicationReplayRejected { .. } => {}
        other => panic!("expected replay reject, got {:?}", other),
    }
    assert!(d.authorization_intent.is_none());
}

fn d02_non_replayed_id_accepts() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let replay = vec!["unrelated-id".to_string()];
    let d = case.executor.evaluate_live_validator_set_application_authorization(&case.request, &case.inputs, &replay);
    assert!(d.is_accept());
}

fn d03_recovery_no_prior_window_clean() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).authorization_intent.unwrap();
    let r = case.executor.recover_live_validator_set_application_authorization_window(None, &intent);
    assert!(r.is_clean());
    assert!(r.is_non_mutating());
}

fn d04_recovery_idempotent_replay_observed() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).authorization_intent.unwrap();
    let r = case.executor.recover_live_validator_set_application_authorization_window(Some(&intent), &intent);
    match r {
        ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome::IdempotentReplayObserved { .. } => {}
        other => panic!("expected idempotent replay, got {:?}", other),
    }
}

fn d05_recovery_unrelated_window_clean() {
    let case_a = add_case(TrustBundleEnvironment::Devnet);
    let case_b = remove_case(TrustBundleEnvironment::Devnet);
    let ia = eval(&case_a).authorization_intent.unwrap();
    let ib = eval(&case_b).authorization_intent.unwrap();
    let r = case_a.executor.recover_live_validator_set_application_authorization_window(Some(&ib), &ia);
    assert!(r.is_clean());
}

fn d06_recovery_disabled_policy() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).authorization_intent.unwrap();
    let disabled = ProductionLiveValidatorSetApplicationAuthorizationExecutor::new(
        ProductionLiveValidatorSetApplicationAuthorizationConfig::default(),
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::default(),
    );
    let r = disabled.recover_live_validator_set_application_authorization_window(Some(&intent), &intent);
    assert_eq!(r, ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome::RecoveryDisabled);
}

fn d07_recovery_same_window_divergent_intent_clean() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let intent = eval(&case).authorization_intent.unwrap();
    let mut divergent = intent.clone();
    divergent.proposed_validator_count += 1;
    let r = case.executor.recover_live_validator_set_application_authorization_window(Some(&intent), &divergent);
    assert!(r.is_clean());
}

fn d08_replay_recovery_is_deterministic() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let i1 = eval(&case).authorization_intent.unwrap();
    let i2 = eval(&case).authorization_intent.unwrap();
    assert_eq!(i1, i2);
}

// ===========================================================================
// E. Non-mutation invariants + named helpers
// ===========================================================================

fn e01_named_helper_default_disabled() {
    assert!(production_live_validator_set_application_authorization_executor_default_is_disabled());
}

fn e02_named_helper_source_test_not_release_binary() {
    assert!(production_live_validator_set_application_authorization_executor_is_source_test_not_release_binary_evidence());
}

fn e03_named_helper_non_mutating() {
    assert!(production_live_validator_set_application_authorization_executor_is_non_mutating());
}

fn e04_named_helper_never_falls_back() {
    assert!(production_live_validator_set_application_authorization_executor_never_falls_back());
}

fn e05_named_helper_no_default_runtime_wiring() {
    assert!(production_live_validator_set_application_authorization_executor_no_default_runtime_wiring());
}

fn e06_named_helper_requires_verified_application_decision() {
    assert!(production_live_validator_set_application_authorization_executor_requires_verified_application_decision());
}

fn e07_every_outcome_is_non_mutating() {
    let outcomes = [
        O::Disabled,
        O::MainNetRefused,
        O::ProductionLiveValidatorSetApplicationAuthorizationUnavailable,
        O::VerifiedApplicationDecisionRequired,
        O::WrongEpochTransitionTarget,
        O::WrongApplicationNonce,
    ];
    for o in outcomes {
        assert!(o.is_non_mutating());
    }
}

fn e08_accept_is_only_mutation_authorizer() {
    assert!(O::AcceptedSourceTestLiveValidatorSetApplicationAuthorization {
        authorization_kind: AK::AuthorizeApplyValidatorAdd,
        environment: TrustBundleEnvironment::Devnet,
        epoch_transition_target: 11,
        live_application_nonce: 1,
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
    assert!(ProductionLiveValidatorSetApplicationAuthorizationConfig::source_test().is_well_formed());
    assert!(ProductionLiveValidatorSetApplicationAuthorizationConfig::default().is_well_formed());
}

fn e11_protocol_version_supported() {
    assert!(ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion::supported().is_supported());
    assert!(!ProductionLiveValidatorSetApplicationAuthorizationProtocolVersion(2).is_supported());
}

fn e12_authorization_kind_from_application_decision_kind_roundtrip() {
    assert_eq!(
        AK::from_application_decision_kind(ValidatorSetRotationApplicationDecisionKind::ApplyValidatorAdd),
        AK::AuthorizeApplyValidatorAdd
    );
    assert_eq!(
        AK::from_application_decision_kind(ValidatorSetRotationApplicationDecisionKind::UnsupportedApplication),
        AK::UnsupportedAuthorization
    );
    assert!(AK::UnsupportedAuthorization.is_unsupported());
    assert!(!AK::AuthorizeApplyValidatorAdd.is_unsupported());
}

fn e13_intent_marked_non_mutating() {
    let intent = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    assert!(intent.is_non_mutating());
}

fn e14_reject_carries_no_intent_but_has_transcript() {
    let case = with_source(Src::LocalOperatorAssertion);
    let d = eval(&case);
    assert!(d.authorization_intent.is_none());
    assert!(d.intent_digest.is_empty());
    assert!(!d.transcript_digest.is_empty());
}

fn e15_all_authorization_kinds_non_mutating() {
    let kinds = [
        AK::AuthorizeApplyNoOpAlreadySynchronized,
        AK::AuthorizeApplyValidatorAdd,
        AK::AuthorizeApplyValidatorRemove,
        AK::AuthorizeApplyValidatorMetadataUpdate,
        AK::AuthorizeApplyValidatorIdentityRotation,
        AK::AuthorizeApplyValidatorRetirement,
        AK::AuthorizeApplyEmergencyValidatorRemoval,
        AK::AuthorizeApplyAuthoritySetSynchronization,
        AK::AuthorizeApplyBulkValidatorSetRotation,
        AK::UnsupportedAuthorization,
    ];
    for k in kinds {
        assert!(k.is_non_mutating());
    }
}

// ===========================================================================
// F. C4/C5 taxonomy status
// ===========================================================================

fn f01_policy_tags_stable() {
    assert_eq!(ProductionLiveValidatorSetApplicationAuthorizationPolicy::Disabled.tag(), "disabled");
    assert_eq!(
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::AllowSourceTestLiveValidatorSetApplicationAuthorization.tag(),
        "allow-source-test-live-validator-set-application-authorization"
    );
}

fn f02_kind_tags_stable() {
    assert_eq!(
        ProductionLiveValidatorSetApplicationAuthorizationKind::SourceTestLiveValidatorSetApplicationAuthorization.tag(),
        "source-test-live-validator-set-application-authorization"
    );
    assert!(
        ProductionLiveValidatorSetApplicationAuthorizationKind::SourceTestLiveValidatorSetApplicationAuthorization.is_source_test()
    );
}

fn f03_authorization_kind_tags_stable() {
    assert_eq!(AK::AuthorizeApplyNoOpAlreadySynchronized.tag(), "authorize-apply-no-op-already-synchronized");
    assert_eq!(AK::AuthorizeApplyBulkValidatorSetRotation.tag(), "authorize-apply-bulk-validator-set-rotation");
    assert_eq!(AK::UnsupportedAuthorization.tag(), "unsupported-authorization");
}

fn f04_outcome_tags_stable() {
    assert_eq!(
        O::AcceptedSourceTestLiveValidatorSetApplicationAuthorization {
            authorization_kind: AK::AuthorizeApplyValidatorAdd,
            environment: TrustBundleEnvironment::Devnet,
            epoch_transition_target: 11,
            live_application_nonce: 1,
        }
        .tag(),
        "accepted-source-test-live-validator-set-application-authorization"
    );
    assert_eq!(O::MainNetRefused.tag(), "mainnet-refused");
    assert_eq!(O::WrongEpochTransitionTarget.tag(), "wrong-epoch-transition-target");
    assert_eq!(O::WrongApplicationNonce.tag(), "wrong-application-nonce");
}

fn f05_policy_predicates() {
    use ProductionLiveValidatorSetApplicationAuthorizationPolicy as Pol;
    assert!(Pol::Disabled.is_disabled());
    assert!(Pol::AllowSourceTestLiveValidatorSetApplicationAuthorization.allows_source_test());
    assert!(Pol::RequireProductionLiveValidatorSetApplicationAuthorization.is_production());
    assert!(Pol::MainnetProductionLiveValidatorSetApplicationAuthorizationRequired.is_mainnet());
}

fn f06_source_test_executor_shape() {
    let e = ProductionLiveValidatorSetApplicationAuthorizationExecutor::source_test();
    assert_eq!(
        e.policy,
        ProductionLiveValidatorSetApplicationAuthorizationPolicy::AllowSourceTestLiveValidatorSetApplicationAuthorization
    );
    assert!(e.config.kind.is_source_test());
}

fn f07_request_new_has_no_evidence_bindings() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    assert!(case.request.custody_binding.is_none());
    assert!(case.request.attestation_binding.is_none());
    assert!(case.request.durable_replay_binding.is_none());
}

fn f08_testnet_and_devnet_have_distinct_intent_digests() {
    let d = eval(&add_case(TrustBundleEnvironment::Devnet)).authorization_intent.unwrap();
    let t = eval(&add_case(TrustBundleEnvironment::Testnet)).authorization_intent.unwrap();
    assert_ne!(d.intent_digest(), t.intent_digest());
}

fn f09_accept_across_all_supported_actions() {
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

fn f10_recovery_outcome_non_mutating() {
    use ProductionLiveValidatorSetApplicationAuthorizationRecoveryOutcome as R;
    assert!(R::NoPriorAuthorizationWindow.is_non_mutating());
    assert!(R::RecoveryDisabled.is_non_mutating());
    assert!(R::IdempotentReplayObserved { authorization_id: "x".to_string() }.is_non_mutating());
}

// ===========================================================================
// G. Release-symbol reachability probe
// ===========================================================================

/// Exercises the Run 307 named free-function digest surfaces and named
/// invariant helpers so they are linked and reachable in the release binary.
fn g01_release_symbol_reachability_probe() {
    let case = add_case(TrustBundleEnvironment::Devnet);
    let d = eval(&case);
    assert!(d.is_accept());
    let intent = d.authorization_intent.clone().expect("accept intent");
    assert!(intent.is_non_mutating());

    // Named free-function digest surfaces are linked and deterministic.
    let intent_digest =
        production_live_validator_set_application_authorization_intent_digest(&intent);
    assert_eq!(intent_digest, intent.intent_digest());
    assert_eq!(intent_digest, d.intent_digest);
    let request_id = production_live_validator_set_application_authorization_request_id(
        PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION,
        &case.inputs.expected_application_intent_digest,
        &case.inputs.authorization_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.live_application_nonce,
    );
    assert_eq!(request_id, d.request_id);
    let transcript_digest =
        production_live_validator_set_application_authorization_transcript_digest(
            PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION,
            &request_id,
            &intent_digest,
            d.outcome.tag(),
        );
    assert_eq!(transcript_digest, d.transcript_digest);

    // Recovery surface is linked and non-mutating.
    let rec = case
        .executor
        .recover_live_validator_set_application_authorization_window(None, &intent);
    assert!(rec.is_clean());
    assert!(rec.is_non_mutating());

    // Named invariant helpers.
    assert!(production_live_validator_set_application_authorization_executor_default_is_disabled());
    assert!(production_live_validator_set_application_authorization_executor_is_source_test_not_release_binary_evidence());
    assert!(production_live_validator_set_application_authorization_executor_mainnet_refused());
    assert!(production_live_validator_set_application_authorization_executor_is_non_mutating());
    assert!(production_live_validator_set_application_authorization_executor_never_falls_back());
    assert!(production_live_validator_set_application_authorization_executor_no_default_runtime_wiring());
    assert!(production_live_validator_set_application_authorization_executor_requires_verified_application_decision());
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
            "docs/devnet/run_308_production_live_validator_set_application_authorization_release_binary/helper_evidence/run_308",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_default_policy_is_disabled_and_inert", a01_default_policy_is_disabled_and_inert as fn()),
        ("accepted_compatible", "a02_devnet_decision_produces_authorization", a02_devnet_decision_produces_authorization as fn()),
        ("accepted_compatible", "a03_testnet_decision_produces_authorization", a03_testnet_decision_produces_authorization as fn()),
        ("accepted_compatible", "a04_noop_authorization_accepted_non_mutating", a04_noop_authorization_accepted_non_mutating as fn()),
        ("accepted_compatible", "a05_validator_add_authorization_non_mutating", a05_validator_add_authorization_non_mutating as fn()),
        ("accepted_compatible", "a06_validator_remove_authorization_non_mutating", a06_validator_remove_authorization_non_mutating as fn()),
        ("accepted_compatible", "a07_validator_update_authorization_non_mutating", a07_validator_update_authorization_non_mutating as fn()),
        ("accepted_compatible", "a08_validator_identity_rotation_authorization_non_mutating", a08_validator_identity_rotation_authorization_non_mutating as fn()),
        ("accepted_compatible", "a09_validator_retirement_authorization_non_mutating", a09_validator_retirement_authorization_non_mutating as fn()),
        ("accepted_compatible", "a10_emergency_validator_removal_authorization_non_mutating", a10_emergency_validator_removal_authorization_non_mutating as fn()),
        ("accepted_compatible", "a11_authority_set_synchronization_authorization_non_mutating", a11_authority_set_synchronization_authorization_non_mutating as fn()),
        ("accepted_compatible", "a12_bulk_validator_set_rotation_authorization_non_mutating", a12_bulk_validator_set_rotation_authorization_non_mutating as fn()),
        ("accepted_compatible", "a13_authorization_binds_environment_chain_genesis_root", a13_authorization_binds_environment_chain_genesis_root as fn()),
        ("accepted_compatible", "a14_authorization_binds_governance_tuple", a14_authorization_binds_governance_tuple as fn()),
        ("accepted_compatible", "a15_authorization_binds_governance_execution_ids_and_digests", a15_authorization_binds_governance_execution_ids_and_digests as fn()),
        ("accepted_compatible", "a16_authorization_binds_rotation_ids_and_digests", a16_authorization_binds_rotation_ids_and_digests as fn()),
        ("accepted_compatible", "a17_authorization_binds_application_decision_tuple", a17_authorization_binds_application_decision_tuple as fn()),
        ("accepted_compatible", "a18_authorization_binds_validator_set_digests_and_versions", a18_authorization_binds_validator_set_digests_and_versions as fn()),
        ("accepted_compatible", "a19_authorization_binds_epoch_transition_target_and_nonces", a19_authorization_binds_epoch_transition_target_and_nonces as fn()),
        ("accepted_compatible", "a20_authorization_binds_quorum_threshold_policies", a20_authorization_binds_quorum_threshold_policies as fn()),
        ("accepted_compatible", "a21_authorization_binds_custody_attestation_durable_where_represented", a21_authorization_binds_custody_attestation_durable_where_represented as fn()),
        ("accepted_compatible", "a22_request_id_deterministic", a22_request_id_deterministic as fn()),
        ("accepted_compatible", "a23_intent_digest_deterministic", a23_intent_digest_deterministic as fn()),
        ("accepted_compatible", "a24_transcript_digest_deterministic", a24_transcript_digest_deterministic as fn()),
        ("accepted_compatible", "a25_different_action_changes_intent_digest", a25_different_action_changes_intent_digest as fn()),
        ("accepted_compatible", "a26_different_live_application_nonce_changes_intent_digest", a26_different_live_application_nonce_changes_intent_digest as fn()),
        ("accepted_compatible", "a27_accept_authorizes_future_mutation_only", a27_accept_authorizes_future_mutation_only as fn()),
        ("accepted_compatible", "a28_accept_outcome_carries_kind_env_target_nonce", a28_accept_outcome_carries_kind_env_target_nonce as fn()),
        ("accepted_compatible", "a29_min_governance_epoch_at_boundary_accepts", a29_min_governance_epoch_at_boundary_accepts as fn()),
        ("accepted_compatible", "a30_persisted_sequence_equal_accepts", a30_persisted_sequence_equal_accepts as fn()),
        ("accepted_compatible", "a31_application_nonce_bound_into_intent", a31_application_nonce_bound_into_intent as fn()),
        ("rejection_fail_closed", "b01_missing_application_decision_rejected", b01_missing_application_decision_rejected as fn()),
        ("rejection_fail_closed", "b02_unverified_application_decision_rejected", b02_unverified_application_decision_rejected as fn()),
        ("rejection_fail_closed", "b03_unverified_application_decision_variant_rejected", b03_unverified_application_decision_variant_rejected as fn()),
        ("rejection_fail_closed", "b04_accepted_decision_without_intent_rejected", b04_accepted_decision_without_intent_rejected as fn()),
        ("rejection_fail_closed", "b05_accepted_decision_without_intent_source_rejected", b05_accepted_decision_without_intent_source_rejected as fn()),
        ("rejection_fail_closed", "b06_rotation_plan_alone_rejected", b06_rotation_plan_alone_rejected as fn()),
        ("rejection_fail_closed", "b07_governance_execution_intent_alone_rejected", b07_governance_execution_intent_alone_rejected as fn()),
        ("rejection_fail_closed", "b08_governance_proof_alone_rejected", b08_governance_proof_alone_rejected as fn()),
        ("rejection_fail_closed", "b09_local_operator_rejected", b09_local_operator_rejected as fn()),
        ("rejection_fail_closed", "b10_peer_majority_rejected", b10_peer_majority_rejected as fn()),
        ("rejection_fail_closed", "b11_custody_only_rejected", b11_custody_only_rejected as fn()),
        ("rejection_fail_closed", "b12_remote_signer_only_rejected", b12_remote_signer_only_rejected as fn()),
        ("rejection_fail_closed", "b13_custody_attestation_only_rejected", b13_custody_attestation_only_rejected as fn()),
        ("rejection_fail_closed", "b14_fixture_only_application_decision_rejected", b14_fixture_only_application_decision_rejected as fn()),
        ("rejection_fail_closed", "b15_arbitrary_validator_set_bytes_rejected", b15_arbitrary_validator_set_bytes_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_application_decision_id_rejected", b16_wrong_application_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_application_request_id_rejected", b17_wrong_application_request_id_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_application_intent_digest_rejected", b18_wrong_application_intent_digest_rejected as fn()),
        ("rejection_fail_closed", "b19_wrong_application_transcript_rejected", b19_wrong_application_transcript_rejected as fn()),
        ("rejection_fail_closed", "b20_tampered_application_intent_integrity_mismatch_rejected", b20_tampered_application_intent_integrity_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b21_wrong_application_policy_id_rejected", b21_wrong_application_policy_id_rejected as fn()),
        ("rejection_fail_closed", "b22_wrong_environment_rejected", b22_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b23_wrong_chain_rejected", b23_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b24_wrong_genesis_rejected", b24_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b25_wrong_authority_root_rejected", b25_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b26_wrong_governance_domain_rejected", b26_wrong_governance_domain_rejected as fn()),
        ("rejection_fail_closed", "b27_wrong_governance_epoch_rejected", b27_wrong_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b28_wrong_proposal_id_rejected", b28_wrong_proposal_id_rejected as fn()),
        ("rejection_fail_closed", "b29_wrong_governance_decision_id_rejected", b29_wrong_governance_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b30_wrong_governance_request_id_rejected", b30_wrong_governance_request_id_rejected as fn()),
        ("rejection_fail_closed", "b31_wrong_governance_intent_digest_rejected", b31_wrong_governance_intent_digest_rejected as fn()),
        ("rejection_fail_closed", "b32_wrong_rotation_decision_id_rejected", b32_wrong_rotation_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b33_wrong_rotation_request_id_rejected", b33_wrong_rotation_request_id_rejected as fn()),
        ("rejection_fail_closed", "b34_wrong_rotation_transcript_rejected", b34_wrong_rotation_transcript_rejected as fn()),
        ("rejection_fail_closed", "b35_wrong_rotation_plan_digest_rejected", b35_wrong_rotation_plan_digest_rejected as fn()),
        ("rejection_fail_closed", "b36_wrong_lifecycle_action_rejected", b36_wrong_lifecycle_action_rejected as fn()),
        ("rejection_fail_closed", "b37_wrong_rotation_action_rejected", b37_wrong_rotation_action_rejected as fn()),
        ("rejection_fail_closed", "b38_wrong_authority_sequence_rejected", b38_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b39_wrong_quorum_rejected", b39_wrong_quorum_rejected as fn()),
        ("rejection_fail_closed", "b40_wrong_threshold_rejected", b40_wrong_threshold_rejected as fn()),
        ("rejection_fail_closed", "b41_wrong_current_set_digest_rejected", b41_wrong_current_set_digest_rejected as fn()),
        ("rejection_fail_closed", "b42_wrong_proposed_set_digest_rejected", b42_wrong_proposed_set_digest_rejected as fn()),
        ("rejection_fail_closed", "b43_wrong_delta_digest_rejected", b43_wrong_delta_digest_rejected as fn()),
        ("rejection_fail_closed", "b44_wrong_validator_set_epoch_rejected", b44_wrong_validator_set_epoch_rejected as fn()),
        ("rejection_fail_closed", "b45_wrong_validator_set_version_rejected", b45_wrong_validator_set_version_rejected as fn()),
        ("rejection_fail_closed", "b46_wrong_proposed_validator_count_rejected", b46_wrong_proposed_validator_count_rejected as fn()),
        ("rejection_fail_closed", "b47_wrong_rotation_nonce_rejected", b47_wrong_rotation_nonce_rejected as fn()),
        ("rejection_fail_closed", "b48_wrong_epoch_transition_target_request_rejected", b48_wrong_epoch_transition_target_request_rejected as fn()),
        ("rejection_fail_closed", "b49_wrong_epoch_transition_target_expected_rejected", b49_wrong_epoch_transition_target_expected_rejected as fn()),
        ("rejection_fail_closed", "b50_wrong_application_nonce_rejected", b50_wrong_application_nonce_rejected as fn()),
        ("rejection_fail_closed", "b51_custody_required_but_missing_rejected", b51_custody_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b52_custody_mismatch_rejected", b52_custody_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b53_attestation_required_but_missing_rejected", b53_attestation_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b54_attestation_mismatch_rejected", b54_attestation_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b55_durable_required_but_missing_rejected", b55_durable_required_but_missing_rejected as fn()),
        ("rejection_fail_closed", "b56_durable_mismatch_rejected", b56_durable_mismatch_rejected as fn()),
        ("rejection_fail_closed", "b57_stale_governance_epoch_rejected", b57_stale_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b58_stale_authority_sequence_rejected", b58_stale_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b59_stale_validator_set_epoch_rejected", b59_stale_validator_set_epoch_rejected as fn()),
        ("rejection_fail_closed", "b60_stale_validator_set_version_rejected", b60_stale_validator_set_version_rejected as fn()),
        ("rejection_fail_closed", "b61_ill_formed_inputs_rejected", b61_ill_formed_inputs_rejected as fn()),
        ("rejection_fail_closed", "b62_application_carried_custody_disagreement_rejected", b62_application_carried_custody_disagreement_rejected as fn()),
        ("mainnet_authority_policy", "c01_mainnet_trust_domain_refused", c01_mainnet_trust_domain_refused as fn()),
        ("mainnet_authority_policy", "c02_mainnet_trust_domain_no_intent", c02_mainnet_trust_domain_no_intent as fn()),
        ("mainnet_authority_policy", "c03_production_policy_unavailable", c03_production_policy_unavailable as fn()),
        ("mainnet_authority_policy", "c04_mainnet_policy_unavailable_on_non_mainnet", c04_mainnet_policy_unavailable_on_non_mainnet as fn()),
        ("mainnet_authority_policy", "c05_mainnet_policy_on_mainnet_domain_unavailable", c05_mainnet_policy_on_mainnet_domain_unavailable as fn()),
        ("mainnet_authority_policy", "c06_reserved_production_kind_unavailable", c06_reserved_production_kind_unavailable as fn()),
        ("mainnet_authority_policy", "c07_disabled_kind_is_disabled", c07_disabled_kind_is_disabled as fn()),
        ("mainnet_authority_policy", "c08_disabled_policy_is_disabled", c08_disabled_policy_is_disabled as fn()),
        ("mainnet_authority_policy", "c09_mainnet_refused_named_helper", c09_mainnet_refused_named_helper as fn()),
        ("replay_recovery_idempotency", "d01_replayed_authorization_id_rejected", d01_replayed_authorization_id_rejected as fn()),
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
        ("non_mutation", "e06_named_helper_requires_verified_application_decision", e06_named_helper_requires_verified_application_decision as fn()),
        ("non_mutation", "e07_every_outcome_is_non_mutating", e07_every_outcome_is_non_mutating as fn()),
        ("non_mutation", "e08_accept_is_only_mutation_authorizer", e08_accept_is_only_mutation_authorizer as fn()),
        ("non_mutation", "e09_disabled_is_not_reject", e09_disabled_is_not_reject as fn()),
        ("non_mutation", "e10_config_source_test_well_formed", e10_config_source_test_well_formed as fn()),
        ("non_mutation", "e11_protocol_version_supported", e11_protocol_version_supported as fn()),
        ("non_mutation", "e12_authorization_kind_from_application_decision_kind_roundtrip", e12_authorization_kind_from_application_decision_kind_roundtrip as fn()),
        ("non_mutation", "e13_intent_marked_non_mutating", e13_intent_marked_non_mutating as fn()),
        ("non_mutation", "e14_reject_carries_no_intent_but_has_transcript", e14_reject_carries_no_intent_but_has_transcript as fn()),
        ("non_mutation", "e15_all_authorization_kinds_non_mutating", e15_all_authorization_kinds_non_mutating as fn()),
        ("reachability_taxonomy", "f01_policy_tags_stable", f01_policy_tags_stable as fn()),
        ("reachability_taxonomy", "f02_kind_tags_stable", f02_kind_tags_stable as fn()),
        ("reachability_taxonomy", "f03_authorization_kind_tags_stable", f03_authorization_kind_tags_stable as fn()),
        ("reachability_taxonomy", "f04_outcome_tags_stable", f04_outcome_tags_stable as fn()),
        ("reachability_taxonomy", "f05_policy_predicates", f05_policy_predicates as fn()),
        ("reachability_taxonomy", "f06_source_test_executor_shape", f06_source_test_executor_shape as fn()),
        ("reachability_taxonomy", "f07_request_new_has_no_evidence_bindings", f07_request_new_has_no_evidence_bindings as fn()),
        ("reachability_taxonomy", "f08_testnet_and_devnet_have_distinct_intent_digests", f08_testnet_and_devnet_have_distinct_intent_digests as fn()),
        ("reachability_taxonomy", "f09_accept_across_all_supported_actions", f09_accept_across_all_supported_actions as fn()),
        ("reachability_taxonomy", "f10_recovery_outcome_non_mutating", f10_recovery_outcome_non_mutating as fn()),
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
    summary.push_str("Run 308 live validator-set application / epoch-transition authorization boundary release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "boundary: crates/qbind-node/src/pqc_production_live_validator_set_application_authorization.rs (Run 307 ProductionLiveValidatorSetApplicationAuthorizationExecutor)\n",
    );
    summary.push_str(
        "mode: real Run 307 live validator-set application / epoch-transition authorization boundary over the real Run 305/306 verified validator-set rotation application accept decision (is_accept() with Some(application_intent); itself composing the Run 303/304 verified validator-set rotation plan accept decision and the Run 301/302 verified governance execution accept decision); DevNet/TestNet source-test accept only; MainNet refused; default Disabled; MainNet/production policy never evaluates and never falls back to fixture / local-operator / peer-majority / governance-proof-alone / governance-execution-intent-alone / rotation-plan-alone / custody-only / remote-signer-only / custody-attestation-only / arbitrary-bytes material; consumes verified validator-set rotation application decisions and produces typed non-mutating live-application authorization intents for a future mutating executor; does not apply a live validator-set change; does not call Run 070; does not mutate LivePqcTrustState; does not mutate a live validator set, consensus state, or epoch counter; does not call BasicHotStuffEngine::transition_to_epoch; does not write meta:current_epoch; does not inject a PAYLOAD_KIND_RECONFIG block; does not write trust-bundle sequence or authority marker files; every failure is a typed non-mutating outcome\n",
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
        .authorization_intent
        .clone()
        .expect("accept authorization intent");
    let application_intent_digest = case.inputs.expected_application_intent_digest.clone();
    let intent_digest =
        production_live_validator_set_application_authorization_intent_digest(&intent);
    let request_id = production_live_validator_set_application_authorization_request_id(
        PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION,
        &application_intent_digest,
        &case.inputs.authorization_policy_id,
        case.request.proposed_epoch_transition_target,
        case.request.live_application_nonce,
    );
    let transcript_digest =
        production_live_validator_set_application_authorization_transcript_digest(
            PRODUCTION_LIVE_VALIDATOR_SET_APPLICATION_AUTHORIZATION_PROTOCOL_VERSION,
            &request_id,
            &intent_digest,
            decision.outcome.tag(),
        );
    fs::write(
        outdir.join("fixtures/run_308_deterministic_digests.txt"),
        format!(
            "application_intent_digest {application_intent_digest}\nintent_digest {intent_digest}\nrequest_id {request_id}\ntranscript_digest {transcript_digest}\noutcome_tag {}\n",
            decision.outcome.tag()
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
