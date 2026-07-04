//! Run 301 — source/test real production governance execution engine
//! integration tests.
//!
//! Source/test only. Run 301 does **not** capture release-binary
//! evidence; release-binary evidence for the production governance
//! execution engine is deferred to **Run 302**. The tests cover:
//!
//! * A. accepted / compatible source-test evidence;
//! * B. rejection / fail-closed paths;
//! * C. MainNet / authority policy refusal;
//! * D. replay / recovery / idempotency;
//! * E. non-mutation invariants (the engine surfaces are pure);
//! * F. C4/C5 taxonomy status.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_301.md`.

use qbind_node::pqc_authority_custody::AuthorityCustodyClass;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_proof::{
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
};
use qbind_node::pqc_production_governance_execution_engine::*;
use qbind_node::pqc_production_onchain_governance_proof_verifier::{
    ProductionOnChainGovernanceProofDecision, ProductionOnChainGovernanceProofOutcome,
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
const DECISION_ID: &str = "decision-id-1";
const TRANSCRIPT_DIGEST: &str = "run299-transcript-digest-1";
const PROOF_DIGEST: &str = "run299-proof-digest-1";
const CHECKPOINT_DIGEST: &str = "run299-checkpoint-digest-1";
const POLICY_ID: &str = "exec-policy-1";

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

/// A well-formed proof binding for `env` requesting an authority-lifecycle
/// rotation. Its transcript / proof digests match [`decision_for`].
fn binding(env: TrustBundleEnvironment) -> GovernanceExecutionProofBinding {
    GovernanceExecutionProofBinding {
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
        lifecycle_action: LocalLifecycleAction::Rotate,
        requested_operation: GovernanceExecutionRequestedOperation::AuthorityLifecycleRotation,
        candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        authority_domain_sequence: SEQ,
        decision_id: DECISION_ID.to_string(),
        proof_transcript_digest: TRANSCRIPT_DIGEST.to_string(),
        proof_digest: PROOF_DIGEST.to_string(),
        trusted_checkpoint_digest: CHECKPOINT_DIGEST.to_string(),
    }
}

/// A Run 299 accept decision consistent with `b`.
fn decision_for(b: &GovernanceExecutionProofBinding) -> ProductionOnChainGovernanceProofDecision {
    ProductionOnChainGovernanceProofDecision {
        outcome: ProductionOnChainGovernanceProofOutcome::AcceptedProductionOnChainGovernanceProof {
            environment: b.environment,
            governance_epoch: b.governance_epoch,
            authority_domain_sequence: b.authority_domain_sequence,
            lifecycle_action: b.lifecycle_action,
            decision_id: b.decision_id.clone(),
        },
        decision_id: b.decision_id.clone(),
        proof_digest: b.proof_digest.clone(),
        transcript_digest: b.proof_transcript_digest.clone(),
    }
}

fn verified_source(b: &GovernanceExecutionProofBinding) -> GovernanceExecutionProofSource {
    GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
        decision: decision_for(b),
        binding: b.clone(),
    }
}

fn inputs(env: TrustBundleEnvironment) -> ProductionGovernanceExecutionInputs {
    ProductionGovernanceExecutionInputs {
        trust_domain: trust_domain(env),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_proposal_digest: PROPOSAL_DIGEST.to_string(),
        expected_proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_requested_operation:
            GovernanceExecutionRequestedOperation::AuthorityLifecycleRotation,
        expected_candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQ,
        expected_quorum: quorum(),
        expected_threshold: threshold(),
        expected_proof_transcript_digest: TRANSCRIPT_DIGEST.to_string(),
        min_governance_epoch: 0,
        persisted_sequence: Some(SEQ - 1),
        execution_policy_id: POLICY_ID.to_string(),
        require_custody_evidence: false,
        expected_custody: None,
        require_attestation_evidence: false,
        expected_attestation: None,
        require_durable_replay_evidence: false,
        expected_durable_replay: None,
    }
}

fn engine() -> ProductionGovernanceExecutionEngine {
    ProductionGovernanceExecutionEngine::source_test()
}

fn empty_replay() -> EmptyGovernanceExecutionReplaySet {
    EmptyGovernanceExecutionReplaySet
}

/// Evaluate a verified request for `env` with the given engine/inputs.
fn eval_verified(
    e: &ProductionGovernanceExecutionEngine,
    b: &GovernanceExecutionProofBinding,
    ins: &ProductionGovernanceExecutionInputs,
) -> ProductionGovernanceExecutionDecision {
    let req = ProductionGovernanceExecutionRequest::from_proof(verified_source(b));
    e.evaluate_production_governance_execution(&req, ins, &empty_replay())
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

// ===========================================================================
// A. Accepted / compatible source-test evidence
// ===========================================================================

#[test]
fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_governance_execution_engine_default_is_disabled());
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::default(),
        ProductionGovernanceExecutionEnginePolicy::default(),
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::Disabled);
    assert!(d.intent.is_none());
}

#[test]
fn a02_valid_devnet_decision_produces_intent() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.intent.is_some());
}

#[test]
fn a03_valid_testnet_decision_produces_intent() {
    let b = binding(TrustBundleEnvironment::Testnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.intent.is_some());
}

#[test]
fn a04_accepted_intent_binds_environment() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().environment, TrustBundleEnvironment::Devnet);
}

#[test]
fn a05_accepted_intent_binds_chain_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().chain_id, "qbind-devnet");
}

#[test]
fn a06_accepted_intent_binds_genesis() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().genesis_hash, GENESIS_HASH);
}

#[test]
fn a07_accepted_intent_binds_authority_root() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let i = d.intent.unwrap();
    assert_eq!(i.authority_root_fingerprint, ROOT_FP);
    assert_eq!(i.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

#[test]
fn a08_accepted_intent_binds_governance_domain() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().governance_domain_id, GOV_DOMAIN);
}

#[test]
fn a09_accepted_intent_binds_governance_epoch() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().governance_epoch, GOV_EPOCH);
}

#[test]
fn a10_accepted_intent_binds_proposal_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proposal_id, PROPOSAL_ID);
}

#[test]
fn a11_accepted_intent_binds_proposal_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proposal_digest, PROPOSAL_DIGEST);
}

#[test]
fn a12_accepted_intent_binds_proposal_outcome() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d.intent.unwrap().proposal_outcome,
        OnChainGovernanceProposalOutcome::Approved
    );
}

#[test]
fn a13_accepted_intent_binds_lifecycle_action() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().lifecycle_action, LocalLifecycleAction::Rotate);
}

#[test]
fn a14_accepted_intent_binds_candidate_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().candidate_v2_digest, CANDIDATE_DIGEST);
}

#[test]
fn a15_accepted_intent_binds_authority_sequence() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().authority_domain_sequence, SEQ);
}

#[test]
fn a16_accepted_intent_binds_decision_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().decision_id, DECISION_ID);
}

#[test]
fn a17_accepted_intent_binds_quorum_threshold() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let i = d.intent.unwrap();
    assert_eq!(i.quorum, quorum());
    assert_eq!(i.threshold, threshold());
}

#[test]
fn a18_accepted_intent_binds_proof_transcript_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proof_transcript_digest, TRANSCRIPT_DIGEST);
}

#[test]
fn a19_accepted_intent_binds_checkpoint_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().trusted_checkpoint_digest, CHECKPOINT_DIGEST);
}

#[test]
fn a20_accepted_intent_binds_custody_evidence_when_represented() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_custody_evidence = true;
    ins.expected_custody = Some(custody());
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.custody_binding = Some(custody());
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert!(d.is_accept());
    assert_eq!(d.intent.unwrap().custody_binding, Some(custody()));
}

#[test]
fn a21_accepted_intent_binds_attestation_evidence_when_represented() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_attestation_evidence = true;
    ins.expected_attestation = Some(attestation());
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.attestation_binding = Some(attestation());
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert!(d.is_accept());
    assert_eq!(d.intent.unwrap().attestation_binding, Some(attestation()));
}

#[test]
fn a22_accepted_intent_binds_durable_replay_evidence_when_represented() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_durable_replay_evidence = true;
    ins.expected_durable_replay = Some(durable());
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.durable_replay_binding = Some(durable());
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert!(d.is_accept());
    assert_eq!(d.intent.unwrap().durable_replay_binding, Some(durable()));
}

#[test]
fn a23_intent_digest_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.intent_digest, d2.intent_digest);
    assert!(!d1.intent_digest.is_empty());
}

#[test]
fn a24_request_id_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.request_id, d2.request_id);
}

#[test]
fn a25_transcript_digest_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
}

#[test]
fn a26_same_decision_same_intent_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d1.intent.unwrap().intent_digest(),
        d2.intent.unwrap().intent_digest()
    );
}

#[test]
fn a27_different_lifecycle_action_changes_intent_digest() {
    let b1 = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b1, &inputs(TrustBundleEnvironment::Devnet));

    let mut b2 = binding(TrustBundleEnvironment::Devnet);
    b2.lifecycle_action = LocalLifecycleAction::Revoke;
    b2.requested_operation = GovernanceExecutionRequestedOperation::AuthorityLifecycleRevocation;
    let mut ins2 = inputs(TrustBundleEnvironment::Devnet);
    ins2.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    ins2.expected_requested_operation =
        GovernanceExecutionRequestedOperation::AuthorityLifecycleRevocation;
    let d2 = eval_verified(&engine(), &b2, &ins2);

    assert!(d1.is_accept() && d2.is_accept());
    assert_ne!(d1.intent_digest, d2.intent_digest);
}

#[test]
fn a28_different_candidate_digest_changes_intent_digest() {
    let b1 = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b1, &inputs(TrustBundleEnvironment::Devnet));

    let mut b2 = binding(TrustBundleEnvironment::Devnet);
    b2.candidate_v2_digest = "candidate-digest-99".to_string();
    let mut ins2 = inputs(TrustBundleEnvironment::Devnet);
    ins2.expected_candidate_v2_digest = "candidate-digest-99".to_string();
    let d2 = eval_verified(&engine(), &b2, &ins2);

    assert_ne!(d1.intent_digest, d2.intent_digest);
}

#[test]
fn a29_emergency_revocation_is_prepared_intent_only() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    b.requested_operation = GovernanceExecutionRequestedOperation::EmergencyRevocation;
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.expected_lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    ins.expected_requested_operation =
        GovernanceExecutionRequestedOperation::EmergencyRevocation;
    let d = eval_verified(&engine(), &b, &ins);
    assert!(d.is_accept());
    let i = d.intent.unwrap();
    assert_eq!(
        i.intent_kind,
        ProductionGovernanceExecutionIntentKind::EmergencyRevocationIntent
    );
    assert!(i.is_non_mutating());
}

#[test]
fn a30_rotate_retire_revoke_are_prepared_intents_only() {
    for (action, op, kind) in [
        (
            LocalLifecycleAction::Rotate,
            GovernanceExecutionRequestedOperation::AuthorityLifecycleRotation,
            ProductionGovernanceExecutionIntentKind::AuthorityLifecycleRotationIntent,
        ),
        (
            LocalLifecycleAction::Retire,
            GovernanceExecutionRequestedOperation::AuthorityLifecycleRetirement,
            ProductionGovernanceExecutionIntentKind::AuthorityLifecycleRetirementIntent,
        ),
        (
            LocalLifecycleAction::Revoke,
            GovernanceExecutionRequestedOperation::AuthorityLifecycleRevocation,
            ProductionGovernanceExecutionIntentKind::AuthorityLifecycleRevocationIntent,
        ),
    ] {
        let mut b = binding(TrustBundleEnvironment::Devnet);
        b.lifecycle_action = action;
        b.requested_operation = op;
        let mut ins = inputs(TrustBundleEnvironment::Devnet);
        ins.expected_lifecycle_action = action;
        ins.expected_requested_operation = op;
        let d = eval_verified(&engine(), &b, &ins);
        assert!(d.is_accept(), "action {:?} should accept", action);
        let i = d.intent.unwrap();
        assert_eq!(i.intent_kind, kind);
        assert!(i.is_non_mutating());
    }
}

#[test]
fn a31_bundle_signing_key_authorization_intent() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.requested_operation = GovernanceExecutionRequestedOperation::BundleSigningKeyAuthorization;
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.expected_requested_operation =
        GovernanceExecutionRequestedOperation::BundleSigningKeyAuthorization;
    let d = eval_verified(&engine(), &b, &ins);
    assert!(d.is_accept());
    assert_eq!(
        d.intent.unwrap().intent_kind,
        ProductionGovernanceExecutionIntentKind::BundleSigningKeyAuthorizationIntent
    );
}

#[test]
fn a32_run299_accept_output_composes_into_engine() {
    // Compose with the real Run 299 verifier accept output. Build a valid
    // Run 299 proof bundle, verify it, extract the transcript/proof digests
    // from the accept decision, and feed a matching binding to the engine.
    use qbind_node::pqc_production_onchain_governance_proof_verifier as v299;

    let env = TrustBundleEnvironment::Devnet;
    let c = v299::ProductionOnChainGovernanceDecisionCommitment {
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
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: "active-fp".to_string(),
        new_bundle_signing_key_fingerprint: Some("new-fp".to_string()),
        revoked_bundle_signing_key_fingerprint: None,
        authority_domain_sequence: SEQ,
        candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        decision_id: DECISION_ID.to_string(),
    };
    let leaf = c.decision_digest();
    let leaves = vec![
        "sibling-a".to_string(),
        leaf.clone(),
        "sibling-b".to_string(),
        "sibling-c".to_string(),
    ];
    let (root_hex, inclusion) = v299::build_merkle_inclusion_proof(&leaves, 1).unwrap();
    let proof = v299::ProductionOnChainGovernanceProof {
        protocol_version: v299::ProductionOnChainGovernanceProofProtocolVersion::supported(),
        proof_suite: v299::ProductionOnChainGovernanceProofSuite::merkle_v1(),
        domain_separation_tag: v299::PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG
            .to_string(),
        commitment: c.clone(),
        inclusion_proof: inclusion,
        proof_bytes_digest: String::new(),
    }
    .seal();
    let checkpoint = v299::ProductionOnChainGovernanceTrustedCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        governance_root_hex: root_hex,
        receipt_root_hex: None,
        event_root_hex: None,
        state_root_hex: None,
        governance_height: GOV_HEIGHT,
        governance_epoch: GOV_EPOCH,
    };
    let v_inputs = v299::ProductionOnChainGovernanceVerificationInputs {
        trusted_checkpoint: checkpoint.clone(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_proposal_digest: PROPOSAL_DIGEST.to_string(),
        expected_proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQ,
        freshness_bounds: v299::ProductionOnChainGovernanceFreshnessBounds {
            min_governance_height: 0,
            max_governance_height: 10_000,
            min_governance_epoch: 0,
            max_governance_epoch: 100,
        },
        persisted_sequence: Some(SEQ - 1),
    };
    let verifier = v299::ProductionOnChainGovernanceProofVerifier::new(
        v299::ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        v299::ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        v299::RealMerkleInclusionVerifier::new(),
    );
    use qbind_node::pqc_production_onchain_governance_proof_verifier::GovernanceProductionOnChainGovernanceProofVerifier;
    let decision = verifier.evaluate_production_onchain_governance_proof(
        &proof,
        &v_inputs,
        &trust_domain(env),
        &v299::EmptyProductionOnChainGovernanceReplaySet,
    );
    assert!(decision.is_accept(), "run299 must accept");

    // Build the engine binding from the same commitment + the real Run 299
    // transcript/proof digests.
    let mut b = binding(env);
    b.proof_transcript_digest = decision.transcript_digest.clone();
    b.proof_digest = decision.proof_digest.clone();
    b.trusted_checkpoint_digest = checkpoint.checkpoint_digest();

    let mut ins = inputs(env);
    ins.expected_proof_transcript_digest = decision.transcript_digest.clone();

    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
            decision,
            binding: b,
        },
    );
    let out = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert!(out.is_accept(), "engine must accept run299 output");
}

#[test]
fn a33_accept_outcome_helpers() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_accept());
    assert!(!d.outcome.is_reject());
    assert!(d.outcome.is_non_mutating());
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(d.authorizes_future_mutation_only());
}

// ===========================================================================
// B. Rejection / fail-closed source-test evidence
// ===========================================================================

fn expect(
    b: &GovernanceExecutionProofBinding,
    ins: &ProductionGovernanceExecutionInputs,
    want: ProductionGovernanceExecutionOutcome,
) {
    let d = eval_verified(&engine(), b, ins);
    assert_eq!(d.outcome, want);
    assert!(d.intent.is_none());
}

#[test]
fn b01_disabled_rejects_before_evaluation() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::Disabled,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::Disabled);
}

#[test]
fn b02_missing_proof_rejected() {
    let req =
        ProductionGovernanceExecutionRequest::from_proof(GovernanceExecutionProofSource::MissingProof);
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::VerifiedOnChainGovernanceProofRequired
    );
}

#[test]
fn b03_unverified_proof_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut decision = decision_for(&b);
    decision.outcome = ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed;
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
            decision,
            binding: b,
        },
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::UnverifiedGovernanceProofRejected
    );
}

#[test]
fn b04_explicit_unverified_source_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut decision = decision_for(&b);
    decision.outcome = ProductionOnChainGovernanceProofOutcome::Disabled;
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::UnverifiedOnChainGovernanceProof { decision },
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::UnverifiedGovernanceProofRejected
    );
}

#[test]
fn b05_fixture_proof_rejected_as_production_authority() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::FixtureGovernanceProof,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::FixtureGovernanceProofRejectedAsProductionAuthority
    );
}

#[test]
fn b06_local_operator_assertion_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::LocalOperatorAssertion,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::LocalOperatorProofRejected
    );
}

#[test]
fn b07_peer_majority_assertion_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::PeerMajorityAssertion,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::PeerMajorityProofRejected
    );
}

#[test]
fn b08_custody_only_evidence_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::CustodyOnlyEvidence,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::CustodyOnlyProofRejected
    );
}

#[test]
fn b09_remote_signer_only_evidence_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::RemoteSignerOnlyEvidence,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::RemoteSignerOnlyProofRejected
    );
}

#[test]
fn b10_custody_attestation_only_evidence_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::CustodyAttestationOnlyEvidence,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::CustodyAttestationOnlyProofRejected
    );
}

#[test]
fn b11_wrong_proof_transcript_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proof_transcript_digest = "wrong-transcript".to_string();
    // Keep decision transcript matching the (wrong) binding so decision
    // consistency passes, but inputs still expect the canonical transcript.
    let mut decision = decision_for(&b);
    decision.transcript_digest = "wrong-transcript".to_string();
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
            decision,
            binding: b,
        },
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceProofTranscriptMismatch
    );
}

#[test]
fn b12_transcript_mismatch_between_binding_and_decision() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut decision = decision_for(&b);
    decision.transcript_digest = "diverged-transcript".to_string();
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
            decision,
            binding: b,
        },
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceProofTranscriptMismatch
    );
}

#[test]
fn b13_wrong_environment_rejected() {
    let b = binding(TrustBundleEnvironment::Testnet);
    // inputs use Devnet trust domain => environment mismatch.
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongEnvironment,
    );
}

#[test]
fn b14_wrong_chain_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.chain_id = "wrong-chain".to_string();
    // Chain is not carried in the Run 299 accept outcome, so decision
    // consistency passes and the binding check surfaces the mismatch.
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongChain,
    );
}

#[test]
fn b15_wrong_genesis_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.genesis_hash = "wrong-genesis".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGenesis,
    );
}

#[test]
fn b16_wrong_authority_root_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.authority_root_fingerprint = "wrong-root".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongAuthorityRoot,
    );
}

#[test]
fn b17_wrong_governance_domain_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.governance_domain_id = "wrong-domain".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGovernanceDomain,
    );
}

#[test]
fn b18_wrong_governance_epoch_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.governance_epoch = GOV_EPOCH + 1;
    // inputs expect GOV_EPOCH.
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGovernanceEpoch,
    );
}

#[test]
fn b19_wrong_proposal_id_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_id = "wrong-proposal".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalId,
    );
}

#[test]
fn b20_wrong_proposal_digest_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_digest = "wrong-digest".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalDigest,
    );
}

#[test]
fn b21_wrong_proposal_outcome_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalOutcome,
    );
}

#[test]
fn b22_wrong_lifecycle_action_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.lifecycle_action = LocalLifecycleAction::Retire;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongLifecycleAction,
    );
}

#[test]
fn b23_wrong_candidate_digest_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.candidate_v2_digest = "wrong-candidate".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongCandidateDigest,
    );
}

#[test]
fn b24_wrong_authority_sequence_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.authority_domain_sequence = SEQ + 5;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongAuthoritySequence,
    );
}

#[test]
fn b25_wrong_decision_id_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.decision_id = "other-decision".to_string();
    // decision keeps the canonical decision id => consistency mismatch.
    let decision = decision_for(&binding(TrustBundleEnvironment::Devnet));
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::VerifiedOnChainGovernanceProof {
            decision,
            binding: b,
        },
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::WrongDecisionId
    );
}

#[test]
fn b26_wrong_quorum_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.quorum = OnChainGovernanceQuorum {
        voters_voted: 3,
        total_voters: 10,
        required_quorum: 6,
    };
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongQuorum,
    );
}

#[test]
fn b27_wrong_threshold_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.threshold = GovernanceThreshold::new(2, 6, 10);
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongThreshold,
    );
}

#[test]
fn b28_missing_custody_evidence_rejected_when_required() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_custody_evidence = true;
    ins.expected_custody = Some(custody());
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::CustodyBackendEvidenceRequired,
    );
}

#[test]
fn b29_wrong_custody_backend_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_custody_evidence = true;
    ins.expected_custody = Some(custody());
    let mut wrong = custody();
    wrong.key_handle = "different-key".to_string();
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.custody_binding = Some(wrong);
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::CustodyBackendMismatch
    );
}

#[test]
fn b30_missing_attestation_rejected_when_required() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_attestation_evidence = true;
    ins.expected_attestation = Some(attestation());
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::CustodyAttestationRequired,
    );
}

#[test]
fn b31_wrong_attestation_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_attestation_evidence = true;
    ins.expected_attestation = Some(attestation());
    let mut wrong = attestation();
    wrong.attestation_transcript_digest = "diff".to_string();
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.attestation_binding = Some(wrong);
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::CustodyAttestationMismatch
    );
}

#[test]
fn b32_missing_durable_replay_rejected_when_required() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_durable_replay_evidence = true;
    ins.expected_durable_replay = Some(durable());
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::DurableReplayEvidenceRequired,
    );
}

#[test]
fn b33_wrong_durable_replay_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.require_durable_replay_evidence = true;
    ins.expected_durable_replay = Some(durable());
    let mut wrong = durable();
    wrong.durable_record_digest = "diff".to_string();
    let mut req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    req.durable_replay_binding = Some(wrong);
    let d = engine().evaluate_production_governance_execution(&req, &ins, &empty_replay());
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::DurableReplayMismatch
    );
}

#[test]
fn b34_replayed_decision_id_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let replay: Vec<String> = vec![DECISION_ID.to_string()];
    let req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &replay,
    );
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::DecisionReplayRejected {
            decision_id: DECISION_ID.to_string()
        }
    );
}

#[test]
fn b35_stale_governance_epoch_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.min_governance_epoch = GOV_EPOCH + 10;
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::StaleGovernanceEpoch,
    );
}

#[test]
fn b36_stale_authority_sequence_rejected() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.persisted_sequence = Some(SEQ + 1);
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::StaleAuthoritySequence,
    );
}

#[test]
fn b37_unsupported_lifecycle_action_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.lifecycle_action = LocalLifecycleAction::ActivateInitial;
    b.requested_operation = GovernanceExecutionRequestedOperation::GovernanceNoOp;
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.expected_lifecycle_action = LocalLifecycleAction::ActivateInitial;
    ins.expected_requested_operation = GovernanceExecutionRequestedOperation::GovernanceNoOp;
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::UnsupportedLifecycleAction,
    );
}

#[test]
fn b38_validator_set_rotation_unsupported() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.expected_requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    expect(
        &b,
        &ins,
        ProductionGovernanceExecutionOutcome::ValidatorSetRotationUnsupported,
    );
}

#[test]
fn b39_engine_kind_disabled_fails_closed() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::new(
            ProductionGovernanceExecutionEngineKind::Disabled,
        ),
        ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    // Kind Disabled routes through the Disabled gate.
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::Disabled);
}

#[test]
fn b40_reserved_production_engine_kind_unavailable() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::new(
            ProductionGovernanceExecutionEngineKind::ProductionGovernanceExecutionEngine,
        ),
        ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceExecutionEngineUnavailable
    );
}

#[test]
fn b41_production_policy_without_prereqs_fails_closed() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::RequireProductionGovernanceExecution,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::ProductionGovernanceExecutionUnavailable
    );
}

#[test]
fn b42_ambiguous_inputs_fail_closed() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let mut ins = inputs(TrustBundleEnvironment::Devnet);
    ins.execution_policy_id = String::new();
    let d = eval_verified(&engine(), &b, &ins);
    assert!(matches!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceExecutionAmbiguous { .. }
    ));
}

#[test]
fn b43_malformed_binding_fails_closed() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_id = String::new();
    // proposal_id empty => binding not well-formed. Keep decision valid.
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(matches!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceExecutionAmbiguous { .. }
    ));
}

// ===========================================================================
// C. MainNet / authority policy evidence
// ===========================================================================

#[test]
fn c01_mainnet_cannot_be_satisfied_by_fixture_proof() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired,
    );
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::FixtureGovernanceProof,
    );
    let d = e.evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Mainnet),
        &empty_replay(),
    );
    // MainNet gate precedes proof classification.
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::MainNetProductionGovernanceExecutionUnavailable
    );
}

#[test]
fn c02_mainnet_cannot_be_satisfied_by_local_operator() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired,
    );
    let b = binding(TrustBundleEnvironment::Mainnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Mainnet));
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::MainNetProductionGovernanceExecutionUnavailable
    );
}

#[test]
fn c03_mainnet_domain_refused_under_source_test_policy() {
    let b = binding(TrustBundleEnvironment::Mainnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Mainnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

#[test]
fn c04_mainnet_decision_env_refused_even_on_devnet_domain() {
    // Binding claims MainNet while the trust domain is DevNet.
    let b = binding(TrustBundleEnvironment::Mainnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

#[test]
fn c05_mainnet_production_policy_on_devnet_fails_closed() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::MainNetProductionGovernanceExecutionUnavailable
    );
}

#[test]
fn c06_valid_devnet_source_test_does_not_enable_mainnet() {
    // A valid DevNet accept must not produce a MainNet-env intent.
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert_ne!(
        d.intent.unwrap().environment,
        TrustBundleEnvironment::Mainnet
    );
}

#[test]
fn c07_mainnet_validator_set_rotation_still_refused() {
    let mut b = binding(TrustBundleEnvironment::Mainnet);
    b.requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    let mut ins = inputs(TrustBundleEnvironment::Mainnet);
    ins.expected_requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    // MainNet gate precedes the validator-set-rotation gate.
    let d = eval_verified(&engine(), &b, &ins);
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

#[test]
fn c08_named_mainnet_refused_helper() {
    assert!(production_governance_execution_engine_mainnet_refused());
}

// ===========================================================================
// D. Replay / recovery / idempotency
// ===========================================================================

fn accepted_intent(env: TrustBundleEnvironment) -> ProductionGovernanceExecutionIntent {
    let b = binding(env);
    eval_verified(&engine(), &b, &inputs(env)).intent.unwrap()
}

#[test]
fn d01_no_prior_window_is_clean_no_op() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let out = engine().recover_production_governance_execution_window(None, &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::NoPriorExecutionWindow
    );
    assert!(out.is_clean());
}

#[test]
fn d02_byte_identical_intent_is_idempotent() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let prior = cur.clone();
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::IdempotentReplayOfSameIntent
    );
    assert!(out.is_clean());
}

#[test]
fn d03_conflicting_proposal_digest_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.proposal_digest = "other".to_string();
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingProposalDigestForSameDecisionId
    );
}

#[test]
fn d04_conflicting_candidate_digest_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.candidate_v2_digest = "other".to_string();
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingCandidateDigestForSameDecisionId
    );
}

#[test]
fn d05_conflicting_lifecycle_action_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.lifecycle_action = LocalLifecycleAction::Revoke;
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingLifecycleActionForSameDecisionId
    );
}

#[test]
fn d06_conflicting_proof_transcript_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.proof_transcript_digest = "other".to_string();
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingProofTranscriptForSameDecisionId
    );
}

#[test]
fn d07_conflicting_custody_evidence_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.custody_binding = Some(custody());
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingCustodyEvidenceForSameDecisionId
    );
}

#[test]
fn d08_conflicting_attestation_evidence_fails_closed() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.attestation_binding = Some(attestation());
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::ConflictingAttestationEvidenceForSameDecisionId
    );
}

#[test]
fn d09_stale_governance_epoch_in_recovery_fails_closed() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let prior = cur.clone();
    let out = engine().recover_production_governance_execution_window(
        Some(&prior),
        &cur,
        GOV_EPOCH + 10,
        None,
    );
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::StaleGovernanceEpoch
    );
}

#[test]
fn d10_stale_authority_sequence_in_recovery_fails_closed() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let prior = cur.clone();
    let out = engine().recover_production_governance_execution_window(
        Some(&prior),
        &cur,
        0,
        Some(SEQ + 1),
    );
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::StaleAuthoritySequence
    );
}

#[test]
fn d11_unrelated_decision_id_is_independent_window() {
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.decision_id = "unrelated".to_string();
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::NoPriorExecutionWindow
    );
}

#[test]
fn d12_ambiguous_recovery_fails_closed() {
    // Same decision id, same everything the recovery checks compare, but a
    // differing bound field (governance_height) => ambiguous.
    let mut prior = accepted_intent(TrustBundleEnvironment::Devnet);
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    prior.governance_height = GOV_HEIGHT + 1;
    let out =
        engine().recover_production_governance_execution_window(Some(&prior), &cur, 0, None);
    assert!(matches!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::AmbiguousRecoveryFailClosed { .. }
    ));
}

#[test]
fn d13_recovery_outcomes_are_non_mutating() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let out = engine().recover_production_governance_execution_window(None, &cur, 0, None);
    assert!(out.is_non_mutating());
}

// ===========================================================================
// E. Non-mutation evidence
// ===========================================================================

#[test]
fn e01_accept_outcome_is_non_mutating() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_non_mutating());
    assert!(d.intent.unwrap().is_non_mutating());
}

#[test]
fn e02_every_reject_outcome_is_non_mutating() {
    for src in [
        GovernanceExecutionProofSource::MissingProof,
        GovernanceExecutionProofSource::FixtureGovernanceProof,
        GovernanceExecutionProofSource::LocalOperatorAssertion,
        GovernanceExecutionProofSource::PeerMajorityAssertion,
        GovernanceExecutionProofSource::CustodyOnlyEvidence,
        GovernanceExecutionProofSource::RemoteSignerOnlyEvidence,
        GovernanceExecutionProofSource::CustodyAttestationOnlyEvidence,
    ] {
        let req = ProductionGovernanceExecutionRequest::from_proof(src);
        let d = engine().evaluate_production_governance_execution(
            &req,
            &inputs(TrustBundleEnvironment::Devnet),
            &empty_replay(),
        );
        assert!(d.outcome.is_non_mutating());
        assert!(d.outcome.is_reject());
        assert!(d.intent.is_none());
    }
}

#[test]
fn e03_reject_does_not_authorize_future_mutation() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::LocalOperatorAssertion,
    );
    let d = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert!(!d.outcome.authorizes_future_mutation_only());
    assert!(!d.authorizes_future_mutation_only());
}

#[test]
fn e04_only_accept_authorizes_future_mutation_only() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.authorizes_future_mutation_only());
}

#[test]
fn e05_disabled_is_not_a_reject_and_not_accept() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::Disabled,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(!d.outcome.is_accept());
    assert!(!d.outcome.is_reject());
    assert!(d.outcome.is_non_mutating());
}

#[test]
fn e06_engine_never_falls_back() {
    assert!(production_governance_execution_engine_never_falls_back());
}

#[test]
fn e07_engine_no_default_runtime_wiring() {
    assert!(production_governance_execution_engine_no_default_runtime_wiring());
}

#[test]
fn e08_engine_is_non_mutating_helper() {
    assert!(production_governance_execution_engine_is_non_mutating());
}

#[test]
fn e09_evaluation_does_not_mutate_replay_set() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let replay: Vec<String> = vec!["another-decision".to_string()];
    let before = replay.clone();
    let req = ProductionGovernanceExecutionRequest::from_proof(verified_source(&b));
    let _ = engine().evaluate_production_governance_execution(
        &req,
        &inputs(TrustBundleEnvironment::Devnet),
        &replay,
    );
    assert_eq!(replay, before);
}

#[test]
fn e10_evaluation_is_pure_repeatable() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1, d2);
}

// ===========================================================================
// F. C4/C5 taxonomy evidence
// ===========================================================================

#[test]
fn f01_run301_is_source_test_not_release_binary_evidence() {
    assert!(
        production_governance_execution_engine_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn f02_default_is_disabled_fail_closed() {
    assert!(production_governance_execution_engine_default_is_disabled());
}

#[test]
fn f03_validator_set_rotation_remains_unsupported() {
    assert!(production_governance_execution_engine_validator_set_rotation_unsupported());
    assert!(GovernanceExecutionRequestedOperation::ValidatorSetRotation.is_validator_set_rotation());
    assert!(GovernanceExecutionRequestedOperation::ValidatorSetRotation
        .intent_kind()
        .is_none());
}

#[test]
fn f04_policy_taxonomy_tags_stable() {
    assert_eq!(
        ProductionGovernanceExecutionEnginePolicy::Disabled.tag(),
        "disabled"
    );
    assert_eq!(
        ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution.tag(),
        "allow-source-test-verified-governance-execution"
    );
    assert_eq!(
        ProductionGovernanceExecutionEnginePolicy::RequireProductionGovernanceExecution.tag(),
        "require-production-governance-execution"
    );
    assert_eq!(
        ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired
            .tag(),
        "mainnet-production-governance-execution-required"
    );
}

#[test]
fn f05_intent_kind_tags_stable() {
    assert_eq!(
        ProductionGovernanceExecutionIntentKind::AuthorityLifecycleRotationIntent.tag(),
        "authority-lifecycle-rotation-intent"
    );
    assert_eq!(
        ProductionGovernanceExecutionIntentKind::EmergencyRevocationIntent.tag(),
        "emergency-revocation-intent"
    );
    assert_eq!(
        ProductionGovernanceExecutionIntentKind::GovernanceNoOpIntent.tag(),
        "governance-no-op-intent"
    );
}

#[test]
fn f06_all_policies_default_to_disabled() {
    let p = ProductionGovernanceExecutionEnginePolicy::default();
    assert!(p.is_disabled());
    assert!(!p.allows_source_test());
    assert!(!p.is_production());
    assert!(!p.is_mainnet());
}

#[test]
fn f07_free_functions_expose_named_digests() {
    let rid = production_governance_execution_request_id(1, "dec", "transcript", "policy");
    let rid2 = production_governance_execution_request_id(1, "dec", "transcript", "policy");
    assert_eq!(rid, rid2);
    assert!(!rid.is_empty());

    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let i = d.intent.unwrap();
    assert_eq!(
        production_governance_execution_intent_digest(&i),
        i.intent_digest()
    );

    let td = production_governance_execution_transcript_digest(1, &rid, "intent", "tag");
    assert!(!td.is_empty());
}

#[test]
fn f08_outcome_tags_are_stable_and_distinct() {
    use ProductionGovernanceExecutionOutcome as O;
    let tags = [
        O::Disabled.tag(),
        O::MainNetRefused.tag(),
        O::ValidatorSetRotationUnsupported.tag(),
        O::UnverifiedGovernanceProofRejected.tag(),
        O::FixtureGovernanceProofRejectedAsProductionAuthority.tag(),
    ];
    // All distinct.
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j]);
        }
    }
}

#[test]
fn f09_protocol_version_supported() {
    assert!(ProductionGovernanceExecutionProtocolVersion::supported().is_supported());
    assert_eq!(
        ProductionGovernanceExecutionProtocolVersion::supported().0,
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION
    );
}

#[test]
fn f10_config_default_is_disabled_kind() {
    let c = ProductionGovernanceExecutionEngineConfig::default();
    assert_eq!(c.kind, ProductionGovernanceExecutionEngineKind::Disabled);
    assert!(c.is_well_formed());
}
