//! Run 302 — release-binary helper for the Run 301 **production governance
//! execution engine**.
//!
//! Release-binary evidence for the Run 301 source/test real production
//! governance execution engine
//! (`crates/qbind-node/src/pqc_production_governance_execution_engine.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 301
//! [`ProductionGovernanceExecutionEngine`] and proves, per check with
//! PASS/FAIL, the accepted / rejection-fail-closed / MainNet-refusal /
//! replay-recovery / non-mutation / taxonomy behavior of the real engine,
//! including the environment / chain / genesis / authority-root /
//! governance-domain / governance-epoch / proposal / lifecycle / candidate /
//! authority-sequence / quorum / threshold / proof-transcript binding and the
//! Run 299 verified-on-chain-governance-proof composition.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the engine only
//! through the source/test engine, only for DevNet/TestNet identities on the
//! accept path, and never enables any production runtime path, MainNet
//! enablement, governance-execution-engine default wiring, validator-set
//! rotation, settlement, or external publication. The engine only ever produces
//! typed non-mutating authority-lifecycle execution intents; it never calls
//! Run 070, never mutates `LivePqcTrustState`, and never writes trust-bundle
//! sequence or authority marker files. Under a MainNet or production policy it
//! never falls back to fixture proofs, local operator config, peer-majority
//! proofs, custody-only or remote-signer-only material.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_302.md`.

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
use qbind_node::pqc_production_governance_execution_engine::*;
use qbind_node::pqc_production_onchain_governance_proof_verifier::{
    ProductionOnChainGovernanceProofDecision, ProductionOnChainGovernanceProofOutcome,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures (mirror the Run 301 source/test fixtures)
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

fn expect(
    b: &GovernanceExecutionProofBinding,
    ins: &ProductionGovernanceExecutionInputs,
    want: ProductionGovernanceExecutionOutcome,
) {
    let d = eval_verified(&engine(), b, ins);
    assert_eq!(d.outcome, want);
    assert!(d.intent.is_none());
}

fn accepted_intent(env: TrustBundleEnvironment) -> ProductionGovernanceExecutionIntent {
    let b = binding(env);
    eval_verified(&engine(), &b, &inputs(env)).intent.unwrap()
}

// ===========================================================================
// A. Accepted / compatible source-test evidence
// ===========================================================================

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

fn a02_valid_devnet_decision_produces_intent() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert!(d.intent.is_some());
}

fn a03_valid_testnet_decision_produces_intent() {
    let b = binding(TrustBundleEnvironment::Testnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Testnet));
    assert!(d.is_accept());
    assert!(d.intent.is_some());
}

fn a04_accepted_intent_binds_environment() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().environment, TrustBundleEnvironment::Devnet);
}

fn a05_accepted_intent_binds_chain_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().chain_id, "qbind-devnet");
}

fn a06_accepted_intent_binds_genesis() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().genesis_hash, GENESIS_HASH);
}

fn a07_accepted_intent_binds_authority_root() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let i = d.intent.unwrap();
    assert_eq!(i.authority_root_fingerprint, ROOT_FP);
    assert_eq!(i.authority_root_suite_id, PQC_LIFECYCLE_SUITE_ML_DSA_44);
}

fn a08_accepted_intent_binds_governance_domain() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().governance_domain_id, GOV_DOMAIN);
}

fn a09_accepted_intent_binds_governance_epoch() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().governance_epoch, GOV_EPOCH);
}

fn a10_accepted_intent_binds_proposal_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proposal_id, PROPOSAL_ID);
}

fn a11_accepted_intent_binds_proposal_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proposal_digest, PROPOSAL_DIGEST);
}

fn a12_accepted_intent_binds_proposal_outcome() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d.intent.unwrap().proposal_outcome,
        OnChainGovernanceProposalOutcome::Approved
    );
}

fn a13_accepted_intent_binds_lifecycle_action() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().lifecycle_action, LocalLifecycleAction::Rotate);
}

fn a14_accepted_intent_binds_candidate_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().candidate_v2_digest, CANDIDATE_DIGEST);
}

fn a15_accepted_intent_binds_authority_sequence() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().authority_domain_sequence, SEQ);
}

fn a16_accepted_intent_binds_decision_id() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().decision_id, DECISION_ID);
}

fn a17_accepted_intent_binds_quorum_threshold() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let i = d.intent.unwrap();
    assert_eq!(i.quorum, quorum());
    assert_eq!(i.threshold, threshold());
}

fn a18_accepted_intent_binds_proof_transcript_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().proof_transcript_digest, TRANSCRIPT_DIGEST);
}

fn a19_accepted_intent_binds_checkpoint_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.intent.unwrap().trusted_checkpoint_digest, CHECKPOINT_DIGEST);
}

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

fn a23_intent_digest_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.intent_digest, d2.intent_digest);
    assert!(!d1.intent_digest.is_empty());
}

fn a24_request_id_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.request_id, d2.request_id);
}

fn a25_transcript_digest_deterministic() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
}

fn a26_same_decision_same_intent_digest() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(
        d1.intent.unwrap().intent_digest(),
        d2.intent.unwrap().intent_digest()
    );
}

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

fn a33_accept_outcome_helpers() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_accept());
    assert!(!d.outcome.is_reject());
    assert!(d.outcome.is_non_mutating());
    assert!(d.outcome.authorizes_future_mutation_only());
    assert!(d.authorizes_future_mutation_only());
}

fn a32_run299_accept_output_composes_into_engine() {
    // Compose with the real Run 299 verifier accept output. Build a valid
    // Run 299 proof bundle, verify it with the real Merkle inclusion verifier,
    // extract the transcript/proof digests from the accept decision, and feed a
    // matching binding to the real Run 301 engine.
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

// ===========================================================================
// B. Rejection / fail-closed source-test evidence
// ===========================================================================

fn b01_disabled_rejects_before_evaluation() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::source_test(),
        ProductionGovernanceExecutionEnginePolicy::Disabled,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::Disabled);
}

fn b02_missing_proof_rejected() {
    let req = ProductionGovernanceExecutionRequest::from_proof(
        GovernanceExecutionProofSource::MissingProof,
    );
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

fn b11_wrong_proof_transcript_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proof_transcript_digest = "wrong-transcript".to_string();
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

fn b13_wrong_environment_rejected() {
    let b = binding(TrustBundleEnvironment::Testnet);
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongEnvironment,
    );
}

fn b14_wrong_chain_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.chain_id = "wrong-chain".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongChain,
    );
}

fn b15_wrong_genesis_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.genesis_hash = "wrong-genesis".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGenesis,
    );
}

fn b16_wrong_authority_root_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.authority_root_fingerprint = "wrong-root".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongAuthorityRoot,
    );
}

fn b17_wrong_governance_domain_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.governance_domain_id = "wrong-domain".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGovernanceDomain,
    );
}

fn b18_wrong_governance_epoch_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.governance_epoch = GOV_EPOCH + 1;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongGovernanceEpoch,
    );
}

fn b19_wrong_proposal_id_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_id = "wrong-proposal".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalId,
    );
}

fn b20_wrong_proposal_digest_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_digest = "wrong-digest".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalDigest,
    );
}

fn b21_wrong_proposal_outcome_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongProposalOutcome,
    );
}

fn b22_wrong_lifecycle_action_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.lifecycle_action = LocalLifecycleAction::Retire;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongLifecycleAction,
    );
}

fn b23_wrong_candidate_digest_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.candidate_v2_digest = "wrong-candidate".to_string();
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongCandidateDigest,
    );
}

fn b24_wrong_authority_sequence_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.authority_domain_sequence = SEQ + 5;
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongAuthoritySequence,
    );
}

fn b25_wrong_decision_id_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.decision_id = "other-decision".to_string();
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

fn b27_wrong_threshold_rejected() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.threshold = GovernanceThreshold::new(2, 6, 10);
    expect(
        &b,
        &inputs(TrustBundleEnvironment::Devnet),
        ProductionGovernanceExecutionOutcome::WrongThreshold,
    );
}

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

fn b39_engine_kind_disabled_fails_closed() {
    let e = ProductionGovernanceExecutionEngine::new(
        ProductionGovernanceExecutionEngineConfig::new(
            ProductionGovernanceExecutionEngineKind::Disabled,
        ),
        ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution,
    );
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&e, &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::Disabled);
}

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

fn b43_malformed_binding_fails_closed() {
    let mut b = binding(TrustBundleEnvironment::Devnet);
    b.proposal_id = String::new();
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(matches!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::GovernanceExecutionAmbiguous { .. }
    ));
}

// ===========================================================================
// C. MainNet / authority policy evidence
// ===========================================================================

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
    assert_eq!(
        d.outcome,
        ProductionGovernanceExecutionOutcome::MainNetProductionGovernanceExecutionUnavailable
    );
}

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

fn c03_mainnet_domain_refused_under_source_test_policy() {
    let b = binding(TrustBundleEnvironment::Mainnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Mainnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

fn c04_mainnet_decision_env_refused_even_on_devnet_domain() {
    let b = binding(TrustBundleEnvironment::Mainnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

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

fn c06_valid_devnet_source_test_does_not_enable_mainnet() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.is_accept());
    assert_ne!(
        d.intent.unwrap().environment,
        TrustBundleEnvironment::Mainnet
    );
}

fn c07_mainnet_validator_set_rotation_still_refused() {
    let mut b = binding(TrustBundleEnvironment::Mainnet);
    b.requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    let mut ins = inputs(TrustBundleEnvironment::Mainnet);
    ins.expected_requested_operation = GovernanceExecutionRequestedOperation::ValidatorSetRotation;
    let d = eval_verified(&engine(), &b, &ins);
    assert_eq!(d.outcome, ProductionGovernanceExecutionOutcome::MainNetRefused);
}

fn c08_named_mainnet_refused_helper() {
    assert!(production_governance_execution_engine_mainnet_refused());
}

// ===========================================================================
// D. Replay / recovery / idempotency
// ===========================================================================

fn d01_no_prior_window_is_clean_no_op() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let out = engine().recover_production_governance_execution_window(None, &cur, 0, None);
    assert_eq!(
        out,
        ProductionGovernanceExecutionRecoveryOutcome::NoPriorExecutionWindow
    );
    assert!(out.is_clean());
}

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

fn d12_ambiguous_recovery_fails_closed() {
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

fn d13_recovery_outcomes_are_non_mutating() {
    let cur = accepted_intent(TrustBundleEnvironment::Devnet);
    let out = engine().recover_production_governance_execution_window(None, &cur, 0, None);
    assert!(out.is_non_mutating());
}

// ===========================================================================
// E. Non-mutation evidence
// ===========================================================================

fn e01_accept_outcome_is_non_mutating() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.outcome.is_non_mutating());
    assert!(d.intent.unwrap().is_non_mutating());
}

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

fn e04_only_accept_authorizes_future_mutation_only() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert!(d.authorizes_future_mutation_only());
}

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

fn e06_engine_never_falls_back() {
    assert!(production_governance_execution_engine_never_falls_back());
}

fn e07_engine_no_default_runtime_wiring() {
    assert!(production_governance_execution_engine_no_default_runtime_wiring());
}

fn e08_engine_is_non_mutating_helper() {
    assert!(production_governance_execution_engine_is_non_mutating());
}

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

fn e10_evaluation_is_pure_repeatable() {
    let b = binding(TrustBundleEnvironment::Devnet);
    let d1 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    let d2 = eval_verified(&engine(), &b, &inputs(TrustBundleEnvironment::Devnet));
    assert_eq!(d1, d2);
}

// ===========================================================================
// F. C4/C5 taxonomy evidence
// ===========================================================================

fn f01_run301_is_source_test_not_release_binary_evidence() {
    assert!(
        production_governance_execution_engine_is_source_test_not_release_binary_evidence()
    );
}

fn f02_default_is_disabled_fail_closed() {
    assert!(production_governance_execution_engine_default_is_disabled());
}

fn f03_validator_set_rotation_remains_unsupported() {
    assert!(production_governance_execution_engine_validator_set_rotation_unsupported());
    assert!(GovernanceExecutionRequestedOperation::ValidatorSetRotation.is_validator_set_rotation());
    assert!(GovernanceExecutionRequestedOperation::ValidatorSetRotation
        .intent_kind()
        .is_none());
}

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

fn f06_all_policies_default_to_disabled() {
    let p = ProductionGovernanceExecutionEnginePolicy::default();
    assert!(p.is_disabled());
    assert!(!p.allows_source_test());
    assert!(!p.is_production());
    assert!(!p.is_mainnet());
}

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

fn f08_outcome_tags_are_stable_and_distinct() {
    use ProductionGovernanceExecutionOutcome as O;
    let tags = [
        O::Disabled.tag(),
        O::MainNetRefused.tag(),
        O::ValidatorSetRotationUnsupported.tag(),
        O::UnverifiedGovernanceProofRejected.tag(),
        O::FixtureGovernanceProofRejectedAsProductionAuthority.tag(),
    ];
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j]);
        }
    }
}

fn f09_protocol_version_supported() {
    assert!(ProductionGovernanceExecutionProtocolVersion::supported().is_supported());
    assert_eq!(
        ProductionGovernanceExecutionProtocolVersion::supported().0,
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION
    );
}

fn f10_config_default_is_disabled_kind() {
    let c = ProductionGovernanceExecutionEngineConfig::default();
    assert_eq!(c.kind, ProductionGovernanceExecutionEngineKind::Disabled);
    assert!(c.is_well_formed());
}

// ===========================================================================
// G. Release-symbol reachability probe
// ===========================================================================

fn g01_release_symbol_reachability_probe() {
    // Touch a broad slice of the Run 301 production governance execution engine
    // surface so the release helper links against and exercises the real
    // production symbols.
    assert_eq!(PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION, 1);
    assert!(ProductionGovernanceExecutionProtocolVersion::supported().is_supported());

    // Engine construction surfaces.
    let cfg = ProductionGovernanceExecutionEngineConfig::default();
    assert!(cfg.is_well_formed());
    assert_eq!(cfg.kind, ProductionGovernanceExecutionEngineKind::Disabled);
    let cfg_st = ProductionGovernanceExecutionEngineConfig::source_test();
    assert_eq!(
        cfg_st.kind,
        ProductionGovernanceExecutionEngineKind::SourceTestGovernanceExecutionEngine
    );
    let _cfg_new = ProductionGovernanceExecutionEngineConfig::new(
        ProductionGovernanceExecutionEngineKind::ProductionGovernanceExecutionEngine,
    );

    // Policy taxonomy surfaces.
    for p in [
        ProductionGovernanceExecutionEnginePolicy::Disabled,
        ProductionGovernanceExecutionEnginePolicy::AllowSourceTestVerifiedGovernanceExecution,
        ProductionGovernanceExecutionEnginePolicy::RequireProductionGovernanceExecution,
        ProductionGovernanceExecutionEnginePolicy::MainnetProductionGovernanceExecutionRequired,
    ] {
        assert!(!p.tag().is_empty());
        let _ = (p.is_disabled(), p.allows_source_test(), p.is_production(), p.is_mainnet());
    }

    let env = TrustBundleEnvironment::Devnet;

    // Real accept path yields a typed non-mutating intent.
    let b = binding(env);
    let decision = eval_verified(&engine(), &b, &inputs(env));
    assert!(decision.is_accept());
    assert!(decision.outcome.is_accept());
    assert!(!decision.outcome.is_reject());
    assert!(decision.outcome.is_non_mutating());
    assert!(decision.authorizes_future_mutation_only());
    assert!(!decision.outcome.tag().is_empty());
    let intent = decision.intent.clone().unwrap();
    assert!(intent.is_non_mutating());
    assert!(!intent.intent_kind.tag().is_empty());

    // Requested-operation / intent-kind surfaces.
    for op in [
        GovernanceExecutionRequestedOperation::AuthorityLifecycleRotation,
        GovernanceExecutionRequestedOperation::AuthorityLifecycleRetirement,
        GovernanceExecutionRequestedOperation::AuthorityLifecycleRevocation,
        GovernanceExecutionRequestedOperation::EmergencyRevocation,
        GovernanceExecutionRequestedOperation::BundleSigningKeyAuthorization,
        GovernanceExecutionRequestedOperation::BundleSigningKeyRetirement,
        GovernanceExecutionRequestedOperation::BundleSigningKeyRevocation,
        GovernanceExecutionRequestedOperation::GovernanceNoOp,
        GovernanceExecutionRequestedOperation::ValidatorSetRotation,
    ] {
        let _ = (op.is_validator_set_rotation(), op.intent_kind());
    }

    // Recovery surfaces.
    let cur = accepted_intent(env);
    let rec = engine().recover_production_governance_execution_window(None, &cur, 0, None);
    assert_eq!(
        rec,
        ProductionGovernanceExecutionRecoveryOutcome::NoPriorExecutionWindow
    );
    assert!(rec.is_clean());
    assert!(rec.is_non_mutating());

    // Named free-function digest surfaces are linked and deterministic.
    let rid = production_governance_execution_request_id(
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION,
        "dec",
        "transcript",
        "policy",
    );
    assert!(!rid.is_empty());
    let idig = production_governance_execution_intent_digest(&intent);
    assert_eq!(idig, intent.intent_digest());
    let tdig = production_governance_execution_transcript_digest(
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION,
        &rid,
        &idig,
        decision.outcome.tag(),
    );
    assert!(!tdig.is_empty());

    // Named invariant helpers.
    assert!(production_governance_execution_engine_default_is_disabled());
    assert!(production_governance_execution_engine_is_source_test_not_release_binary_evidence());
    assert!(production_governance_execution_engine_mainnet_refused());
    assert!(production_governance_execution_engine_validator_set_rotation_unsupported());
    assert!(production_governance_execution_engine_is_non_mutating());
    assert!(production_governance_execution_engine_never_falls_back());
    assert!(production_governance_execution_engine_no_default_runtime_wiring());
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
            "docs/devnet/run_302_production_governance_execution_engine_release_binary/helper_evidence/run_302",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_default_policy_is_disabled_and_inert", a01_default_policy_is_disabled_and_inert as fn()),
        ("accepted_compatible", "a02_valid_devnet_decision_produces_intent", a02_valid_devnet_decision_produces_intent as fn()),
        ("accepted_compatible", "a03_valid_testnet_decision_produces_intent", a03_valid_testnet_decision_produces_intent as fn()),
        ("accepted_compatible", "a04_accepted_intent_binds_environment", a04_accepted_intent_binds_environment as fn()),
        ("accepted_compatible", "a05_accepted_intent_binds_chain_id", a05_accepted_intent_binds_chain_id as fn()),
        ("accepted_compatible", "a06_accepted_intent_binds_genesis", a06_accepted_intent_binds_genesis as fn()),
        ("accepted_compatible", "a07_accepted_intent_binds_authority_root", a07_accepted_intent_binds_authority_root as fn()),
        ("accepted_compatible", "a08_accepted_intent_binds_governance_domain", a08_accepted_intent_binds_governance_domain as fn()),
        ("accepted_compatible", "a09_accepted_intent_binds_governance_epoch", a09_accepted_intent_binds_governance_epoch as fn()),
        ("accepted_compatible", "a10_accepted_intent_binds_proposal_id", a10_accepted_intent_binds_proposal_id as fn()),
        ("accepted_compatible", "a11_accepted_intent_binds_proposal_digest", a11_accepted_intent_binds_proposal_digest as fn()),
        ("accepted_compatible", "a12_accepted_intent_binds_proposal_outcome", a12_accepted_intent_binds_proposal_outcome as fn()),
        ("accepted_compatible", "a13_accepted_intent_binds_lifecycle_action", a13_accepted_intent_binds_lifecycle_action as fn()),
        ("accepted_compatible", "a14_accepted_intent_binds_candidate_digest", a14_accepted_intent_binds_candidate_digest as fn()),
        ("accepted_compatible", "a15_accepted_intent_binds_authority_sequence", a15_accepted_intent_binds_authority_sequence as fn()),
        ("accepted_compatible", "a16_accepted_intent_binds_decision_id", a16_accepted_intent_binds_decision_id as fn()),
        ("accepted_compatible", "a17_accepted_intent_binds_quorum_threshold", a17_accepted_intent_binds_quorum_threshold as fn()),
        ("accepted_compatible", "a18_accepted_intent_binds_proof_transcript_digest", a18_accepted_intent_binds_proof_transcript_digest as fn()),
        ("accepted_compatible", "a19_accepted_intent_binds_checkpoint_digest", a19_accepted_intent_binds_checkpoint_digest as fn()),
        ("accepted_compatible", "a20_accepted_intent_binds_custody_evidence_when_represented", a20_accepted_intent_binds_custody_evidence_when_represented as fn()),
        ("accepted_compatible", "a21_accepted_intent_binds_attestation_evidence_when_represented", a21_accepted_intent_binds_attestation_evidence_when_represented as fn()),
        ("accepted_compatible", "a22_accepted_intent_binds_durable_replay_evidence_when_represented", a22_accepted_intent_binds_durable_replay_evidence_when_represented as fn()),
        ("accepted_compatible", "a23_intent_digest_deterministic", a23_intent_digest_deterministic as fn()),
        ("accepted_compatible", "a24_request_id_deterministic", a24_request_id_deterministic as fn()),
        ("accepted_compatible", "a25_transcript_digest_deterministic", a25_transcript_digest_deterministic as fn()),
        ("accepted_compatible", "a26_same_decision_same_intent_digest", a26_same_decision_same_intent_digest as fn()),
        ("accepted_compatible", "a27_different_lifecycle_action_changes_intent_digest", a27_different_lifecycle_action_changes_intent_digest as fn()),
        ("accepted_compatible", "a28_different_candidate_digest_changes_intent_digest", a28_different_candidate_digest_changes_intent_digest as fn()),
        ("accepted_compatible", "a29_emergency_revocation_is_prepared_intent_only", a29_emergency_revocation_is_prepared_intent_only as fn()),
        ("accepted_compatible", "a30_rotate_retire_revoke_are_prepared_intents_only", a30_rotate_retire_revoke_are_prepared_intents_only as fn()),
        ("accepted_compatible", "a31_bundle_signing_key_authorization_intent", a31_bundle_signing_key_authorization_intent as fn()),
        ("accepted_compatible", "a32_run299_accept_output_composes_into_engine", a32_run299_accept_output_composes_into_engine as fn()),
        ("accepted_compatible", "a33_accept_outcome_helpers", a33_accept_outcome_helpers as fn()),
        ("rejection_fail_closed", "b01_disabled_rejects_before_evaluation", b01_disabled_rejects_before_evaluation as fn()),
        ("rejection_fail_closed", "b02_missing_proof_rejected", b02_missing_proof_rejected as fn()),
        ("rejection_fail_closed", "b03_unverified_proof_rejected", b03_unverified_proof_rejected as fn()),
        ("rejection_fail_closed", "b04_explicit_unverified_source_rejected", b04_explicit_unverified_source_rejected as fn()),
        ("rejection_fail_closed", "b05_fixture_proof_rejected_as_production_authority", b05_fixture_proof_rejected_as_production_authority as fn()),
        ("rejection_fail_closed", "b06_local_operator_assertion_rejected", b06_local_operator_assertion_rejected as fn()),
        ("rejection_fail_closed", "b07_peer_majority_assertion_rejected", b07_peer_majority_assertion_rejected as fn()),
        ("rejection_fail_closed", "b08_custody_only_evidence_rejected", b08_custody_only_evidence_rejected as fn()),
        ("rejection_fail_closed", "b09_remote_signer_only_evidence_rejected", b09_remote_signer_only_evidence_rejected as fn()),
        ("rejection_fail_closed", "b10_custody_attestation_only_evidence_rejected", b10_custody_attestation_only_evidence_rejected as fn()),
        ("rejection_fail_closed", "b11_wrong_proof_transcript_rejected", b11_wrong_proof_transcript_rejected as fn()),
        ("rejection_fail_closed", "b12_transcript_mismatch_between_binding_and_decision", b12_transcript_mismatch_between_binding_and_decision as fn()),
        ("rejection_fail_closed", "b13_wrong_environment_rejected", b13_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b14_wrong_chain_rejected", b14_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b15_wrong_genesis_rejected", b15_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_authority_root_rejected", b16_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_governance_domain_rejected", b17_wrong_governance_domain_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_governance_epoch_rejected", b18_wrong_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b19_wrong_proposal_id_rejected", b19_wrong_proposal_id_rejected as fn()),
        ("rejection_fail_closed", "b20_wrong_proposal_digest_rejected", b20_wrong_proposal_digest_rejected as fn()),
        ("rejection_fail_closed", "b21_wrong_proposal_outcome_rejected", b21_wrong_proposal_outcome_rejected as fn()),
        ("rejection_fail_closed", "b22_wrong_lifecycle_action_rejected", b22_wrong_lifecycle_action_rejected as fn()),
        ("rejection_fail_closed", "b23_wrong_candidate_digest_rejected", b23_wrong_candidate_digest_rejected as fn()),
        ("rejection_fail_closed", "b24_wrong_authority_sequence_rejected", b24_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b25_wrong_decision_id_rejected", b25_wrong_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b26_wrong_quorum_rejected", b26_wrong_quorum_rejected as fn()),
        ("rejection_fail_closed", "b27_wrong_threshold_rejected", b27_wrong_threshold_rejected as fn()),
        ("rejection_fail_closed", "b28_missing_custody_evidence_rejected_when_required", b28_missing_custody_evidence_rejected_when_required as fn()),
        ("rejection_fail_closed", "b29_wrong_custody_backend_rejected", b29_wrong_custody_backend_rejected as fn()),
        ("rejection_fail_closed", "b30_missing_attestation_rejected_when_required", b30_missing_attestation_rejected_when_required as fn()),
        ("rejection_fail_closed", "b31_wrong_attestation_rejected", b31_wrong_attestation_rejected as fn()),
        ("rejection_fail_closed", "b32_missing_durable_replay_rejected_when_required", b32_missing_durable_replay_rejected_when_required as fn()),
        ("rejection_fail_closed", "b33_wrong_durable_replay_rejected", b33_wrong_durable_replay_rejected as fn()),
        ("rejection_fail_closed", "b34_replayed_decision_id_rejected", b34_replayed_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b35_stale_governance_epoch_rejected", b35_stale_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b36_stale_authority_sequence_rejected", b36_stale_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b37_unsupported_lifecycle_action_rejected", b37_unsupported_lifecycle_action_rejected as fn()),
        ("rejection_fail_closed", "b38_validator_set_rotation_unsupported", b38_validator_set_rotation_unsupported as fn()),
        ("rejection_fail_closed", "b39_engine_kind_disabled_fails_closed", b39_engine_kind_disabled_fails_closed as fn()),
        ("rejection_fail_closed", "b40_reserved_production_engine_kind_unavailable", b40_reserved_production_engine_kind_unavailable as fn()),
        ("rejection_fail_closed", "b41_production_policy_without_prereqs_fails_closed", b41_production_policy_without_prereqs_fails_closed as fn()),
        ("rejection_fail_closed", "b42_ambiguous_inputs_fail_closed", b42_ambiguous_inputs_fail_closed as fn()),
        ("rejection_fail_closed", "b43_malformed_binding_fails_closed", b43_malformed_binding_fails_closed as fn()),
        ("mainnet_authority_policy", "c01_mainnet_cannot_be_satisfied_by_fixture_proof", c01_mainnet_cannot_be_satisfied_by_fixture_proof as fn()),
        ("mainnet_authority_policy", "c02_mainnet_cannot_be_satisfied_by_local_operator", c02_mainnet_cannot_be_satisfied_by_local_operator as fn()),
        ("mainnet_authority_policy", "c03_mainnet_domain_refused_under_source_test_policy", c03_mainnet_domain_refused_under_source_test_policy as fn()),
        ("mainnet_authority_policy", "c04_mainnet_decision_env_refused_even_on_devnet_domain", c04_mainnet_decision_env_refused_even_on_devnet_domain as fn()),
        ("mainnet_authority_policy", "c05_mainnet_production_policy_on_devnet_fails_closed", c05_mainnet_production_policy_on_devnet_fails_closed as fn()),
        ("mainnet_authority_policy", "c06_valid_devnet_source_test_does_not_enable_mainnet", c06_valid_devnet_source_test_does_not_enable_mainnet as fn()),
        ("mainnet_authority_policy", "c07_mainnet_validator_set_rotation_still_refused", c07_mainnet_validator_set_rotation_still_refused as fn()),
        ("mainnet_authority_policy", "c08_named_mainnet_refused_helper", c08_named_mainnet_refused_helper as fn()),
        ("replay_recovery_idempotency", "d01_no_prior_window_is_clean_no_op", d01_no_prior_window_is_clean_no_op as fn()),
        ("replay_recovery_idempotency", "d02_byte_identical_intent_is_idempotent", d02_byte_identical_intent_is_idempotent as fn()),
        ("replay_recovery_idempotency", "d03_conflicting_proposal_digest_fails_closed", d03_conflicting_proposal_digest_fails_closed as fn()),
        ("replay_recovery_idempotency", "d04_conflicting_candidate_digest_fails_closed", d04_conflicting_candidate_digest_fails_closed as fn()),
        ("replay_recovery_idempotency", "d05_conflicting_lifecycle_action_fails_closed", d05_conflicting_lifecycle_action_fails_closed as fn()),
        ("replay_recovery_idempotency", "d06_conflicting_proof_transcript_fails_closed", d06_conflicting_proof_transcript_fails_closed as fn()),
        ("replay_recovery_idempotency", "d07_conflicting_custody_evidence_fails_closed", d07_conflicting_custody_evidence_fails_closed as fn()),
        ("replay_recovery_idempotency", "d08_conflicting_attestation_evidence_fails_closed", d08_conflicting_attestation_evidence_fails_closed as fn()),
        ("replay_recovery_idempotency", "d09_stale_governance_epoch_in_recovery_fails_closed", d09_stale_governance_epoch_in_recovery_fails_closed as fn()),
        ("replay_recovery_idempotency", "d10_stale_authority_sequence_in_recovery_fails_closed", d10_stale_authority_sequence_in_recovery_fails_closed as fn()),
        ("replay_recovery_idempotency", "d11_unrelated_decision_id_is_independent_window", d11_unrelated_decision_id_is_independent_window as fn()),
        ("replay_recovery_idempotency", "d12_ambiguous_recovery_fails_closed", d12_ambiguous_recovery_fails_closed as fn()),
        ("replay_recovery_idempotency", "d13_recovery_outcomes_are_non_mutating", d13_recovery_outcomes_are_non_mutating as fn()),
        ("non_mutation", "e01_accept_outcome_is_non_mutating", e01_accept_outcome_is_non_mutating as fn()),
        ("non_mutation", "e02_every_reject_outcome_is_non_mutating", e02_every_reject_outcome_is_non_mutating as fn()),
        ("non_mutation", "e03_reject_does_not_authorize_future_mutation", e03_reject_does_not_authorize_future_mutation as fn()),
        ("non_mutation", "e04_only_accept_authorizes_future_mutation_only", e04_only_accept_authorizes_future_mutation_only as fn()),
        ("non_mutation", "e05_disabled_is_not_a_reject_and_not_accept", e05_disabled_is_not_a_reject_and_not_accept as fn()),
        ("non_mutation", "e06_engine_never_falls_back", e06_engine_never_falls_back as fn()),
        ("non_mutation", "e07_engine_no_default_runtime_wiring", e07_engine_no_default_runtime_wiring as fn()),
        ("non_mutation", "e08_engine_is_non_mutating_helper", e08_engine_is_non_mutating_helper as fn()),
        ("non_mutation", "e09_evaluation_does_not_mutate_replay_set", e09_evaluation_does_not_mutate_replay_set as fn()),
        ("non_mutation", "e10_evaluation_is_pure_repeatable", e10_evaluation_is_pure_repeatable as fn()),
        ("reachability_taxonomy", "f01_run301_is_source_test_not_release_binary_evidence", f01_run301_is_source_test_not_release_binary_evidence as fn()),
        ("reachability_taxonomy", "f02_default_is_disabled_fail_closed", f02_default_is_disabled_fail_closed as fn()),
        ("reachability_taxonomy", "f03_validator_set_rotation_remains_unsupported", f03_validator_set_rotation_remains_unsupported as fn()),
        ("reachability_taxonomy", "f04_policy_taxonomy_tags_stable", f04_policy_taxonomy_tags_stable as fn()),
        ("reachability_taxonomy", "f05_intent_kind_tags_stable", f05_intent_kind_tags_stable as fn()),
        ("reachability_taxonomy", "f06_all_policies_default_to_disabled", f06_all_policies_default_to_disabled as fn()),
        ("reachability_taxonomy", "f07_free_functions_expose_named_digests", f07_free_functions_expose_named_digests as fn()),
        ("reachability_taxonomy", "f08_outcome_tags_are_stable_and_distinct", f08_outcome_tags_are_stable_and_distinct as fn()),
        ("reachability_taxonomy", "f09_protocol_version_supported", f09_protocol_version_supported as fn()),
        ("reachability_taxonomy", "f10_config_default_is_disabled_kind", f10_config_default_is_disabled_kind as fn()),
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
    summary.push_str("Run 302 production governance execution engine release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "engine: crates/qbind-node/src/pqc_production_governance_execution_engine.rs (Run 301 ProductionGovernanceExecutionEngine)\n",
    );
    summary.push_str(
        "mode: real Run 301 production governance execution engine over the real Run 299 verified on-chain governance proof decision; DevNet/TestNet source-test accept only; MainNet refused; default Disabled; MainNet/production policy never evaluates and never falls back to fixture / local-operator / peer-majority / custody-only / remote-signer / custody-attestation material; consumes verified on-chain governance proof decisions and produces typed non-mutating authority-lifecycle execution intents; does not call Run 070; does not mutate LivePqcTrustState; does not write trust-bundle sequence or authority marker files; does not implement validator-set rotation; every failure is a typed non-mutating outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let b = binding(env);
    let decision = eval_verified(&engine(), &b, &inputs(env));
    let intent = decision.intent.clone().expect("accept intent");
    let intent_digest = production_governance_execution_intent_digest(&intent);
    let request_id = production_governance_execution_request_id(
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION,
        DECISION_ID,
        TRANSCRIPT_DIGEST,
        POLICY_ID,
    );
    let transcript_digest = production_governance_execution_transcript_digest(
        PRODUCTION_GOVERNANCE_EXECUTION_ENGINE_PROTOCOL_VERSION,
        &request_id,
        &intent_digest,
        decision.outcome.tag(),
    );
    fs::write(
        outdir.join("fixtures/run_302_deterministic_digests.txt"),
        format!(
            "request_id {request_id}\nintent_digest {intent_digest}\ntranscript_digest {transcript_digest}\noutcome_tag {}\n",
            decision.outcome.tag()
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}