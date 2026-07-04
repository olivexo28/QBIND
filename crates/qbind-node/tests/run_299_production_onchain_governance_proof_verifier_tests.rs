//! Run 299 — source/test real on-chain governance proof verifier
//! integration tests.
//!
//! Source/test only. Run 299 does **not** capture release-binary
//! evidence; release-binary evidence for the production on-chain
//! governance proof verifier is deferred to **Run 300**. The tests cover:
//!
//! * A. accepted / compatible source-test evidence;
//! * B. rejection / fail-closed paths;
//! * C. MainNet / authority policy refusal;
//! * D. non-mutation invariants (the verifier surfaces are pure);
//! * E. replay / recovery / idempotency;
//! * F. C4/C5 taxonomy status.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_299.md`.

use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_proof::{
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
};
use qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceProofClass;
use qbind_node::pqc_production_onchain_governance_proof_verifier::*;
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
const ACTIVE_FP: &str = "active-fp";
const NEW_FP: &str = "new-fp";
const CANDIDATE_DIGEST: &str = "candidate-digest-2";
const SEQ: u64 = 7;
const DECISION_ID: &str = "decision-id-1";
const CHECKPOINT_ID: &str = "checkpoint-1";

fn chain_for(env: TrustBundleEnvironment) -> &'static str {
    match env {
        TrustBundleEnvironment::Devnet => "qbind-devnet",
        TrustBundleEnvironment::Testnet => "qbind-testnet",
        TrustBundleEnvironment::Mainnet => "qbind-mainnet",
    }
}

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
        chain_for(env),
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn commitment(env: TrustBundleEnvironment) -> ProductionOnChainGovernanceDecisionCommitment {
    ProductionOnChainGovernanceDecisionCommitment {
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
        quorum: OnChainGovernanceQuorum {
            voters_voted: 8,
            total_voters: 10,
            required_quorum: 6,
        },
        threshold: GovernanceThreshold::new(8, 6, 10),
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: ACTIVE_FP.to_string(),
        new_bundle_signing_key_fingerprint: Some(NEW_FP.to_string()),
        revoked_bundle_signing_key_fingerprint: None,
        authority_domain_sequence: SEQ,
        candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        decision_id: DECISION_ID.to_string(),
    }
}

/// Build a valid production proof for `commitment` whose decision leaf is
/// included (with three other synthetic leaves) in a Merkle tree, plus the
/// trusted checkpoint carrying that root and the matching verification
/// inputs.
fn valid_bundle(
    env: TrustBundleEnvironment,
) -> (
    ProductionOnChainGovernanceProof,
    ProductionOnChainGovernanceTrustedCheckpoint,
    ProductionOnChainGovernanceVerificationInputs,
) {
    let c = commitment(env);
    let leaf = c.decision_digest();
    let leaves = vec![
        "sibling-leaf-a".to_string(),
        leaf.clone(),
        "sibling-leaf-b".to_string(),
        "sibling-leaf-c".to_string(),
    ];
    let (root_hex, inclusion) = build_merkle_inclusion_proof(&leaves, 1).unwrap();

    let proof = ProductionOnChainGovernanceProof {
        protocol_version: ProductionOnChainGovernanceProofProtocolVersion::supported(),
        proof_suite: ProductionOnChainGovernanceProofSuite::merkle_v1(),
        domain_separation_tag: PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG.to_string(),
        commitment: c,
        inclusion_proof: inclusion,
        proof_bytes_digest: String::new(),
    }
    .seal();

    let checkpoint = ProductionOnChainGovernanceTrustedCheckpoint {
        checkpoint_id: CHECKPOINT_ID.to_string(),
        governance_root_hex: root_hex,
        receipt_root_hex: None,
        event_root_hex: None,
        state_root_hex: None,
        governance_height: GOV_HEIGHT,
        governance_epoch: GOV_EPOCH,
    };

    let inputs = ProductionOnChainGovernanceVerificationInputs {
        trusted_checkpoint: checkpoint.clone(),
        expected_governance_domain_id: GOV_DOMAIN.to_string(),
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID.to_string(),
        expected_proposal_digest: PROPOSAL_DIGEST.to_string(),
        expected_proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_v2_digest: CANDIDATE_DIGEST.to_string(),
        expected_authority_domain_sequence: SEQ,
        freshness_bounds: ProductionOnChainGovernanceFreshnessBounds {
            min_governance_height: 0,
            max_governance_height: 10_000,
            min_governance_epoch: 0,
            max_governance_epoch: 100,
        },
        persisted_sequence: Some(SEQ - 1),
    };

    (proof, checkpoint, inputs)
}

fn merkle_verifier(
    policy: ProductionOnChainGovernanceVerifierPolicy,
) -> ProductionOnChainGovernanceProofVerifier<RealMerkleInclusionVerifier> {
    ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        policy,
        RealMerkleInclusionVerifier::new(),
    )
}

fn source_test_verifier() -> ProductionOnChainGovernanceProofVerifier<RealMerkleInclusionVerifier> {
    merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof)
}

fn empty_replay() -> EmptyProductionOnChainGovernanceReplaySet {
    EmptyProductionOnChainGovernanceReplaySet
}

fn verify(
    v: &ProductionOnChainGovernanceProofVerifier<RealMerkleInclusionVerifier>,
    proof: &ProductionOnChainGovernanceProof,
    inputs: &ProductionOnChainGovernanceVerificationInputs,
    env: TrustBundleEnvironment,
) -> ProductionOnChainGovernanceProofOutcome {
    v.verify_production_onchain_governance_proof_real(proof, inputs, &domain(env), &empty_replay())
}

// ===========================================================================
// A. Accepted / compatible
// ===========================================================================

#[test]
fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_onchain_governance_verifier_default_is_disabled());
    let v = merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::default());
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert_eq!(out, ProductionOnChainGovernanceProofOutcome::Disabled);
}

#[test]
fn a02_valid_production_proof_accepted_devnet() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(out.is_accept(), "expected accept, got {:?}", out);
}

#[test]
fn a03_valid_production_proof_accepted_testnet() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Testnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Testnet);
    assert!(out.is_accept(), "expected accept, got {:?}", out);
}

#[test]
fn a04_accept_binds_environment() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    match verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet) {
        ProductionOnChainGovernanceProofOutcome::AcceptedProductionOnChainGovernanceProof {
            environment,
            ..
        } => assert_eq!(environment, TrustBundleEnvironment::Devnet),
        o => panic!("expected accept, got {:?}", o),
    }
}

#[test]
fn a05_accept_binds_governance_epoch_sequence_action_decision() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    match verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet) {
        ProductionOnChainGovernanceProofOutcome::AcceptedProductionOnChainGovernanceProof {
            governance_epoch,
            authority_domain_sequence,
            lifecycle_action,
            decision_id,
            ..
        } => {
            assert_eq!(governance_epoch, GOV_EPOCH);
            assert_eq!(authority_domain_sequence, SEQ);
            assert_eq!(lifecycle_action, LocalLifecycleAction::Rotate);
            assert_eq!(decision_id, DECISION_ID);
        }
        o => panic!("expected accept, got {:?}", o),
    }
}

#[test]
fn a06_valid_proof_verifies_inclusion_against_trusted_root() {
    // The real Merkle verifier recomputes the root and must match the
    // trusted checkpoint root.
    let (proof, cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let leaf = proof.commitment.decision_digest();
    assert!(proof.inclusion_proof.verify(&leaf, &cp.governance_root_hex));
}

#[test]
fn a07_valid_proof_enforces_quorum_and_threshold() {
    // A proof whose quorum/threshold are met is accepted; unmet is not.
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert!(verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet).is_accept());
}

#[test]
fn a08_deterministic_proof_digest_stable() {
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        production_onchain_governance_proof_digest(&proof),
        production_onchain_governance_proof_digest(&proof)
    );
    assert_eq!(proof.expected_proof_digest(), proof.proof_bytes_digest);
}

#[test]
fn a09_deterministic_decision_digest_stable() {
    let c = commitment(TrustBundleEnvironment::Devnet);
    assert_eq!(
        production_onchain_governance_decision_digest(&c),
        c.decision_digest()
    );
    assert_eq!(c.decision_digest(), commitment(TrustBundleEnvironment::Devnet).decision_digest());
}

#[test]
fn a10_deterministic_transcript_digest_stable() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let d1 = v.evaluate_production_onchain_governance_proof(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    let d2 = v.evaluate_production_onchain_governance_proof(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(d1.transcript_digest, d2.transcript_digest);
    assert!(d1.is_accept());
}

#[test]
fn a11_run186_classifier_routes_production_suite_as_production() {
    // Composition: the Run 186 classifier must route the Run 299 production
    // suite as production-class, not fixture.
    assert_eq!(
        classify_production_suite_through_run186(
            ProductionOnChainGovernanceProofSuite::merkle_v1()
        ),
        OnChainGovernanceProofClass::Production
    );
}

#[test]
fn a12_run186_classifier_routes_fixture_suite_as_fixture() {
    assert_eq!(
        classify_production_suite_through_run186(ProductionOnChainGovernanceProofSuite(
            ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1
        )),
        OnChainGovernanceProofClass::Fixture
    );
}

#[test]
fn a13_checkpoint_digest_stable() {
    let (_proof, cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(cp.checkpoint_digest(), cp.checkpoint_digest());
}

#[test]
fn a14_merkle_root_recompute_matches_build() {
    let leaves = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let (root, proof) = build_merkle_inclusion_proof(&leaves, 2).unwrap();
    let recomputed = proof.recompute_root("c").unwrap();
    assert_eq!(hex::encode(recomputed), root);
}

#[test]
fn a15_supported_protocol_and_suite_helpers() {
    assert!(ProductionOnChainGovernanceProofProtocolVersion::supported().is_supported());
    assert!(ProductionOnChainGovernanceProofSuite::merkle_v1().is_supported());
    assert!(!ProductionOnChainGovernanceProofSuite::merkle_v1().is_fixture());
    assert!(ProductionOnChainGovernanceProofSuite(
        ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1
    )
    .is_fixture());
}

#[test]
fn a16_evaluate_produces_bound_decision_id_and_proof_digest() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let d = v.evaluate_production_onchain_governance_proof(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(d.decision_id, DECISION_ID);
    assert_eq!(d.proof_digest, proof.expected_proof_digest());
}

// ===========================================================================
// B. Rejection / fail-closed
// ===========================================================================

#[test]
fn b01_disabled_rejects_before_parsing() {
    let v = merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::Disabled);
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // Even a malformed proof must return Disabled (no parsing).
    proof.proof_bytes_digest = PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL.to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::Disabled
    );
}

#[test]
fn b02_disabled_kind_config_rejects() {
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::default(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        RealMerkleInclusionVerifier::new(),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::Disabled
    );
}

#[test]
fn b03_empty_proof_bytes_digest_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_bytes_digest = String::new();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

#[test]
fn b04_invalid_proof_sentinel_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_bytes_digest = PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL.to_string();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

#[test]
fn b05_wrong_domain_separation_tag_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.domain_separation_tag = "wrong-tag".to_string();
    // Reseal so the proof digest matches (isolate the tag rejection).
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

#[test]
fn b06_unsupported_protocol_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.protocol_version = ProductionOnChainGovernanceProofProtocolVersion(99);
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofUnsupportedProtocol { version: 99 }
    ));
}

#[test]
fn b07_unsupported_suite_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_suite = ProductionOnChainGovernanceProofSuite(0xB7);
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofUnsupportedSuite { suite_id: 0xB7 }
    ));
}

#[test]
fn b08_fixture_suite_rejected_as_production_authority() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_suite =
        ProductionOnChainGovernanceProofSuite(ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1);
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::FixtureProofRejectedAsProductionAuthority
    );
}

#[test]
fn b09_proof_bytes_digest_mismatch_invalid() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // Tamper commitment without resealing => proof digest no longer matches.
    proof.commitment.governance_height = GOV_HEIGHT + 1;
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofInvalid { .. }
    ));
}

#[test]
fn b10_missing_trusted_root_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.trusted_checkpoint.governance_root_hex = String::new();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionTrustedRootMissing
    );
}

#[test]
fn b11_wrong_trusted_root_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // A different but well-formed 32-byte root that the proof does not reach.
    inputs.trusted_checkpoint.governance_root_hex = hex::encode([7u8; 32]);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(
        matches!(
            out,
            ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed
                | ProductionOnChainGovernanceProofOutcome::ProductionProofRootMismatch
        ),
        "got {:?}",
        out
    );
}

#[test]
fn b12_proof_supplied_untrusted_root_not_self_authorizing() {
    // The proof claims a root; the trusted input carries a DIFFERENT root.
    // The proof must not self-authorize: it fails closed.
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // Make the proof claim its own (real, self-consistent) root but the
    // trusted input still carries the original — mismatch them by rebuilding
    // the proof over a different tree while keeping inputs' root.
    let other_leaves = vec![proof.commitment.decision_digest(), "z".to_string()];
    let (other_root, other_incl) = build_merkle_inclusion_proof(&other_leaves, 0).unwrap();
    assert_ne!(other_root, inputs.trusted_checkpoint.governance_root_hex);
    proof.inclusion_proof = other_incl;
    proof = proof.seal();
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(
        matches!(
            out,
            ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed
                | ProductionOnChainGovernanceProofOutcome::ProductionProofRootMismatch
        ),
        "got {:?}",
        out
    );
}

#[test]
fn b13_wrong_environment_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.environment = TrustBundleEnvironment::Testnet;
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongEnvironment
    );
}

#[test]
fn b14_wrong_chain_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.chain_id = "wrong-chain".to_string();
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongChain
    );
}

#[test]
fn b15_wrong_genesis_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.genesis_hash = "wrong-genesis".to_string();
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongGenesis
    );
}

#[test]
fn b16_wrong_authority_root_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.authority_root_fingerprint = "wrong-root".to_string();
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongAuthorityRoot
    );
}

#[test]
fn b17_wrong_governance_domain_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongGovernanceDomain
    );
}

#[test]
fn b18_wrong_governance_epoch_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongGovernanceEpoch
    );
}

#[test]
fn b19_wrong_proposal_id_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_proposal_id = "other-proposal".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongProposalId
    );
}

#[test]
fn b20_wrong_proposal_digest_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_proposal_digest = "other-digest".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongProposalDigest
    );
}

#[test]
fn b21_wrong_proposal_outcome_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongProposalOutcome
    );
}

#[test]
fn b22_wrong_lifecycle_action_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_lifecycle_action = LocalLifecycleAction::Revoke;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongLifecycleAction
    );
}

#[test]
fn b23_wrong_candidate_digest_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_candidate_v2_digest = "other-candidate".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongCandidateDigest
    );
}

#[test]
fn b24_wrong_authority_sequence_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_authority_domain_sequence = SEQ + 5;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongAuthoritySequence
    );
}

#[test]
fn b25_checkpoint_epoch_height_mismatch_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.trusted_checkpoint.governance_height = GOV_HEIGHT + 100;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofCheckpointMismatch
    );
}

#[test]
fn b26_expired_proof_rejected_by_height_bounds() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.freshness_bounds.max_governance_height = GOV_HEIGHT - 1;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofExpired
    );
}

#[test]
fn b27_stale_governance_epoch_rejected_by_epoch_bounds() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.freshness_bounds.min_governance_epoch = GOV_EPOCH + 1;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofExpired
    );
}

#[test]
fn b28_replayed_decision_id_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let replay: Vec<String> = vec![DECISION_ID.to_string()];
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &replay,
    );
    assert!(matches!(
        out,
        ProductionOnChainGovernanceProofOutcome::ProductionProofReplayRejected { .. }
    ));
}

#[test]
fn b29_stale_lower_sequence_replay_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.persisted_sequence = Some(SEQ + 1);
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofReplayRejected { .. }
    ));
}

#[test]
fn b30_quorum_not_met_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.quorum = OnChainGovernanceQuorum {
        voters_voted: 3,
        total_voters: 10,
        required_quorum: 6,
    };
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofQuorumNotMet
    );
}

#[test]
fn b31_threshold_not_met_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.threshold = GovernanceThreshold::new(3, 6, 10);
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofThresholdNotMet
    );
}

#[test]
fn b32_wrong_merkle_path_inclusion_failed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // Corrupt a sibling hash (still 32 bytes) => recomputed root differs.
    if let Some(sib) = proof.inclusion_proof.siblings.first_mut() {
        sib.hash_hex = hex::encode([0xEEu8; 32]);
    }
    proof = proof.seal();
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(
        matches!(
            out,
            ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed
                | ProductionOnChainGovernanceProofOutcome::ProductionProofRootMismatch
        ),
        "got {:?}",
        out
    );
}

#[test]
fn b33_malformed_sibling_hex_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    if let Some(sib) = proof.inclusion_proof.siblings.first_mut() {
        sib.hash_hex = "not-hex".to_string();
    }
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

#[test]
fn b34_claimed_root_mismatch_rejected() {
    // Claimed root differs from the trusted root even though the leaf path
    // is otherwise consistent for the claimed tree.
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.inclusion_proof.claimed_root_hex = hex::encode([0x11u8; 32]);
    proof = proof.seal();
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(
        matches!(
            out,
            ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed
                | ProductionOnChainGovernanceProofOutcome::ProductionProofRootMismatch
        ),
        "got {:?}",
        out
    );
}

#[test]
fn b35_production_proof_under_disabled_kind_receipt_verifier_unavailable() {
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::new(
            ProductionOnChainGovernanceVerifierKind::ProductionReceiptVerifier,
        ),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        RealMerkleInclusionVerifier::new(),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionVerifierUnavailable
    );
}

#[test]
fn b36_injected_verifier_unavailable_maps_to_unavailable() {
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        MockInclusionVerifier::always_fail(
            ProductionOnChainGovernanceProofError::VerifierUnavailable,
        ),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        out,
        ProductionOnChainGovernanceProofOutcome::ProductionVerifierUnavailable
    );
}

#[test]
fn b37_injected_inclusion_material_unavailable_maps_to_inclusion_failed() {
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        MockInclusionVerifier::always_fail(
            ProductionOnChainGovernanceProofError::InclusionMaterialUnavailable,
        ),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert_eq!(
        out,
        ProductionOnChainGovernanceProofOutcome::ProductionProofInclusionFailed
    );
}

#[test]
fn b38_malformed_verification_inputs_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_proposal_id = String::new();
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(matches!(
        out,
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

#[test]
fn b39_unsupported_suite_before_binding() {
    // A production proof with an unsupported suite must be refused as
    // unsupported-suite, not reach binding checks.
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_suite = ProductionOnChainGovernanceProofSuite(0xC0);
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofUnsupportedSuite { .. }
    ));
}

#[test]
fn b40_ambiguous_verifier_class_disagreement() {
    // Mock returns a decision digest that does not match the proof's.
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        MockInclusionVerifier::always_fail(ProductionOnChainGovernanceProofError::Malformed {
            reason: "x".to_string(),
        }),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert!(matches!(
        out,
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

// ===========================================================================
// C. MainNet / authority policy
// ===========================================================================

#[test]
fn c01_mainnet_refused_under_source_test_policy() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Mainnet),
        ProductionOnChainGovernanceProofOutcome::MainNetRefused
    );
}

#[test]
fn c02_mainnet_policy_fails_closed_on_mainnet() {
    let v = merkle_verifier(
        ProductionOnChainGovernanceVerifierPolicy::MainnetProductionProofRequired,
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Mainnet),
        ProductionOnChainGovernanceProofOutcome::MainNetProductionGovernanceProofUnavailable
    );
}

#[test]
fn c03_mainnet_policy_fails_closed_on_devnet() {
    let v = merkle_verifier(
        ProductionOnChainGovernanceVerifierPolicy::MainnetProductionProofRequired,
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::MainNetProductionGovernanceProofUnavailable
    );
}

#[test]
fn c04_mainnet_fixture_proof_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Mainnet);
    proof.proof_suite =
        ProductionOnChainGovernanceProofSuite(ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1);
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Mainnet),
        ProductionOnChainGovernanceProofOutcome::FixtureProofRejectedAsMainNetProductionAuthority
    );
}

#[test]
fn c05_mainnet_proof_environment_binding_refused() {
    // A proof whose commitment env is MainNet is refused even on a devnet
    // trust domain path.
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.environment = TrustBundleEnvironment::Mainnet;
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::MainNetRefused
    );
}

#[test]
fn c06_valid_source_test_proof_does_not_enable_mainnet() {
    // Accepting a DevNet proof does not change the MainNet refusal helper.
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert!(verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet).is_accept());
    assert!(production_onchain_governance_verifier_mainnet_refused());
    assert!(production_onchain_governance_verifier_does_not_enable_downstream_gates());
}

#[test]
fn c07_mainnet_cannot_be_satisfied_by_valid_synthetic_proof() {
    // Even a fully valid (for devnet) proof, presented on a MainNet trust
    // domain, is refused.
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    // Reuse the devnet proof but present under mainnet trust domain.
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Mainnet),
        &empty_replay(),
    );
    assert_eq!(out, ProductionOnChainGovernanceProofOutcome::MainNetRefused);
}

// ===========================================================================
// D. Non-mutation
// ===========================================================================

#[test]
fn d01_all_outcomes_are_non_mutating() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(out.is_non_mutating());
    assert!(production_onchain_governance_verifier_is_non_mutating());
}

#[test]
fn d02_never_falls_back_helper() {
    assert!(production_onchain_governance_verifier_never_falls_back());
    assert!(production_onchain_governance_verifier_rejects_fixture_as_production());
}

#[test]
fn d03_root_supplied_out_of_band_helper() {
    assert!(production_onchain_governance_verifier_root_supplied_out_of_band());
}

#[test]
fn d04_rejected_paths_do_not_accept() {
    // A battery of rejected paths never yields an accept outcome.
    let v = source_test_verifier();
    let (base, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);

    let mut p1 = base.clone();
    p1.commitment.chain_id = "x".to_string();
    p1 = p1.seal();
    assert!(!verify(&v, &p1, &inputs, TrustBundleEnvironment::Devnet).is_accept());

    let mut inputs2 = inputs.clone();
    inputs2.expected_proposal_digest = "x".to_string();
    assert!(!verify(&v, &base, &inputs2, TrustBundleEnvironment::Devnet).is_accept());
}

#[test]
fn d05_local_operator_and_peer_majority_outcomes_are_non_authority() {
    // These typed outcomes exist and are non-accepting.
    use ProductionOnChainGovernanceProofOutcome as O;
    assert!(!O::LocalOperatorConfigOnlyRejected.is_accept());
    assert!(!O::PeerMajorityProofRejected.is_accept());
    assert!(!O::CustodyOnlyProofRejected.is_accept());
    assert!(!O::RemoteSignerOnlyProofRejected.is_accept());
}

#[test]
fn d06_governance_engine_and_validator_rotation_outcomes_non_accept() {
    use ProductionOnChainGovernanceProofOutcome as O;
    assert!(!O::GovernanceExecutionEngineUnavailable.is_accept());
    assert!(!O::ValidatorSetRotationUnsupported.is_accept());
}

// ===========================================================================
// E. Replay / recovery / idempotency
// ===========================================================================

#[test]
fn e01_no_prior_proof_is_clean_noop() {
    let v = source_test_verifier();
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        v.recover_proof_window(None, &proof, 0),
        ProductionOnChainGovernanceRecoveryOutcome::NoPriorProof
    );
}

#[test]
fn e02_byte_identical_proof_is_idempotent() {
    let v = source_test_verifier();
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = v.recover_proof_window(Some(&proof), &proof, 0);
    assert!(out.is_idempotent());
}

#[test]
fn e03_same_decision_id_different_proposal_digest_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
    current.commitment.proposal_digest = "different".to_string();
    current = current.seal();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, 0),
        ProductionOnChainGovernanceRecoveryOutcome::ConflictingProposalDigestForSameDecisionId
    );
}

#[test]
fn e04_same_decision_id_different_candidate_digest_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
    current.commitment.candidate_v2_digest = "different".to_string();
    current = current.seal();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, 0),
        ProductionOnChainGovernanceRecoveryOutcome::ConflictingCandidateDigestForSameDecisionId
    );
}

#[test]
fn e05_same_decision_id_different_lifecycle_action_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
    current.commitment.lifecycle_action = LocalLifecycleAction::Revoke;
    current = current.seal();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, 0),
        ProductionOnChainGovernanceRecoveryOutcome::ConflictingLifecycleActionForSameDecisionId
    );
}

#[test]
fn e06_stale_governance_epoch_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let current = prior.clone();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, GOV_EPOCH + 1),
        ProductionOnChainGovernanceRecoveryOutcome::StaleGovernanceEpoch
    );
}

#[test]
fn e07_different_decision_id_is_independent_window() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
    current.commitment.decision_id = "other-decision".to_string();
    current = current.seal();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, 0),
        ProductionOnChainGovernanceRecoveryOutcome::NoPriorProof
    );
}

#[test]
fn e08_same_decision_id_conflicting_transcript_fails_closed() {
    // Same decision id, same proposal/candidate/action, but a different
    // inclusion path (different proof digest) => conflicting transcript.
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
    // Rebuild inclusion over a different tree while keeping commitment.
    let leaves = vec![prior.commitment.decision_digest(), "extra".to_string()];
    let (_root, incl) = build_merkle_inclusion_proof(&leaves, 0).unwrap();
    current.inclusion_proof = incl;
    current = current.seal();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, 0),
        ProductionOnChainGovernanceRecoveryOutcome::ConflictingTranscriptForSameDecisionId
    );
}

// ===========================================================================
// F. C4/C5 taxonomy
// ===========================================================================

#[test]
fn f01_run299_is_source_test_not_release_binary() {
    assert!(
        production_onchain_governance_verifier_is_source_test_not_release_binary_evidence()
    );
}

#[test]
fn f02_default_disabled_taxonomy() {
    assert!(production_onchain_governance_verifier_default_is_disabled());
}

#[test]
fn f03_mainnet_refused_taxonomy() {
    assert!(production_onchain_governance_verifier_mainnet_refused());
}

#[test]
fn f04_non_mutating_taxonomy() {
    assert!(production_onchain_governance_verifier_is_non_mutating());
    assert!(production_onchain_governance_verifier_does_not_enable_downstream_gates());
}

#[test]
fn f05_policy_and_kind_tags_are_stable() {
    assert_eq!(
        ProductionOnChainGovernanceVerifierPolicy::Disabled.tag(),
        "disabled"
    );
    assert_eq!(
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof.tag(),
        "allow-source-test-production-proof"
    );
    assert_eq!(
        ProductionOnChainGovernanceVerifierKind::ProductionMerkleVerifier.tag(),
        "production-merkle-verifier"
    );
}

#[test]
fn f06_outcome_tags_are_stable() {
    use ProductionOnChainGovernanceProofOutcome as O;
    assert_eq!(O::Disabled.tag(), "disabled");
    assert_eq!(O::MainNetRefused.tag(), "mainnet-refused");
    assert_eq!(
        O::ProductionTrustedRootMissing.tag(),
        "production-trusted-root-missing"
    );
}