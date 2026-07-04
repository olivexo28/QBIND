//! Run 300 — release-binary helper for the Run 299 **production on-chain
//! governance proof verifier**.
//!
//! Release-binary evidence for the Run 299 source/test real on-chain
//! governance proof verifier
//! (`crates/qbind-node/src/pqc_production_onchain_governance_proof_verifier.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 299
//! [`ProductionOnChainGovernanceProofVerifier`] over a real SHA3-256 Merkle
//! inclusion verifier, reachable-but-fail-closed unavailable inclusion stubs,
//! and a programmable mock inclusion verifier in release mode and proves, per
//! check with PASS/FAIL, the accepted / rejection-fail-closed / MainNet-refusal
//! / non-mutation / replay-recovery behavior of the real verifier, including
//! environment / chain / genesis / authority-root / governance-domain /
//! governance-epoch / proposal / lifecycle / candidate / authority-sequence /
//! quorum / threshold / Merkle-inclusion / trusted-root binding and the Run 186
//! production-suite classification composition.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It constructs the verifier only
//! through source/test Merkle/stub/mock inclusion verifiers, only for
//! DevNet/TestNet identities on the accept path, and never enables any
//! production runtime path, MainNet enablement, on-chain-governance-proof
//! default enablement, governance execution engine, validator-set rotation,
//! settlement, or external publication. Under a MainNet or production policy it
//! never falls back to fixture proofs, local operator config, peer-majority
//! proofs, custody-only or remote-signer-only material; the trusted governance
//! root / checkpoint is always supplied explicitly out-of-band and the proof
//! can never self-authorize its own root.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_300.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

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
// Shared fixtures (mirrors the Run 299 source/test fixtures)
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
/// trusted checkpoint carrying that root and the matching verification inputs.
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

fn a01_default_policy_is_disabled_and_inert() {
    assert!(production_onchain_governance_verifier_default_is_disabled());
    let v = merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::default());
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert_eq!(out, ProductionOnChainGovernanceProofOutcome::Disabled);
}

fn a02_valid_production_proof_accepted_devnet() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert!(verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet).is_accept());
}

fn a03_valid_production_proof_accepted_testnet() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Testnet);
    assert!(verify(&v, &proof, &inputs, TrustBundleEnvironment::Testnet).is_accept());
}

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

fn a05_accept_binds_epoch_sequence_action_decision() {
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

fn a06_valid_proof_verifies_inclusion_against_trusted_root() {
    let (proof, cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let leaf = proof.commitment.decision_digest();
    assert!(proof.inclusion_proof.verify(&leaf, &cp.governance_root_hex));
}

fn a07_deterministic_proof_digest_stable() {
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        production_onchain_governance_proof_digest(&proof),
        production_onchain_governance_proof_digest(&proof)
    );
    assert_eq!(proof.expected_proof_digest(), proof.proof_bytes_digest);
}

fn a08_deterministic_decision_digest_stable() {
    let c = commitment(TrustBundleEnvironment::Devnet);
    assert_eq!(
        production_onchain_governance_decision_digest(&c),
        c.decision_digest()
    );
    assert_eq!(
        c.decision_digest(),
        commitment(TrustBundleEnvironment::Devnet).decision_digest()
    );
}

fn a09_deterministic_transcript_digest_stable() {
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

fn a10_run186_classifier_routes_production_suite_as_production() {
    assert_eq!(
        classify_production_suite_through_run186(
            ProductionOnChainGovernanceProofSuite::merkle_v1()
        ),
        OnChainGovernanceProofClass::Production
    );
}

fn a11_run186_classifier_routes_fixture_suite_as_fixture() {
    assert_eq!(
        classify_production_suite_through_run186(ProductionOnChainGovernanceProofSuite(
            ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1
        )),
        OnChainGovernanceProofClass::Fixture
    );
}

fn a12_checkpoint_digest_stable() {
    let (_proof, cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(cp.checkpoint_digest(), cp.checkpoint_digest());
}

fn a13_supported_protocol_and_suite_helpers() {
    assert!(ProductionOnChainGovernanceProofProtocolVersion::supported().is_supported());
    assert!(ProductionOnChainGovernanceProofSuite::merkle_v1().is_supported());
    assert!(!ProductionOnChainGovernanceProofSuite::merkle_v1().is_fixture());
    assert!(
        ProductionOnChainGovernanceProofSuite(ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1)
            .is_fixture()
    );
}

fn a14_evaluate_produces_bound_decision_id_and_proof_digest() {
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

fn b01_disabled_rejects_before_parsing() {
    let v = merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::Disabled);
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_bytes_digest = PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL.to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::Disabled
    );
}

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

fn b03_empty_proof_bytes_digest_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_bytes_digest = String::new();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

fn b04_invalid_proof_sentinel_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.proof_bytes_digest = PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL.to_string();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

fn b05_wrong_domain_separation_tag_malformed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.domain_separation_tag = "wrong-tag".to_string();
    proof = proof.seal();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

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

fn b09_proof_bytes_digest_mismatch_invalid() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.governance_height = GOV_HEIGHT + 1;
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofInvalid { .. }
    ));
}

fn b10_missing_trusted_root_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.trusted_checkpoint.governance_root_hex = String::new();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionTrustedRootMissing
    );
}

fn b11_wrong_trusted_root_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
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

fn b12_proof_supplied_untrusted_root_not_self_authorizing() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
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

fn b17_wrong_governance_domain_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_governance_domain_id = "other-domain".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongGovernanceDomain
    );
}

fn b18_wrong_governance_epoch_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_governance_epoch = GOV_EPOCH + 1;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongGovernanceEpoch
    );
}

fn b19_wrong_candidate_digest_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_candidate_v2_digest = "other-candidate".to_string();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongCandidateDigest
    );
}

fn b20_wrong_authority_sequence_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_authority_domain_sequence = SEQ + 5;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofWrongAuthoritySequence
    );
}

fn b21_expired_proof_rejected_by_height_bounds() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.freshness_bounds.max_governance_height = GOV_HEIGHT - 1;
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofExpired
    );
}

fn b22_replayed_decision_id_rejected() {
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

fn b23_quorum_not_met_rejected() {
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

fn b24_threshold_not_met_rejected() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.threshold = GovernanceThreshold::new(3, 6, 10);
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofThresholdNotMet
    );
}

fn b25_wrong_merkle_path_inclusion_failed() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
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

fn b26_malformed_sibling_hex_malformed() {
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

fn b27_production_reserved_kind_unavailable() {
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

fn b28_injected_verifier_unavailable_maps_to_unavailable() {
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

fn b29_unavailable_inclusion_stub_fails_closed() {
    let v = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        UnavailableInclusionVerifierStub::unavailable(),
    );
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = v.verify_production_onchain_governance_proof_real(
        &proof,
        &inputs,
        &domain(TrustBundleEnvironment::Devnet),
        &empty_replay(),
    );
    assert!(!out.is_accept());
}

fn b30_malformed_verification_inputs_rejected() {
    let v = source_test_verifier();
    let (proof, _cp, mut inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    inputs.expected_proposal_id = String::new();
    assert!(matches!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::ProductionProofMalformed { .. }
    ));
}

// ===========================================================================
// C. MainNet / authority policy
// ===========================================================================

fn c01_mainnet_refused_under_source_test_policy() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Mainnet),
        ProductionOnChainGovernanceProofOutcome::MainNetRefused
    );
}

fn c02_mainnet_policy_fails_closed_on_mainnet() {
    let v =
        merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::MainnetProductionProofRequired);
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Mainnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Mainnet),
        ProductionOnChainGovernanceProofOutcome::MainNetProductionGovernanceProofUnavailable
    );
}

fn c03_mainnet_policy_fails_closed_on_devnet() {
    let v =
        merkle_verifier(ProductionOnChainGovernanceVerifierPolicy::MainnetProductionProofRequired);
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::MainNetProductionGovernanceProofUnavailable
    );
}

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

fn c05_mainnet_proof_environment_binding_refused() {
    let v = source_test_verifier();
    let (mut proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    proof.commitment.environment = TrustBundleEnvironment::Mainnet;
    proof = proof.seal();
    assert_eq!(
        verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet),
        ProductionOnChainGovernanceProofOutcome::MainNetRefused
    );
}

fn c06_valid_source_test_proof_does_not_enable_mainnet() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert!(verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet).is_accept());
    assert!(production_onchain_governance_verifier_mainnet_refused());
    assert!(production_onchain_governance_verifier_does_not_enable_downstream_gates());
}

fn c07_mainnet_cannot_be_satisfied_by_valid_synthetic_proof() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
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

fn d01_all_outcomes_are_non_mutating() {
    let v = source_test_verifier();
    let (proof, _cp, inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let out = verify(&v, &proof, &inputs, TrustBundleEnvironment::Devnet);
    assert!(out.is_non_mutating());
    assert!(production_onchain_governance_verifier_is_non_mutating());
}

fn d02_never_falls_back_helper() {
    assert!(production_onchain_governance_verifier_never_falls_back());
    assert!(production_onchain_governance_verifier_rejects_fixture_as_production());
}

fn d03_root_supplied_out_of_band_helper() {
    assert!(production_onchain_governance_verifier_root_supplied_out_of_band());
}

fn d04_rejected_paths_do_not_accept() {
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

fn d05_non_authority_outcomes_are_non_accepting() {
    use ProductionOnChainGovernanceProofOutcome as O;
    assert!(!O::LocalOperatorConfigOnlyRejected.is_accept());
    assert!(!O::PeerMajorityProofRejected.is_accept());
    assert!(!O::CustodyOnlyProofRejected.is_accept());
    assert!(!O::RemoteSignerOnlyProofRejected.is_accept());
    assert!(!O::GovernanceExecutionEngineUnavailable.is_accept());
    assert!(!O::ValidatorSetRotationUnsupported.is_accept());
}

// ===========================================================================
// E. Replay / recovery / idempotency
// ===========================================================================

fn e01_no_prior_proof_is_clean_noop() {
    let v = source_test_verifier();
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert_eq!(
        v.recover_proof_window(None, &proof, 0),
        ProductionOnChainGovernanceRecoveryOutcome::NoPriorProof
    );
}

fn e02_byte_identical_proof_is_idempotent() {
    let v = source_test_verifier();
    let (proof, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    assert!(v.recover_proof_window(Some(&proof), &proof, 0).is_idempotent());
}

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

fn e06_stale_governance_epoch_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let current = prior.clone();
    assert_eq!(
        v.recover_proof_window(Some(&prior), &current, GOV_EPOCH + 1),
        ProductionOnChainGovernanceRecoveryOutcome::StaleGovernanceEpoch
    );
}

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

fn e08_same_decision_id_conflicting_transcript_fails_closed() {
    let v = source_test_verifier();
    let (prior, _cp, _inputs) = valid_bundle(TrustBundleEnvironment::Devnet);
    let mut current = prior.clone();
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
// F. Reachability / C4-C5 taxonomy
// ===========================================================================

fn f01_run299_is_source_test_not_release_binary() {
    assert!(production_onchain_governance_verifier_is_source_test_not_release_binary_evidence());
}

fn f02_default_disabled_taxonomy() {
    assert!(production_onchain_governance_verifier_default_is_disabled());
}

fn f03_mainnet_refused_taxonomy() {
    assert!(production_onchain_governance_verifier_mainnet_refused());
}

fn f04_non_mutating_taxonomy() {
    assert!(production_onchain_governance_verifier_is_non_mutating());
    assert!(production_onchain_governance_verifier_does_not_enable_downstream_gates());
}

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

fn f06_outcome_tags_are_stable() {
    use ProductionOnChainGovernanceProofOutcome as O;
    assert_eq!(O::Disabled.tag(), "disabled");
    assert_eq!(O::MainNetRefused.tag(), "mainnet-refused");
    assert_eq!(
        O::ProductionTrustedRootMissing.tag(),
        "production-trusted-root-missing"
    );
}

fn g01_release_symbol_reachability_probe() {
    // Touch a broad slice of the Run 299 verifier surface so the release
    // helper links against and exercises the real production symbols.
    assert_eq!(PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION, 1);
    assert_eq!(PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1, 0xA3);
    assert!(!PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG.is_empty());
    assert!(!PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL.is_empty());

    let env = TrustBundleEnvironment::Devnet;
    let (proof, cp, inputs) = valid_bundle(env);

    // Real Merkle verifier over the source/test proof.
    let verifier = source_test_verifier();
    let outcome: ProductionOnChainGovernanceProofOutcome =
        verify(&verifier, &proof, &inputs, env);
    assert!(outcome.is_accept());
    let decision: ProductionOnChainGovernanceProofDecision = verifier
        .evaluate_production_onchain_governance_proof(&proof, &inputs, &domain(env), &empty_replay());
    assert!(decision.is_accept());
    let recovery: ProductionOnChainGovernanceRecoveryOutcome =
        verifier.recover_proof_window(None, &proof, 0);
    assert_eq!(
        recovery,
        ProductionOnChainGovernanceRecoveryOutcome::NoPriorProof
    );

    // Digest surfaces are linked and deterministic.
    let proof_digest = production_onchain_governance_proof_digest(&proof);
    let decision_digest = production_onchain_governance_decision_digest(&proof.commitment);
    let checkpoint_digest = cp.checkpoint_digest();
    let transcript = production_onchain_governance_transcript_digest(
        PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION,
        &decision_digest,
        &checkpoint_digest,
        &proof_digest,
        outcome.tag(),
    );
    assert!(!transcript.is_empty());

    // Real Merkle inclusion verifier counts its calls.
    let counting = RealMerkleInclusionVerifier::new();
    let counting_verifier = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        counting,
    );
    assert!(
        verify(&counting_verifier, &proof, &inputs, env).is_accept()
    );
    assert!(counting_verifier.inclusion_verifier.call_count() >= 1);

    // Reachable-but-fail-closed unavailable inclusion stub.
    let stub_verifier = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        UnavailableInclusionVerifierStub::unavailable(),
    );
    assert!(!stub_verifier
        .verify_production_onchain_governance_proof_real(
            &proof,
            &inputs,
            &domain(env),
            &empty_replay(),
        )
        .is_accept());

    // Programmable mock inclusion verifier implements the same boundary trait.
    let mock_verifier = ProductionOnChainGovernanceProofVerifier::new(
        ProductionOnChainGovernanceProofVerifierConfig::merkle(),
        ProductionOnChainGovernanceVerifierPolicy::AllowSourceTestProductionProof,
        MockInclusionVerifier::always_fail(
            ProductionOnChainGovernanceProofError::VerifierUnavailable,
        ),
    );
    assert_eq!(
        mock_verifier.verify_production_onchain_governance_proof_real(
            &proof,
            &inputs,
            &domain(env),
            &empty_replay(),
        ),
        ProductionOnChainGovernanceProofOutcome::ProductionVerifierUnavailable
    );

    // Run 186 classifier composition is linked in release mode.
    assert_eq!(
        classify_production_suite_through_run186(
            ProductionOnChainGovernanceProofSuite::merkle_v1()
        ),
        OnChainGovernanceProofClass::Production
    );

    // Invariant helpers.
    assert!(production_onchain_governance_verifier_default_is_disabled());
    assert!(production_onchain_governance_verifier_rejects_fixture_as_production());
    assert!(production_onchain_governance_verifier_mainnet_refused());
    assert!(production_onchain_governance_verifier_root_supplied_out_of_band());
    assert!(production_onchain_governance_verifier_never_falls_back());
    assert!(production_onchain_governance_verifier_is_non_mutating());
    assert!(production_onchain_governance_verifier_does_not_enable_downstream_gates());
    assert!(production_onchain_governance_verifier_is_source_test_not_release_binary_evidence());
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
            "docs/devnet/run_300_production_onchain_governance_proof_verifier_release_binary/helper_evidence/run_300",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_default_policy_is_disabled_and_inert", a01_default_policy_is_disabled_and_inert as fn()),
        ("accepted_compatible", "a02_valid_production_proof_accepted_devnet", a02_valid_production_proof_accepted_devnet as fn()),
        ("accepted_compatible", "a03_valid_production_proof_accepted_testnet", a03_valid_production_proof_accepted_testnet as fn()),
        ("accepted_compatible", "a04_accept_binds_environment", a04_accept_binds_environment as fn()),
        ("accepted_compatible", "a05_accept_binds_epoch_sequence_action_decision", a05_accept_binds_epoch_sequence_action_decision as fn()),
        ("accepted_compatible", "a06_valid_proof_verifies_inclusion_against_trusted_root", a06_valid_proof_verifies_inclusion_against_trusted_root as fn()),
        ("accepted_compatible", "a07_deterministic_proof_digest_stable", a07_deterministic_proof_digest_stable as fn()),
        ("accepted_compatible", "a08_deterministic_decision_digest_stable", a08_deterministic_decision_digest_stable as fn()),
        ("accepted_compatible", "a09_deterministic_transcript_digest_stable", a09_deterministic_transcript_digest_stable as fn()),
        ("accepted_compatible", "a10_run186_classifier_routes_production_suite_as_production", a10_run186_classifier_routes_production_suite_as_production as fn()),
        ("accepted_compatible", "a11_run186_classifier_routes_fixture_suite_as_fixture", a11_run186_classifier_routes_fixture_suite_as_fixture as fn()),
        ("accepted_compatible", "a12_checkpoint_digest_stable", a12_checkpoint_digest_stable as fn()),
        ("accepted_compatible", "a13_supported_protocol_and_suite_helpers", a13_supported_protocol_and_suite_helpers as fn()),
        ("accepted_compatible", "a14_evaluate_produces_bound_decision_id_and_proof_digest", a14_evaluate_produces_bound_decision_id_and_proof_digest as fn()),
        ("rejection_fail_closed", "b01_disabled_rejects_before_parsing", b01_disabled_rejects_before_parsing as fn()),
        ("rejection_fail_closed", "b02_disabled_kind_config_rejects", b02_disabled_kind_config_rejects as fn()),
        ("rejection_fail_closed", "b03_empty_proof_bytes_digest_malformed", b03_empty_proof_bytes_digest_malformed as fn()),
        ("rejection_fail_closed", "b04_invalid_proof_sentinel_malformed", b04_invalid_proof_sentinel_malformed as fn()),
        ("rejection_fail_closed", "b05_wrong_domain_separation_tag_malformed", b05_wrong_domain_separation_tag_malformed as fn()),
        ("rejection_fail_closed", "b06_unsupported_protocol_rejected", b06_unsupported_protocol_rejected as fn()),
        ("rejection_fail_closed", "b07_unsupported_suite_rejected", b07_unsupported_suite_rejected as fn()),
        ("rejection_fail_closed", "b08_fixture_suite_rejected_as_production_authority", b08_fixture_suite_rejected_as_production_authority as fn()),
        ("rejection_fail_closed", "b09_proof_bytes_digest_mismatch_invalid", b09_proof_bytes_digest_mismatch_invalid as fn()),
        ("rejection_fail_closed", "b10_missing_trusted_root_rejected", b10_missing_trusted_root_rejected as fn()),
        ("rejection_fail_closed", "b11_wrong_trusted_root_rejected", b11_wrong_trusted_root_rejected as fn()),
        ("rejection_fail_closed", "b12_proof_supplied_untrusted_root_not_self_authorizing", b12_proof_supplied_untrusted_root_not_self_authorizing as fn()),
        ("rejection_fail_closed", "b13_wrong_environment_rejected", b13_wrong_environment_rejected as fn()),
        ("rejection_fail_closed", "b14_wrong_chain_rejected", b14_wrong_chain_rejected as fn()),
        ("rejection_fail_closed", "b15_wrong_genesis_rejected", b15_wrong_genesis_rejected as fn()),
        ("rejection_fail_closed", "b16_wrong_authority_root_rejected", b16_wrong_authority_root_rejected as fn()),
        ("rejection_fail_closed", "b17_wrong_governance_domain_rejected", b17_wrong_governance_domain_rejected as fn()),
        ("rejection_fail_closed", "b18_wrong_governance_epoch_rejected", b18_wrong_governance_epoch_rejected as fn()),
        ("rejection_fail_closed", "b19_wrong_candidate_digest_rejected", b19_wrong_candidate_digest_rejected as fn()),
        ("rejection_fail_closed", "b20_wrong_authority_sequence_rejected", b20_wrong_authority_sequence_rejected as fn()),
        ("rejection_fail_closed", "b21_expired_proof_rejected_by_height_bounds", b21_expired_proof_rejected_by_height_bounds as fn()),
        ("rejection_fail_closed", "b22_replayed_decision_id_rejected", b22_replayed_decision_id_rejected as fn()),
        ("rejection_fail_closed", "b23_quorum_not_met_rejected", b23_quorum_not_met_rejected as fn()),
        ("rejection_fail_closed", "b24_threshold_not_met_rejected", b24_threshold_not_met_rejected as fn()),
        ("rejection_fail_closed", "b25_wrong_merkle_path_inclusion_failed", b25_wrong_merkle_path_inclusion_failed as fn()),
        ("rejection_fail_closed", "b26_malformed_sibling_hex_malformed", b26_malformed_sibling_hex_malformed as fn()),
        ("rejection_fail_closed", "b27_production_reserved_kind_unavailable", b27_production_reserved_kind_unavailable as fn()),
        ("rejection_fail_closed", "b28_injected_verifier_unavailable_maps_to_unavailable", b28_injected_verifier_unavailable_maps_to_unavailable as fn()),
        ("rejection_fail_closed", "b29_unavailable_inclusion_stub_fails_closed", b29_unavailable_inclusion_stub_fails_closed as fn()),
        ("rejection_fail_closed", "b30_malformed_verification_inputs_rejected", b30_malformed_verification_inputs_rejected as fn()),
        ("mainnet_authority_policy", "c01_mainnet_refused_under_source_test_policy", c01_mainnet_refused_under_source_test_policy as fn()),
        ("mainnet_authority_policy", "c02_mainnet_policy_fails_closed_on_mainnet", c02_mainnet_policy_fails_closed_on_mainnet as fn()),
        ("mainnet_authority_policy", "c03_mainnet_policy_fails_closed_on_devnet", c03_mainnet_policy_fails_closed_on_devnet as fn()),
        ("mainnet_authority_policy", "c04_mainnet_fixture_proof_rejected", c04_mainnet_fixture_proof_rejected as fn()),
        ("mainnet_authority_policy", "c05_mainnet_proof_environment_binding_refused", c05_mainnet_proof_environment_binding_refused as fn()),
        ("mainnet_authority_policy", "c06_valid_source_test_proof_does_not_enable_mainnet", c06_valid_source_test_proof_does_not_enable_mainnet as fn()),
        ("mainnet_authority_policy", "c07_mainnet_cannot_be_satisfied_by_valid_synthetic_proof", c07_mainnet_cannot_be_satisfied_by_valid_synthetic_proof as fn()),
        ("non_mutation", "d01_all_outcomes_are_non_mutating", d01_all_outcomes_are_non_mutating as fn()),
        ("non_mutation", "d02_never_falls_back_helper", d02_never_falls_back_helper as fn()),
        ("non_mutation", "d03_root_supplied_out_of_band_helper", d03_root_supplied_out_of_band_helper as fn()),
        ("non_mutation", "d04_rejected_paths_do_not_accept", d04_rejected_paths_do_not_accept as fn()),
        ("non_mutation", "d05_non_authority_outcomes_are_non_accepting", d05_non_authority_outcomes_are_non_accepting as fn()),
        ("replay_recovery_idempotency", "e01_no_prior_proof_is_clean_noop", e01_no_prior_proof_is_clean_noop as fn()),
        ("replay_recovery_idempotency", "e02_byte_identical_proof_is_idempotent", e02_byte_identical_proof_is_idempotent as fn()),
        ("replay_recovery_idempotency", "e03_same_decision_id_different_proposal_digest_fails_closed", e03_same_decision_id_different_proposal_digest_fails_closed as fn()),
        ("replay_recovery_idempotency", "e04_same_decision_id_different_candidate_digest_fails_closed", e04_same_decision_id_different_candidate_digest_fails_closed as fn()),
        ("replay_recovery_idempotency", "e05_same_decision_id_different_lifecycle_action_fails_closed", e05_same_decision_id_different_lifecycle_action_fails_closed as fn()),
        ("replay_recovery_idempotency", "e06_stale_governance_epoch_fails_closed", e06_stale_governance_epoch_fails_closed as fn()),
        ("replay_recovery_idempotency", "e07_different_decision_id_is_independent_window", e07_different_decision_id_is_independent_window as fn()),
        ("replay_recovery_idempotency", "e08_same_decision_id_conflicting_transcript_fails_closed", e08_same_decision_id_conflicting_transcript_fails_closed as fn()),
        ("reachability_taxonomy", "f01_run299_is_source_test_not_release_binary", f01_run299_is_source_test_not_release_binary as fn()),
        ("reachability_taxonomy", "f02_default_disabled_taxonomy", f02_default_disabled_taxonomy as fn()),
        ("reachability_taxonomy", "f03_mainnet_refused_taxonomy", f03_mainnet_refused_taxonomy as fn()),
        ("reachability_taxonomy", "f04_non_mutating_taxonomy", f04_non_mutating_taxonomy as fn()),
        ("reachability_taxonomy", "f05_policy_and_kind_tags_are_stable", f05_policy_and_kind_tags_are_stable as fn()),
        ("reachability_taxonomy", "f06_outcome_tags_are_stable", f06_outcome_tags_are_stable as fn()),
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
    summary.push_str("Run 300 production on-chain governance proof verifier release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "verifier: crates/qbind-node/src/pqc_production_onchain_governance_proof_verifier.rs (Run 299 ProductionOnChainGovernanceProofVerifier)\n",
    );
    summary.push_str(
        "mode: real Run 299 verifier over a real SHA3-256 Merkle inclusion verifier, reachable-but-fail-closed unavailable inclusion stubs, and a programmable mock inclusion verifier; DevNet/TestNet source-test accept only; MainNet refused; default Disabled; MainNet/production policy never verifies and never falls back to fixture / local-operator / peer-majority / custody-only / remote-signer material; trusted governance root/checkpoint supplied explicitly out-of-band; proof cannot self-authorize its root; production proof acceptance uses verified Merkle inclusion against an explicit trusted root; every failure is a typed non-mutating outcome\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let env = TrustBundleEnvironment::Devnet;
    let (proof, cp, inputs) = valid_bundle(env);
    let proof_digest = production_onchain_governance_proof_digest(&proof);
    let decision_digest = production_onchain_governance_decision_digest(&proof.commitment);
    let checkpoint_digest = cp.checkpoint_digest();
    let merkle_root = cp.governance_root_hex.clone();
    let verifier = source_test_verifier();
    let decision = verifier.evaluate_production_onchain_governance_proof(
        &proof,
        &inputs,
        &domain(env),
        &empty_replay(),
    );
    let transcript_digest = decision.transcript_digest.clone();
    fs::write(
        outdir.join("fixtures/run_300_deterministic_digests.txt"),
        format!(
            "proof_digest {proof_digest}\ndecision_digest {decision_digest}\ncheckpoint_digest {checkpoint_digest}\nmerkle_root {merkle_root}\ntranscript_digest {transcript_digest}\n"
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}
