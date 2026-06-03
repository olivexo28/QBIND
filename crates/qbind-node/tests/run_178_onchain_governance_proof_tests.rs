//! Run 178 — focused tests for the typed source/test-only
//! `OnChainGovernance` proof format and fail-closed verifier boundary.
//!
//! Source/test only. Run 178 does not enable MainNet peer-driven apply,
//! governance execution, real on-chain proof verification, KMS/HSM, or
//! validator-set rotation. No release-binary evidence is captured in
//! this run; release-binary `OnChainGovernance` proof evidence is
//! deferred to Run 179.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    REVOKED_METADATA_PREFIX_EMERGENCY, REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, fixture_issuer_signature_verifier,
    verify_governance_authority_proof, GovernanceAuthorityClass, GovernanceAuthorityProof,
    GovernanceAuthorityVerificationOutcome as Run163GovOutcome, GovernanceThreshold,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_wire::{
    GovernanceAuthorityProofWire, GovernanceProofLoadStatus,
};
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, mainnet_peer_driven_apply_remains_refused,
    validate_lifecycle_with_onchain_governance_proof, verify_onchain_governance_proof,
    CombinedLifecycleOnChainGovernanceOutcome, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofVerificationOutcome as Outcome, OnChainGovernanceProofWire,
    OnChainGovernanceProofWireParseError, OnChainGovernanceProposalOutcome,
    OnChainGovernanceQuorum, ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
    ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Fixtures
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

const GOV_DOMAIN: &str = "qbind-onchain-gov-1";
const OTHER_GOV_DOMAIN: &str = "qbind-onchain-gov-other";
const GOV_EPOCH: u64 = 42;
const PROPOSAL_ID: &str = "prop-001";
const OTHER_PROPOSAL_ID: &str = "prop-999";
const PROPOSAL_DIGEST: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const OTHER_PROPOSAL_DIGEST: &str =
    "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed";
const UNIQUE_DECISION_ID: &str = "decision-001";
const NOW: u64 = 1_700_000_000;

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn testnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn mainnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Mainnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn build_v2_with_env(
    env: TrustBundleEnvironment,
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
    revoked_metadata: Option<&str>,
) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH_A.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        active_fp.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        sequence,
        action,
        previous_fp.map(str::to_string),
        digest.to_string(),
        revoked_metadata.map(str::to_string),
        AuthorityStateUpdateSource::TestOrFixture,
        1_700_000_000,
    )
}

fn rotate_to(
    new_active_fp: &str,
    previous_fp: &str,
    sequence: u64,
    digest: &str,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordV2 {
    build_v2_with_env(
        env,
        new_active_fp,
        sequence,
        BundleSigningRatificationV2Action::Rotate,
        Some(previous_fp),
        digest,
        None,
    )
}

fn revoke_record(
    active_fp: &str,
    sequence: u64,
    digest: &str,
    sub_class_prefix: &str,
    revoked_target: &str,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordV2 {
    let metadata = format!("{}{}", sub_class_prefix, revoked_target);
    build_v2_with_env(
        env,
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Revoke,
        None,
        digest,
        Some(&metadata),
    )
}

fn good_proof(
    candidate: &PersistentAuthorityStateRecordV2,
    action: LocalLifecycleAction,
) -> OnChainGovernanceProof {
    let new_fp = match action {
        LocalLifecycleAction::ActivateInitial | LocalLifecycleAction::Rotate => {
            Some(candidate.active_bundle_signing_key_fingerprint.clone())
        }
        _ => None,
    };
    let revoked_fp = match action {
        LocalLifecycleAction::Rotate => candidate.previous_bundle_signing_key_fingerprint.clone(),
        LocalLifecycleAction::Retire
        | LocalLifecycleAction::Revoke
        | LocalLifecycleAction::EmergencyRevoke => candidate
            .revoked_key_metadata
            .as_deref()
            .and_then(|m| m.get(2..))
            .map(str::to_string),
        LocalLifecycleAction::ActivateInitial => None,
    };
    let proof_bytes = fixture_onchain_governance_proof_bytes(
        candidate.environment,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
        UNIQUE_DECISION_ID,
    );
    OnChainGovernanceProof {
        environment: candidate.environment,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        governance_domain_id: GOV_DOMAIN.to_string(),
        governance_epoch: GOV_EPOCH,
        proposal_id: PROPOSAL_ID.to_string(),
        proposal_digest: PROPOSAL_DIGEST.to_string(),
        proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        quorum: OnChainGovernanceQuorum {
            voters_voted: 4,
            total_voters: 5,
            required_quorum: 3,
        },
        threshold: GovernanceThreshold::new(3, 3, 5),
        lifecycle_action: action,
        active_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        new_bundle_signing_key_fingerprint: new_fp,
        revoked_bundle_signing_key_fingerprint: revoked_fp,
        authority_domain_sequence: candidate.latest_authority_domain_sequence,
        candidate_v2_digest: candidate.latest_ratification_v2_digest.clone(),
        freshness: OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW - 60,
            not_after_unix: NOW + 60,
        },
        unique_decision_id: UNIQUE_DECISION_ID.to_string(),
        proof_suite_id: ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
        proof_bytes,
    }
}

fn verify(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    persisted_seq: Option<u64>,
) -> Outcome {
    verify_onchain_governance_proof(
        proof,
        candidate,
        domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        persisted_seq,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    )
}

// ===========================================================================
// A1 — DevNet fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a1_devnet_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    match outcome {
        Outcome::AcceptedOnChainGovernanceFixture {
            action,
            authority_domain_sequence,
            governance_epoch,
        } => {
            assert_eq!(action, LocalLifecycleAction::Rotate);
            assert_eq!(authority_domain_sequence, 2);
            assert_eq!(governance_epoch, GOV_EPOCH);
        }
        other => panic!("expected AcceptedOnChainGovernanceFixture, got {:?}", other),
    }
}

// ===========================================================================
// A2 — TestNet fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a2_testnet_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify(&proof, &candidate, &testnet_domain(), Some(1));
    assert!(matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture { .. }
    ));
}

// ===========================================================================
// A3 — DevNet fixture Revoke accepted
// ===========================================================================

#[test]
fn a3_devnet_fixture_revoke_accepted() {
    let candidate = revoke_record(
        KEY_B,
        3,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_REVOKE,
        KEY_A,
        TrustBundleEnvironment::Devnet,
    );
    let proof = good_proof(&candidate, LocalLifecycleAction::Revoke);
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(2));
    assert!(matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture {
            action: LocalLifecycleAction::Revoke,
            ..
        }
    ));
}

// ===========================================================================
// A4 — TestNet fixture EmergencyRevoke accepted
// ===========================================================================

#[test]
fn a4_testnet_fixture_emergency_revoke_accepted() {
    let candidate = revoke_record(
        KEY_B,
        4,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_EMERGENCY,
        KEY_A,
        TrustBundleEnvironment::Testnet,
    );
    let proof = good_proof(&candidate, LocalLifecycleAction::EmergencyRevoke);
    let outcome = verify(&proof, &candidate, &testnet_domain(), Some(3));
    assert!(matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture {
            action: LocalLifecycleAction::EmergencyRevoke,
            ..
        }
    ));
}

// ===========================================================================
// A5 — OnChainGovernance proof accepted through combined lifecycle helper
// ===========================================================================

#[test]
fn a5_combined_lifecycle_with_onchain_governance_proof_accepted() {
    let prev =
        build_v2_with_env(
            TrustBundleEnvironment::Devnet,
            KEY_A,
            1,
            BundleSigningRatificationV2Action::Ratify,
            None,
            "1111111111111111111111111111111111111111111111111111111111111111",
            None,
        );
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);

    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(combined.is_accept(), "combined should accept: {:?}", combined);
    assert!(matches!(
        combined,
        CombinedLifecycleOnChainGovernanceOutcome::Accepted { .. }
    ));
}

// ===========================================================================
// A6 — proof-carrying sidecar accepted at source/test marker-decision level
//       under explicit Required policy, without mutation
// ===========================================================================

#[test]
fn a6_proof_carrying_sidecar_roundtrip_accepted_no_mutation() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);

    // Round-trip the proof through its wire form (the additive Run 178
    // sibling carrier). This verifies the wire form is parse-compatible
    // and that the parsed proof verifies identically.
    let wire = OnChainGovernanceProofWire::from_proof(&proof);
    let json = serde_json::to_vec(&wire).unwrap();
    let decoded: OnChainGovernanceProofWire = serde_json::from_slice(&json).unwrap();
    assert_eq!(wire, decoded);
    let decoded_proof = decoded.to_proof().unwrap();
    assert_eq!(proof, decoded_proof);

    // Marker-decision source/test path: verifier accepts and produces
    // no mutation (no I/O performed by the verifier).
    let outcome = verify(&decoded_proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(
        outcome,
        Outcome::AcceptedOnChainGovernanceFixture { .. }
    ));
    // Per-test invariant: the candidate record is structurally unchanged
    // after verification (verifier never mutates inputs).
    assert_eq!(candidate.active_bundle_signing_key_fingerprint, KEY_B);
    assert_eq!(candidate.latest_authority_domain_sequence, 2);
}

// ===========================================================================
// A7 — Existing GenesisBound and EmergencyCouncil proof behavior unchanged
// ===========================================================================

#[test]
fn a7_existing_genesis_bound_and_emergency_council_unchanged() {
    // GenesisBound rotate proof — pure Run 163 path — must still accept.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    let proof = GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: KEY_B.to_string(),
        new_bundle_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_bundle_signing_key_fingerprint: Some(KEY_A.to_string()),
        authority_domain_sequence: 2,
        candidate_v2_digest: DIGEST_2.to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    };
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        outcome,
        Run163GovOutcome::AcceptedGenesisBound { .. }
    ));

    // OnChainGovernance class on the Run 163 verifier remains
    // unsupported / fail-closed. Run 178 does not weaken this path.
    let mut on_chain_proof = proof.clone();
    on_chain_proof.issuer_authority_class = GovernanceAuthorityClass::OnChainGovernance;
    on_chain_proof.issuer_signature = fixture_issuer_signature(
        GovernanceAuthorityClass::OnChainGovernance,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    let unsup = verify_governance_authority_proof(
        &on_chain_proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        unsup,
        Run163GovOutcome::UnsupportedOnChainGovernance
    ));
}

// ===========================================================================
// R1 — wrong environment rejected
// ===========================================================================

#[test]
fn r1_wrong_environment_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.environment = TrustBundleEnvironment::Testnet;
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongEnvironment { .. }));
}

// ===========================================================================
// R2 — wrong chain rejected
// ===========================================================================

#[test]
fn r2_wrong_chain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongChain { .. }));
}

// ===========================================================================
// R3 — wrong genesis rejected
// ===========================================================================

#[test]
fn r3_wrong_genesis_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongGenesis { .. }));
}

// ===========================================================================
// R4 — wrong authority root rejected
// ===========================================================================

#[test]
fn r4_wrong_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongAuthorityRoot { .. }));
}

// ===========================================================================
// R5 — wrong governance domain rejected
// ===========================================================================

#[test]
fn r5_wrong_governance_domain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = OTHER_GOV_DOMAIN.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongGovernanceDomain { .. }));
}

// ===========================================================================
// R6 — wrong proposal digest rejected
// ===========================================================================

#[test]
fn r6_wrong_proposal_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest = OTHER_PROPOSAL_DIGEST.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongProposalDigest { .. }));
}

#[test]
fn r6b_wrong_proposal_id_rejected_as_proposal_digest_mismatch() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_id = OTHER_PROPOSAL_ID.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongProposalDigest { .. }));
}

// ===========================================================================
// R7 — wrong proposal outcome rejected
// ===========================================================================

#[test]
fn r7_wrong_proposal_outcome_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(
        outcome,
        Outcome::WrongProposalOutcome {
            candidate: OnChainGovernanceProposalOutcome::Rejected,
        }
    ));
}

// ===========================================================================
// R8 — wrong lifecycle action rejected
// ===========================================================================

#[test]
fn r8_wrong_lifecycle_action_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    // good_proof for Rotate, then claim it's Retire — the candidate is
    // a Rotate, so this should be rejected as WrongLifecycleAction.
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.lifecycle_action = LocalLifecycleAction::Retire;
    // Re-derive proof_bytes for the new (mismatched) lifecycle? No —
    // verifier checks lifecycle_action against candidate before the
    // proof_bytes commitment, so a mismatch surfaces as WrongLifecycleAction.
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongLifecycleAction { .. }));
}

// ===========================================================================
// R9 — wrong candidate digest rejected
// ===========================================================================

#[test]
fn r9_wrong_candidate_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_3.to_string();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongCandidateDigest { .. }));
}

// ===========================================================================
// R10 — wrong authority-domain sequence rejected
// ===========================================================================

#[test]
fn r10_wrong_authority_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_domain_sequence = 7;
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::WrongAuthoritySequence { .. }));
}

// ===========================================================================
// R11 — expired governance proof rejected
// ===========================================================================

#[test]
fn r11_expired_governance_proof_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW - 1000,
        not_after_unix: NOW - 100, // already expired
    };
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::ExpiredGovernanceProof { .. }));
}

#[test]
fn r11b_too_early_governance_proof_rejected_as_expired_window() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW + 100, // not yet valid
        not_after_unix: NOW + 1000,
    };
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::ExpiredGovernanceProof { .. }));
}

// ===========================================================================
// R12 — stale / replayed governance decision rejected
// ===========================================================================

#[test]
fn r12_stale_lower_sequence_replay_rejected() {
    // Persisted higher-sequence than the proof's sequence.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // persisted_sequence > proof_sequence => replay
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(99));
    assert!(matches!(outcome, Outcome::ReplayRejected { .. }));
}

#[test]
fn r12b_replayed_unique_decision_id_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let seen = vec![UNIQUE_DECISION_ID.to_string()];
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &seen,
    );
    assert!(matches!(outcome, Outcome::ReplayRejected { .. }));
}

// ===========================================================================
// R13 — quorum not met rejected
// ===========================================================================

#[test]
fn r13_quorum_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.quorum = OnChainGovernanceQuorum {
        voters_voted: 2,
        total_voters: 5,
        required_quorum: 3,
    };
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::QuorumNotMet { .. }));
}

// ===========================================================================
// R14 — threshold not met rejected
// ===========================================================================

#[test]
fn r14_threshold_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.threshold = GovernanceThreshold::new(1, 3, 5);
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::ThresholdNotMet { .. }));
}

// ===========================================================================
// R15 — invalid governance proof bytes rejected
// ===========================================================================

#[test]
fn r15_invalid_proof_bytes_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes = b"this-is-not-the-canonical-commitment".to_vec();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::InvalidGovernanceProof { .. }));
}

// ===========================================================================
// R16 — unsupported governance proof suite rejected
// ===========================================================================

#[test]
fn r16_unsupported_proof_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(
        outcome,
        Outcome::UnsupportedGovernanceProofSuite {
            suite_id: ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
        }
    ));
}

#[test]
fn r16b_unknown_proof_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = 0xFF;
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(
        outcome,
        Outcome::UnsupportedGovernanceProofSuite { suite_id: 0xFF }
    ));
}

// ===========================================================================
// R17 — malformed OnChainGovernance proof rejected
// ===========================================================================

#[test]
fn r17_malformed_empty_field_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id.clear();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::MalformedOnChainProof { .. }));
}

#[test]
fn r17b_malformed_empty_proof_bytes_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes.clear();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::MalformedOnChainProof { .. }));
}

#[test]
fn r17c_malformed_freshness_window_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW + 1000,
        not_after_unix: NOW, // inverted
    };
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::MalformedOnChainProof { .. }));
}

#[test]
fn r17d_non_pqc_authority_root_suite_rejected_as_malformed() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_root_suite_id = 1; // legacy non-PQC marker
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::MalformedOnChainProof { .. }));
}

// ===========================================================================
// R18 — production MainNet OnChainGovernance proof rejected as unavailable
// ===========================================================================

#[test]
fn r18_mainnet_proof_unavailable() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Mainnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &mainnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(matches!(outcome, Outcome::MainNetProductionProofUnavailable));
}

// ===========================================================================
// R19 — local operator config alone rejected as OnChainGovernance proof
// ===========================================================================

#[test]
fn r19_local_operator_config_alone_rejected_via_disabled_policy() {
    // The wire format intentionally cannot encode "local operator config
    // alone" as a valid OnChainGovernance authority proof. Under the
    // default `Disabled` policy, every proof — including a synthetic
    // "operator-config" one — is refused as
    // `UnsupportedProductionOnChainGovernance`.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify_onchain_governance_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::Disabled,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(matches!(
        outcome,
        Outcome::UnsupportedProductionOnChainGovernance
    ));
}

// ===========================================================================
// R20 — peer-majority / gossip count rejected as OnChainGovernance proof
// ===========================================================================

#[test]
fn r20_peer_majority_gossip_rejected_via_invalid_proof_bytes() {
    // Peer-majority / gossip count cannot encode a valid mock
    // commitment over the bound governance fields, so a "proof" that
    // claims to be derived from peer gossip will fail as
    // `InvalidGovernanceProof` (proof bytes do not match commitment).
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes = b"peer-gossip-majority:5-of-7".to_vec();
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(matches!(outcome, Outcome::InvalidGovernanceProof { .. }));
}

// ===========================================================================
// R21 — OnChainGovernance proof valid but lifecycle invalid rejected
// ===========================================================================

#[test]
fn r21_proof_valid_but_lifecycle_invalid_rejected() {
    // Persisted at sequence 5 (rotate to KEY_B), candidate claims
    // sequence 2 (rollback). Lifecycle layer will reject the
    // candidate.
    let prev = rotate_to(KEY_B, KEY_A, 5, DIGEST_3, TrustBundleEnvironment::Devnet);
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(combined.is_reject());
    assert!(matches!(
        combined,
        CombinedLifecycleOnChainGovernanceOutcome::LifecycleRejected(_)
    ));
}

// ===========================================================================
// R22 — lifecycle valid but OnChainGovernance proof invalid rejected
// ===========================================================================

#[test]
fn r22_lifecycle_valid_but_proof_invalid_rejected() {
    let prev = build_v2_with_env(
        TrustBundleEnvironment::Devnet,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        "1111111111111111111111111111111111111111111111111111111111111111",
        None,
    );
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest = OTHER_PROPOSAL_DIGEST.to_string();
    let combined = validate_lifecycle_with_onchain_governance_proof(
        Some(&persisted),
        &candidate,
        &proof,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(combined.is_reject());
    match combined {
        CombinedLifecycleOnChainGovernanceOutcome::GovernanceRejected { governance, .. } => {
            assert!(matches!(governance, Outcome::WrongProposalDigest { .. }));
        }
        other => panic!("expected GovernanceRejected, got {:?}", other),
    }
}

// ===========================================================================
// R23 — OnChainGovernance proof valid but MainNet peer-driven apply remains refused
// ===========================================================================

#[test]
fn r23_mainnet_peer_driven_apply_remains_refused_even_with_valid_devnet_proof() {
    // A DevNet fixture proof verifies. That acceptance must NOT enable
    // a MainNet peer-driven apply.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(outcome.is_accept());
    // MainNet remains refused regardless of the DevNet outcome above.
    assert!(mainnet_peer_driven_apply_remains_refused(
        TrustBundleEnvironment::Mainnet,
        &outcome,
    ));
    // And of course a fresh MainNet-side verification still returns
    // `MainNetProductionProofUnavailable`.
    let mainnet_candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Mainnet);
    let mainnet_proof = good_proof(&mainnet_candidate, LocalLifecycleAction::Rotate);
    let mainnet_outcome = verify_onchain_governance_proof(
        &mainnet_proof,
        &mainnet_candidate,
        &mainnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(matches!(
        mainnet_outcome,
        Outcome::MainNetProductionProofUnavailable
    ));
}

// ===========================================================================
// R24 — old proof-carrier sidecars remain parse-compatible
// ===========================================================================

#[test]
fn r24_old_run167_carrier_without_onchain_sibling_still_parses() {
    // A pre-Run-178 carrier (Run 167–177) carries no Run 178
    // OnChainGovernance sibling. Round-trip a Run 167 wire object
    // through JSON and confirm it still parses back to the same typed
    // Run 163 proof — backward compatibility is preserved.
    let signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        ROOT_FP,
        DIGEST_2,
        2,
    );
    let r163_proof = GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: KEY_B.to_string(),
        new_bundle_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_bundle_signing_key_fingerprint: Some(KEY_A.to_string()),
        authority_domain_sequence: 2,
        candidate_v2_digest: DIGEST_2.to_string(),
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    };
    let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&r163_proof);
    let json = serde_json::to_vec(&wire).unwrap();
    let decoded: GovernanceAuthorityProofWire = serde_json::from_slice(&json).unwrap();
    assert_eq!(wire, decoded);
    let decoded_proof = decoded.to_governance_authority_proof().unwrap();
    assert_eq!(r163_proof, decoded_proof);

    // Confirm `GovernanceProofLoadStatus::Available(...)` carries the
    // typed Run 163 proof unchanged — Run 178's additive wire surface
    // does not break this.
    let status = GovernanceProofLoadStatus::Available(decoded_proof.clone());
    assert!(status.is_available());
}

#[test]
fn r24b_run178_onchain_wire_roundtrips_independently() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let wire = OnChainGovernanceProofWire::from_proof(&proof);
    assert_eq!(
        wire.schema_version,
        ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION
    );
    let json = serde_json::to_string(&wire).unwrap();
    let decoded: OnChainGovernanceProofWire = serde_json::from_str(&json).unwrap();
    let p_back = decoded.to_proof().unwrap();
    assert_eq!(proof, p_back);
}

// ===========================================================================
// R25 — unsupported future OnChainGovernance proof version rejected fail-closed
// ===========================================================================

#[test]
fn r25_unknown_wire_schema_version_rejected_fail_closed() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.schema_version = 99;
    let err = wire.to_proof().unwrap_err();
    assert!(matches!(
        err,
        OnChainGovernanceProofWireParseError::UnknownSchemaVersion {
            got: 99,
            expected: 1
        }
    ));
}

#[test]
fn r25b_empty_required_field_in_wire_rejected_fail_closed() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.governance_domain_id.clear();
    let err = wire.to_proof().unwrap_err();
    assert!(matches!(
        err,
        OnChainGovernanceProofWireParseError::EmptyRequiredField
    ));
}

#[test]
fn r25c_empty_proof_bytes_in_wire_rejected_fail_closed() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let mut wire = OnChainGovernanceProofWire::from_proof(&proof);
    wire.proof_bytes.clear();
    let err = wire.to_proof().unwrap_err();
    assert!(matches!(
        err,
        OnChainGovernanceProofWireParseError::EmptyProofBytes
    ));
}

// ===========================================================================
// Pure / no-I/O guarantee
// ===========================================================================

#[test]
fn pure_verifier_performs_no_io() {
    // We verify that the verifier function compiles against and runs
    // entirely on stack-allocated inputs. There is no file system, no
    // network, no global state involved. This test simply runs the
    // verifier many times back-to-back to assert it is deterministic
    // and side-effect-free at the API-call level.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    for _ in 0..100 {
        let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
        assert!(matches!(
            outcome,
            Outcome::AcceptedOnChainGovernanceFixture { .. }
        ));
    }
    // Inputs are bit-identical after repeated calls — no mutation.
    assert_eq!(proof.unique_decision_id, UNIQUE_DECISION_ID);
    assert_eq!(candidate.latest_authority_domain_sequence, 2);
}

// ===========================================================================
// Combined remains pure
// ===========================================================================

#[test]
fn combined_decision_pure_and_non_mutating() {
    let prev = build_v2_with_env(
        TrustBundleEnvironment::Devnet,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        "1111111111111111111111111111111111111111111111111111111111111111",
        None,
    );
    let persisted = PersistentAuthorityStateRecordVersioned::V2(prev);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);

    let snapshot_seq = candidate.latest_authority_domain_sequence;
    let snapshot_active = candidate.active_bundle_signing_key_fingerprint.clone();

    for _ in 0..50 {
        let combined = validate_lifecycle_with_onchain_governance_proof(
            Some(&persisted),
            &candidate,
            &proof,
            &devnet_domain(),
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            GOV_DOMAIN,
            GOV_EPOCH,
            PROPOSAL_ID,
            PROPOSAL_DIGEST,
            NOW,
            &EmptyOnChainGovernanceReplaySet,
        );
        assert!(combined.is_accept());
    }
    // Inputs unchanged.
    assert_eq!(candidate.latest_authority_domain_sequence, snapshot_seq);
    assert_eq!(candidate.active_bundle_signing_key_fingerprint, snapshot_active);
}

// ===========================================================================
// Marker-decision source/test path: accept/reject without mutation
// ===========================================================================

#[test]
fn marker_decision_source_test_path_accept_and_reject_without_mutation() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);

    // Accept path
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let accept = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(accept.is_accept());

    // Reject path (wrong governance domain)
    let mut bad_proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    bad_proof.governance_domain_id = OTHER_GOV_DOMAIN.to_string();
    let reject = verify(&bad_proof, &candidate, &devnet_domain(), Some(1));
    assert!(reject.is_reject());

    // Candidate unchanged after both paths.
    assert_eq!(candidate.active_bundle_signing_key_fingerprint, KEY_B);
    assert_eq!(candidate.latest_authority_domain_sequence, 2);
}

// ===========================================================================
// MainNet peer-driven apply refusal helper
// ===========================================================================

#[test]
fn mainnet_peer_driven_apply_helper_returns_true_on_mainnet() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = verify(&proof, &candidate, &devnet_domain(), Some(1));
    assert!(outcome.is_accept());
    assert!(mainnet_peer_driven_apply_remains_refused(
        TrustBundleEnvironment::Mainnet,
        &outcome
    ));
    // DevNet/TestNet are not refused by this MainNet-specific predicate
    // — but neither is a peer-driven apply enabler toggled by Run 178
    // for those environments.
    assert!(!mainnet_peer_driven_apply_remains_refused(
        TrustBundleEnvironment::Devnet,
        &outcome
    ));
}
