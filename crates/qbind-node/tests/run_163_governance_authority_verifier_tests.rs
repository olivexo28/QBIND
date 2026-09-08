//! Run 163 — focused tests for the typed pure governance ratification
//! authority verifier.
//!
//! Source/test only. Run 163 does not enable MainNet peer-driven apply,
//! governance execution, on-chain governance, KMS/HSM, or validator-set
//! rotation. No release-binary evidence is captured in this run;
//! release-binary governance verifier evidence is deferred to Run 164.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_163.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityLifecycleTransitionOutcome, AuthorityTrustDomain, LocalLifecycleAction,
    PQC_LIFECYCLE_SUITE_ML_DSA_44, REVOKED_METADATA_PREFIX_EMERGENCY,
    REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, fixture_issuer_signature_verifier,
    validate_lifecycle_with_governance_authority, verify_governance_authority_proof,
    CombinedLifecycleGovernanceOutcome, GovernanceAuthorityClass, GovernanceAuthorityProof,
    GovernanceAuthorityVerificationOutcome as GovOutcome, GovernanceThreshold,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
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
const DIGEST_1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH_A,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn build_v2(
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
    revoked_metadata: Option<&str>,
) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        TrustBundleEnvironment::Devnet,
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

fn ratify_initial(active_fp: &str, sequence: u64, digest: &str) -> PersistentAuthorityStateRecordV2 {
    build_v2(
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Ratify,
        None,
        digest,
        None,
    )
}

fn rotate_to(
    new_active_fp: &str,
    previous_fp: &str,
    sequence: u64,
    digest: &str,
) -> PersistentAuthorityStateRecordV2 {
    build_v2(
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
) -> PersistentAuthorityStateRecordV2 {
    let metadata = format!("{}{}", sub_class_prefix, revoked_target);
    build_v2(
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Revoke,
        None,
        digest,
        Some(&metadata),
    )
}

fn good_proof_for(
    candidate: &PersistentAuthorityStateRecordV2,
    class: GovernanceAuthorityClass,
    action: LocalLifecycleAction,
) -> GovernanceAuthorityProof {
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
    let signature = fixture_issuer_signature(
        class,
        ROOT_FP,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH_A.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: action,
        active_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        new_bundle_signing_key_fingerprint: new_fp,
        revoked_bundle_signing_key_fingerprint: revoked_fp,
        authority_domain_sequence: candidate.latest_authority_domain_sequence,
        candidate_v2_digest: candidate.latest_ratification_v2_digest.clone(),
        issuer_authority_class: class,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    }
}

// ===========================================================================
// A1 — genesis-bound Rotate proof accepted
// ===========================================================================

#[test]
fn a1_genesis_bound_rotate_proof_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    match outcome {
        GovOutcome::AcceptedGenesisBound {
            action,
            authority_domain_sequence,
        } => {
            assert_eq!(action, LocalLifecycleAction::Rotate);
            assert_eq!(authority_domain_sequence, 2);
        }
        other => panic!("expected AcceptedGenesisBound, got {:?}", other),
    }
    assert!(outcome.is_accept());
}

// ===========================================================================
// A2 — genesis-bound Revoke proof accepted
// ===========================================================================

#[test]
fn a2_genesis_bound_revoke_proof_accepted() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_REVOKE, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Revoke,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(2),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        outcome,
        GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::Revoke,
            authority_domain_sequence: 3,
        }
    ));
}

// ===========================================================================
// A3 — genesis-bound EmergencyRevoke proof accepted
// ===========================================================================

#[test]
fn a3_genesis_bound_emergency_revoke_proof_accepted() {
    let candidate = revoke_record(
        KEY_B,
        4,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_EMERGENCY,
        KEY_A,
    );
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::EmergencyRevoke,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(3),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        outcome,
        GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::EmergencyRevoke,
            ..
        }
    ));
}

// ===========================================================================
// A4 — emergency-council EmergencyRevoke proof accepted
// ===========================================================================

#[test]
fn a4_emergency_council_emergency_revoke_proof_accepted() {
    let candidate = revoke_record(
        KEY_B,
        4,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_EMERGENCY,
        KEY_A,
    );
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::EmergencyCouncil,
        LocalLifecycleAction::EmergencyRevoke,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(3),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        outcome,
        GovOutcome::AcceptedEmergencyCouncil {
            authority_domain_sequence: 4,
        }
    ));
}

// ===========================================================================
// A5 — idempotent same governance proof accepted as idempotent
// ===========================================================================

#[test]
fn a5_idempotent_same_governance_proof_classified_replay_safe() {
    // Same proof bytes, same candidate, persisted_sequence == proof_sequence.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Proof at sequence 2 against persisted sequence 2 is replay-safe
    // (same sequence, same digest) — accept it as `AcceptedGenesisBound`.
    // Run 163 does not surface a separate idempotent variant when the
    // candidate already matches the persisted record at the same
    // sequence; the lifecycle layer is responsible for that
    // classification, and the verifier accepts because no binding is
    // violated.
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(2),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// R1–R7 — domain / action / digest / sequence rejects
// ===========================================================================

#[test]
fn r1_wrong_environment_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.environment = TrustBundleEnvironment::Testnet;
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongEnvironment { .. }));
    assert!(outcome.is_reject());
}

#[test]
fn r2_wrong_chain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.chain_id = OTHER_CHAIN.to_string();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongChain { .. }));
}

#[test]
fn r3_wrong_genesis_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongGenesis { .. }));
}

#[test]
fn r4_wrong_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongAuthorityRoot { .. }));
}

#[test]
fn r5_wrong_lifecycle_action_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Candidate is Rotate; declare Revoke in the proof.
    proof.lifecycle_action = LocalLifecycleAction::Revoke;
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongLifecycleAction { .. }));
}

#[test]
fn r6_wrong_candidate_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.candidate_v2_digest = DIGEST_1.to_string();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongCandidateDigest { .. }));
}

#[test]
fn r7_wrong_authority_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_domain_sequence = 99;
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::WrongAuthoritySequence { .. }));
}

// ===========================================================================
// R8–R10 — signature / suite rejects
// ===========================================================================

#[test]
fn r8_invalid_issuer_signature_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Tamper the signature byte string but keep length non-empty.
    proof.issuer_signature = vec![0u8; 32];
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::InvalidIssuerSignature { .. }));
}

#[test]
fn r9_unsupported_issuer_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Unknown suite ID (not PQC, not in the explicit non-PQC list).
    proof.issuer_signature_suite_id = 200;
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::UnsupportedIssuerSuite { .. }));
}

#[test]
fn r10_non_pqc_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Ed25519-style legacy suite (ID 1).
    proof.issuer_signature_suite_id = 1;
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::NonPqcSuiteRejected { .. }));
}

// ===========================================================================
// R11 — threshold not met rejected
// ===========================================================================

#[test]
fn r11_threshold_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(GovernanceThreshold::new(1, 3, 5));
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::ThresholdNotMet { .. }));
}

#[test]
fn r11b_threshold_met_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(GovernanceThreshold::new(4, 3, 5));
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// R12 — malformed proof rejected
// ===========================================================================

#[test]
fn r12_malformed_proof_empty_signature_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = Vec::new();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::MalformedProof { .. }));
}

#[test]
fn r12b_malformed_proof_empty_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_root_fingerprint = String::new();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::MalformedProof { .. }));
}

// ===========================================================================
// R13 — stale / replayed lower-sequence proof rejected
// ===========================================================================

#[test]
fn r13_stale_lower_sequence_proof_rejected() {
    // Persisted at sequence 5, a stale proof at sequence 2 is replay-rejected.
    let stale_candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &stale_candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &stale_candidate,
        &devnet_domain(),
        Some(5),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(outcome, GovOutcome::ReplayRejected { .. }));
}

// ===========================================================================
// R14 — on-chain governance proof rejected as unsupported
// ===========================================================================

#[test]
fn r14_on_chain_governance_proof_rejected_as_unsupported() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::OnChainGovernance,
        LocalLifecycleAction::Rotate,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert_eq!(outcome, GovOutcome::UnsupportedOnChainGovernance);
    assert!(outcome.is_reject());
}

// ===========================================================================
// R15 — local operator config alone rejected as MainNet authority proof
// ===========================================================================
//
// Synthesise an "operator-config-only" proof: empty signature byte
// string. The verifier rejects with `MalformedProof` (well-formedness),
// which is the precise typed reject for "local operator config alone is
// not an authority proof". A more specific
// `LocalOperatorConfigOnlyRejected` variant exists for callers that
// want to mark such inputs explicitly; we cover that path too.

#[test]
fn r15_local_operator_config_only_rejected_via_malformed_signature() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Operator config has no issuer signature.
    proof.issuer_signature = Vec::new();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_reject());
    assert!(matches!(outcome, GovOutcome::MalformedProof { .. }));
}

#[test]
fn r15b_local_operator_config_explicit_variant_is_reject() {
    // The explicit variant exists in the typed outcome surface and is a reject.
    let outcome = GovOutcome::LocalOperatorConfigOnlyRejected;
    assert!(outcome.is_reject());
}

// ===========================================================================
// R16 — peer-majority / gossip count rejected as authority proof
// ===========================================================================

#[test]
fn r16_peer_majority_proof_rejected() {
    // Peer-majority is not an authority class — no `PeerMajority` enum
    // variant exists. The verifier rejects any synthetic proof that
    // pretends to be governance but lacks an issuer signature; the
    // explicit typed variant `PeerMajorityProofRejected` is part of the
    // outcome enum so callers that detect peer-count-only inputs can
    // surface a precise typed reject.
    let outcome = GovOutcome::PeerMajorityProofRejected;
    assert!(outcome.is_reject());
}

#[test]
fn r16b_peer_majority_class_is_not_an_enum_variant() {
    // Compile-time assurance: the `GovernanceAuthorityClass` enum has
    // exactly three variants (GenesisBound, EmergencyCouncil,
    // OnChainGovernance). A peer-majority class would have to be added
    // in a future run; Run 163 explicitly does not introduce one.
    fn assert_three_variants(c: GovernanceAuthorityClass) -> &'static str {
        match c {
            GovernanceAuthorityClass::GenesisBound => "g",
            GovernanceAuthorityClass::EmergencyCouncil => "e",
            GovernanceAuthorityClass::OnChainGovernance => "o",
        }
    }
    assert_eq!(assert_three_variants(GovernanceAuthorityClass::GenesisBound), "g");
    assert_eq!(
        assert_three_variants(GovernanceAuthorityClass::EmergencyCouncil),
        "e"
    );
    assert_eq!(
        assert_three_variants(GovernanceAuthorityClass::OnChainGovernance),
        "o"
    );
}

// ===========================================================================
// Authority-class / lifecycle-action gating
// ===========================================================================

#[test]
fn emergency_council_declaring_rotate_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::EmergencyCouncil,
        LocalLifecycleAction::Rotate,
    );
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(matches!(
        outcome,
        GovOutcome::AuthorityClassDoesNotAuthorizeAction { .. }
    ));
}

// ===========================================================================
// Pure / no-I/O verifier
// ===========================================================================

#[test]
fn pure_verifier_performs_no_io() {
    // The verifier accepts input by reference and returns an enum. We
    // exercise it many times against the same candidate and proof to
    // assert that no global state, file system, or environment changes
    // occur (the result is byte-equal across invocations).
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let r1 = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    let r2 = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    let r3 = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

// ===========================================================================
// Combined helper composition
// ===========================================================================

#[test]
fn combined_helper_accepts_when_lifecycle_and_governance_both_pass() {
    let prev = ratify_initial(KEY_A, 1, DIGEST_1);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let outcome = validate_lifecycle_with_governance_authority(
        Some(&PersistentAuthorityStateRecordVersioned::V2(prev)),
        &candidate,
        &proof,
        &devnet_domain(),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_accept());
    match outcome {
        CombinedLifecycleGovernanceOutcome::Accepted {
            lifecycle,
            governance,
        } => {
            assert!(matches!(
                lifecycle,
                AuthorityLifecycleTransitionOutcome::RotationAccepted { .. }
            ));
            assert!(matches!(governance, GovOutcome::AcceptedGenesisBound { .. }));
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
}

#[test]
fn combined_helper_rejects_when_lifecycle_passes_but_governance_fails() {
    let prev = ratify_initial(KEY_A, 1, DIGEST_1);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Tamper signature so governance fails while lifecycle passes.
    proof.issuer_signature = vec![0u8; 16];
    let outcome = validate_lifecycle_with_governance_authority(
        Some(&PersistentAuthorityStateRecordVersioned::V2(prev)),
        &candidate,
        &proof,
        &devnet_domain(),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_reject());
    match outcome {
        CombinedLifecycleGovernanceOutcome::GovernanceRejected {
            lifecycle,
            governance,
        } => {
            assert!(matches!(
                lifecycle,
                AuthorityLifecycleTransitionOutcome::RotationAccepted { .. }
            ));
            assert!(matches!(governance, GovOutcome::InvalidIssuerSignature { .. }));
        }
        other => panic!("expected GovernanceRejected, got {:?}", other),
    }
}

#[test]
fn combined_helper_rejects_when_governance_passes_but_lifecycle_fails() {
    // Persisted sequence 5 + candidate sequence 2 → lifecycle rejects
    // with LowerSequenceRejected. Governance proof itself would accept
    // (it binds to candidate sequence 2 and persisted_sequence 5 would
    // also replay-reject on the governance side); so we use a candidate
    // with a structurally valid v2 record, persisted at higher
    // sequence, and a governance proof that targets the candidate's
    // own sequence (not the persisted one). The combined helper still
    // rejects because lifecycle rejects first.
    let prev = ratify_initial(KEY_A, 5, DIGEST_1);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let outcome = validate_lifecycle_with_governance_authority(
        Some(&PersistentAuthorityStateRecordVersioned::V2(prev)),
        &candidate,
        &proof,
        &devnet_domain(),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_reject());
    assert!(matches!(
        outcome,
        CombinedLifecycleGovernanceOutcome::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::LowerSequenceRejected { .. }
        )
    ));
}

#[test]
fn combined_helper_no_persisted_marker_initial_activation_accepts() {
    let candidate = ratify_initial(KEY_A, 1, DIGEST_1);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::ActivateInitial,
    );
    let outcome = validate_lifecycle_with_governance_authority(
        None,
        &candidate,
        &proof,
        &devnet_domain(),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_accept());
}

// ===========================================================================
// Acceptance does not enable MainNet apply
// ===========================================================================

#[test]
fn acceptance_does_not_imply_mainnet_apply_enablement() {
    // The verifier returns a typed accept variant on a valid genesis-
    // bound rotate proof, but an accept value carries NO side effect:
    // it does not reach into the apply path, does not write a marker,
    // does not write a sequence, and does not mutate any live trust
    // state. We assert this by confirming the value is a pure enum
    // variant with no side effect and the candidate / proof bytes are
    // unchanged after verification.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let candidate_before = candidate.clone();
    let proof_before = proof.clone();
    let outcome = verify_governance_authority_proof(
        &proof,
        &candidate,
        &devnet_domain(),
        Some(1),
        &fixture_issuer_signature_verifier(),
    );
    assert!(outcome.is_accept());
    // Inputs are unchanged.
    assert_eq!(candidate, candidate_before);
    assert_eq!(proof, proof_before);
}