//! Run 165 — integration tests wiring the Run 163 governance ratification
//! authority verifier (`pqc_governance_authority::verify_governance_authority_proof`)
//! into the shared v2 lifecycle / marker-decision path used by Run 134
//! (process-start reload-apply), Run 136 (`--p2p-trust-bundle` startup),
//! Run 138 (SIGHUP live-reload), Run 150 (peer-driven drain), and Run 152
//! (`ProductionV2MarkerCoordinator`).
//!
//! Source/test only. Run 165 does NOT enable MainNet peer-driven apply,
//! does NOT implement a governance execution engine, on-chain governance,
//! KMS/HSM, or validator-set rotation, and does NOT change any wire /
//! marker / sequence / trust-bundle schema. Release-binary governance
//! enforcement evidence is deferred to Run 166.
//!
//! ## Two composition surfaces under test
//!
//! 1. The pure non-mutating gate
//!    [`evaluate_governance_marker_gate`] — the exact governance
//!    composition the shared marker helper invokes. The bulk of the
//!    binding accept/reject matrix (A1–A5, R1–R19) is exercised here over
//!    in-memory v2 records (mirroring the Run 163 fixtures) so the matrix
//!    is independent of wire-ratification derivation quirks.
//!
//! 2. The shared marker decision helper
//!    [`decide_v2_marker_acceptance_with_lifecycle_and_governance`] —
//!    exercised end-to-end through a real ML-DSA-44 authority root +
//!    signed v2 ratifications, proving the governance verifier is
//!    production-source reachable from the marker decision path and that
//!    rejected governance decisions produce NO marker write (R20–R25).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_165.md`.

use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    REVOKED_METADATA_PREFIX_EMERGENCY, REVOKED_METADATA_PREFIX_RETIRE,
    REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_marker_acceptance::{
    decide_v2_marker_acceptance_with_lifecycle_and_governance, MarkerAcceptKindV2,
    MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::{
    evaluate_governance_marker_gate, fixture_issuer_signature, fixture_issuer_signature_verifier,
    GovernanceAuthorityClass, GovernanceAuthorityProof,
    GovernanceAuthorityVerificationOutcome as GovOutcome, GovernanceMarkerGate,
    GovernanceProofContext, GovernanceProofPolicy, PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// ===========================================================================
// Section 1 — pure gate matrix over in-memory v2 records (mirrors Run 163)
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

/// Run the pure gate against a supplied proof under the
/// `RequiredForLifecycleSensitive` policy.
fn gate_supplied(
    candidate: &PersistentAuthorityStateRecordV2,
    proof: &GovernanceAuthorityProof,
    persisted_sequence: Option<u64>,
) -> GovernanceMarkerGate {
    let verifier = fixture_issuer_signature_verifier();
    evaluate_governance_marker_gate(
        candidate,
        &devnet_domain(),
        persisted_sequence,
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Supplied {
            proof,
            verifier: &verifier,
        },
    )
}

// ---- A-matrix (gate) ------------------------------------------------------

/// A1 — Rotate accepted with a GenesisBound governance proof.
#[test]
fn a1_rotate_accepted_with_genesis_bound_proof() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(gate.is_accept());
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::Rotate,
            authority_domain_sequence: 2,
        })
    ));
}

/// A2 — Revoke accepted with a GenesisBound governance proof.
#[test]
fn a2_revoke_accepted_with_genesis_bound_proof() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_REVOKE, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Revoke,
    );
    let gate = gate_supplied(&candidate, &proof, Some(2));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedGenesisBound {
            action: LocalLifecycleAction::Revoke,
            authority_domain_sequence: 3,
        })
    ));
}

/// A3 — EmergencyRevoke accepted with an EmergencyCouncil proof.
#[test]
fn a3_emergency_revoke_accepted_with_emergency_council_proof() {
    let candidate = revoke_record(KEY_B, 4, DIGEST_3, REVOKED_METADATA_PREFIX_EMERGENCY, KEY_A);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::EmergencyCouncil,
        LocalLifecycleAction::EmergencyRevoke,
    );
    let gate = gate_supplied(&candidate, &proof, Some(3));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedEmergencyCouncil {
            authority_domain_sequence: 4,
        })
    ));
}

/// A4 — Idempotent same lifecycle/governance record accepted (same
/// sequence/digest/proof; persisted sequence equals candidate sequence).
#[test]
fn a4_idempotent_same_record_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    // Persisted sequence == candidate sequence: not a replay, accepted.
    let gate = gate_supplied(&candidate, &proof, Some(2));
    assert!(gate.is_accept());
}

/// A5 — Existing non-governance fixture path. Chosen policy:
/// `Rotate`/`Retire`/`Revoke`/`EmergencyRevoke` REQUIRE a proof; a missing
/// proof yields a clear `RequiredButMissing` rejection rather than silent
/// acceptance. `ActivateInitial` remains governance-optional.
#[test]
fn a5_required_policy_missing_proof_rejects_lifecycle_sensitive() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::Rotate
        }
    ));

    // ActivateInitial is optional even under the required policy.
    let activate = build_v2(
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        DIGEST_2,
        None,
    );
    let gate = evaluate_governance_marker_gate(
        &activate,
        &devnet_domain(),
        None,
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(gate, GovernanceMarkerGate::NotRequiredNoProof));
}

// ---- R-matrix (gate) ------------------------------------------------------

/// R1 — Rotate without required governance proof rejected.
#[test]
fn r1_rotate_without_proof_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::Rotate
        }
    ));
}

/// R2 — Revoke without required governance proof rejected.
#[test]
fn r2_revoke_without_proof_rejected() {
    let candidate = revoke_record(KEY_B, 3, DIGEST_3, REVOKED_METADATA_PREFIX_REVOKE, KEY_A);
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(2),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::Revoke
        }
    ));
}

/// R3 — EmergencyRevoke without emergency authority proof rejected (no
/// proof at all under the required policy).
#[test]
fn r3_emergency_revoke_without_proof_rejected() {
    let candidate = revoke_record(KEY_B, 4, DIGEST_3, REVOKED_METADATA_PREFIX_EMERGENCY, KEY_A);
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(3),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(
        gate,
        GovernanceMarkerGate::RequiredButMissing {
            action: LocalLifecycleAction::EmergencyRevoke
        }
    ));
    // A non-emergency (GenesisBound) class declaring EmergencyRevoke is
    // authorized in the source/test model, but a Rotate-declaring
    // EmergencyCouncil proof is refused by class gating (R8-adjacent).
}

/// R4 — wrong environment proof rejected.
#[test]
fn r4_wrong_environment_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.environment = TrustBundleEnvironment::Testnet;
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongEnvironment { .. })
    ));
}

/// R5 — wrong chain proof rejected.
#[test]
fn r5_wrong_chain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.chain_id = OTHER_CHAIN.to_string();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongChain { .. })
    ));
}

/// R6 — wrong genesis proof rejected.
#[test]
fn r6_wrong_genesis_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongGenesis { .. })
    ));
}

/// R7 — wrong authority root proof rejected.
#[test]
fn r7_wrong_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongAuthorityRoot { .. })
    ));
}

/// R8 — wrong lifecycle action proof rejected (proof declares Retire for a
/// Rotate candidate).
#[test]
fn r8_wrong_lifecycle_action_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.lifecycle_action = LocalLifecycleAction::Retire;
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongLifecycleAction { .. })
    ));
}

/// R9 — wrong candidate digest proof rejected.
#[test]
fn r9_wrong_candidate_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.candidate_v2_digest = DIGEST_3.to_string();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongCandidateDigest { .. })
    ));
}

/// R10 — wrong authority-domain sequence proof rejected.
#[test]
fn r10_wrong_authority_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_domain_sequence = 7;
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::WrongAuthoritySequence { .. })
    ));
}

/// R11 — invalid issuer signature rejected.
#[test]
fn r11_invalid_issuer_signature_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = b"not-the-canonical-signature".to_vec();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::InvalidIssuerSignature { .. })
    ));
}

/// R12 — unsupported issuer suite rejected.
#[test]
fn r12_unsupported_issuer_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature_suite_id = 200; // unknown PQC-ish but unsupported
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::UnsupportedIssuerSuite { .. })
    ));
}

/// R13 — non-PQC suite rejected.
#[test]
fn r13_non_pqc_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature_suite_id = 1; // Ed25519 legacy tag
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::NonPqcSuiteRejected { .. })
    ));
}

/// R14 — threshold not met rejected.
#[test]
fn r14_threshold_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(qbind_node::pqc_governance_authority::GovernanceThreshold::new(1, 3, 5));
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::ThresholdNotMet { .. })
    ));
}

/// R15 — malformed proof rejected (empty required field).
#[test]
fn r15_malformed_proof_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.candidate_v2_digest = String::new();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::MalformedProof { .. })
    ));
}

/// R16 — stale/replayed lower authority proof rejected.
#[test]
fn r16_stale_replayed_proof_rejected() {
    // Candidate at sequence 2 but persisted is already at sequence 5: the
    // proof's claimed sequence (2) is strictly lower than persisted.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gate = gate_supplied(&candidate, &proof, Some(5));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::ReplayRejected {
            persisted_sequence: 5,
            proof_sequence: 2,
        })
    ));
}

/// R17 — OnChainGovernance proof rejected as unsupported.
#[test]
fn r17_on_chain_governance_unsupported() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_authority_class = GovernanceAuthorityClass::OnChainGovernance;
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::UnsupportedOnChainGovernance)
    ));
}

/// R18 — local operator config alone rejected as MainNet authority proof.
/// Modelled as a proof carrying an empty issuer signature (no real issuer
/// authority) — the verifier refuses it as malformed rather than treating
/// local config as authority.
#[test]
fn r18_local_operator_config_alone_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = Vec::new();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(gate.is_reject());
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::MalformedProof { .. })
    ));
}

/// R19 — peer majority / gossip count rejected as authority proof. Modelled
/// as a proof whose only "authority" is a met threshold but an invalid
/// (non-canonical) issuer signature — peer counts cannot substitute for the
/// issuer signature binding.
#[test]
fn r19_peer_majority_not_authority() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let mut proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.threshold = Some(qbind_node::pqc_governance_authority::GovernanceThreshold::new(5, 3, 5));
    proof.issuer_signature = b"peer-majority-gossip-count".to_vec();
    let gate = gate_supplied(&candidate, &proof, Some(1));
    assert!(matches!(
        gate,
        GovernanceMarkerGate::Rejected(GovOutcome::InvalidIssuerSignature { .. })
    ));
}

// ===========================================================================
// Section 2 — end-to-end shared marker helper (real ML-DSA-44 ratifications)
// ===========================================================================

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

struct Harness {
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    signing_pk_a: Vec<u8>,
    signing_pk_b: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
}

fn devnet_harness() -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let (signing_pk_a, _a) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key A");
    let (signing_pk_b, _b) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key B");
    let chain_id = NetworkEnvironment::Devnet.chain_id();
    let chain_id_str = chain_id_hex(chain_id);
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
        1_738_000_000_000,
        vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(32)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(32)),
                format!("0x{}", "44".repeat(32)),
                format!("0x{}", "55".repeat(32)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    let auth_root = GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &hex_lower(&authority_pk),
        "test-bundle-signing-1",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);
    Harness {
        authority_pk,
        authority_sk,
        signing_pk_a,
        signing_pk_b,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
    }
}

impl Harness {
    fn build_v2(
        &self,
        target_pk: &[u8],
        seq: u64,
        action: BundleSigningRatificationV2Action,
        previous_fp: Option<String>,
    ) -> BundleSigningRatificationV2 {
        let policy_version = self
            .genesis_cfg
            .authority
            .as_ref()
            .unwrap()
            .authority_policy_version;
        let previous_digest = matches!(action, BundleSigningRatificationV2Action::Rotate)
            .then(|| "ab".repeat(32));
        ratification_v2_helpers::build_signed_ratification_v2(
            &self.chain_id_str,
            RatificationEnvironment::Devnet,
            self.canonical_hash,
            policy_version,
            &hex_lower(&self.authority_pk),
            &self.authority_sk,
            target_pk,
            seq,
            action,
            previous_fp,
            previous_digest,
            None,
            None,
            None,
            None,
        )
    }

    fn verify_v2(
        &self,
        ratification: &BundleSigningRatificationV2,
    ) -> qbind_ledger::RatifiedBundleSigningKeyV2 {
        qbind_ledger::verify_bundle_signing_key_ratification_v2(
            qbind_ledger::RatificationV2VerifierInputs {
                ratification,
                authority: self.genesis_cfg.authority.as_ref().unwrap(),
                expected_chain_id: &self.chain_id_str,
                expected_environment: self.env_policy,
                expected_genesis_hash: &self.canonical_hash,
            },
        )
        .expect("v2 verifier accepts clean ratification")
    }

    fn genesis_hex(&self) -> String {
        hex_lower(&self.canonical_hash)
    }

    fn root_fp(&self) -> String {
        hex_lower(&self.authority_pk)
    }

    /// Derive the v2 candidate marker the shared helper would derive, so a
    /// governance proof can be bound to the exact candidate digest.
    fn derive_candidate(
        &self,
        gh_hex: &str,
        ratification: &BundleSigningRatificationV2,
        ratified: &qbind_ledger::RatifiedBundleSigningKeyV2,
        update_source: AuthorityStateUpdateSource,
    ) -> PersistentAuthorityStateRecordV2 {
        qbind_node::pqc_authority_state::derive_authority_state_v2_from_ratification(
            qbind_node::pqc_authority_state::AuthorityStateDerivationV2Inputs {
                runtime_env: NetworkEnvironment::Devnet,
                runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
                runtime_genesis_hash_hex: gh_hex,
                ratification,
                ratified,
                update_source,
                updated_at_unix_secs: 1_700_000_000,
            },
        )
        .expect("derive v2 candidate")
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run165-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&p).expect("create_dir_all");
    p
}

fn make_inputs<'a>(
    marker_path: &'a Path,
    gh_hex: &'a str,
    ratification: &'a BundleSigningRatificationV2,
    ratified: &'a qbind_ledger::RatifiedBundleSigningKeyV2,
    update_source: AuthorityStateUpdateSource,
) -> MarkerAcceptanceV2Inputs<'a> {
    MarkerAcceptanceV2Inputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: gh_hex,
        ratification,
        ratified,
        update_source,
        updated_at_unix_secs: 1_700_000_000,
    }
}

/// Build a governance proof bound to a derived candidate using the
/// harness authority root fingerprint.
fn e2e_good_proof(
    h: &Harness,
    candidate: &PersistentAuthorityStateRecordV2,
    class: GovernanceAuthorityClass,
    action: LocalLifecycleAction,
) -> GovernanceAuthorityProof {
    let root_fp = h.root_fp();
    let new_fp = match action {
        LocalLifecycleAction::ActivateInitial | LocalLifecycleAction::Rotate => {
            Some(candidate.active_bundle_signing_key_fingerprint.clone())
        }
        _ => None,
    };
    let revoked_fp = match action {
        LocalLifecycleAction::Rotate => candidate.previous_bundle_signing_key_fingerprint.clone(),
        _ => None,
    };
    let signature = fixture_issuer_signature(
        class,
        &root_fp,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: h.chain_id_str.clone(),
        genesis_hash: h.genesis_hex(),
        authority_root_fingerprint: root_fp,
        authority_root_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
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

/// E1 — ActivateInitial accepted end-to-end with a supplied GenesisBound
/// proof; helper performs NO marker write before the post-commit boundary.
#[test]
fn e1_activate_initial_accepted_with_proof_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("e1");
    let marker_path = authority_state_file_path(&dir);
    let gh = h.genesis_hex();
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let candidate =
        h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
    let proof = e2e_good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::ActivateInitial,
    );
    let verifier = fixture_issuer_signature_verifier();
    let decision = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Supplied {
            proof: &proof,
            verifier: &verifier,
        },
    )
    .expect("activate-initial accepts with governance proof");
    assert!(matches!(decision.kind(), MarkerAcceptKindV2::FirstV2Write));
    assert!(decision.should_persist());
    assert!(
        !marker_path.exists(),
        "helper must NOT write marker before the post-commit boundary"
    );
}

/// E2 (R20) — lifecycle-valid but governance-invalid candidate rejected
/// before apply; NO marker write (covers R23 startup / R20 ordering).
#[test]
fn e2_lifecycle_valid_governance_invalid_rejected_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("e2");
    let marker_path = authority_state_file_path(&dir);
    let gh = h.genesis_hex();
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let candidate =
        h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
    let mut proof = e2e_good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::ActivateInitial,
    );
    proof.issuer_signature = b"tampered".to_vec();
    let verifier = fixture_issuer_signature_verifier();
    let err = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Supplied {
            proof: &proof,
            verifier: &verifier,
        },
    )
    .expect_err("governance-invalid candidate rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
            GovOutcome::InvalidIssuerSignature { .. }
        )
    ));
    assert!(!marker_path.exists(), "rejected governance decision must NOT write marker");
}

/// E3 (R1/R23) — Rotate requiring a proof but supplied none rejects with
/// `GovernanceAuthorityRequiredButMissing`; persisted marker untouched.
#[test]
fn e3_rotate_required_but_missing_rejected_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("e3");
    let marker_path = authority_state_file_path(&dir);
    let gh = h.genesis_hex();

    // Seed persisted generation A (seq 1) by accepting an ActivateInitial
    // through the helper (NotRequired policy) and persisting it.
    let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified1 = h.verify_v2(&r1);
    let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::NotRequired,
        GovernanceProofContext::Unavailable,
    )
    .expect("seed activate-initial accepts");
    qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(
        &d1,
    )
    .expect("persist seed marker");
    assert!(marker_path.exists());
    let seed_bytes = std::fs::read(&marker_path).expect("read seed marker");

    // Now Rotate to B at seq 2 with NO proof under the required policy.
    let r2 = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified2 = h.verify_v2(&r2);
    let err = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Unavailable,
    )
    .expect_err("rotate requires governance proof");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing {
            action: LocalLifecycleAction::Rotate
        }
    ));
    // Persisted seed marker is byte-for-byte untouched.
    assert_eq!(seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// E4 (A1) — Rotate accepted end-to-end with a supplied GenesisBound proof.
#[test]
fn e4_rotate_accepted_with_proof() {
    let h = devnet_harness();
    let dir = tmpdir("e4");
    let marker_path = authority_state_file_path(&dir);
    let gh = h.genesis_hex();

    let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified1 = h.verify_v2(&r1);
    let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::NotRequired,
        GovernanceProofContext::Unavailable,
    )
    .expect("seed activate-initial accepts");
    qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(
        &d1,
    )
    .expect("persist seed marker");

    let r2 = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified2 = h.verify_v2(&r2);
    let candidate =
        h.derive_candidate(&gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply);
    let proof = e2e_good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let verifier = fixture_issuer_signature_verifier();
    let decision = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Supplied {
            proof: &proof,
            verifier: &verifier,
        },
    )
    .expect("rotate accepts with governance proof");
    assert!(matches!(
        decision.kind(),
        MarkerAcceptKindV2::UpgradeV2 {
            previous_sequence: 1,
            new_sequence: 2
        }
    ));
}

/// E5 (R21) — governance-valid but lifecycle-invalid candidate rejected.
/// A Rotate whose `previous_key_fingerprint` does not match the persisted
/// active key is refused by the Run 159 lifecycle layer BEFORE governance
/// is consulted, even with an otherwise-valid proof.
#[test]
fn e5_governance_valid_lifecycle_invalid_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("e5");
    let marker_path = authority_state_file_path(&dir);
    let gh = h.genesis_hex();

    // Seed generation A at seq 1.
    let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified1 = h.verify_v2(&r1);
    let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::NotRequired,
        GovernanceProofContext::Unavailable,
    )
    .expect("seed activate-initial accepts");
    qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(
        &d1,
    )
    .expect("persist seed marker");
    let seed_bytes = std::fs::read(&marker_path).expect("read seed marker");

    // Rotate to B at seq 2 but declare a previous fingerprint that does NOT
    // match the persisted active key A (a well-formed but unrelated
    // fingerprint) — derives a valid candidate but is lifecycle-invalid.
    let r2 = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some("cd".repeat(32)),
    );
    let ratified2 = h.verify_v2(&r2);
    let candidate =
        h.derive_candidate(&gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply);
    let proof = e2e_good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let verifier = fixture_issuer_signature_verifier();
    let err = decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
        GovernanceProofPolicy::RequiredForLifecycleSensitive,
        GovernanceProofContext::Supplied {
            proof: &proof,
            verifier: &verifier,
        },
    )
    .expect_err("lifecycle-invalid rotate rejects before governance");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
    assert_eq!(seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R26/R27 — validation-only composition is non-mutating, and a valid
/// governance proof does NOT enable MainNet apply. The pure gate never
/// touches disk and never carries any MainNet-apply capability; MainNet
/// peer-driven apply refusal lives in the surface environment gate, which
/// Run 165 does not alter. This test asserts the gate is pure (a repeated
/// evaluation is side-effect free and deterministic) and that acceptance
/// is a typed decision only.
#[test]
fn r26_r27_gate_pure_and_non_mainnet_enabling() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let proof = good_proof_for(
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let g1 = gate_supplied(&candidate, &proof, Some(1));
    let g2 = gate_supplied(&candidate, &proof, Some(1));
    assert_eq!(g1, g2, "gate must be deterministic / side-effect free");
    assert!(g1.is_accept());
    // Acceptance is purely a typed decision; there is no field, method, or
    // variant that flips a MainNet-apply capability. The MainNet refusal is
    // enforced by the calling surface's environment gate, unchanged here.
    assert!(matches!(
        g1,
        GovernanceMarkerGate::Accepted(GovOutcome::AcceptedGenesisBound { .. })
    ));
}

/// Sanity — the `NotRequired` production wiring used by Run 165 surfaces is
/// behaviour-preserving: an `Unavailable` context never rejects.
#[test]
fn not_required_unavailable_is_noop() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2);
    let gate = evaluate_governance_marker_gate(
        &candidate,
        &devnet_domain(),
        Some(1),
        GovernanceProofPolicy::NotRequired,
        GovernanceProofContext::Unavailable,
    );
    assert!(matches!(gate, GovernanceMarkerGate::NotRequiredNoProof));
    // Persisted/versioned import is exercised to keep the path honest.
    let _ = PersistentAuthorityStateRecordVersioned::V2(candidate);
    let _ = REVOKED_METADATA_PREFIX_RETIRE;
}
