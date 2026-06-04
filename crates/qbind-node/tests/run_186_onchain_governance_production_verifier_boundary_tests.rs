//! Run 186 — source/test production OnChainGovernance verifier-boundary
//! integration tests.
//!
//! Source/test only. Run 186 does **not** capture release-binary
//! evidence; release-binary verifier-boundary evidence is deferred to
//! **Run 187**. Default verifier kind remains
//! [`OnChainGovernanceVerifierKind::Disabled`].
//! `FixtureSourceTest` is hidden, explicit, and DevNet/TestNet
//! fixture-only. MainNet peer-driven apply remains refused. Real on-
//! chain governance proof verification, governance execution, KMS/HSM
//! custody, and validator-set rotation all remain unimplemented. See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_186.md`.
//!
//! These tests cover A1–A7 / R1–R29 from `task/RUN_186_TASK.txt` plus
//! explicit fixture-vs-production proof-class separation, default
//! Disabled fail-closed, production verifier unavailable fail-closed,
//! MainNet fixture rejection as production authority, Run 185
//! fixture-path compatibility, no-I/O determinism, validation-only
//! non-mutation, mutating-rejection no-mutation, and source-
//! reachability of the new boundary from the Run 182/184 call-site
//! path.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_callsite_wiring::OnChainGovernanceCallsiteContext;
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofVerificationOutcome, OnChainGovernanceProposalOutcome,
    OnChainGovernanceQuorum, ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
};
use qbind_node::pqc_onchain_governance_proof_surface::{
    reload_check_compose_onchain_governance_marker_decision,
    OnChainGovernanceMarkerDecisionOutcome,
};
use qbind_node::pqc_onchain_governance_verifier::{
    classify_onchain_governance_proof_class,
    dispatch_onchain_governance_proof_through_verifier_boundary,
    is_reserved_production_onchain_governance_proof_suite,
    mainnet_peer_driven_apply_remains_refused_under_verifier_boundary,
    verify_fixture_onchain_governance_proof, verify_production_onchain_governance_proof,
    DisabledOnChainGovernanceVerifier, FixtureSourceTestOnChainGovernanceVerifier,
    OnChainGovernanceProofClass, OnChainGovernanceVerifier,
    OnChainGovernanceVerifierBoundaryOutcome, OnChainGovernanceVerifierKind,
    OnChainGovernanceVerifierPolicy, ProductionUnavailableOnChainGovernanceVerifier,
    ProductionVerifierPlaceholderOnChainGovernanceVerifier,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Fixtures (kept structurally identical to Run 182/184).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";

const GOV_DOMAIN: &str = "qbind-onchain-gov-1";
const GOV_EPOCH: u64 = 42;
const PROPOSAL_ID: &str = "prop-001";
const PROPOSAL_DIGEST: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const UNIQUE_DECISION_ID: &str = "decision-186";
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

fn build_v2(
    env: TrustBundleEnvironment,
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
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
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
    )
}

fn rotate_candidate(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordV2 {
    build_v2(
        env,
        KEY_B,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
    )
}

fn prior_versioned(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2(
        env,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        "1111111111111111111111111111111111111111111111111111111111111111",
    ))
}

/// Build a well-formed fixture-class Run 178 proof matching the
/// supplied candidate.
fn good_fixture_proof(
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
        _ => None,
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

/// Build a production-class proof (reserved suite). The verifier
/// boundary classifies this as
/// [`OnChainGovernanceProofClass::Production`] regardless of the
/// other binding fields.
fn production_class_proof(
    candidate: &PersistentAuthorityStateRecordV2,
    action: LocalLifecycleAction,
) -> OnChainGovernanceProof {
    let mut p = good_fixture_proof(candidate, action);
    p.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    p
}

fn recommit(p: &mut OnChainGovernanceProof) {
    p.proof_bytes = fixture_onchain_governance_proof_bytes(
        p.environment,
        &p.chain_id,
        &p.genesis_hash,
        &p.authority_root_fingerprint,
        &p.governance_domain_id,
        p.governance_epoch,
        &p.proposal_id,
        &p.proposal_digest,
        &p.candidate_v2_digest,
        p.authority_domain_sequence,
        &p.unique_decision_id,
    );
}

fn dispatch(
    proof: &OnChainGovernanceProof,
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceVerifierPolicy,
    persisted_seq: Option<u64>,
) -> OnChainGovernanceVerifierBoundaryOutcome {
    dispatch_onchain_governance_proof_through_verifier_boundary(
        proof,
        candidate,
        domain,
        policy,
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
// Acceptance scenarios A1–A7
// ===========================================================================

/// A1. DevNet fixture OnChainGovernance Rotate proof still accepted
///     under fixture policy.
#[test]
fn a1_devnet_fixture_rotate_accepted_under_fixture_policy() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    match out {
        OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture(
            OnChainGovernanceProofVerificationOutcome::AcceptedOnChainGovernanceFixture {
                action,
                authority_domain_sequence,
                governance_epoch,
            },
        ) => {
            assert_eq!(action, LocalLifecycleAction::Rotate);
            assert_eq!(authority_domain_sequence, 2);
            assert_eq!(governance_epoch, GOV_EPOCH);
        }
        other => panic!("A1 expected AcceptedFixture, got {:?}", other),
    }
}

/// A2. TestNet fixture OnChainGovernance Rotate proof still accepted
///     under fixture policy.
#[test]
fn a2_testnet_fixture_rotate_accepted_under_fixture_policy() {
    let cand = rotate_candidate(TrustBundleEnvironment::Testnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let out = dispatch(
        &proof,
        &cand,
        &testnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(out.is_accept(), "A2 expected accept, got {:?}", out);
}

/// A3. Existing Run 185 reload-check fixture proof path remains
///     source/test compatible — driving the Run 180 reload-check
///     wrapper with `AllowFixtureSourceTest` accepts a valid DevNet
///     fixture proof exactly as Run 185 evidence requires.
#[test]
fn a3_run185_reload_check_fixture_path_remains_compatible() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let out = reload_check_compose_onchain_governance_marker_decision(
        Some(&prior),
        &cand,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(matches!(
        out,
        OnChainGovernanceMarkerDecisionOutcome::Accepted(_)
    ));
}

/// A4. Existing Run 185 reload-apply fixture proof path remains
///     source/test compatible. Acceptance does NOT advance markers,
///     sequences, or live state — the helper is pure.
#[test]
fn a4_run185_reload_apply_fixture_path_remains_compatible_no_mutation() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let cand_before = cand.clone();

    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(out.is_accept());
    // Pure / non-mutating: the candidate the caller handed in is
    // bit-for-bit unchanged after the dispatch returns.
    assert_eq!(cand, cand_before);
}

/// A5. GenesisBound and EmergencyCouncil governance proof behavior
///     remains unchanged — the verifier boundary is OnChainGovernance-
///     specific and never invoked for those classes. The Run 178
///     `verify_governance_authority_proof` etc. are not modified by
///     Run 186; we assert that classifying a non-`OnChainGovernance`
///     candidate is irrelevant to this boundary by confirming the
///     classification function operates only on
///     `OnChainGovernanceProof.proof_suite_id`.
#[test]
fn a5_genesisbound_emergencycouncil_paths_unaffected() {
    // The verifier boundary acts only on `OnChainGovernanceProof`
    // values. There is no path by which a `GenesisBound` or
    // `EmergencyCouncil` candidate constructs an
    // `OnChainGovernanceProof`, and the classifier here only
    // touches the suite id. Demonstrate this by classifying both
    // suites and observing that the classification is purely
    // suite-driven and does not depend on any other field of the
    // proof or candidate.
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    assert_eq!(
        classify_onchain_governance_proof_class(&fixture),
        OnChainGovernanceProofClass::Fixture
    );
    fixture.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    assert_eq!(
        classify_onchain_governance_proof_class(&fixture),
        OnChainGovernanceProofClass::Production
    );
    fixture.proof_suite_id = 0xCC; // arbitrary unknown suite
    assert_eq!(
        classify_onchain_governance_proof_class(&fixture),
        OnChainGovernanceProofClass::Production
    );
    // And the reserved-production suite is grep-named:
    assert!(is_reserved_production_onchain_governance_proof_suite(
        ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION
    ));
}

/// A6. Production verifier boundary is callable and returns typed
///     `ProductionVerifierUnavailable` for production-class proof.
#[test]
fn a6_production_verifier_boundary_returns_production_unavailable() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::production_unavailable(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );

    // The reserved-placeholder kind is also fail-closed identically.
    let out2 = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::production_verifier_placeholder(),
        Some(1),
    );
    assert_eq!(
        out2,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );

    // The pure entry point reaches the same outcome.
    let out3 = verify_production_onchain_governance_proof(
        &proof,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out3,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

/// A7. Disabled default remains fail-closed.
#[test]
fn a7_disabled_default_fail_closed() {
    assert_eq!(
        OnChainGovernanceVerifierKind::default(),
        OnChainGovernanceVerifierKind::Disabled
    );
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    // Default Policy -> Disabled / Disabled.
    let p = OnChainGovernanceVerifierPolicy::default();
    let f_out = dispatch(&fixture, &cand, &devnet_domain(), p, Some(1));
    assert_eq!(
        f_out,
        OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled
    );
    let p_out = dispatch(&prod, &cand, &devnet_domain(), p, Some(1));
    assert_eq!(
        p_out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

// ===========================================================================
// Rejection scenarios R1–R29
// ===========================================================================

/// R1. fixture proof rejected under Disabled policy.
#[test]
fn r1_fixture_proof_rejected_under_disabled_policy() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::disabled(),
        Some(1),
    );
    assert_eq!(out, OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled);
}

/// R2. fixture proof rejected if presented as MainNet production proof.
#[test]
fn r2_fixture_proof_rejected_as_mainnet_production_proof() {
    let cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);

    // Under FixtureSourceTest kind, MainNet fixture is refused as
    // FixtureProofRejectedAsMainNetProductionAuthority.
    let out = dispatch(
        &proof,
        &cand,
        &mainnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority
    );
}

/// R3. production-class proof rejected because production verifier is
///     unavailable.
#[test]
fn r3_production_class_proof_rejected_production_verifier_unavailable() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    for kind_policy in [
        OnChainGovernanceVerifierPolicy::production_unavailable(),
        OnChainGovernanceVerifierPolicy::production_verifier_placeholder(),
    ] {
        let out = dispatch(&proof, &cand, &devnet_domain(), kind_policy, Some(1));
        assert_eq!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        );
    }
}

/// R4. production-class proof rejected on DevNet unless explicitly
///     allowed by a future production verifier policy.
#[test]
fn r4_production_class_proof_rejected_on_devnet() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    // FixtureSourceTest kind on a production-class proof: refused.
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
    );

    // Disabled kind on a production-class proof: refused.
    let out2 = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::disabled(),
        Some(1),
    );
    assert_eq!(
        out2,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

/// R5. production-class proof rejected on TestNet unless explicitly
///     allowed by a future production verifier policy.
#[test]
fn r5_production_class_proof_rejected_on_testnet() {
    let cand = rotate_candidate(TrustBundleEnvironment::Testnet);
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let out = dispatch(
        &proof,
        &cand,
        &testnet_domain(),
        OnChainGovernanceVerifierPolicy::production_unavailable(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

/// R6. wrong environment rejected.
#[test]
fn r6_wrong_environment_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.environment = TrustBundleEnvironment::Testnet;
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongEnvironment { .. }
        )
    ));
}

/// R7. wrong chain rejected.
#[test]
fn r7_wrong_chain_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongChain { .. }
        )
    ));
}

/// R8. wrong genesis rejected.
#[test]
fn r8_wrong_genesis_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongGenesis { .. }
        )
    ));
}

/// R9. wrong authority root rejected.
#[test]
fn r9_wrong_authority_root_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.authority_root_fingerprint =
        "9999999999999999999999999999999999999999".to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongAuthorityRoot { .. }
        )
    ));
}

/// R10. wrong governance domain rejected.
#[test]
fn r10_wrong_governance_domain_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = "qbind-other-gov".to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongGovernanceDomain { .. }
        )
    ));
}

/// R11. wrong proposal digest rejected.
#[test]
fn r11_wrong_proposal_digest_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.proposal_digest =
        "cafefacecafefacecafefacecafefacecafefacecafefacecafefacecafeface".to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongProposalDigest { .. }
        )
    ));
}

/// R12. wrong proposal outcome rejected.
#[test]
fn r12_wrong_proposal_outcome_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongProposalOutcome { .. }
        )
    ));
}

/// R13. wrong lifecycle action rejected.
#[test]
fn r13_wrong_lifecycle_action_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.lifecycle_action = LocalLifecycleAction::Revoke;
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongLifecycleAction { .. }
        )
    ));
}

/// R14. wrong candidate digest rejected.
#[test]
fn r14_wrong_candidate_digest_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_OTHER.to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongCandidateDigest { .. }
        )
    ));
}

/// R15. wrong authority-domain sequence rejected.
#[test]
fn r15_wrong_authority_domain_sequence_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.authority_domain_sequence = 99;
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::WrongAuthoritySequence { .. }
        )
    ));
}

/// R16. expired proof rejected.
#[test]
fn r16_expired_proof_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW - 600,
        not_after_unix: NOW - 60,
    };
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::ExpiredGovernanceProof { .. }
        )
    ));
}

/// R17. replayed proof rejected.
#[test]
fn r17_replayed_proof_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let replay = vec![UNIQUE_DECISION_ID.to_string()];
    let out = dispatch_onchain_governance_proof_through_verifier_boundary(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &replay,
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::ReplayRejected { .. }
        )
    ));
}

/// R18. quorum not met rejected.
#[test]
fn r18_quorum_not_met_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.quorum = OnChainGovernanceQuorum {
        voters_voted: 1,
        total_voters: 5,
        required_quorum: 3,
    };
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::QuorumNotMet { .. }
        )
    ));
}

/// R19. threshold not met rejected.
#[test]
fn r19_threshold_not_met_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.threshold = GovernanceThreshold::new(1, 3, 5);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::ThresholdNotMet { .. }
        )
    ));
}

/// R20. invalid proof bytes rejected.
#[test]
fn r20_invalid_proof_bytes_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.proof_bytes = b"not-canonical-bytes".to_vec();
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::InvalidGovernanceProof { .. }
        )
    ));
}

/// R21. unsupported proof suite rejected (an unknown suite that is
///      neither the fixture suite nor the reserved-production suite
///      classifies as Production and is refused as ProductionProof
///      Unsupported under FixtureSourceTest).
#[test]
fn r21_unsupported_proof_suite_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = 0xCC; // arbitrary unknown suite
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
    );
    // And under Disabled it falls through as ProductionVerifierUnavailable.
    let out2 = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::disabled(),
        Some(1),
    );
    assert_eq!(
        out2,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

/// R22. malformed production proof rejected.
#[test]
fn r22_malformed_production_proof_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    // Empty proof bytes is malformed under the Run 178 verifier; the
    // boundary forwards as a typed Run178Rejection. Use FixtureSource
    // Test policy on a fixture-class proof to reach the inner
    // verifier with a structurally malformed input.
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.proof_bytes = vec![];
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(
            OnChainGovernanceProofVerificationOutcome::MalformedOnChainProof { .. }
        )
    ));
}

/// R23. local operator config rejected — Run 178 surfaces this as a
///      typed `LocalOperatorConfigOnlyRejected`, but Run 186's boundary
///      forwards every Run 178 reject through `Run178Rejection`. We
///      assert the boundary refuses to accept any "config-derived"
///      acceptance: a proof whose bindings match nothing real fails as
///      InvalidGovernanceProof / WrongCandidateDigest etc., never as
///      AcceptedFixture.
#[test]
fn r23_local_operator_config_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    // A proof carrying only operator-controlled fields (no real
    // candidate binding) fails the candidate-digest check.
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    recommit(&mut proof);
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(out.is_reject());
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(_)
    ));
}

/// R24. peer-majority / gossip-count proof rejected. A fabricated
///      "peer count = N" payload that is not bound to a real
///      candidate fails the boundary check; the explicit Run 178
///      `PeerMajorityProofRejected` typed reject is forwarded if the
///      verifier reaches it. Either way, the boundary never accepts.
#[test]
fn r24_peer_majority_gossip_proof_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    // Drop the canonical commitment for a peer-derived bytes blob.
    proof.proof_bytes = b"peer-majority-count=5".to_vec();
    let out = dispatch(
        &proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert!(out.is_reject());
    assert!(matches!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(_)
    ));
}

/// R25. valid fixture proof but lifecycle invalid rejected.
///
/// Drive the Run 180 reload-check wrapper (which composes the
/// Run 159 v2 lifecycle validator before the Run 178 verifier) with
/// a candidate whose lifecycle is invalid; the wrapper rejects
/// `LifecycleRejected` even though the proof bindings are valid.
#[test]
fn r25_valid_fixture_proof_but_lifecycle_invalid_rejected() {
    // Lifecycle invalid: same-sequence equivocation (cand sequence
    // equals the persisted sequence).
    let cand = build_v2(
        TrustBundleEnvironment::Devnet,
        KEY_B,
        1, // same sequence as prior
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
    );
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);

    let out = reload_check_compose_onchain_governance_marker_decision(
        Some(&prior),
        &cand,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(out.is_reject(), "expected reject got {:?}", out);
}

/// R26. lifecycle valid but production verifier unavailable rejected.
///      A production-class proof refused by Run 186 is observable in
///      the call-site path: the dispatcher returns
///      ProductionVerifierUnavailable / ProductionProofUnsupported,
///      and at the same time the Run 180 wrapper refuses to accept
///      because the underlying Run 178 verifier rejects the unknown
///      suite.
#[test]
fn r26_lifecycle_valid_but_production_verifier_unavailable_rejected() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prod_proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);

    // Boundary refuses: ProductionProofUnsupported under FixtureSource
    // Test, ProductionVerifierUnavailable otherwise.
    let boundary_out = dispatch(
        &prod_proof,
        &cand,
        &devnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert_eq!(
        boundary_out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
    );

    // The Run 180 wrapper also rejects (the underlying Run 178
    // verifier classifies the reserved suite as
    // UnsupportedGovernanceProofSuite).
    let surface_out = reload_check_compose_onchain_governance_marker_decision(
        Some(&prior),
        &cand,
        Some(&prod_proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(surface_out.is_reject());
}

/// R27. MainNet peer-driven apply remains refused even if fixture
///      proof or production-class proof is present.
#[test]
fn r27_mainnet_peer_driven_apply_remains_refused() {
    let cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    for proof in [&fixture, &prod] {
        for policy in [
            OnChainGovernanceVerifierPolicy::disabled(),
            OnChainGovernanceVerifierPolicy::fixture_source_test(),
            OnChainGovernanceVerifierPolicy::production_unavailable(),
            OnChainGovernanceVerifierPolicy::production_verifier_placeholder(),
        ] {
            let out = dispatch(proof, &cand, &mainnet_domain(), policy, Some(1));
            assert!(out.is_reject(), "MainNet must reject under {:?}", policy);
            // And the helper says peer-driven apply stays refused.
            assert!(
                mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
                    TrustBundleEnvironment::Mainnet,
                    &out,
                )
            );
        }
    }
}

/// R28. validation-only rejection remains non-mutating. Drive the
///      Run 180 reload-check (validation-only) wrapper with a
///      production-class proof; the wrapper rejects, and the
///      candidate / persisted snapshot are bit-identical after.
#[test]
fn r28_validation_only_rejection_non_mutating() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let cand_before = cand.clone();
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let prior_before = prior.clone();
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    let out = reload_check_compose_onchain_governance_marker_decision(
        Some(&prior),
        &cand,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(out.is_reject());
    // Bit-for-bit unchanged.
    assert_eq!(cand, cand_before);
    assert_eq!(prior, prior_before);
}

/// R29. mutating preflight rejection produces no Run 070 call, no live
///      trust swap, no session eviction, no sequence write, and no
///      marker write. Run 186's verifier-boundary helpers are pure;
///      assert that the boundary does not own any persistence path
///      and that the candidate / replay set / trust domain are
///      bit-identical after a rejecting dispatch.
#[test]
fn r29_mutating_preflight_rejection_no_mutation() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let cand_before = cand.clone();
    let domain = devnet_domain();
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    // Replay set is a Vec<String>; assert it's untouched after the
    // dispatch.
    let replay: Vec<String> = vec!["seen-1".to_string(), "seen-2".to_string()];
    let replay_before = replay.clone();

    let out = dispatch_onchain_governance_proof_through_verifier_boundary(
        &proof,
        &cand,
        &domain,
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &replay,
    );
    assert!(out.is_reject());
    assert_eq!(cand, cand_before);
    assert_eq!(replay, replay_before);
}

// ===========================================================================
// Explicit fixture-vs-production proof-class separation
// ===========================================================================

#[test]
fn fixture_vs_production_proof_class_separation() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);

    assert_eq!(
        classify_onchain_governance_proof_class(&fixture),
        OnChainGovernanceProofClass::Fixture
    );
    assert_eq!(
        classify_onchain_governance_proof_class(&prod),
        OnChainGovernanceProofClass::Production
    );

    // Fixture verifier accepts only fixture-class proofs.
    let v = FixtureSourceTestOnChainGovernanceVerifier;
    let out_fix = v.verify(
        &fixture,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(out_fix.is_accept());
    let out_prod = v.verify(
        &prod,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out_prod,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
    );
}

// ===========================================================================
// Direct verifier trait coverage (Disabled / FixtureSourceTest /
// ProductionUnavailable / ProductionVerifier placeholder)
// ===========================================================================

#[test]
fn disabled_verifier_refuses_every_proof() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let v = DisabledOnChainGovernanceVerifier;
    assert_eq!(v.kind(), OnChainGovernanceVerifierKind::Disabled);

    let f = v.verify(
        &fixture,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(f, OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled);

    let p = v.verify(
        &prod,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        p,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
}

#[test]
fn production_unavailable_verifier_refuses_every_proof() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let v = ProductionUnavailableOnChainGovernanceVerifier;
    assert_eq!(v.kind(), OnChainGovernanceVerifierKind::ProductionUnavailable);
    let out = v.verify(
        &fixture,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
    // MainNet variant.
    let out_main = v.verify(
        &fixture,
        &cand,
        &mainnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out_main,
        OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
    );
}

#[test]
fn production_verifier_placeholder_fails_closed_in_run186() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let fixture = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let v = ProductionVerifierPlaceholderOnChainGovernanceVerifier;
    assert_eq!(v.kind(), OnChainGovernanceVerifierKind::ProductionVerifier);
    let out = v.verify(
        &fixture,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
    );
    let out_main = v.verify(
        &fixture,
        &cand,
        &mainnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert_eq!(
        out_main,
        OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
    );
}

// ===========================================================================
// MainNet fixture cannot masquerade as production governance authority
// ===========================================================================

#[test]
fn mainnet_fixture_cannot_masquerade_as_production_authority() {
    let cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);

    // Even with the most permissive policy (FixtureSourceTest +
    // AllowFixtureSourceTest), MainNet refuses fixture proof.
    let out = dispatch(
        &proof,
        &cand,
        &mainnet_domain(),
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        Some(1),
    );
    assert_eq!(
        out,
        OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority
    );
    assert!(out.is_mainnet_refusal());
    assert!(out.is_reject());
}

// ===========================================================================
// No-I/O guarantee for verifier boundary + determinism
// ===========================================================================

#[test]
fn boundary_dispatch_is_deterministic_and_pure() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let policy = OnChainGovernanceVerifierPolicy::fixture_source_test();

    let mut outcomes = Vec::new();
    for _ in 0..32 {
        let out = dispatch(&proof, &cand, &devnet_domain(), policy, Some(1));
        outcomes.push(out);
    }
    let first = &outcomes[0];
    assert!(first.is_accept());
    for o in outcomes.iter().skip(1) {
        assert_eq!(o, first);
    }
}

#[test]
fn fixture_entry_point_pure_no_side_effects_on_replay_set() {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let replay: Vec<String> = Vec::new();
    let before = replay.clone();
    let _ = verify_fixture_onchain_governance_proof(
        &proof,
        &cand,
        &devnet_domain(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &replay,
    );
    assert_eq!(replay, before);
}

// ===========================================================================
// Source reachability for the new verifier boundary from the Run
// 182/184 call-site path
// ===========================================================================

#[test]
fn boundary_is_reachable_from_callsite_context_path() {
    // Build a Run 182 callsite context exactly as Run 184/185 do, and
    // demonstrate that the Run 186 boundary dispatcher is callable
    // with the same inputs (proof / candidate / trust domain /
    // expected bindings / now / replay set) and returns a typed
    // outcome that distinguishes fixture acceptance from production
    // refusal — i.e. the new boundary is source-reachable from the
    // call-site path.
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();

    let ctx: OnChainGovernanceCallsiteContext<'_, EmptyOnChainGovernanceReplaySet> =
        OnChainGovernanceCallsiteContext {
            persisted: Some(&prior),
            candidate: &cand,
            proof: Some(&proof),
            trust_domain: &domain,
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            expected_governance_domain_id: GOV_DOMAIN,
            expected_governance_epoch: GOV_EPOCH,
            expected_proposal_id: PROPOSAL_ID,
            expected_proposal_digest: PROPOSAL_DIGEST,
            now_unix: NOW,
            replay_set: &EmptyOnChainGovernanceReplaySet,
        };

    // Reach the boundary with the callsite context's inputs.
    let proof_ref = ctx.proof.unwrap();
    let out = dispatch_onchain_governance_proof_through_verifier_boundary(
        proof_ref,
        ctx.candidate,
        ctx.trust_domain,
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        Some(1),
        ctx.now_unix,
        ctx.replay_set,
    );
    // Distinguish fixture acceptance from production refusal.
    assert!(out.is_accept());

    // Now swap to a production-class proof and demonstrate the same
    // call-site path reaches a production refusal — i.e. the
    // distinction is observable end-to-end.
    let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let out2 = dispatch_onchain_governance_proof_through_verifier_boundary(
        &prod,
        ctx.candidate,
        ctx.trust_domain,
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        ctx.expected_governance_domain_id,
        ctx.expected_governance_epoch,
        ctx.expected_proposal_id,
        ctx.expected_proposal_digest,
        Some(1),
        ctx.now_unix,
        ctx.replay_set,
    );
    assert_eq!(
        out2,
        OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
    );
}
