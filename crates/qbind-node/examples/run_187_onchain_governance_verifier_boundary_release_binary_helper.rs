//! Run 187 — release-built helper that exercises the Run 186
//! production OnChainGovernance verifier-boundary corpus end-to-end
//! **in release mode** through the production library symbols
//! [`qbind_node::pqc_onchain_governance_verifier`], with the Run 178
//! typed verifier and the Run 180 per-surface composed wrapper as
//! the underlying acceptance / rejection boundary for fixture-class
//! proofs.
//!
//! Per `task/RUN_187_TASK.txt`, Run 187 is a **release-binary
//! evidence / boundary** run for the Run 186 source/test typed
//! production verifier boundary. This helper is fixture-tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema, or any reachable production caller of
//!   `verify_onchain_governance_proof` or
//!   `dispatch_onchain_governance_proof_through_verifier_boundary`
//!   beyond what Run 178 / 180 / 182 / 184 / 185 / 186 already
//!   established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state;
//! * does NOT open a P2P socket;
//! * never elevates a fixture acceptance into a MainNet apply
//!   (MainNet always refuses fixture proof as
//!   `FixtureProofRejectedAsMainNetProductionAuthority` and refuses
//!   production-class proof as `MainNetProductionVerifierUnavailable`);
//! * exists alongside (and does NOT replace) the Run 186 source/test
//!   target
//!   `crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected>\t<match>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable expected map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps
//! <OUT_DIR>/scenarios/<id>/policy.txt
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/scenarios/<id>/note.txt
//! <OUT_DIR>/proof_class_table.txt     # fixture vs production classifier evidence
//! <OUT_DIR>/verifier_kinds_table.txt  # 4 verifier traits exercised explicitly
//! <OUT_DIR>/no_mutation_evidence.txt  # bit-equality of inputs across reject scenarios
//! <OUT_DIR>/helper_summary.txt        # release-built helper verdict
//! ```
//!
//! The helper exits non-zero if any scenario does not match its
//! expected typed outcome, mirroring the Run 168 / Run 178 / Run 179 /
//! Run 185 release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_187_onchain_governance_verifier_boundary_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProofVerificationOutcome, OnChainGovernanceProposalOutcome,
    OnChainGovernanceQuorum, ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
};
use qbind_node::pqc_onchain_governance_proof_surface::{
    reload_apply_compose_onchain_governance_marker_decision,
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

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 186 test target so the
// typed verifier-boundary semantics carry over end-to-end in release mode.
// ---------------------------------------------------------------------------

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
const UNIQUE_DECISION_ID: &str = "decision-187";
const NOW: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror `tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
// ---------------------------------------------------------------------------

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
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
    trust_domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceVerifierPolicy,
    persisted_seq: Option<u64>,
) -> OnChainGovernanceVerifierBoundaryOutcome {
    dispatch_onchain_governance_proof_through_verifier_boundary(
        proof,
        candidate,
        trust_domain,
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

// ---------------------------------------------------------------------------
// Expected outcome — one symbolic label per typed boundary outcome, plus
// labels for the Run 180 reload-check / reload-apply marker-decision wrapper
// surface that Run 185 fixture-paths are reused on.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    AcceptedFixture,
    FixtureDisabled,
    ProductionVerifierUnavailable,
    ProductionProofUnsupported,
    MainNetProductionVerifierUnavailable,
    FixtureProofRejectedAsMainNetProductionAuthority,
    Run178Rejection,
    /// Run 180 reload-check / reload-apply wrapper surface accept.
    SurfaceAccept,
    /// Run 180 reload-check / reload-apply wrapper surface reject.
    SurfaceReject,
}

impl Expect {
    fn label(&self) -> &'static str {
        match self {
            Expect::AcceptedFixture => "accepted_fixture",
            Expect::FixtureDisabled => "fixture_disabled",
            Expect::ProductionVerifierUnavailable => "production_verifier_unavailable",
            Expect::ProductionProofUnsupported => "production_proof_unsupported",
            Expect::MainNetProductionVerifierUnavailable => {
                "mainnet_production_verifier_unavailable"
            }
            Expect::FixtureProofRejectedAsMainNetProductionAuthority => {
                "fixture_proof_rejected_as_mainnet_production_authority"
            }
            Expect::Run178Rejection => "run178_rejection",
            Expect::SurfaceAccept => "surface_accept",
            Expect::SurfaceReject => "surface_reject",
        }
    }

    fn matches_boundary(&self, outcome: &OnChainGovernanceVerifierBoundaryOutcome) -> bool {
        match (self, outcome) {
            (Expect::AcceptedFixture, OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture(_)) => true,
            (Expect::FixtureDisabled, OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled) => true,
            (
                Expect::ProductionVerifierUnavailable,
                OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable,
            ) => true,
            (
                Expect::ProductionProofUnsupported,
                OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported,
            ) => true,
            (
                Expect::MainNetProductionVerifierUnavailable,
                OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable,
            ) => true,
            (
                Expect::FixtureProofRejectedAsMainNetProductionAuthority,
                OnChainGovernanceVerifierBoundaryOutcome::FixtureProofRejectedAsMainNetProductionAuthority,
            ) => true,
            (Expect::Run178Rejection, OnChainGovernanceVerifierBoundaryOutcome::Run178Rejection(_)) => true,
            _ => false,
        }
    }

    fn matches_surface(&self, outcome: &OnChainGovernanceMarkerDecisionOutcome) -> bool {
        match self {
            Expect::SurfaceAccept => outcome.is_accept(),
            Expect::SurfaceReject => outcome.is_reject(),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Boundary scenario record (driven through the Run 186 dispatcher).
// ---------------------------------------------------------------------------

struct BoundaryScenario {
    id: String,
    note: String,
    proof: OnChainGovernanceProof,
    candidate: PersistentAuthorityStateRecordV2,
    trust_domain: AuthorityTrustDomain,
    policy: OnChainGovernanceVerifierPolicy,
    /// Some(replay_set_decisions) overrides the default empty replay set
    /// for the dispatcher invocation.
    replay_seen: Option<Vec<String>>,
    expect: Expect,
}

fn run_boundary_scenarios(
    out_dir: &Path,
    manifest: &mut String,
    expected: &mut String,
    actual: &mut String,
) -> std::io::Result<(usize, usize)> {
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;

    let mut pass = 0usize;
    let mut fail = 0usize;

    let mut scenarios: Vec<BoundaryScenario> = Vec::new();

    // ---------------- Acceptance scenarios A1..A8 (boundary surface)
    {
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A1_devnet_fixture_rotate_accepted_under_fixture_policy".into(),
            note: "DevNet FixtureSourceTest + valid Rotate fixture proof -> AcceptedFixture".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::AcceptedFixture,
        });
    }
    {
        let cand = rotate_candidate(TrustBundleEnvironment::Testnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A2_testnet_fixture_rotate_accepted_under_fixture_policy".into(),
            note: "TestNet FixtureSourceTest + valid Rotate fixture proof -> AcceptedFixture".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Testnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::AcceptedFixture,
        });
    }
    {
        // A6 -- callable production-unavailable kind on a production-class proof
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A6_production_unavailable_kind_returns_production_unavailable".into(),
            note: "DevNet ProductionUnavailable kind + production-class proof -> ProductionVerifierUnavailable".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::production_unavailable(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }
    {
        // A6b -- placeholder kind also fails closed identically
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A6b_production_verifier_placeholder_returns_production_unavailable".into(),
            note: "DevNet ProductionVerifierPlaceholder + production-class proof -> ProductionVerifierUnavailable".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::production_verifier_placeholder(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }
    {
        // A8 -- Disabled default fixture-class -> FixtureDisabled
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A8_disabled_default_fixture_class_fixture_disabled".into(),
            note: "Default Disabled policy + fixture proof -> FixtureDisabled (no Run 178 invoked)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::default(),
            replay_seen: None,
            expect: Expect::FixtureDisabled,
        });
    }
    {
        // A8b -- Disabled default production-class -> ProductionVerifierUnavailable
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "A8b_disabled_default_production_class_production_unavailable".into(),
            note: "Default Disabled policy + production-class proof -> ProductionVerifierUnavailable"
                .into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::default(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }

    // ---------------- Rejection scenarios R1..R29 (boundary surface)
    {
        // R1
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R1_fixture_proof_rejected_under_disabled_policy".into(),
            note: "Disabled policy + fixture proof -> FixtureDisabled".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::disabled(),
            replay_seen: None,
            expect: Expect::FixtureDisabled,
        });
    }
    {
        // R2 — fixture proof presented as MainNet -> typed mainnet refusal
        let cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R2_fixture_proof_rejected_as_mainnet_production_proof".into(),
            note: "MainNet FixtureSourceTest + valid Mainnet fixture proof -> FixtureProofRejectedAsMainNetProductionAuthority".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Mainnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::FixtureProofRejectedAsMainNetProductionAuthority,
        });
    }
    {
        // R3 — production-class rejected because production verifier unavailable
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R3_production_class_rejected_production_unavailable".into(),
            note: "DevNet ProductionUnavailable + production-class proof -> ProductionVerifierUnavailable".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::production_unavailable(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }
    {
        // R4 — production-class rejected on DevNet under FixtureSourceTest -> Unsupported
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R4_production_class_rejected_on_devnet_under_fixture_kind_unsupported".into(),
            note: "DevNet FixtureSourceTest + production-class proof -> ProductionProofUnsupported".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::ProductionProofUnsupported,
        });
    }
    {
        // R5 — production-class rejected on TestNet under ProductionUnavailable
        let cand = rotate_candidate(TrustBundleEnvironment::Testnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R5_production_class_rejected_on_testnet_under_production_unavailable".into(),
            note: "TestNet ProductionUnavailable + production-class proof -> ProductionVerifierUnavailable".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Testnet),
            policy: OnChainGovernanceVerifierPolicy::production_unavailable(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }
    {
        // R6 — wrong environment forwarded as Run178 reject
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.environment = TrustBundleEnvironment::Testnet;
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R6_wrong_environment_rejected".into(),
            note: "DevNet candidate + TestNet-environment proof -> Run178Rejection(WrongEnvironment)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R7 — wrong chain
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.chain_id = OTHER_CHAIN.to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R7_wrong_chain_rejected".into(),
            note: "DevNet + foreign chain_id -> Run178Rejection(WrongChain)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R8 — wrong genesis
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.genesis_hash = GENESIS_HASH_B.to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R8_wrong_genesis_rejected".into(),
            note: "DevNet + foreign genesis_hash -> Run178Rejection(WrongGenesis)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R9 — wrong authority root
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.authority_root_fingerprint = "9999999999999999999999999999999999999999".to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R9_wrong_authority_root_rejected".into(),
            note: "DevNet + foreign authority_root_fingerprint -> Run178Rejection(WrongAuthorityRoot)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R10 — wrong governance domain
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.governance_domain_id = "qbind-other-gov".to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R10_wrong_governance_domain_rejected".into(),
            note: "DevNet + foreign governance_domain_id -> Run178Rejection(WrongGovernanceDomain)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R11 — wrong proposal digest
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proposal_digest =
            "cafefacecafefacecafefacecafefacecafefacecafefacecafefacecafeface".to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R11_wrong_proposal_digest_rejected".into(),
            note: "DevNet + foreign proposal_digest -> Run178Rejection(WrongProposalDigest)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R12 — wrong proposal outcome
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
        scenarios.push(BoundaryScenario {
            id: "R12_wrong_proposal_outcome_rejected".into(),
            note: "DevNet + Rejected proposal_outcome -> Run178Rejection(WrongProposalOutcome)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R13 — wrong lifecycle action
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.lifecycle_action = LocalLifecycleAction::Revoke;
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R13_wrong_lifecycle_action_rejected".into(),
            note: "DevNet + Revoke lifecycle_action against Rotate candidate -> Run178Rejection(WrongLifecycleAction)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R14 — wrong candidate digest
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.candidate_v2_digest = DIGEST_OTHER.to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R14_wrong_candidate_digest_rejected".into(),
            note: "DevNet + foreign candidate_v2_digest -> Run178Rejection(WrongCandidateDigest)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R15 — wrong authority-domain sequence
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.authority_domain_sequence = 99;
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R15_wrong_authority_domain_sequence_rejected".into(),
            note: "DevNet + sequence=99 -> Run178Rejection(WrongAuthoritySequence)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R16 — expired proof
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.freshness = OnChainGovernanceFreshnessWindow {
            not_before_unix: NOW - 600,
            not_after_unix: NOW - 60,
        };
        scenarios.push(BoundaryScenario {
            id: "R16_expired_proof_rejected".into(),
            note: "DevNet + freshness window in the past -> Run178Rejection(ExpiredGovernanceProof)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R17 — replayed proof
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(BoundaryScenario {
            id: "R17_replayed_proof_rejected".into(),
            note: "DevNet + replay-set already containing unique_decision_id -> Run178Rejection(ReplayRejected)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: Some(vec![UNIQUE_DECISION_ID.to_string()]),
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R18 — quorum not met
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.quorum = OnChainGovernanceQuorum {
            voters_voted: 1,
            total_voters: 5,
            required_quorum: 3,
        };
        scenarios.push(BoundaryScenario {
            id: "R18_quorum_not_met_rejected".into(),
            note: "DevNet + quorum 1/3 -> Run178Rejection(QuorumNotMet)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R19 — threshold not met
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.threshold = GovernanceThreshold::new(1, 3, 5);
        scenarios.push(BoundaryScenario {
            id: "R19_threshold_not_met_rejected".into(),
            note: "DevNet + threshold 1/3 -> Run178Rejection(ThresholdNotMet)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R20 — invalid proof bytes
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proof_bytes = b"not-canonical-bytes".to_vec();
        scenarios.push(BoundaryScenario {
            id: "R20_invalid_proof_bytes_rejected".into(),
            note: "DevNet + non-canonical proof_bytes -> Run178Rejection(InvalidGovernanceProof)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R21 — unsupported proof suite under FixtureSourceTest -> Unsupported
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proof_suite_id = 0xCC;
        scenarios.push(BoundaryScenario {
            id: "R21_unsupported_proof_suite_rejected_under_fixture_kind".into(),
            note: "DevNet FixtureSourceTest + unknown suite 0xCC -> ProductionProofUnsupported (classified as Production)".into(),
            proof: proof.clone(),
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::ProductionProofUnsupported,
        });
        scenarios.push(BoundaryScenario {
            id: "R21b_unsupported_proof_suite_rejected_under_disabled".into(),
            note: "DevNet Disabled + unknown suite 0xCC -> ProductionVerifierUnavailable".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::disabled(),
            replay_seen: None,
            expect: Expect::ProductionVerifierUnavailable,
        });
    }
    {
        // R22 — malformed production proof (empty proof bytes)
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proof_bytes = vec![];
        scenarios.push(BoundaryScenario {
            id: "R22_malformed_production_proof_rejected".into(),
            note: "DevNet FixtureSourceTest + empty proof_bytes -> Run178Rejection(MalformedOnChainProof)".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R23 — local operator config rejected (zero candidate digest)
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.candidate_v2_digest =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        recommit(&mut proof);
        scenarios.push(BoundaryScenario {
            id: "R23_local_operator_config_rejected".into(),
            note: "DevNet + zero candidate_v2_digest (operator-config-only fabrication) -> Run178Rejection".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R24 — peer-majority / gossip-count proof rejected
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let mut proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        proof.proof_bytes = b"peer-majority-count=5".to_vec();
        scenarios.push(BoundaryScenario {
            id: "R24_peer_majority_gossip_proof_rejected".into(),
            note: "DevNet + peer-majority bytes blob -> Run178Rejection".into(),
            proof,
            candidate: cand.clone(),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceVerifierPolicy::fixture_source_test(),
            replay_seen: None,
            expect: Expect::Run178Rejection,
        });
    }
    {
        // R27 — MainNet refusal across every policy + every proof class
        let cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
        let fix = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        let prod = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        let policies = [
            ("disabled", OnChainGovernanceVerifierPolicy::disabled()),
            (
                "fixture_source_test",
                OnChainGovernanceVerifierPolicy::fixture_source_test(),
            ),
            (
                "production_unavailable",
                OnChainGovernanceVerifierPolicy::production_unavailable(),
            ),
            (
                "production_verifier_placeholder",
                OnChainGovernanceVerifierPolicy::production_verifier_placeholder(),
            ),
        ];
        for (label, p) in policies {
            // Fixture proof
            let exp_fix = match p.kind {
                OnChainGovernanceVerifierKind::Disabled => Expect::FixtureDisabled,
                OnChainGovernanceVerifierKind::FixtureSourceTest => {
                    Expect::FixtureProofRejectedAsMainNetProductionAuthority
                }
                // ProductionUnavailable / ProductionVerifierPlaceholder route a
                // fixture-class proof through `verify_production_onchain_governance_proof`,
                // which short-circuits on the proof class before the MainNet
                // environment check, returning `ProductionProofUnsupported`.
                _ => Expect::ProductionProofUnsupported,
            };
            scenarios.push(BoundaryScenario {
                id: format!("R27_mainnet_refusal_{}_fixture_proof", label),
                note: format!(
                    "MainNet {} + valid fixture proof -> {}",
                    label,
                    exp_fix.label()
                ),
                proof: fix.clone(),
                candidate: cand.clone(),
                trust_domain: domain(TrustBundleEnvironment::Mainnet),
                policy: p,
                replay_seen: None,
                expect: exp_fix,
            });
            // Production proof
            let exp_prod = match p.kind {
                OnChainGovernanceVerifierKind::Disabled => Expect::ProductionVerifierUnavailable,
                OnChainGovernanceVerifierKind::FixtureSourceTest => {
                    Expect::ProductionProofUnsupported
                }
                _ => Expect::MainNetProductionVerifierUnavailable,
            };
            scenarios.push(BoundaryScenario {
                id: format!("R27_mainnet_refusal_{}_production_proof", label),
                note: format!(
                    "MainNet {} + production-class proof -> {}",
                    label,
                    exp_prod.label()
                ),
                proof: prod.clone(),
                candidate: cand.clone(),
                trust_domain: domain(TrustBundleEnvironment::Mainnet),
                policy: p,
                replay_seen: None,
                expect: exp_prod,
            });
        }
    }

    // Run every boundary scenario through the dispatcher and capture
    // the typed outcome.
    for s in &scenarios {
        let scenario_dir = scenarios_dir.join(&s.id);
        fs::create_dir_all(&scenario_dir)?;

        let outcome = match &s.replay_seen {
            None => dispatch(&s.proof, &s.candidate, &s.trust_domain, s.policy, Some(1)),
            Some(seen) => dispatch_onchain_governance_proof_through_verifier_boundary(
                &s.proof,
                &s.candidate,
                &s.trust_domain,
                s.policy,
                GOV_DOMAIN,
                GOV_EPOCH,
                PROPOSAL_ID,
                PROPOSAL_DIGEST,
                Some(1),
                NOW,
                seen,
            ),
        };

        fs::write(scenario_dir.join("note.txt"), format!("{}\n", s.note))?;
        fs::write(scenario_dir.join("policy.txt"), format!("{:?}\n", s.policy))?;
        fs::write(scenario_dir.join("expected.txt"), format!("{}\n", s.expect.label()))?;
        let actual_dump = format!("{:?}\n", outcome);
        fs::write(scenario_dir.join("actual.txt"), &actual_dump)?;

        let matched = s.expect.matches_boundary(&outcome);
        manifest.push_str(&format!(
            "{}\texpect={}\tactual_match={}\n",
            s.id,
            s.expect.label(),
            matched
        ));
        expected.push_str(&format!("{}\t{}\n", s.id, s.expect.label()));
        actual.push_str(&format!("{}\t{:?}\n", s.id, outcome));
        if matched {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-187-helper] FAIL boundary scenario {} expected {} got {:?}",
                s.id,
                s.expect.label(),
                outcome
            );
        }
    }

    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Run 185 reload-check / reload-apply fixture-path compatibility scenarios.
// These exercise the Run 180 per-surface composed wrappers (which Run 186
// does NOT modify) with the same fixture proofs used above so the Run 185
// accepted-proof boundary remains compatible with Run 186 source/test.
// ---------------------------------------------------------------------------

struct SurfaceScenario {
    id: String,
    note: String,
    proof: Option<OnChainGovernanceProof>,
    candidate: PersistentAuthorityStateRecordV2,
    persisted: PersistentAuthorityStateRecordVersioned,
    trust_domain: AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    surface: &'static str, // "reload_check" | "reload_apply"
    expect: Expect,
}

fn run_surface_scenarios(
    out_dir: &Path,
    manifest: &mut String,
    expected: &mut String,
    actual: &mut String,
) -> std::io::Result<(usize, usize)> {
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut scenarios: Vec<SurfaceScenario> = Vec::new();

    {
        // A3 reload-check fixture path remains compatible
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(SurfaceScenario {
            id: "A3_reload_check_fixture_path_compat".into(),
            note: "Run 185 reload-check fixture path remains accepted under Run 180 wrapper (Run 186 unchanged)".into(),
            proof: Some(proof),
            candidate: cand.clone(),
            persisted: prior_versioned(TrustBundleEnvironment::Devnet),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            surface: "reload_check",
            expect: Expect::SurfaceAccept,
        });
    }
    {
        // A4 reload-apply fixture path remains compatible
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(SurfaceScenario {
            id: "A4_reload_apply_fixture_path_compat".into(),
            note: "Run 185 reload-apply fixture path remains accepted under Run 180 wrapper".into(),
            proof: Some(proof),
            candidate: cand.clone(),
            persisted: prior_versioned(TrustBundleEnvironment::Devnet),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            surface: "reload_apply",
            expect: Expect::SurfaceAccept,
        });
    }
    {
        // R25 — fixture proof valid but lifecycle invalid (same-sequence equivocation)
        let cand = build_v2(
            TrustBundleEnvironment::Devnet,
            KEY_B,
            1, // same sequence as prior
            BundleSigningRatificationV2Action::Rotate,
            Some(KEY_A),
            DIGEST_2,
        );
        let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(SurfaceScenario {
            id: "R25_valid_fixture_proof_but_lifecycle_invalid_rejected".into(),
            note: "Run 180 reload-check rejects when lifecycle invalid (same-sequence) regardless of valid fixture proof".into(),
            proof: Some(proof),
            candidate: cand.clone(),
            persisted: prior_versioned(TrustBundleEnvironment::Devnet),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            surface: "reload_check",
            expect: Expect::SurfaceReject,
        });
    }
    {
        // R26 — lifecycle valid but production verifier unavailable rejected
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(SurfaceScenario {
            id: "R26_lifecycle_valid_production_verifier_unavailable_rejected".into(),
            note: "Run 180 reload-check rejects production-class (reserved) proof; underlying verifier classifies as UnsupportedGovernanceProofSuite".into(),
            proof: Some(proof),
            candidate: cand.clone(),
            persisted: prior_versioned(TrustBundleEnvironment::Devnet),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            surface: "reload_check",
            expect: Expect::SurfaceReject,
        });
    }
    {
        // R28 validation-only rejection non-mutating: production-class proof
        let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
        let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
        scenarios.push(SurfaceScenario {
            id: "R28_validation_only_rejection_non_mutating".into(),
            note: "Reload-check (validation-only) rejects production-class proof; candidate / persisted bit-equal after".into(),
            proof: Some(proof),
            candidate: cand.clone(),
            persisted: prior_versioned(TrustBundleEnvironment::Devnet),
            trust_domain: domain(TrustBundleEnvironment::Devnet),
            policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            surface: "reload_check",
            expect: Expect::SurfaceReject,
        });
    }

    for s in &scenarios {
        let scenario_dir = scenarios_dir.join(&s.id);
        fs::create_dir_all(&scenario_dir)?;
        // Snapshot inputs to assert non-mutation post-call.
        let cand_before = s.candidate.clone();
        let prior_before = s.persisted.clone();

        let outcome = match s.surface {
            "reload_check" => reload_check_compose_onchain_governance_marker_decision(
                Some(&s.persisted),
                &s.candidate,
                s.proof.as_ref(),
                &s.trust_domain,
                s.policy,
                GOV_DOMAIN,
                GOV_EPOCH,
                PROPOSAL_ID,
                PROPOSAL_DIGEST,
                NOW,
                &EmptyOnChainGovernanceReplaySet,
            ),
            "reload_apply" => reload_apply_compose_onchain_governance_marker_decision(
                Some(&s.persisted),
                &s.candidate,
                s.proof.as_ref(),
                &s.trust_domain,
                s.policy,
                GOV_DOMAIN,
                GOV_EPOCH,
                PROPOSAL_ID,
                PROPOSAL_DIGEST,
                NOW,
                &EmptyOnChainGovernanceReplaySet,
            ),
            other => panic!("unknown surface: {}", other),
        };

        fs::write(scenario_dir.join("note.txt"), format!("{}\n", s.note))?;
        fs::write(
            scenario_dir.join("policy.txt"),
            format!(
                "surface={} policy={:?}\n",
                s.surface, s.policy
            ),
        )?;
        fs::write(scenario_dir.join("expected.txt"), format!("{}\n", s.expect.label()))?;
        let actual_dump = format!("{:?}\n", outcome);
        fs::write(scenario_dir.join("actual.txt"), &actual_dump)?;

        let mut matched = s.expect.matches_surface(&outcome);
        // Non-mutation invariant for surface scenarios.
        let no_mut = s.candidate == cand_before && s.persisted == prior_before;
        if !no_mut {
            matched = false;
            eprintln!(
                "[run-187-helper] FAIL surface scenario {} mutated inputs",
                s.id
            );
        }

        manifest.push_str(&format!(
            "{}\texpect={}\tactual_match={}\tno_mutation={}\n",
            s.id,
            s.expect.label(),
            matched,
            no_mut
        ));
        expected.push_str(&format!("{}\t{}\n", s.id, s.expect.label()));
        actual.push_str(&format!("{}\t{:?}\n", s.id, outcome));
        if matched {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-187-helper] FAIL surface scenario {} expected {} got {:?}",
                s.id,
                s.expect.label(),
                outcome
            );
        }
    }

    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Direct verifier-trait coverage — one row per concrete verifier impl.
// Records that all four Run 186 traits are reachable in release mode and
// produce the typed outcomes the Run 186 corpus declares.
// ---------------------------------------------------------------------------

fn run_verifier_kinds_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;

    let cand_dev = rotate_candidate(TrustBundleEnvironment::Devnet);
    let cand_main = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let fixture_dev = good_fixture_proof(&cand_dev, LocalLifecycleAction::Rotate);
    let prod_dev = production_class_proof(&cand_dev, LocalLifecycleAction::Rotate);
    let dev_dom = domain(TrustBundleEnvironment::Devnet);
    let main_dom = domain(TrustBundleEnvironment::Mainnet);

    let mut record = |label: &str, expected: &str, got: String, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-187-helper] FAIL kind row {} expected {} got {}",
                label, expected, got
            );
        }
        buf.push_str(&format!(
            "{}\texpected={}\tgot={}\tok={}\n",
            label, expected, got, ok
        ));
    };

    // Disabled
    let v = DisabledOnChainGovernanceVerifier;
    let kind_ok = v.kind() == OnChainGovernanceVerifierKind::Disabled;
    let f = v.verify(
        &fixture_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "DisabledOnChainGovernanceVerifier::kind",
        "Disabled",
        format!("{:?}", v.kind()),
        kind_ok,
    );
    record(
        "DisabledOnChainGovernanceVerifier::verify(fixture_dev)",
        "FixtureDisabled",
        format!("{:?}", f),
        matches!(f, OnChainGovernanceVerifierBoundaryOutcome::FixtureDisabled),
    );
    let p = v.verify(
        &prod_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "DisabledOnChainGovernanceVerifier::verify(prod_dev)",
        "ProductionVerifierUnavailable",
        format!("{:?}", p),
        matches!(
            p,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        ),
    );

    // FixtureSourceTest
    let v = FixtureSourceTestOnChainGovernanceVerifier;
    record(
        "FixtureSourceTestOnChainGovernanceVerifier::kind",
        "FixtureSourceTest",
        format!("{:?}", v.kind()),
        v.kind() == OnChainGovernanceVerifierKind::FixtureSourceTest,
    );
    let out = v.verify(
        &fixture_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "FixtureSourceTestOnChainGovernanceVerifier::verify(fixture_dev)",
        "AcceptedFixture",
        format!("{:?}", out),
        out.is_accept(),
    );
    let out = v.verify(
        &prod_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "FixtureSourceTestOnChainGovernanceVerifier::verify(prod_dev)",
        "ProductionProofUnsupported",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionProofUnsupported
        ),
    );

    // ProductionUnavailable
    let v = ProductionUnavailableOnChainGovernanceVerifier;
    record(
        "ProductionUnavailableOnChainGovernanceVerifier::kind",
        "ProductionUnavailable",
        format!("{:?}", v.kind()),
        v.kind() == OnChainGovernanceVerifierKind::ProductionUnavailable,
    );
    let out = v.verify(
        &fixture_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "ProductionUnavailableOnChainGovernanceVerifier::verify(fixture_dev)",
        "ProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        ),
    );
    let out = v.verify(
        &fixture_dev,
        &cand_main,
        &main_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "ProductionUnavailableOnChainGovernanceVerifier::verify(mainnet)",
        "MainNetProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
        ),
    );

    // ProductionVerifierPlaceholder
    let v = ProductionVerifierPlaceholderOnChainGovernanceVerifier;
    record(
        "ProductionVerifierPlaceholderOnChainGovernanceVerifier::kind",
        "ProductionVerifier",
        format!("{:?}", v.kind()),
        v.kind() == OnChainGovernanceVerifierKind::ProductionVerifier,
    );
    let out = v.verify(
        &fixture_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "ProductionVerifierPlaceholderOnChainGovernanceVerifier::verify(devnet)",
        "ProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        ),
    );
    let out = v.verify(
        &fixture_dev,
        &cand_main,
        &main_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "ProductionVerifierPlaceholderOnChainGovernanceVerifier::verify(mainnet)",
        "MainNetProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
        ),
    );

    // Pure typed entry points
    let out = verify_fixture_onchain_governance_proof(
        &fixture_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "verify_fixture_onchain_governance_proof(devnet,fixture)",
        "AcceptedFixture",
        format!("{:?}", out),
        out.is_accept(),
    );
    let out = verify_production_onchain_governance_proof(
        &prod_dev,
        &cand_dev,
        &dev_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "verify_production_onchain_governance_proof(devnet,production)",
        "ProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable
        ),
    );
    let out = verify_production_onchain_governance_proof(
        &prod_dev,
        &cand_main,
        &main_dom,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    record(
        "verify_production_onchain_governance_proof(mainnet,production)",
        "MainNetProductionVerifierUnavailable",
        format!("{:?}", out),
        matches!(
            out,
            OnChainGovernanceVerifierBoundaryOutcome::MainNetProductionVerifierUnavailable
        ),
    );

    // MainNet-refusal helper.
    let dummy = OnChainGovernanceVerifierBoundaryOutcome::ProductionVerifierUnavailable;
    let mn = mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
        TrustBundleEnvironment::Mainnet,
        &dummy,
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(MainNet)",
        "true",
        format!("{}", mn),
        mn,
    );
    let dn = mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(
        TrustBundleEnvironment::Devnet,
        &dummy,
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_verifier_boundary(DevNet)",
        "false",
        format!("{}", dn),
        !dn,
    );

    fs::write(out_dir.join("verifier_kinds_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Proof-class classifier table.
// ---------------------------------------------------------------------------

fn run_proof_class_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;

    let mut record = |label: &str, expected: &str, got: String, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-187-helper] FAIL classifier row {} expected {} got {}",
                label, expected, got
            );
        }
        buf.push_str(&format!(
            "{}\texpected={}\tgot={}\tok={}\n",
            label, expected, got, ok
        ));
    };

    let mut p = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let cls = classify_onchain_governance_proof_class(&p);
    record(
        "fixture_suite",
        "Fixture",
        format!("{:?}", cls),
        cls == OnChainGovernanceProofClass::Fixture,
    );

    p.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    let cls = classify_onchain_governance_proof_class(&p);
    record(
        "reserved_production_suite",
        "Production",
        format!("{:?}", cls),
        cls == OnChainGovernanceProofClass::Production,
    );

    p.proof_suite_id = 0xCC;
    let cls = classify_onchain_governance_proof_class(&p);
    record(
        "unknown_suite_0xCC",
        "Production",
        format!("{:?}", cls),
        cls == OnChainGovernanceProofClass::Production,
    );

    record(
        "is_reserved_production(suite_reserved_production)",
        "true",
        "true".into(),
        is_reserved_production_onchain_governance_proof_suite(
            ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
        ),
    );
    record(
        "is_reserved_production(suite_fixture)",
        "false",
        "false".into(),
        !is_reserved_production_onchain_governance_proof_suite(
            ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
        ),
    );

    fs::write(out_dir.join("proof_class_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// No-mutation evidence: snapshot inputs, run a rejecting dispatch, assert
// every input is bit-identical afterward.
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let cand_before = cand.clone();
    let dom = domain(TrustBundleEnvironment::Devnet);
    let dom_before = dom.clone();
    let proof = production_class_proof(&cand, LocalLifecycleAction::Rotate);
    let proof_before = proof.clone();
    let replay: Vec<String> = vec!["seen-1".to_string(), "seen-2".to_string()];
    let replay_before = replay.clone();

    let outcome = dispatch_onchain_governance_proof_through_verifier_boundary(
        &proof,
        &cand,
        &dom,
        OnChainGovernanceVerifierPolicy::fixture_source_test(),
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        Some(1),
        NOW,
        &replay,
    );

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-187-helper] FAIL no-mutation invariant: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    record("outcome_is_reject", outcome.is_reject());
    record("candidate_unchanged", cand == cand_before);
    record("trust_domain_unchanged", dom == dom_before);
    record("proof_unchanged", proof == proof_before);
    record("replay_set_unchanged", replay == replay_before);

    buf.push_str(&format!("dispatch_outcome\t{:?}\n", outcome));
    fs::write(out_dir.join("no_mutation_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Determinism: 32 dispatches yield identical accept outcome.
// ---------------------------------------------------------------------------

fn run_determinism_check(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_fixture_proof(&cand, LocalLifecycleAction::Rotate);
    let dom = domain(TrustBundleEnvironment::Devnet);
    let policy = OnChainGovernanceVerifierPolicy::fixture_source_test();

    let mut outcomes = Vec::new();
    for _ in 0..32 {
        outcomes.push(dispatch(&proof, &cand, &dom, policy, Some(1)));
    }
    let first = outcomes[0].clone();
    let all_eq = outcomes.iter().all(|o| *o == first);
    let first_accept = first.is_accept();

    let mut buf = String::new();
    buf.push_str(&format!("samples={}\n", outcomes.len()));
    buf.push_str(&format!("first_accept={}\n", first_accept));
    buf.push_str(&format!("all_equal={}\n", all_eq));
    buf.push_str(&format!("sample_outcome_debug={:?}\n", first));
    fs::write(out_dir.join("determinism_evidence.txt"), buf)?;
    Ok((if all_eq && first_accept { 1 } else { 0 }, if all_eq && first_accept { 0 } else { 1 }))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1);
    let out_dir: PathBuf = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: run_187_onchain_governance_verifier_boundary_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).expect("create out_dir");

    let mut manifest = String::new();
    let mut expected = String::new();
    let mut actual = String::new();

    let (b_pass, b_fail) =
        run_boundary_scenarios(&out_dir, &mut manifest, &mut expected, &mut actual)
            .expect("boundary scenarios");
    let (s_pass, s_fail) =
        run_surface_scenarios(&out_dir, &mut manifest, &mut expected, &mut actual)
            .expect("surface scenarios");
    let (k_pass, k_fail) = run_verifier_kinds_table(&out_dir).expect("verifier kinds table");
    let (c_pass, c_fail) = run_proof_class_table(&out_dir).expect("proof class table");
    let (n_pass, n_fail) = run_no_mutation_evidence(&out_dir).expect("no mutation evidence");
    let (d_pass, d_fail) = run_determinism_check(&out_dir).expect("determinism check");

    fs::write(out_dir.join("manifest.txt"), manifest).expect("write manifest");
    fs::write(out_dir.join("expected_outcomes.txt"), expected).expect("write expected");
    fs::write(out_dir.join("actual_outcomes.txt"), actual).expect("write actual");

    let total_pass = b_pass + s_pass + k_pass + c_pass + n_pass + d_pass;
    let total_fail = b_fail + s_fail + k_fail + c_fail + n_fail + d_fail;
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };

    let mut summary = fs::File::create(out_dir.join("helper_summary.txt"))
        .expect("create helper_summary.txt");
    writeln!(
        summary,
        "Run 187 helper — release-mode OnChainGovernance production verifier-boundary corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(
        summary,
        "boundary_scenarios_pass: {}\nboundary_scenarios_fail: {}",
        b_pass, b_fail
    )
    .unwrap();
    writeln!(
        summary,
        "surface_scenarios_pass: {}\nsurface_scenarios_fail: {}",
        s_pass, s_fail
    )
    .unwrap();
    writeln!(
        summary,
        "verifier_kinds_pass: {}\nverifier_kinds_fail: {}",
        k_pass, k_fail
    )
    .unwrap();
    writeln!(
        summary,
        "proof_class_pass: {}\nproof_class_fail: {}",
        c_pass, c_fail
    )
    .unwrap();
    writeln!(
        summary,
        "no_mutation_pass: {}\nno_mutation_fail: {}",
        n_pass, n_fail
    )
    .unwrap();
    writeln!(
        summary,
        "determinism_pass: {}\ndeterminism_fail: {}",
        d_pass, d_fail
    )
    .unwrap();
    writeln!(summary, "production_symbols_exercised:").unwrap();
    for s in &[
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifierKind",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceProofClass",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifierPolicy",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifierBoundaryOutcome",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifier",
        "qbind_node::pqc_onchain_governance_verifier::DisabledOnChainGovernanceVerifier",
        "qbind_node::pqc_onchain_governance_verifier::FixtureSourceTestOnChainGovernanceVerifier",
        "qbind_node::pqc_onchain_governance_verifier::ProductionUnavailableOnChainGovernanceVerifier",
        "qbind_node::pqc_onchain_governance_verifier::ProductionVerifierPlaceholderOnChainGovernanceVerifier",
        "qbind_node::pqc_onchain_governance_verifier::classify_onchain_governance_proof_class",
        "qbind_node::pqc_onchain_governance_verifier::is_reserved_production_onchain_governance_proof_suite",
        "qbind_node::pqc_onchain_governance_verifier::verify_fixture_onchain_governance_proof",
        "qbind_node::pqc_onchain_governance_verifier::verify_production_onchain_governance_proof",
        "qbind_node::pqc_onchain_governance_verifier::dispatch_onchain_governance_proof_through_verifier_boundary",
        "qbind_node::pqc_onchain_governance_verifier::mainnet_peer_driven_apply_remains_refused_under_verifier_boundary",
        "qbind_node::pqc_onchain_governance_proof_surface::reload_check_compose_onchain_governance_marker_decision",
        "qbind_node::pqc_onchain_governance_proof_surface::reload_apply_compose_onchain_governance_marker_decision",
    ] {
        writeln!(summary, "  - {}", s).unwrap();
    }
    writeln!(summary, "honest_limits:").unwrap();
    for line in &[
        "default OnChainGovernanceVerifierKind::Disabled fail-closed on every surface",
        "FixtureSourceTest gated by OnChainGovernanceProofPolicy::AllowFixtureSourceTest selector (DevNet/TestNet only)",
        "MainNet fixture proof always refused (FixtureProofRejectedAsMainNetProductionAuthority)",
        "MainNet production-class proof always refused (MainNetProductionVerifierUnavailable)",
        "no real on-chain governance proof verifier wired in Run 187",
        "no governance execution / no KMS-HSM / no validator-set rotation",
        "no schema/wire/metric drift; no marker write; no sequence write; pure dispatch",
    ] {
        writeln!(summary, "  {}", line).unwrap();
    }

    if total_fail != 0 {
        std::process::exit(1);
    }
}
