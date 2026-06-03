//! Run 182 — production call-site wiring tests for the Run 180
//! per-surface OnChainGovernance preflight wrappers.
//!
//! Source/test only. Run 182 does **not** capture release-binary
//! evidence; release-binary `OnChainGovernance` production-surface
//! evidence is deferred to **Run 183**. Default policy remains
//! [`OnChainGovernanceProofPolicy::Disabled`]. `AllowFixtureSourceTest`
//! is hidden, explicit, and DevNet/TestNet fixture-only. MainNet
//! peer-driven apply remains refused. Real on-chain governance proof
//! verification, governance execution, KMS/HSM custody, and validator-
//! set rotation all remain unimplemented. See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`.
//!
//! These tests target the public wiring entries in
//! [`qbind_node::pqc_onchain_governance_callsite_wiring`] using a
//! shared [`OnChainGovernanceCallsiteContext`] argument bundle. Each
//! entry delegates verbatim to the matching Run 180 wrapper; the
//! `peer_driven_drain` entry additionally layers a surface-level
//! MainNet refusal before invoking the underlying verifier (Run 152).

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_callsite_wiring::{
    live_inbound_0x05_callsite_onchain_governance_marker_decision,
    local_peer_candidate_check_callsite_onchain_governance_marker_decision,
    peer_driven_drain_callsite_onchain_governance_marker_decision,
    reload_apply_callsite_onchain_governance_marker_decision,
    reload_check_callsite_onchain_governance_marker_decision,
    sighup_callsite_onchain_governance_marker_decision,
    startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision,
    OnChainGovernanceCallsiteContext,
};
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
};
use qbind_node::pqc_onchain_governance_proof_surface::OnChainGovernanceMarkerDecisionOutcome;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Fixtures
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
const UNIQUE_DECISION_ID: &str = "decision-182";
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

fn ctx_with<'a>(
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    proof: Option<&'a OnChainGovernanceProof>,
    domain: &'a AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
    replay: &'a EmptyOnChainGovernanceReplaySet,
) -> OnChainGovernanceCallsiteContext<'a, EmptyOnChainGovernanceReplaySet> {
    OnChainGovernanceCallsiteContext {
        persisted,
        candidate,
        proof,
        trust_domain: domain,
        policy,
        expected_governance_domain_id: GOV_DOMAIN,
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID,
        expected_proposal_digest: PROPOSAL_DIGEST,
        now_unix: NOW,
        replay_set: replay,
    }
}

// Cross-surface helper: invoke every non-MainNet-aware wiring entry on
// the supplied context and return the produced outcomes in declaration
// order. The peer-driven drain entry is also invoked as the final
// element because it must agree with the others on non-MainNet
// candidates.
fn run_all_callsite_entries(
    ctx: &OnChainGovernanceCallsiteContext<'_, EmptyOnChainGovernanceReplaySet>,
) -> Vec<(&'static str, OnChainGovernanceMarkerDecisionOutcome)> {
    vec![
        (
            "reload_check",
            reload_check_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "reload_apply",
            reload_apply_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "startup_p2p_trust_bundle",
            startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "sighup",
            sighup_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "local_peer_candidate_check",
            local_peer_candidate_check_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "live_inbound_0x05",
            live_inbound_0x05_callsite_onchain_governance_marker_decision(ctx),
        ),
        (
            "peer_driven_drain",
            peer_driven_drain_callsite_onchain_governance_marker_decision(ctx),
        ),
    ]
}

// ===========================================================================
// A1 — Default Disabled rejects (bypasses) OnChainGovernance proof at
// every production call-site entry.
// ===========================================================================

#[test]
fn a1_default_disabled_bypasses_at_every_callsite_entry() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::Disabled,
        &replay,
    );
    for (name, outcome) in run_all_callsite_entries(&ctx) {
        assert_eq!(
            outcome,
            OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled,
            "{} entry must bypass under default Disabled",
            name
        );
        assert!(outcome.is_bypassed(), "{}", name);
        assert!(!outcome.is_accept(), "{}", name);
        assert!(!outcome.is_reject(), "{}", name);
    }
}

// ===========================================================================
// A2 — reload-check accepts a valid DevNet OnChainGovernance Rotate
// proof under AllowFixtureSourceTest.
// ===========================================================================

#[test]
fn a2_reload_check_accepts_valid_devnet_rotate_under_allow_fixture_source_test() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A3 — reload-apply accepts a valid DevNet Rotate proof.
// ===========================================================================

#[test]
fn a3_reload_apply_accepts_valid_devnet_rotate() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A4 — startup `--p2p-trust-bundle` accepts valid fixture proof.
// ===========================================================================

#[test]
fn a4_startup_p2p_trust_bundle_accepts_valid_fixture_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A5 — SIGHUP preflight accepts valid fixture proof.
// ===========================================================================

#[test]
fn a5_sighup_accepts_valid_fixture_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A6 — local peer-candidate-check accepts valid fixture proof.
// ===========================================================================

#[test]
fn a6_local_peer_candidate_check_accepts_valid_fixture_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = local_peer_candidate_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A7 — live inbound `0x05` accepts valid fixture proof when proof
// context is supplied. (Production wire today supplies `proof: None`;
// this test exercises the wiring entry directly with an in-process
// fixture proof to demonstrate reachability.)
// ===========================================================================

#[test]
fn a7_live_inbound_0x05_accepts_valid_fixture_proof_when_supplied() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = live_inbound_0x05_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A8 — peer-driven drain coordinator accepts valid fixture proof on a
// DevNet candidate when proof is supplied.
// ===========================================================================

#[test]
fn a8_peer_driven_drain_accepts_valid_fixture_proof_on_devnet() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A9 — Proof absent under AllowFixtureSourceTest produces
// NoOnChainGovernanceProofSupplied at every entry (this is the
// behaviour every production source call-site sees today since no
// existing wire/sidecar carries a typed proof). GenesisBound /
// EmergencyCouncil / non-OnChainGovernance proof modes remain
// unchanged because they do not enter this call-site path.
// ===========================================================================

#[test]
fn a9_no_proof_under_allow_fixture_source_test_produces_no_proof_supplied() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        None,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    for (name, outcome) in run_all_callsite_entries(&ctx) {
        assert_eq!(
            outcome,
            OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied,
            "{} entry must report NoOnChainGovernanceProofSupplied when proof is absent",
            name
        );
    }
}

// ===========================================================================
// R1 — Disabled policy bypasses even a valid proof (covered above by A1
// but asserted explicitly here).
// ===========================================================================

#[test]
fn r1_disabled_policy_bypasses_valid_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::Disabled,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled);
}

// ===========================================================================
// R2 — Selector unset / false preserves Disabled. The selector helper
// is fully exercised by Run 180 / Run 171; we verify here that the
// wiring entries see the resulting policy through the context.
// ===========================================================================

#[test]
fn r2_selector_unset_preserves_disabled_at_wiring_entry() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let policy =
        qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_selector(
            false,
        );
    assert_eq!(policy, OnChainGovernanceProofPolicy::Disabled);
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        policy,
        &replay,
    );
    let outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled);
}

// ===========================================================================
// R3 — MainNet peer-driven drain refuses unconditionally.
// ===========================================================================

#[test]
fn r3_mainnet_peer_driven_drain_refuses_with_valid_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx);
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::MainNetRefused);
    assert!(!outcome.is_accept());
}

#[test]
fn r3b_mainnet_peer_driven_drain_refuses_with_no_proof() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        None,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx);
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::MainNetRefused);
}

// ===========================================================================
// R4 — wrong environment rejected.
// ===========================================================================

#[test]
fn r4_wrong_environment_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.environment = TrustBundleEnvironment::Testnet;
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R5 — wrong chain rejected.
// ===========================================================================

#[test]
fn r5_wrong_chain_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R6 — wrong genesis rejected.
// ===========================================================================

#[test]
fn r6_wrong_genesis_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R7 — wrong authority root rejected.
// ===========================================================================

#[test]
fn r7_wrong_authority_root_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_root_fingerprint = "9999999999999999999999999999999999999999".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R8 — wrong governance domain rejected.
// ===========================================================================

#[test]
fn r8_wrong_governance_domain_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = "qbind-onchain-gov-other".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = local_peer_candidate_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R9 — wrong proposal digest rejected.
// ===========================================================================

#[test]
fn r9_wrong_proposal_digest_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest =
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = live_inbound_0x05_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R10 — wrong proposal outcome rejected.
// ===========================================================================

#[test]
fn r10_wrong_proposal_outcome_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R11 — wrong lifecycle action rejected.
// ===========================================================================

#[test]
fn r11_wrong_lifecycle_action_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.lifecycle_action = LocalLifecycleAction::ActivateInitial;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R12 — wrong candidate digest rejected.
// ===========================================================================

#[test]
fn r12_wrong_candidate_digest_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_OTHER.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R13 — wrong authority-domain sequence rejected.
// ===========================================================================

#[test]
fn r13_wrong_authority_domain_sequence_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_domain_sequence = candidate.latest_authority_domain_sequence + 99;
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R14 — expired governance proof rejected.
// ===========================================================================

#[test]
fn r14_expired_governance_proof_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Window ends well before NOW.
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW - 1000,
        not_after_unix: NOW - 100,
    };
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R15 — replayed governance decision rejected.
// ===========================================================================

#[test]
fn r15_replayed_decision_rejected() {
    use std::collections::HashSet;
    use qbind_node::pqc_onchain_governance_proof::OnChainGovernanceReplaySet;

    struct PreloadedReplaySet {
        seen: HashSet<String>,
    }
    impl OnChainGovernanceReplaySet for PreloadedReplaySet {
        fn contains(&self, decision_id: &str) -> bool {
            self.seen.contains(decision_id)
        }
    }

    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let mut seen = HashSet::new();
    seen.insert(UNIQUE_DECISION_ID.to_string());
    let replay = PreloadedReplaySet { seen };
    let ctx = OnChainGovernanceCallsiteContext::<PreloadedReplaySet> {
        persisted: Some(&persisted),
        candidate: &candidate,
        proof: Some(&proof),
        trust_domain: &domain,
        policy: OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        expected_governance_domain_id: GOV_DOMAIN,
        expected_governance_epoch: GOV_EPOCH,
        expected_proposal_id: PROPOSAL_ID,
        expected_proposal_digest: PROPOSAL_DIGEST,
        now_unix: NOW,
        replay_set: &replay,
    };
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R16 — quorum not met rejected.
// ===========================================================================

#[test]
fn r16_quorum_not_met_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.quorum = OnChainGovernanceQuorum {
        voters_voted: 1,
        total_voters: 5,
        required_quorum: 3,
    };
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R17 — threshold not met rejected.
// ===========================================================================

#[test]
fn r17_threshold_not_met_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Threshold not met: required = 5 of 5 but only met = 1
    proof.threshold = GovernanceThreshold::new(1, 3, 5);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = local_peer_candidate_check_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R18 — invalid proof bytes rejected (commitment mismatch).
// ===========================================================================

#[test]
fn r18_invalid_proof_bytes_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Corrupt the bytes commitment without re-committing.
    if let Some(b) = proof.proof_bytes.first_mut() {
        *b ^= 0xFF;
    }
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R19 — unsupported proof suite rejected.
// ===========================================================================

#[test]
fn r19_unsupported_proof_suite_rejected() {
    use qbind_node::pqc_onchain_governance_proof::ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R20 — malformed proof rejected (empty proof bytes).
// ===========================================================================

#[test]
fn r20_malformed_proof_bytes_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes.clear();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = sighup_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R21 — local operator config (a context with no proof) under
// AllowFixtureSourceTest reports NoOnChainGovernanceProofSupplied;
// it does NOT auto-accept based on local config.
// ===========================================================================

#[test]
fn r21_no_proof_does_not_auto_accept_from_local_config() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        None,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert_eq!(
        outcome,
        OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied
    );
    assert!(!outcome.is_accept());
}

// ===========================================================================
// R22 — peer-majority / gossip count alone is not sufficient. The
// wiring entries see only the typed proof (or its absence); a count
// of peer messages is irrelevant. The proof carrier is what matters.
// ===========================================================================

#[test]
fn r22_peer_majority_alone_is_not_sufficient() {
    // Simulate "peer-majority count present but proof absent": the
    // wiring entry must still refuse because no typed proof was
    // supplied.
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        None,
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx);
    assert!(!outcome.is_accept());
}

// ===========================================================================
// R23 — Valid OnChainGovernance proof but lifecycle invalid (rotate
// with mismatched previous_fp on candidate / proof) rejected.
// ===========================================================================

#[test]
fn r23_valid_proof_but_lifecycle_invalid_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Break revocation binding so lifecycle binding fails.
    proof.revoked_bundle_signing_key_fingerprint =
        Some("ffffffffffffffffffffffffffffffffffffffff".to_string());
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R24 — Lifecycle valid but OnChainGovernance proof invalid rejected
// (already covered by R4-R20). Asserted explicitly here on the
// reload-apply surface.
// ===========================================================================

#[test]
fn r24_lifecycle_valid_but_proof_invalid_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Lifecycle remains valid; proof binding broken.
    proof.proposal_id = "prop-002".to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R25 — Validation-only entries (`reload_check`,
// `local_peer_candidate_check`, `live_inbound_0x05`) preserve
// non-mutating semantics. These wiring entries are pure functions
// returning a typed outcome; they cannot mutate marker, sequence,
// trust state, or sessions because they take only borrows. Verified
// by construction: rejection on a validation-only entry returns the
// rejection outcome and does not touch any state visible from the
// caller.
// ===========================================================================

#[test]
fn r25_validation_only_rejection_is_non_mutating() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_epoch = GOV_EPOCH + 1;
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    // Capture the candidate's pre-call state.
    let candidate_before = candidate.clone();
    let outcome_check = reload_check_callsite_onchain_governance_marker_decision(&ctx);
    let outcome_local = local_peer_candidate_check_callsite_onchain_governance_marker_decision(&ctx);
    let outcome_wire = live_inbound_0x05_callsite_onchain_governance_marker_decision(&ctx);
    assert!(outcome_check.is_reject());
    assert!(outcome_local.is_reject());
    assert!(outcome_wire.is_reject());
    // The candidate is borrowed; it cannot have changed. This is a
    // structural property guaranteed by the borrow checker, but we
    // assert a value equality for documentation.
    assert_eq!(candidate.latest_ratification_v2_digest, candidate_before.latest_ratification_v2_digest);
    assert_eq!(candidate.latest_authority_domain_sequence, candidate_before.latest_authority_domain_sequence);
}

// ===========================================================================
// R26 — Mutating preflight rejection produces no Run 070 call, no live
// trust swap, no session eviction, no sequence write, and no marker
// write. The wiring entries are pure functions over borrows; they
// have no Run 070 access, no live trust handle, no session handle,
// no sequence path, and no marker path. Verified by construction.
// ===========================================================================

#[test]
fn r26_mutating_preflight_rejection_is_pure() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_OTHER.to_string();
    recommit(&mut proof);
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    // Each mutating wiring entry must reject; the function takes only
    // borrows so no marker/sequence/trust/session can be mutated.
    let outcomes = [
        reload_apply_callsite_onchain_governance_marker_decision(&ctx),
        startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&ctx),
        sighup_callsite_onchain_governance_marker_decision(&ctx),
        peer_driven_drain_callsite_onchain_governance_marker_decision(&ctx),
    ];
    for outcome in outcomes {
        assert!(outcome.is_reject(), "got {:?}", outcome);
    }
}

// ===========================================================================
// R27 — Invalid live `0x05` OnChainGovernance proof candidate is not
// propagated, staged, or applied. The wiring entry is observation-
// only and returns a typed outcome; the `0x05` validator surface
// uses the existing Run 142 conflict path to suppress propagation
// and the Run 146 staging path to suppress staging. Here we assert
// the wiring entry returns a non-accepting outcome on an invalid
// fixture proof, which is a necessary condition for the surface
// not to mark it valid.
// ===========================================================================

#[test]
fn r27_invalid_live_0x05_proof_does_not_accept() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let replay = EmptyOnChainGovernanceReplaySet;
    let ctx = ctx_with(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        &replay,
    );
    let outcome = live_inbound_0x05_callsite_onchain_governance_marker_decision(&ctx);
    assert!(!outcome.is_accept(), "got {:?}", outcome);
    assert!(outcome.is_reject() || outcome.is_bypassed(), "got {:?}", outcome);
}
