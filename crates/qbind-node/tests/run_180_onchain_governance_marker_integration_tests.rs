//! Run 180 — focused tests for the source/test production marker-
//! decision composition of the Run 178 typed `OnChainGovernance`
//! fixture proof verifier behind the hidden DevNet/TestNet
//! `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` selector.
//!
//! Source/test only. Run 180 does **not** enable MainNet peer-driven
//! apply, governance execution, real on-chain proof verification,
//! KMS/HSM, or validator-set rotation. No release-binary evidence is
//! captured in this run; release-binary `OnChainGovernance`
//! production-surface evidence is deferred to Run 181. See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
    REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceThreshold;
use qbind_node::pqc_onchain_governance_proof::{
    fixture_onchain_governance_proof_bytes, EmptyOnChainGovernanceReplaySet,
    OnChainGovernanceFreshnessWindow, OnChainGovernanceProof, OnChainGovernanceProofPolicy,
    OnChainGovernanceProposalOutcome, OnChainGovernanceQuorum,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1,
    ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION,
};
use qbind_node::pqc_onchain_governance_proof_surface::{
    compose_onchain_governance_marker_decision,
    live_inbound_0x05_compose_onchain_governance_marker_decision,
    local_peer_candidate_check_compose_onchain_governance_marker_decision,
    mainnet_peer_driven_apply_remains_refused_for_onchain_governance,
    onchain_governance_fixture_allowed_env_selector_enabled,
    onchain_governance_proof_policy_from_cli_or_env,
    onchain_governance_proof_policy_from_selector,
    peer_driven_drain_compose_onchain_governance_marker_decision,
    reload_apply_compose_onchain_governance_marker_decision,
    reload_check_compose_onchain_governance_marker_decision,
    sighup_compose_onchain_governance_marker_decision,
    startup_p2p_trust_bundle_compose_onchain_governance_marker_decision,
    OnChainGovernanceMarkerDecisionOutcome,
    QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

use std::sync::{Mutex, OnceLock};

// ===========================================================================
// Env-var serialization
// ===========================================================================
//
// Several Run 180 tests probe
// `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`;
// `std::env` mutation is process-wide so we serialize the env-touching
// tests behind a single Mutex to keep them deterministic when run in
// parallel (mirrors the Run 171 selector-test pattern).

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    prior: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(value: Option<&str>) -> Self {
        let lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior =
            std::env::var(QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV).ok();
        match value {
            Some(v) => std::env::set_var(
                QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV,
                v,
            ),
            None => std::env::remove_var(
                QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV,
            ),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(
                QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV,
                v,
            ),
            None => std::env::remove_var(
                QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED_ENV,
            ),
        }
    }
}

// ===========================================================================
// Fixtures
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH_A: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENESIS_HASH_B: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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
const UNIQUE_DECISION_ID: &str = "decision-180";
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

fn previous_v2_versioned(
    active_fp: &str,
    sequence: u64,
    digest: &str,
    env: TrustBundleEnvironment,
) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2_with_env(
        env,
        active_fp,
        sequence,
        BundleSigningRatificationV2Action::Ratify,
        None,
        digest,
        None,
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
        LocalLifecycleAction::Rotate => {
            candidate.previous_bundle_signing_key_fingerprint.clone()
        }
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

/// Re-builds the proof_bytes commitment to match the proof's current
/// (possibly mutated) bindings. Used by rejection tests that mutate a
/// non-bytes binding and want the rejection to surface from the
/// targeted binding rather than from the proof-bytes commitment.
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

#[allow(clippy::too_many_arguments)]
fn run_compose(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: Option<&OnChainGovernanceProof>,
    domain: &AuthorityTrustDomain,
    policy: OnChainGovernanceProofPolicy,
) -> OnChainGovernanceMarkerDecisionOutcome {
    compose_onchain_governance_marker_decision(
        persisted,
        candidate,
        proof,
        domain,
        policy,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    )
}

/// Build a persisted v2 record reflecting the prior key (`KEY_A` at
/// sequence 1) for the supplied environment. Used by every test that
/// exercises a `Rotate` candidate (Run 159 lifecycle requires a
/// persisted authority marker for non-`ActivateInitial` actions).
fn prior_v2_for_rotate(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2_with_env(
        env,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        "1111111111111111111111111111111111111111111111111111111111111111",
        None,
    ))
}

/// Build a persisted v2 record reflecting the prior key (`KEY_B` at
/// sequence 2) for the supplied environment, used by `Revoke`
/// candidates (sequence 3).
fn prior_v2_for_revoke(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2_with_env(
        env,
        KEY_B,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
        None,
    ))
}

// ===========================================================================
// A1 — default policy is Disabled (selector helpers)
// ===========================================================================

#[test]
fn a1_default_policy_is_disabled_and_proof_rejected() {
    // Default selector inputs (false flag + no env var) MUST resolve
    // to `OnChainGovernanceProofPolicy::Disabled`.
    let _g = EnvGuard::set(None);
    let policy = onchain_governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, OnChainGovernanceProofPolicy::Disabled);

    // Even a fully-valid DevNet fixture proof MUST be refused under
    // the default `Disabled` policy.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = run_compose(None, &candidate, Some(&proof), &devnet_domain(), policy);
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled);
    assert!(!outcome.is_accept());
    assert!(!outcome.is_reject());
    assert!(outcome.is_bypassed());
}

// ===========================================================================
// A2 — hidden CLI/env selector enables AllowFixtureSourceTest
// ===========================================================================

#[test]
fn a2_selector_parsing_cli_flag_set_enables_allow_fixture_source_test() {
    assert_eq!(
        onchain_governance_proof_policy_from_selector(true),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest
    );
    assert_eq!(
        onchain_governance_proof_policy_from_selector(false),
        OnChainGovernanceProofPolicy::Disabled
    );
}

// Env tests are merged into a single serially-executed test below
// (`a2_selector_parsing_env_serially`) to avoid env-var contamination
// across the parallel test runner.

#[test]
fn a2_selector_parsing_env_serially() {
    // Truthy values enable the selector.
    for v in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"] {
        let _g = EnvGuard::set(Some(v));
        assert!(
            onchain_governance_fixture_allowed_env_selector_enabled(),
            "expected env value {:?} to enable selector",
            v
        );
        assert_eq!(
            onchain_governance_proof_policy_from_cli_or_env(false),
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            "env value {:?} should resolve to AllowFixtureSourceTest",
            v
        );
    }
    // Falsey values preserve the Disabled default.
    for v in ["", "0", "false", "FALSE", "no", "off", "anything-else"] {
        let _g = EnvGuard::set(Some(v));
        assert!(
            !onchain_governance_fixture_allowed_env_selector_enabled(),
            "expected env value {:?} to leave selector disabled",
            v
        );
        assert_eq!(
            onchain_governance_proof_policy_from_cli_or_env(false),
            OnChainGovernanceProofPolicy::Disabled,
            "env value {:?} should preserve Disabled",
            v
        );
    }
    // Unset preserves Disabled.
    let _g = EnvGuard::set(None);
    assert!(!onchain_governance_fixture_allowed_env_selector_enabled());
    assert_eq!(
        onchain_governance_proof_policy_from_cli_or_env(false),
        OnChainGovernanceProofPolicy::Disabled
    );
    // CLI flag set must enable even when env is unset.
    assert_eq!(
        onchain_governance_proof_policy_from_cli_or_env(true),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest
    );
}

// ===========================================================================
// A3 — reload-check DevNet fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a3_reload_check_devnet_fixture_rotate_accepted_under_allow_fixture_source_test() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = previous_v2_versioned(KEY_A, 1, DIGEST_2, TrustBundleEnvironment::Devnet);
    let outcome = reload_check_compose_onchain_governance_marker_decision(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A4 — reload-check TestNet fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a4_reload_check_testnet_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Testnet);
    let outcome = reload_check_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &testnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A5 — reload-apply DevNet fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a5_reload_apply_devnet_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Devnet);
    let outcome = reload_apply_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A6 — local peer-candidate-check fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a6_local_peer_candidate_check_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Devnet);
    let outcome = local_peer_candidate_check_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A7 — live inbound 0x05 fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a7_live_inbound_0x05_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Testnet);
    let outcome = live_inbound_0x05_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &testnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A8 — peer-driven drain coordinator fixture OnChainGovernance Rotate accepted
// ===========================================================================

#[test]
fn a8_peer_driven_drain_coordinator_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Devnet);
    let outcome = peer_driven_drain_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// Also exercise the SIGHUP and startup wrappers so every Run 180
// per-surface name has at least one acceptance test.

#[test]
fn a8b_sighup_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Devnet);
    let outcome = sighup_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

#[test]
fn a8c_startup_p2p_trust_bundle_fixture_rotate_accepted() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let persisted = prior_v2_for_rotate(TrustBundleEnvironment::Devnet);
    let outcome = startup_p2p_trust_bundle_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        Some(&persisted),
        &candidate,
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
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A9 — GenesisBound / EmergencyCouncil proof behavior unchanged.
//
// Run 180 only adds a new policy gate for the `OnChainGovernance`
// authority class. When no `OnChainGovernanceProof` is supplied (which
// is the case for every `GenesisBound` / `EmergencyCouncil` candidate
// in production today), the helper returns
// `NoOnChainGovernanceProofSupplied` and never invokes the Run 178
// verifier — preserving Run 169/Run 173/Run 176 behavior bit-for-bit.
// ===========================================================================

#[test]
fn a9_no_proof_supplied_bypasses_run178_verifier() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let outcome = run_compose(
        None,
        &candidate,
        None,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert_eq!(
        outcome,
        OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied
    );
    assert!(outcome.is_bypassed());
}

// ===========================================================================
// R1 — OnChainGovernance proof rejected under default Disabled policy.
// ===========================================================================

#[test]
fn r1_default_disabled_policy_rejects_proof() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = run_compose(
        None,
        &candidate,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::Disabled,
    );
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled);
}

// ===========================================================================
// R2 — selector unset / false rejects.
// ===========================================================================

#[test]
fn r2_selector_unset_rejects() {
    let _g = EnvGuard::set(None);
    let policy = onchain_governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, OnChainGovernanceProofPolicy::Disabled);
}

// ===========================================================================
// R3 — MainNet peer-driven apply remains refused even under
// `AllowFixtureSourceTest` with an otherwise-valid fixture proof.
// ===========================================================================

#[test]
fn r3_mainnet_peer_driven_apply_remains_refused_even_under_allow_fixture_source_test() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Mainnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = run_compose(
        None,
        &candidate,
        Some(&proof),
        &mainnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert_eq!(outcome, OnChainGovernanceMarkerDecisionOutcome::MainNetRefused);
    assert!(outcome.is_reject());

    // The pure environment-driven helper agrees.
    assert!(mainnet_peer_driven_apply_remains_refused_for_onchain_governance(
        TrustBundleEnvironment::Mainnet
    ));
}

// ===========================================================================
// R4–R20 — wrong-binding / freshness / replay / quorum / threshold /
// invalid / malformed / unsupported-suite rejections all surface
// through the helper as `Rejected(...)` (not `Accepted`).
// ===========================================================================

fn assert_helper_rejects(
    candidate: &PersistentAuthorityStateRecordV2,
    proof: &OnChainGovernanceProof,
    domain: &AuthorityTrustDomain,
) {
    let outcome = run_compose(
        None,
        candidate,
        Some(proof),
        domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert!(
        outcome.is_reject() && !outcome.is_accept(),
        "expected reject, got {:?}",
        outcome
    );
}

#[test]
fn r4_wrong_environment_rejected() {
    // Proof says Devnet but trust domain says Testnet.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Build a candidate on Testnet with the same shape so the
    // composed lifecycle accepts but the proof environment binding
    // mismatches the trust domain.
    let testnet_candidate =
        rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    assert_helper_rejects(&testnet_candidate, &proof, &testnet_domain());
}

#[test]
fn r5_wrong_chain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.chain_id = OTHER_CHAIN.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r6_wrong_genesis_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.genesis_hash = GENESIS_HASH_B.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r7_wrong_authority_root_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r8_wrong_governance_domain_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = OTHER_GOV_DOMAIN.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r9_wrong_proposal_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_digest = OTHER_PROPOSAL_DIGEST.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r10_wrong_proposal_outcome_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_outcome = OnChainGovernanceProposalOutcome::Rejected;
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r11_wrong_lifecycle_action_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.lifecycle_action = LocalLifecycleAction::Retire;
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r12_wrong_candidate_digest_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.candidate_v2_digest = DIGEST_3.to_string();
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r13_wrong_authority_domain_sequence_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.authority_domain_sequence = candidate.latest_authority_domain_sequence + 7;
    recommit(&mut proof);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r14_expired_governance_proof_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.freshness = OnChainGovernanceFreshnessWindow {
        not_before_unix: NOW - 1000,
        not_after_unix: NOW - 500, // already expired at NOW
    };
    // freshness is not part of the proof_bytes commitment, so do not
    // recommit.
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r15_replayed_governance_decision_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let replay_set: Vec<String> = vec![UNIQUE_DECISION_ID.to_string()];
    let outcome = compose_onchain_governance_marker_decision(
        None,
        &candidate,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &replay_set,
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

#[test]
fn r16_quorum_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.quorum = OnChainGovernanceQuorum {
        voters_voted: 1,
        total_voters: 5,
        required_quorum: 3,
    };
    // quorum is not part of the proof_bytes commitment.
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r17_threshold_not_met_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.threshold = GovernanceThreshold::new(1, 3, 5);
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r18_invalid_proof_bytes_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Corrupt without recommitting.
    proof.proof_bytes = b"corrupted-bytes".to_vec();
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r19_unsupported_proof_suite_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_suite_id = ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION;
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

#[test]
fn r20_malformed_proof_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    // Empty chain_id violates structural well-formedness.
    proof.chain_id = String::new();
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

// ===========================================================================
// R21 — local operator config alone is not an OnChainGovernance proof.
// (Asserted by the absence of a typed OnChainGovernanceProof: the
// helper returns `NoOnChainGovernanceProofSupplied` and never accepts
// without a typed proof object.)
// ===========================================================================

#[test]
fn r21_local_operator_config_alone_does_not_accept() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let outcome = run_compose(
        None,
        &candidate,
        None,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert!(!outcome.is_accept());
    assert_eq!(
        outcome,
        OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied
    );
}

// ===========================================================================
// R22 — peer-majority / gossip count is not an OnChainGovernance proof.
// (Run 180 introduces no peer-majority acceptance path; absence of a
// typed proof object remains the only no-op outcome and never elevates
// to acceptance.)
// ===========================================================================

#[test]
fn r22_peer_majority_alone_does_not_accept() {
    // Same shape as R21 — Run 180 has no peer-majority acceptance
    // surface; the helper has no input by which to express one.
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let outcome = run_compose(
        None,
        &candidate,
        None,
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert!(!outcome.is_accept());
}

// ===========================================================================
// R23 — OnChainGovernance proof valid but lifecycle invalid rejected.
// ===========================================================================

#[test]
fn r23_proof_valid_but_lifecycle_invalid_rejected() {
    // Persisted sequence 5 with a v2 record; candidate at sequence 2
    // (lower) → Run 159 lifecycle rejects on anti-rollback.
    let persisted = previous_v2_versioned(KEY_A, 5, DIGEST_3, TrustBundleEnvironment::Devnet);
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    let outcome = run_compose(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert!(outcome.is_reject(), "got {:?}", outcome);
}

// ===========================================================================
// R24 — lifecycle valid but OnChainGovernance proof invalid rejected.
// ===========================================================================

#[test]
fn r24_lifecycle_valid_but_proof_invalid_rejected() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proof_bytes = b"corrupted".to_vec();
    assert_helper_rejects(&candidate, &proof, &devnet_domain());
}

// ===========================================================================
// R25 — validation-only rejection remains non-mutating.
//
// The helpers are pure (no I/O, no marker write, no sequence write,
// no live-trust swap, no session eviction, no Run 070 invocation).
// Asserting that we can call any validation-only wrapper repeatedly
// with the same inputs and observe the same outcome, with no side-
// effects observable from the caller's process state.
// ===========================================================================

#[test]
fn r25_validation_only_rejection_is_non_mutating_and_deterministic() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_domain_id = OTHER_GOV_DOMAIN.to_string();
    recommit(&mut proof);
    let domain = devnet_domain();

    let first = reload_check_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let second = local_peer_candidate_check_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let third = live_inbound_0x05_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &domain,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(first.is_reject());
    assert_eq!(first, second);
    assert_eq!(second, third);
}

// ===========================================================================
// R26 — mutating preflight rejection produces no Run 070 call, no live
// trust swap, no session eviction, no sequence write, and no marker
// write.
//
// The helpers are pure — they have no input by which they could
// invoke Run 070, swap live trust, evict sessions, write a sequence,
// or write a marker. We assert this structurally by exercising every
// mutating-preflight wrapper with a rejection input and observing
// that they return without panicking and without permitting
// acceptance, and that a follow-up call returns identical output
// (deterministic / pure).
// ===========================================================================

#[test]
fn r26_mutating_preflight_rejection_is_pure() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Devnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.proposal_id = OTHER_PROPOSAL_ID.to_string();
    recommit(&mut proof);
    let d = devnet_domain();

    let r1 = reload_apply_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &d,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let r2 = startup_p2p_trust_bundle_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &d,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let r3 = sighup_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &d,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    let r4 = peer_driven_drain_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &d,
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );

    assert!(r1.is_reject() && r2.is_reject() && r3.is_reject() && r4.is_reject());
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
    assert_eq!(r3, r4);
}

// ===========================================================================
// R27 — invalid live `0x05` OnChainGovernance proof candidate is not
// propagated, staged, or applied.
//
// The Run 180 live-inbound-`0x05` wrapper short-circuits at the
// preflight before any staging path is reached. Asserting the
// rejection variant is the only observable result.
// ===========================================================================

#[test]
fn r27_invalid_live_0x05_onchain_governance_proof_short_circuits_before_stage() {
    let candidate = rotate_to(KEY_B, KEY_A, 2, DIGEST_2, TrustBundleEnvironment::Testnet);
    let mut proof = good_proof(&candidate, LocalLifecycleAction::Rotate);
    proof.governance_epoch = GOV_EPOCH + 100;
    recommit(&mut proof);
    let outcome = live_inbound_0x05_compose_onchain_governance_marker_decision::<
        EmptyOnChainGovernanceReplaySet,
    >(
        None,
        &candidate,
        Some(&proof),
        &testnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
        GOV_DOMAIN,
        GOV_EPOCH,
        PROPOSAL_ID,
        PROPOSAL_DIGEST,
        NOW,
        &EmptyOnChainGovernanceReplaySet,
    );
    assert!(outcome.is_reject());
    assert!(!outcome.is_accept());
}

// ===========================================================================
// Bonus — Revoke acceptance under the helper (broader matrix coverage).
// ===========================================================================

#[test]
fn revoke_under_helper_accepted_devnet() {
    let candidate = revoke_record(
        KEY_B,
        3,
        DIGEST_3,
        REVOKED_METADATA_PREFIX_REVOKE,
        KEY_A,
        TrustBundleEnvironment::Devnet,
    );
    let proof = good_proof(&candidate, LocalLifecycleAction::Revoke);
    let persisted = prior_v2_for_revoke(TrustBundleEnvironment::Devnet);
    let outcome = run_compose(
        Some(&persisted),
        &candidate,
        Some(&proof),
        &devnet_domain(),
        OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}