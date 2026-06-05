//! Run 192 — source/test hidden authority-custody policy selector and
//! production preflight integration tests.
//!
//! Source/test only. Run 192 does **not** capture release-binary
//! evidence; release-binary custody-policy selector evidence is
//! deferred to **Run 193**. Default policy remains
//! [`AuthorityCustodyPolicy::Disabled`]. Real KMS / HSM / cloud-KMS /
//! PKCS#11 / remote-signer backends remain unimplemented; every
//! production-class custody attempt fails closed via the Run 188
//! validator regardless of selector. MainNet peer-driven apply
//! remains the Run 147 / 148 / 152 FATAL refusal regardless of
//! selector, even with `MainnetProductionCustodyRequired` and
//! metadata claiming KMS/HSM/RemoteSigner. Real on-chain governance
//! proof verification, governance execution, and validator-set
//! rotation all remain unimplemented. Full C4 remains open. C5
//! remains open.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_192.md`.
//!
//! These tests cover the full A1–A10 / R1–R29 matrix from
//! `task/RUN_192_TASK.txt`:
//!
//! * the typed selector parsers
//!   ([`authority_custody_policy_from_selector`],
//!   [`authority_custody_policy_env_selector`],
//!   [`authority_custody_policy_from_cli_or_env`]) including default,
//!   CLI, env, CLI-over-env precedence, and invalid-value
//!   fail-closed;
//! * source reachability — the resolved policy reaches all seven
//!   production-context per-surface preflight wrappers
//!   ([`preflight_v2_marker_authority_custody_for_*`]);
//! * accepted scenarios A1–A10 (where representable);
//! * rejection scenarios R1–R29;
//! * no-mutation invariants (validation-only and mutating-rejection);
//! * MainNet refusal invariants (fixture/local rejected on MainNet,
//!   peer-driven drain refuses MainNet regardless of metadata).
//!
//! The tests construct only data values and call the pure helpers /
//! routing wrappers — no I/O, no marker write, no sequence write, no
//! live trust swap, no session eviction, no Run 070 invocation.

use std::sync::{Mutex, OnceLock};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
    AuthorityCustodyValidationOutcome, LifecycleGovernanceCustodyOutcome,
};
use qbind_node::pqc_authority_custody_payload_carrying::{
    AuthorityCustodyAttestationPayloadParseError, AuthorityCustodyLoadStatus,
    AuthorityCustodyPayloadCarryingDecisionOutcome,
};
use qbind_node::pqc_authority_custody_policy_surface::{
    authority_custody_policy_env_selector, authority_custody_policy_from_cli_or_env,
    authority_custody_policy_from_selector,
    preflight_v2_marker_authority_custody_for_live_inbound_0x05,
    preflight_v2_marker_authority_custody_for_local_peer_candidate_check,
    preflight_v2_marker_authority_custody_for_peer_driven_drain,
    preflight_v2_marker_authority_custody_for_reload_apply,
    preflight_v2_marker_authority_custody_for_reload_check,
    preflight_v2_marker_authority_custody_for_sighup,
    preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle,
    AuthorityCustodyPolicySelectorParseError,
    QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Env-var serialization (selector tests mutate the process env)
// ===========================================================================

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
            std::env::var(QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV).ok();
        match value {
            Some(v) => std::env::set_var(
                QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV,
                v,
            ),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(
                QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV,
                v,
            ),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV),
        }
    }
}

// ===========================================================================
// Shared fixtures (mirrors Run 188 / Run 190 test corpus exactly so
// the binding tuple matches the Run 188 validator).
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PRIOR_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-192";
const CUSTODY_KEY_ID: &str = "custody-key-id-192";
const OTHER_CUSTODY_KEY_ID: &str = "custody-key-id-OTHER";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const EXPIRED_AT: u64 = 1_699_999_000;

fn devnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Devnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn testnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Testnet,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn mainnet_domain() -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        TrustBundleEnvironment::Mainnet,
        CHAIN_ID,
        GENESIS_HASH,
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
        GENESIS_HASH.to_string(),
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
        PRIOR_DIGEST,
    ))
}

fn good_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
    class: AuthorityCustodyClass,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: class,
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

/// Run 192 — invoke the reload-check per-surface preflight wrapper
/// with the standard fixture-binding tuple.
fn rc(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    preflight_v2_marker_authority_custody_for_reload_check(
        persisted,
        candidate,
        domain,
        policy,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        loaded,
    )
}

// ===========================================================================
// Selector parsing (default / CLI / env / precedence / invalid)
// ===========================================================================

#[test]
fn selector_parser_default_absent_resolves_to_disabled() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        authority_custody_policy_from_cli_or_env(None).unwrap(),
        AuthorityCustodyPolicy::Disabled
    );
}

#[test]
fn selector_parser_all_canonical_tags_round_trip() {
    let _g = EnvGuard::set(None);
    for (tag, policy) in [
        ("disabled", AuthorityCustodyPolicy::Disabled),
        ("fixture-only", AuthorityCustodyPolicy::FixtureOnly),
        ("devnet-local-allowed", AuthorityCustodyPolicy::DevnetLocalAllowed),
        ("testnet-local-allowed", AuthorityCustodyPolicy::TestnetLocalAllowed),
        (
            "production-custody-required",
            AuthorityCustodyPolicy::ProductionCustodyRequired,
        ),
        (
            "mainnet-production-custody-required",
            AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        ),
    ] {
        assert_eq!(authority_custody_policy_from_selector(tag).unwrap(), policy);
        assert_eq!(
            authority_custody_policy_from_cli_or_env(Some(tag)).unwrap(),
            policy
        );
    }
}

#[test]
fn selector_parser_is_case_insensitive_and_trims_whitespace() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        authority_custody_policy_from_selector("  FIXTURE-ONLY ").unwrap(),
        AuthorityCustodyPolicy::FixtureOnly
    );
    assert_eq!(
        authority_custody_policy_from_selector("Devnet-Local-Allowed").unwrap(),
        AuthorityCustodyPolicy::DevnetLocalAllowed
    );
}

#[test]
fn r1_invalid_cli_selector_value_rejected() {
    let _g = EnvGuard::set(None);
    let e = authority_custody_policy_from_cli_or_env(Some("kms-required")).unwrap_err();
    assert!(matches!(
        e,
        AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
    ));
    let e2 = authority_custody_policy_from_cli_or_env(Some("")).unwrap_err();
    assert_eq!(e2, AuthorityCustodyPolicySelectorParseError::Empty);
    let e3 = authority_custody_policy_from_cli_or_env(Some("   ")).unwrap_err();
    assert_eq!(e3, AuthorityCustodyPolicySelectorParseError::Empty);
}

#[test]
fn r2_invalid_env_selector_value_rejected() {
    let _g = EnvGuard::set(Some("definitely-not-a-policy"));
    let e = authority_custody_policy_env_selector().unwrap_err();
    assert!(matches!(
        e,
        AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
    ));
    let e2 = authority_custody_policy_from_cli_or_env(None).unwrap_err();
    assert!(matches!(
        e2,
        AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
    ));
}

#[test]
fn r2_empty_env_selector_value_rejected() {
    let _g = EnvGuard::set(Some(""));
    let e = authority_custody_policy_env_selector().unwrap_err();
    assert_eq!(e, AuthorityCustodyPolicySelectorParseError::Empty);
}

#[test]
fn r3_unrelated_env_does_not_enable_custody_policy() {
    let _g = EnvGuard::set(None);
    // Even if some neighboring env var is set elsewhere, the
    // custody-policy resolver only reads its own env var.
    std::env::set_var("QBIND_SOME_UNRELATED_ENV_VAR", "fixture-only");
    let resolved = authority_custody_policy_from_cli_or_env(None).unwrap();
    std::env::remove_var("QBIND_SOME_UNRELATED_ENV_VAR");
    assert_eq!(resolved, AuthorityCustodyPolicy::Disabled);
}

#[test]
fn a3_env_fixture_only_resolves_via_env() {
    let _g = EnvGuard::set(Some("fixture-only"));
    assert_eq!(
        authority_custody_policy_env_selector().unwrap().unwrap(),
        AuthorityCustodyPolicy::FixtureOnly
    );
    assert_eq!(
        authority_custody_policy_from_cli_or_env(None).unwrap(),
        AuthorityCustodyPolicy::FixtureOnly
    );
}

#[test]
fn a5_env_testnet_local_allowed_resolves_via_env() {
    let _g = EnvGuard::set(Some("testnet-local-allowed"));
    assert_eq!(
        authority_custody_policy_from_cli_or_env(None).unwrap(),
        AuthorityCustodyPolicy::TestnetLocalAllowed
    );
}

#[test]
fn cli_over_env_precedence_holds_when_both_supplied() {
    // CLI supplies fixture-only, env supplies devnet-local-allowed —
    // CLI wins.
    let _g = EnvGuard::set(Some("devnet-local-allowed"));
    assert_eq!(
        authority_custody_policy_from_cli_or_env(Some("fixture-only")).unwrap(),
        AuthorityCustodyPolicy::FixtureOnly
    );
}

#[test]
fn cli_invalid_with_valid_env_still_errors_does_not_silently_fall_back() {
    let _g = EnvGuard::set(Some("disabled"));
    let e = authority_custody_policy_from_cli_or_env(Some("nope-policy")).unwrap_err();
    assert!(matches!(
        e,
        AuthorityCustodyPolicySelectorParseError::UnknownValue { .. }
    ));
}

// ===========================================================================
// A1 — default selector absent => Disabled => legacy no-custody payload
// remains accepted (bypass variant).
// ===========================================================================

#[test]
fn a1_default_disabled_legacy_no_custody_payload_bypassed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let loaded = AuthorityCustodyLoadStatus::Absent;
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::Disabled,
        &loaded,
    );
    assert_eq!(
        outcome,
        AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied
    );
    assert!(outcome.is_bypassed());
}

// ===========================================================================
// A2 — CLI fixture-only selects FixtureOnly, DevNet fixture custody
// accepted.
// ===========================================================================

#[test]
fn a2_cli_fixture_only_devnet_fixture_attestation_accepted() {
    let _g = EnvGuard::set(None);
    let policy =
        authority_custody_policy_from_cli_or_env(Some("fixture-only")).unwrap();
    assert_eq!(policy, AuthorityCustodyPolicy::FixtureOnly);

    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att =
        good_attestation(TrustBundleEnvironment::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = AuthorityCustodyLoadStatus::Available(att);

    let outcome = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome.is_accept(), "expected accept, got {:?}", outcome);
    match outcome {
        AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(
            LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
        ) => assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
        )),
        other => panic!("expected accepted fixture custody, got {:?}", other),
    }
}

// ===========================================================================
// A3 — env fixture-only on TestNet — fixture custody accepted.
// ===========================================================================

#[test]
fn a3_env_fixture_only_testnet_fixture_attestation_accepted() {
    let _g = EnvGuard::set(Some("fixture-only"));
    let policy = authority_custody_policy_from_cli_or_env(None).unwrap();
    assert_eq!(policy, AuthorityCustodyPolicy::FixtureOnly);

    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome.is_accept(), "expected accept, got {:?}", outcome);
}

// ===========================================================================
// A4 — CLI devnet-local-allowed: DevNet local-operator custody accepted.
// ===========================================================================

#[test]
fn a4_cli_devnet_local_allowed_local_operator_attestation_accepted() {
    let _g = EnvGuard::set(None);
    let policy =
        authority_custody_policy_from_cli_or_env(Some("devnet-local-allowed")).unwrap();
    assert_eq!(policy, AuthorityCustodyPolicy::DevnetLocalAllowed);

    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome.is_accept(), "got {:?}", outcome);
    match outcome {
        AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(
            LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
        ) => assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }
        )),
        other => panic!("expected accepted local operator custody, got {:?}", other),
    }
}

// ===========================================================================
// A5 — env testnet-local-allowed: TestNet local custody accepted (env-source).
// ===========================================================================

#[test]
fn a5_env_testnet_local_allowed_local_operator_accepted() {
    let _g = EnvGuard::set(Some("testnet-local-allowed"));
    let policy = authority_custody_policy_from_cli_or_env(None).unwrap();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A6 — production-custody-required reaches validator and fails closed
// for any custody class (fixture / local / KMS / HSM / RemoteSigner).
// ===========================================================================

#[test]
fn a6_production_custody_required_fixture_fails_closed_unavailable() {
    let _g = EnvGuard::set(None);
    let policy =
        authority_custody_policy_from_cli_or_env(Some("production-custody-required"))
            .unwrap();
    assert_eq!(policy, AuthorityCustodyPolicy::ProductionCustodyRequired);

    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome.is_reject());
    // Either PolicyRefusesCustodyClass or ProductionCustodyUnavailable —
    // both are typed fail-closed outcomes.
    match outcome {
        AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(
            LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
        ) => assert!(
            matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable { .. }
                    | AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }
            ),
            "got {:?}",
            custody_outcome
        ),
        other => panic!("expected typed custody rejection, got {:?}", other),
    }
}

// ===========================================================================
// A7 — mainnet-production-custody-required fails closed; peer-driven
// drain on MainNet refuses unconditionally regardless of metadata.
// ===========================================================================

#[test]
fn a7_mainnet_production_custody_required_fails_closed_and_drain_refuses_mainnet() {
    let _g = EnvGuard::set(None);
    let policy = authority_custody_policy_from_cli_or_env(Some(
        "mainnet-production-custody-required",
    ))
    .unwrap();
    assert_eq!(
        policy,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired
    );

    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    // Even with metadata claiming KMS — fail closed.
    let mut att =
        good_attestation(TrustBundleEnvironment::Mainnet, &candidate, AuthorityCustodyClass::Kms);
    att.governance_authority_class = GovernanceAuthorityClass::GenesisBound;
    let loaded = AuthorityCustodyLoadStatus::Available(att);

    // Reload-check on MainNet: validator fails closed (KMS unavailable).
    let outcome_rc = rc(Some(&persisted), &candidate, &domain, policy, &loaded);
    assert!(outcome_rc.is_reject());

    // Peer-driven drain on MainNet: refused before validation.
    let outcome_drain = preflight_v2_marker_authority_custody_for_peer_driven_drain(
        Some(&persisted),
        &candidate,
        &domain,
        policy,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &loaded,
    );
    assert!(outcome_drain.is_mainnet_peer_driven_apply_refused());
}

// ===========================================================================
// A8 — under Disabled, the routing wrapper does not change
// GenesisBound proof behavior (legacy no-custody bypass variant).
// ===========================================================================

#[test]
fn a8_disabled_does_not_change_genesisbound_proof_behavior() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::Disabled,
        &AuthorityCustodyLoadStatus::Absent,
    );
    // Bypass — no validator invocation, no acceptance/rejection of
    // governance class.
    assert!(outcome.is_bypassed());
}

// ===========================================================================
// A9 — mutating reload-apply DevNet fixture custody under FixtureOnly
// accepts where lifecycle / governance / custody all pass.
// ===========================================================================

#[test]
fn a9_mutating_reload_apply_devnet_fixture_under_fixture_only_accepts() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);

    let outcome = preflight_v2_marker_authority_custody_for_reload_apply(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &loaded,
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);
}

// ===========================================================================
// A10 — live inbound 0x05 receives the selected policy.
// ===========================================================================

#[test]
fn a10_live_inbound_0x05_receives_selected_policy() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);

    let outcome = preflight_v2_marker_authority_custody_for_live_inbound_0x05(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &loaded,
    );
    assert!(outcome.is_accept(), "got {:?}", outcome);

    // And the same surface fails closed under Disabled+absent (legacy
    // bypass) versus required-but-absent under FixtureOnly+absent.
    let outcome_absent_disabled = preflight_v2_marker_authority_custody_for_live_inbound_0x05(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::Disabled,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome_absent_disabled.is_bypassed());

    let outcome_absent_fixture = preflight_v2_marker_authority_custody_for_live_inbound_0x05(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome_absent_fixture.is_required_but_absent());
}

// ===========================================================================
// Source reachability — the resolved policy reaches all seven
// production-context per-surface preflight wrappers.
// ===========================================================================

#[test]
fn selected_policy_reaches_all_seven_production_context_helpers() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let policy = AuthorityCustodyPolicy::FixtureOnly;

    macro_rules! call {
        ($f:ident) => {{
            $f(
                Some(&persisted),
                &candidate,
                &domain,
                policy,
                GovernanceAuthorityClass::GenesisBound,
                LocalLifecycleAction::Rotate,
                DIGEST_2,
                2,
                Some(CUSTODY_KEY_ID),
                NOW,
                &loaded,
            )
        }};
    }

    assert!(call!(preflight_v2_marker_authority_custody_for_reload_check).is_accept());
    assert!(call!(preflight_v2_marker_authority_custody_for_reload_apply).is_accept());
    assert!(call!(preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle).is_accept());
    assert!(call!(preflight_v2_marker_authority_custody_for_sighup).is_accept());
    assert!(call!(
        preflight_v2_marker_authority_custody_for_local_peer_candidate_check
    )
    .is_accept());
    assert!(call!(preflight_v2_marker_authority_custody_for_live_inbound_0x05).is_accept());
    // Devnet candidate -> peer-driven drain runs the validator path.
    assert!(call!(preflight_v2_marker_authority_custody_for_peer_driven_drain).is_accept());
}

// ===========================================================================
// R4 — no-custody payload rejected under FixtureOnly.
// ===========================================================================

#[test]
fn r4_no_custody_payload_rejected_under_fixture_only() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R5 — no-custody payload rejected under DevnetLocalAllowed.
// ===========================================================================

#[test]
fn r5_no_custody_payload_rejected_under_devnet_local_allowed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
}

// ===========================================================================
// R6 — fixture custody rejected under ProductionCustodyRequired.
// R7 — local operator custody rejected under ProductionCustodyRequired.
// ===========================================================================

#[test]
fn r6_fixture_custody_rejected_under_production_custody_required() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        &loaded,
    );
    assert!(outcome.is_reject());
}

#[test]
fn r7_local_operator_custody_rejected_under_production_custody_required() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        &loaded,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R8 — fixture custody rejected on MainNet.
// R9 — local custody rejected on MainNet.
// ===========================================================================

#[test]
fn r8_fixture_custody_rejected_on_mainnet_under_fixture_only_validator() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let att = good_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    // Reload-check on MainNet under FixtureOnly: validator must
    // fail closed (fixture custody refused for MainNet).
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        &loaded,
    );
    assert!(outcome.is_reject());
}

#[test]
fn r9_local_custody_rejected_on_mainnet_under_devnet_local_validator() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    let att = good_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &loaded,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R10 — DevNet local custody rejected under TestnetLocalAllowed.
// R11 — TestNet local custody rejected under DevnetLocalAllowed.
// ===========================================================================

#[test]
fn r10_devnet_local_custody_rejected_under_testnet_local_allowed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        &loaded,
    );
    assert!(outcome.is_reject());
}

#[test]
fn r11_testnet_local_custody_rejected_under_devnet_local_allowed() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let domain = testnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Testnet);
    let att = good_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        &loaded,
    );
    assert!(outcome.is_reject());
}

// ===========================================================================
// R12 — KMS placeholder rejected as unavailable under
// ProductionCustodyRequired.
// R13 — HSM placeholder rejected as unavailable.
// R14 — RemoteSigner placeholder rejected as unavailable.
// ===========================================================================

#[test]
fn r12_r13_r14_production_placeholders_rejected_as_unavailable() {
    for class in [
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::RemoteSigner,
    ] {
        let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
        let domain = devnet_domain();
        let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
        let att = good_attestation(TrustBundleEnvironment::Devnet, &candidate, class);
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        let outcome = rc(
            Some(&persisted),
            &candidate,
            &domain,
            AuthorityCustodyPolicy::ProductionCustodyRequired,
            &loaded,
        );
        assert!(outcome.is_reject(), "{:?} should reject", class);
    }
}

// ===========================================================================
// R15 — malformed custody metadata rejected (Run 190 short-circuit).
// ===========================================================================

#[test]
fn r15_malformed_custody_metadata_rejected_short_circuits_validator() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let loaded = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic".to_string(),
        },
    );
    let outcome = rc(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        &loaded,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R16–R23 — wrong-binding rejections via the fixture-only policy.
// ===========================================================================

fn run_with_attestation(
    domain: &AuthorityTrustDomain,
    candidate: &PersistentAuthorityStateRecordV2,
    persisted: &PersistentAuthorityStateRecordVersioned,
    att: AuthorityCustodyAttestation,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    let loaded = AuthorityCustodyLoadStatus::Available(att);
    rc(
        Some(persisted),
        candidate,
        domain,
        AuthorityCustodyPolicy::FixtureOnly,
        &loaded,
    )
}

#[test]
fn r16_wrong_environment_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.environment = TrustBundleEnvironment::Testnet;
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r17_wrong_chain_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.chain_id = OTHER_CHAIN.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r18_wrong_genesis_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.genesis_hash = OTHER_GENESIS.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r19_wrong_authority_root_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r20_wrong_signing_key_fingerprint_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.bundle_signing_key_fingerprint = KEY_A.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r21_wrong_candidate_digest_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.candidate_digest = DIGEST_OTHER.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r22_wrong_authority_domain_sequence_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.authority_domain_sequence = 99;
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r23_expired_attestation_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.expires_at_unix = Some(EXPIRED_AT);
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

// ===========================================================================
// R24 — custody key id mismatch rejected.
// R25 — unsupported custody suite rejected.
// ===========================================================================

#[test]
fn r24_custody_key_id_mismatch_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_key_id = OTHER_CUSTODY_KEY_ID.to_string();
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

#[test]
fn r25_unsupported_custody_suite_rejected() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let mut att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_suite_id = 0xFE;
    let outcome = run_with_attestation(&domain, &candidate, &persisted, att);
    assert!(outcome.is_reject());
}

// ===========================================================================
// R26 — validation-only rejection writes no marker and no sequence.
// R27 — mutating rejection produces no Run 070 call, no live trust
//   swap, no session eviction, no sequence write, no marker write.
// ===========================================================================
//
// The wrappers are pure data transforms — they cannot themselves
// write a marker, advance a sequence, swap live trust state, evict
// sessions, or invoke Run 070, so the *only* observable behavior
// available to assert is the typed rejection outcome. Test the
// validation-only AND the mutating routing wrappers under a rejection
// scenario and assert the typed reject.

#[test]
fn r26_validation_only_rejection_is_pure_no_mutation_observable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = preflight_v2_marker_authority_custody_for_local_peer_candidate_check(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome.is_required_but_absent());
    // Re-running the wrapper is idempotent: the helper has no I/O, so
    // a second call yields exactly the same typed rejection.
    let outcome2 = preflight_v2_marker_authority_custody_for_local_peer_candidate_check(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert_eq!(outcome, outcome2);
}

#[test]
fn r27_mutating_rejection_is_pure_no_mutation_observable() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);
    let loaded = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic".to_string(),
        },
    );
    let outcome = preflight_v2_marker_authority_custody_for_reload_apply(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &loaded,
    );
    assert!(outcome.is_malformed_payload());
    assert!(outcome.is_reject());
}

// ===========================================================================
// R28 — live inbound 0x05 invalid custody-metadata candidate is not
// propagated, staged, or applied.
// ===========================================================================

#[test]
fn r28_live_inbound_0x05_invalid_custody_not_propagated() {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let domain = devnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Devnet);

    // Malformed payload — fail closed before validator.
    let malformed = AuthorityCustodyLoadStatus::Malformed(
        AuthorityCustodyAttestationPayloadParseError::Json {
            error: "synthetic".to_string(),
        },
    );
    let outcome_malformed = preflight_v2_marker_authority_custody_for_live_inbound_0x05(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &malformed,
    );
    assert!(outcome_malformed.is_malformed_payload());

    // Absent under FixtureOnly — required-but-absent.
    let outcome_absent = preflight_v2_marker_authority_custody_for_live_inbound_0x05(
        Some(&persisted),
        &candidate,
        &domain,
        AuthorityCustodyPolicy::FixtureOnly,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &AuthorityCustodyLoadStatus::Absent,
    );
    assert!(outcome_absent.is_required_but_absent());
}

// ===========================================================================
// R29 — MainNet peer-driven apply remains refused even with
// MainnetProductionCustodyRequired and metadata claiming KMS/HSM.
// ===========================================================================

#[test]
fn r29_mainnet_peer_driven_apply_refused_under_mainnet_production_required_kms_hsm_metadata() {
    let _g = EnvGuard::set(None);
    let policy = authority_custody_policy_from_cli_or_env(Some(
        "mainnet-production-custody-required",
    ))
    .unwrap();

    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let domain = mainnet_domain();
    let persisted = prior_versioned(TrustBundleEnvironment::Mainnet);
    for class in [AuthorityCustodyClass::Kms, AuthorityCustodyClass::Hsm] {
        let att = good_attestation(TrustBundleEnvironment::Mainnet, &candidate, class);
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        let outcome = preflight_v2_marker_authority_custody_for_peer_driven_drain(
            Some(&persisted),
            &candidate,
            &domain,
            policy,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
            &loaded,
        );
        assert!(
            outcome.is_mainnet_peer_driven_apply_refused(),
            "MainNet peer-driven apply must remain refused for {:?}, got {:?}",
            class,
            outcome
        );
    }
}
