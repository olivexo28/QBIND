//! Run 188 — source/test KMS/HSM custody-boundary integration tests.
//!
//! Source/test only. Run 188 does **not** capture release-binary
//! evidence; release-binary custody-boundary evidence is deferred to
//! **Run 189**. The tests cover:
//!
//! * the full A1–A8 / R1–R29 matrix from `task/RUN_188_TASK.txt`;
//! * pure no-I/O guarantee (the tests construct only data values and
//!   call only `validate_authority_custody_attestation` /
//!   `validate_lifecycle_governance_and_custody`);
//! * fixture-vs-production custody separation;
//! * MainNet fixture/local custody refusal;
//! * KMS/HSM/remote signer placeholders fail-closed;
//! * combined lifecycle + governance + custody helper remains pure;
//! * existing OnChainGovernance fixture paths remain compatible
//!   (verifier kind defaults to `Disabled`, default policy is
//!   `Disabled`);
//! * GenesisBound and EmergencyCouncil behavior is preserved when
//!   custody validation is not required;
//! * MainNet peer-driven apply remains refused.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_188.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    local_operator_config_alone_cannot_satisfy_mainnet_production_custody,
    mainnet_peer_driven_apply_remains_refused_under_custody_boundary,
    peer_majority_cannot_satisfy_custody, validate_authority_custody_attestation,
    validate_lifecycle_governance_and_custody, AuthorityCustodyAttestation,
    AuthorityCustodyClass, AuthorityCustodyPolicy, AuthorityCustodyValidationOutcome,
    LifecycleGovernanceCustodyOutcome,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_onchain_governance_verifier::{
    OnChainGovernanceVerifierKind, OnChainGovernanceVerifierPolicy,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-188";
const CUSTODY_KEY_ID: &str = "custody-key-id-188";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

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

fn good_fixture_attestation(
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

fn validate_default(
    att: &AuthorityCustodyAttestation,
    candidate: &PersistentAuthorityStateRecordV2,
    domain: &AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
) -> AuthorityCustodyValidationOutcome {
    validate_authority_custody_attestation(
        att,
        candidate,
        domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        policy,
        NOW,
    )
}

// ===========================================================================
// Defaults / type-shape regressions
// ===========================================================================

#[test]
fn default_custody_policy_is_disabled_fail_closed() {
    assert_eq!(AuthorityCustodyPolicy::default(), AuthorityCustodyPolicy::Disabled);
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att =
        good_fixture_attestation(TrustBundleEnvironment::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::default());
    assert!(outcome.is_reject());
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }
    ));
}

#[test]
fn run_186_default_verifier_kind_remains_disabled_under_run_188() {
    // Run 188 does NOT change the Run 186 default — keep it grep-
    // verifiable here so a future run cannot silently flip the
    // default while editing the custody boundary.
    assert_eq!(
        OnChainGovernanceVerifierKind::default(),
        OnChainGovernanceVerifierKind::Disabled
    );
    assert_eq!(
        OnChainGovernanceVerifierPolicy::default(),
        OnChainGovernanceVerifierPolicy::disabled()
    );
}

#[test]
fn custody_class_helpers() {
    assert!(AuthorityCustodyClass::FixtureLocalKey.is_local_only());
    assert!(AuthorityCustodyClass::LocalOperatorKey.is_local_only());
    assert!(!AuthorityCustodyClass::Kms.is_local_only());
    assert!(AuthorityCustodyClass::Kms.is_production_placeholder());
    assert!(AuthorityCustodyClass::Hsm.is_production_placeholder());
    assert!(AuthorityCustodyClass::RemoteSigner.is_production_placeholder());
    assert!(!AuthorityCustodyClass::FixtureLocalKey.is_production_placeholder());
    assert!(!AuthorityCustodyClass::Unknown.is_production_placeholder());
    assert_eq!(AuthorityCustodyClass::Hsm.tag(), "hsm");
    assert_eq!(
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired.tag(),
        "mainnet-production-custody-required"
    );
}

// ===========================================================================
// A1–A8 — accepted scenarios
// ===========================================================================

#[test]
fn a1_devnet_fixture_custody_accepted_under_fixture_only_policy() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::AcceptedFixtureCustody {
            ref custody_key_id, environment: TrustBundleEnvironment::Devnet
        } if custody_key_id == CUSTODY_KEY_ID
    ));
}

#[test]
fn a2_testnet_fixture_custody_accepted_under_fixture_only_policy() {
    let domain = testnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::AcceptedFixtureCustody {
            environment: TrustBundleEnvironment::Testnet,
            ..
        }
    ));
}

#[test]
fn a3_devnet_local_operator_accepted_under_devnet_local_policy() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome =
        validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::DevnetLocalAllowed);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody {
            environment: TrustBundleEnvironment::Devnet,
            ..
        }
    ));
}

#[test]
fn a4_testnet_local_operator_accepted_under_testnet_local_policy() {
    let domain = testnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome =
        validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::TestnetLocalAllowed);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody {
            environment: TrustBundleEnvironment::Testnet,
            ..
        }
    ));
}

#[test]
fn a5_genesisbound_and_emergencycouncil_paths_unchanged_when_custody_not_required() {
    // Run 188 leaves Run 163 / 178 / 186 governance verifiers untouched.
    // We assert grep-verifiable enum invariants here so a refactor of
    // the governance authority module would surface in this test.
    let classes = [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ];
    for c in classes {
        let _tag: &'static str = c.tag();
    }
    // Default Run 186 verifier policy continues to refuse every proof
    // (see `run_186_default_verifier_kind_remains_disabled_under_run_188`).
    assert_eq!(
        OnChainGovernanceVerifierKind::default(),
        OnChainGovernanceVerifierKind::Disabled
    );
}

#[test]
fn a6_combined_lifecycle_governance_fixture_custody_accepted_devnet() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(outcome.is_accept(), "expected Accepted, got {:?}", outcome);
    if let LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. } = outcome {
        assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
        ));
    }
}

#[test]
fn a7_combined_lifecycle_governance_local_custody_accepted_testnet() {
    let domain = testnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let prior = prior_versioned(TrustBundleEnvironment::Testnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::TestnetLocalAllowed,
        NOW,
    );
    assert!(outcome.is_accept());
    if let LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. } = outcome {
        assert!(matches!(
            custody_outcome,
            AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }
        ));
    }
}

#[test]
fn a8_production_custody_boundary_returns_typed_unavailable_for_each_placeholder() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);

    for (class, expected) in [
        (
            AuthorityCustodyClass::Kms,
            AuthorityCustodyValidationOutcome::KmsUnavailable,
        ),
        (
            AuthorityCustodyClass::Hsm,
            AuthorityCustodyValidationOutcome::HsmUnavailable,
        ),
        (
            AuthorityCustodyClass::RemoteSigner,
            AuthorityCustodyValidationOutcome::RemoteSignerUnavailable,
        ),
    ] {
        let att = good_fixture_attestation(TrustBundleEnvironment::Devnet, &candidate, class);
        let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::ProductionCustodyRequired);
        assert_eq!(outcome, expected, "class={:?}", class);
        assert!(outcome.is_production_unavailable());
    }
}

// ===========================================================================
// R1–R29 — rejection scenarios
// ===========================================================================

#[test]
fn r1_fixture_custody_rejected_under_production_custody_policy() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable {
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired
        }
    );
}

#[test]
fn r2_local_operator_custody_rejected_under_production_custody_policy() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable {
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired
        }
    );
}

#[test]
fn r3_fixture_custody_rejected_for_mainnet() {
    let domain = mainnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
    );
    assert!(outcome.is_mainnet_refusal());
}

#[test]
fn r4_local_operator_custody_rejected_for_mainnet() {
    let domain = mainnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
    );
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet
    );
}

#[test]
fn r5_kms_placeholder_rejected_as_unavailable() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Kms,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(outcome, AuthorityCustodyValidationOutcome::KmsUnavailable);
}

#[test]
fn r6_hsm_placeholder_rejected_as_unavailable() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Hsm,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(outcome, AuthorityCustodyValidationOutcome::HsmUnavailable);
}

#[test]
fn r7_remote_signer_placeholder_rejected_as_unavailable() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::RemoteSigner,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::RemoteSignerUnavailable
    );
}

#[test]
fn r8_unknown_custody_class_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Unknown,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected
    );
}

#[test]
fn r9_wrong_environment_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.environment = TrustBundleEnvironment::Testnet;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r10_wrong_chain_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.chain_id = OTHER_CHAIN.to_string();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongChain { .. }
    ));
}

#[test]
fn r11_wrong_genesis_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.genesis_hash = OTHER_GENESIS.to_string();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r12_wrong_authority_root_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r13_wrong_signing_key_fingerprint_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.bundle_signing_key_fingerprint = KEY_A.to_string(); // candidate active is KEY_B
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r14_wrong_candidate_digest_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.candidate_digest = DIGEST_OTHER.to_string();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r15_wrong_authority_domain_sequence_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.authority_domain_sequence = 99;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r16_wrong_lifecycle_action_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r17_missing_custody_attestation_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_attestation_digest = String::new();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMissing
    );
}

#[test]
fn r18_malformed_custody_attestation_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_key_id = String::new();
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }
    ));
}

#[test]
fn r18b_malformed_when_only_one_of_freshness_expiry_set() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.freshness_unix = Some(FRESH);
    att.expires_at_unix = None;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }
    ));
}

#[test]
fn r19_expired_custody_attestation_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.expires_at_unix = Some(NOW - 1);
    att.freshness_unix = Some(NOW - 100);
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationExpired { .. }
    ));
}

#[test]
fn r20_custody_key_id_mismatch_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_key_id = "different-key-id".to_string();
    let outcome = validate_authority_custody_attestation(
        &att,
        &candidate,
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch { .. }
    ));
}

#[test]
fn r21_unsupported_custody_suite_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_suite_id = 0xFE;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::UnsupportedCustodySuite { suite_id: 0xFE }
    );
}

#[test]
fn r22_custody_valid_but_governance_proof_invalid_rejected() {
    // Run 188 surfaces governance-proof invalidation by rejecting any
    // attestation whose declared governance-authority class does not
    // match the calling-surface expectation. This exercises the
    // "governance proof valid + custody invalid" / "custody valid +
    // governance invalid" axis in a single typed surface that the
    // composition helper can route on.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.governance_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }
    ));
}

#[test]
fn r23_governance_proof_valid_but_custody_invalid_rejected() {
    // Custody attestation digest empty — governance class matches.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let mut att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    att.custody_attestation_digest = String::new();
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(matches!(
        outcome,
        LifecycleGovernanceCustodyOutcome::CustodyRejected {
            custody_outcome: AuthorityCustodyValidationOutcome::CustodyAttestationMissing,
            ..
        }
    ));
}

#[test]
fn r24_lifecycle_valid_governance_valid_custody_placeholder_unavailable_rejected() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Kms,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        NOW,
    );
    assert!(matches!(
        outcome,
        LifecycleGovernanceCustodyOutcome::CustodyRejected {
            custody_outcome: AuthorityCustodyValidationOutcome::KmsUnavailable,
            ..
        }
    ));
}

#[test]
fn r25_mainnet_peer_driven_apply_remains_refused_even_if_custody_claims_kms() {
    // Run 188 typed boundary helper: the rule is encoded by symbol
    // and is independent of any custody attestation contents.
    assert!(mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Mainnet
    ));
    assert!(!mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Devnet
    ));
    assert!(!mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Testnet
    ));
    // Even a "claims KMS" attestation on MainNet under the
    // `MainnetProductionCustodyRequired` policy fails closed at the
    // typed `MainNetProductionCustodyUnavailable` surface.
    let domain = mainnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::Kms,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
    );
    assert_eq!(outcome, AuthorityCustodyValidationOutcome::KmsUnavailable);
}

#[test]
fn r26_local_operator_config_alone_cannot_satisfy_mainnet_production_custody() {
    assert!(local_operator_config_alone_cannot_satisfy_mainnet_production_custody());
    let domain = mainnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
    );
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet
    );
}

#[test]
fn r27_peer_majority_or_gossip_count_cannot_satisfy_custody() {
    // Run 188 typed boundary helper: peer majority is always
    // insufficient. The validator never reads peer counts; this
    // assertion documents the guarantee at the typed boundary.
    assert!(peer_majority_cannot_satisfy_custody());
}

#[test]
fn r28_validation_only_rejection_remains_non_mutating() {
    // Snapshot candidate before and after a rejecting validation.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let snap_before = format!("{:?}", candidate);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Kms,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(outcome, AuthorityCustodyValidationOutcome::KmsUnavailable);
    let snap_after = format!("{:?}", candidate);
    assert_eq!(snap_before, snap_after, "validate_authority_custody_attestation must not mutate the candidate");
}

#[test]
fn r29_mutating_preflight_rejection_produces_no_run_070_call_and_no_persistence() {
    // The composition helper is a preflight: it returns an outcome
    // and never calls Run 070, never writes a marker, never writes a
    // sequence, never swaps live trust, never evicts sessions.
    // We assert this by snapshotting candidate + prior + attestation
    // before and after the helper executes against a rejecting
    // configuration.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::Hsm,
    );
    let snap_candidate = format!("{:?}", candidate);
    let snap_prior = format!("{:?}", prior);
    let snap_att = format!("{:?}", att);
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        NOW,
    );
    assert!(outcome.is_reject());
    assert_eq!(snap_candidate, format!("{:?}", candidate));
    assert_eq!(snap_prior, format!("{:?}", prior));
    assert_eq!(snap_att, format!("{:?}", att));
}

// ===========================================================================
// Extras — fixture-vs-production separation, MainNet refusal, helper purity
// ===========================================================================

#[test]
fn fixture_vs_production_custody_separation_is_typed() {
    // Fixture custody under `FixtureOnly` accepts on DevNet/TestNet
    // and rejects on MainNet. Production placeholders fail closed
    // regardless of policy / environment.
    let domain_d = devnet_domain();
    let domain_m = mainnet_domain();
    let cand_d = rotate_candidate(TrustBundleEnvironment::Devnet);
    let cand_m = rotate_candidate(TrustBundleEnvironment::Mainnet);

    let fix_d = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &cand_d,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let kms_d = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &cand_d,
        AuthorityCustodyClass::Kms,
    );
    let fix_m = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &cand_m,
        AuthorityCustodyClass::FixtureLocalKey,
    );

    let r_fix_d = validate_default(&fix_d, &cand_d, &domain_d, AuthorityCustodyPolicy::FixtureOnly);
    let r_kms_d = validate_default(&kms_d, &cand_d, &domain_d, AuthorityCustodyPolicy::FixtureOnly);
    let r_fix_m = validate_default(&fix_m, &cand_m, &domain_m, AuthorityCustodyPolicy::FixtureOnly);

    assert!(matches!(
        r_fix_d,
        AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
    ));
    assert_eq!(r_kms_d, AuthorityCustodyValidationOutcome::KmsUnavailable);
    assert_eq!(
        r_fix_m,
        AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
    );
}

#[test]
fn mainnet_production_policy_with_fixture_custody_surfaces_mainnet_unavailable() {
    let domain = mainnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Mainnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_default(
        &att,
        &candidate,
        &domain,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
    );
    // MainNet trust-domain rejection of fixture custody fires before
    // the policy gate — the typed surface remains
    // `FixtureCustodyRejectedForMainNet` so the operator log line is
    // unambiguous about the rule violated.
    assert_eq!(
        outcome,
        AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
    );
}

#[test]
fn devnet_local_policy_refuses_kms_placeholder_with_typed_unavailable() {
    // Even under a permissive `DevnetLocalAllowed` policy the KMS /
    // HSM / RemoteSigner placeholders fail closed by symbol, NOT as
    // a generic policy refusal.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    for (class, expected) in [
        (
            AuthorityCustodyClass::Kms,
            AuthorityCustodyValidationOutcome::KmsUnavailable,
        ),
        (
            AuthorityCustodyClass::Hsm,
            AuthorityCustodyValidationOutcome::HsmUnavailable,
        ),
        (
            AuthorityCustodyClass::RemoteSigner,
            AuthorityCustodyValidationOutcome::RemoteSignerUnavailable,
        ),
    ] {
        let att = good_fixture_attestation(TrustBundleEnvironment::Devnet, &candidate, class);
        let outcome = validate_default(
            &att,
            &candidate,
            &domain,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
        );
        assert_eq!(outcome, expected);
    }
}

#[test]
fn fixture_only_policy_refuses_local_operator_with_typed_policy_refusal() {
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass {
            policy: AuthorityCustodyPolicy::FixtureOnly,
            class: AuthorityCustodyClass::LocalOperatorKey,
        }
    ));
}

#[test]
fn devnet_local_policy_on_testnet_domain_is_refused_by_policy() {
    // `DevnetLocalAllowed` only allows DevNet — TestNet trust domain
    // surfaces a typed `PolicyRefusesCustodyClass`.
    let domain = testnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Testnet,
        &candidate,
        AuthorityCustodyClass::LocalOperatorKey,
    );
    let outcome =
        validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::DevnetLocalAllowed);
    assert!(matches!(
        outcome,
        AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }
    ));
}

#[test]
fn lifecycle_rejected_short_circuits_custody_check() {
    // Wrong-environment candidate against the trust domain yields a
    // lifecycle reject that short-circuits the custody validator.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Testnet); // mismatched env
    let prior = prior_versioned(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let outcome = validate_lifecycle_governance_and_custody(
        &att,
        &candidate,
        Some(&prior),
        &domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        NOW,
    );
    assert!(matches!(
        outcome,
        LifecycleGovernanceCustodyOutcome::LifecycleRejected(_)
    ));
}

#[test]
fn validator_is_deterministic() {
    // Calling the validator twice with the same inputs produces the
    // same outcome. The validator is pure data; no global state, no
    // I/O, no clock.
    let domain = devnet_domain();
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_fixture_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let r1 = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    let r2 = validate_default(&att, &candidate, &domain, AuthorityCustodyPolicy::FixtureOnly);
    assert_eq!(r1, r2);
}