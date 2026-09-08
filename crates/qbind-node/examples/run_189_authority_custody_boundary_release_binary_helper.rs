//! Run 189 — release-built helper that exercises the Run 188
//! authority custody-boundary corpus end-to-end **in release mode**
//! through the production library symbols
//! [`qbind_node::pqc_authority_custody`].
//!
//! Per `task/RUN_189_TASK.txt`, Run 189 is a **release-binary
//! evidence / boundary** run for the Run 188 source/test typed
//! authority-custody boundary. This helper is fixture-tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–188 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state;
//! * does NOT open a P2P socket;
//! * does NOT implement any real KMS / HSM / cloud KMS / PKCS#11 /
//!   remote-signer backend;
//! * never elevates a fixture / local-operator custody acceptance
//!   into MainNet production custody (MainNet always refuses fixture
//!   custody as `FixtureCustodyRejectedForMainNet` and local-operator
//!   custody as `LocalCustodyRejectedForMainNet`, ahead of the policy
//!   gate); production-class placeholders on MainNet under the
//!   `MainnetProductionCustodyRequired` policy continue to fail closed
//!   as the typed `KmsUnavailable` / `HsmUnavailable` /
//!   `RemoteSignerUnavailable` (custody-class-specific routing layered
//!   ahead of the policy gate);
//! * exists alongside (and does NOT replace) the Run 188 source/test
//!   target
//!   `crates/qbind-node/tests/run_188_authority_custody_boundary_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected>\t<match>\t<no_mutation>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable expected map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps
//! <OUT_DIR>/scenarios/<id>/policy.txt
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/scenarios/<id>/note.txt
//! <OUT_DIR>/custody_class_table.txt   # custody class helpers + policy helpers
//! <OUT_DIR>/named_helpers_table.txt   # MainNet-refusal / peer-majority / local-operator helpers
//! <OUT_DIR>/no_mutation_evidence.txt  # bit-equality of inputs across reject scenarios
//! <OUT_DIR>/determinism_evidence.txt  # 32 dispatches yield identical outcome
//! <OUT_DIR>/helper_summary.txt        # release-built helper verdict
//! ```
//!
//! The helper exits non-zero if any scenario does not match its
//! expected typed outcome, mirroring the Run 168 / Run 178 / Run 185 /
//! Run 187 release-built-helper pattern.
//!
//! Usage:
//! ```text
//! run_189_authority_custody_boundary_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 188 test target so the
// typed custody-boundary semantics carry over end-to-end in release mode.
// ---------------------------------------------------------------------------

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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-189";
const CUSTODY_KEY_ID: &str = "custody-key-id-189";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror `tests/run_188_authority_custody_boundary_tests.rs`.
// ---------------------------------------------------------------------------

fn domain_for(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN_ID, GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
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
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

fn validate(
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

// ---------------------------------------------------------------------------
// Expected typed outcome — symbolic labels for the boundary surface and for
// the combined lifecycle/governance/custody helper surface.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    AcceptedFixtureCustody,
    AcceptedLocalOperatorCustody,
    ProductionCustodyUnavailable,
    KmsUnavailable,
    HsmUnavailable,
    RemoteSignerUnavailable,
    UnknownCustodyClassRejected,
    WrongEnvironment,
    WrongChain,
    WrongGenesis,
    WrongAuthorityRoot,
    WrongSigningKeyFingerprint,
    WrongCandidateDigest,
    WrongAuthorityDomainSequence,
    WrongLifecycleAction,
    CustodyAttestationMissing,
    CustodyAttestationMalformed,
    CustodyAttestationExpired,
    CustodyKeyIdMismatch,
    UnsupportedCustodySuite,
    FixtureCustodyRejectedForMainNet,
    LocalCustodyRejectedForMainNet,
    /// MainnetProductionCustodyRequired policy reaches its
    /// MainNet-specific "production custody unavailable" arm only
    /// on a non-MainNet trust domain (since MainNet itself rejects
    /// fixture/local custody by symbol earlier — see
    /// `pqc_authority_custody.rs` step 16). The Run 188 A1–A8 /
    /// R1–R29 corpus does not synthesise that DevNet/TestNet +
    /// MainnetProductionCustodyRequired combination, but the
    /// matcher arm and label intentionally stay wired so the
    /// production outcome remains symmetrical with this `Expect`
    /// enum. `#[allow(dead_code)]` is therefore a deliberate,
    /// documented assertion of that symmetry.
    #[allow(dead_code)]
    MainNetProductionCustodyUnavailable,
    PolicyRefusesCustodyClass,
    /// Combined helper surface accept.
    ComboAccepted,
    /// Combined helper surface custody-rejected.
    ComboCustodyRejected,
    /// Combined helper surface lifecycle-rejected.
    ComboLifecycleRejected,
}

impl Expect {
    fn label(&self) -> &'static str {
        match self {
            Expect::AcceptedFixtureCustody => "accepted_fixture_custody",
            Expect::AcceptedLocalOperatorCustody => "accepted_local_operator_custody",
            Expect::ProductionCustodyUnavailable => "production_custody_unavailable",
            Expect::KmsUnavailable => "kms_unavailable",
            Expect::HsmUnavailable => "hsm_unavailable",
            Expect::RemoteSignerUnavailable => "remote_signer_unavailable",
            Expect::UnknownCustodyClassRejected => "unknown_custody_class_rejected",
            Expect::WrongEnvironment => "wrong_environment",
            Expect::WrongChain => "wrong_chain",
            Expect::WrongGenesis => "wrong_genesis",
            Expect::WrongAuthorityRoot => "wrong_authority_root",
            Expect::WrongSigningKeyFingerprint => "wrong_signing_key_fingerprint",
            Expect::WrongCandidateDigest => "wrong_candidate_digest",
            Expect::WrongAuthorityDomainSequence => "wrong_authority_domain_sequence",
            Expect::WrongLifecycleAction => "wrong_lifecycle_action",
            Expect::CustodyAttestationMissing => "custody_attestation_missing",
            Expect::CustodyAttestationMalformed => "custody_attestation_malformed",
            Expect::CustodyAttestationExpired => "custody_attestation_expired",
            Expect::CustodyKeyIdMismatch => "custody_key_id_mismatch",
            Expect::UnsupportedCustodySuite => "unsupported_custody_suite",
            Expect::FixtureCustodyRejectedForMainNet => "fixture_custody_rejected_for_mainnet",
            Expect::LocalCustodyRejectedForMainNet => "local_custody_rejected_for_mainnet",
            Expect::MainNetProductionCustodyUnavailable => "mainnet_production_custody_unavailable",
            Expect::PolicyRefusesCustodyClass => "policy_refuses_custody_class",
            Expect::ComboAccepted => "combo_accepted",
            Expect::ComboCustodyRejected => "combo_custody_rejected",
            Expect::ComboLifecycleRejected => "combo_lifecycle_rejected",
        }
    }

    fn matches_boundary(&self, outcome: &AuthorityCustodyValidationOutcome) -> bool {
        match (self, outcome) {
            (Expect::AcceptedFixtureCustody, AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }) => true,
            (Expect::AcceptedLocalOperatorCustody, AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }) => true,
            (Expect::ProductionCustodyUnavailable, AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable { .. }) => true,
            (Expect::KmsUnavailable, AuthorityCustodyValidationOutcome::KmsUnavailable) => true,
            (Expect::HsmUnavailable, AuthorityCustodyValidationOutcome::HsmUnavailable) => true,
            (Expect::RemoteSignerUnavailable, AuthorityCustodyValidationOutcome::RemoteSignerUnavailable) => true,
            (Expect::UnknownCustodyClassRejected, AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected) => true,
            (Expect::WrongEnvironment, AuthorityCustodyValidationOutcome::WrongEnvironment { .. }) => true,
            (Expect::WrongChain, AuthorityCustodyValidationOutcome::WrongChain { .. }) => true,
            (Expect::WrongGenesis, AuthorityCustodyValidationOutcome::WrongGenesis { .. }) => true,
            (Expect::WrongAuthorityRoot, AuthorityCustodyValidationOutcome::WrongAuthorityRoot { .. }) => true,
            (Expect::WrongSigningKeyFingerprint, AuthorityCustodyValidationOutcome::WrongSigningKeyFingerprint { .. }) => true,
            (Expect::WrongCandidateDigest, AuthorityCustodyValidationOutcome::WrongCandidateDigest { .. }) => true,
            (Expect::WrongAuthorityDomainSequence, AuthorityCustodyValidationOutcome::WrongAuthorityDomainSequence { .. }) => true,
            (Expect::WrongLifecycleAction, AuthorityCustodyValidationOutcome::WrongLifecycleAction { .. }) => true,
            (Expect::CustodyAttestationMissing, AuthorityCustodyValidationOutcome::CustodyAttestationMissing) => true,
            (Expect::CustodyAttestationMalformed, AuthorityCustodyValidationOutcome::CustodyAttestationMalformed { .. }) => true,
            (Expect::CustodyAttestationExpired, AuthorityCustodyValidationOutcome::CustodyAttestationExpired { .. }) => true,
            (Expect::CustodyKeyIdMismatch, AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch { .. }) => true,
            (Expect::UnsupportedCustodySuite, AuthorityCustodyValidationOutcome::UnsupportedCustodySuite { .. }) => true,
            (Expect::FixtureCustodyRejectedForMainNet, AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet) => true,
            (Expect::LocalCustodyRejectedForMainNet, AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet) => true,
            (Expect::MainNetProductionCustodyUnavailable, AuthorityCustodyValidationOutcome::MainNetProductionCustodyUnavailable) => true,
            (Expect::PolicyRefusesCustodyClass, AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }) => true,
            _ => false,
        }
    }

    fn matches_combo(&self, outcome: &LifecycleGovernanceCustodyOutcome) -> bool {
        match (self, outcome) {
            (Expect::ComboAccepted, LifecycleGovernanceCustodyOutcome::Accepted { .. }) => true,
            (Expect::ComboCustodyRejected, LifecycleGovernanceCustodyOutcome::CustodyRejected { .. }) => true,
            (Expect::ComboLifecycleRejected, LifecycleGovernanceCustodyOutcome::LifecycleRejected(_)) => true,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Boundary scenarios driven through `validate_authority_custody_attestation`.
// ---------------------------------------------------------------------------

struct BoundaryScenario {
    id: String,
    note: String,
    att: AuthorityCustodyAttestation,
    candidate: PersistentAuthorityStateRecordV2,
    trust_domain: AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expect: Expect,
}

#[allow(clippy::too_many_lines)]
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

    // ---------------- Accepted scenarios A1..A4, A8 (boundary surface)
    for (env, id, note) in [
        (
            TrustBundleEnvironment::Devnet,
            "A1_devnet_fixture_custody_accepted_under_fixture_only_policy",
            "DevNet FixtureOnly + valid fixture attestation -> AcceptedFixtureCustody",
        ),
        (
            TrustBundleEnvironment::Testnet,
            "A2_testnet_fixture_custody_accepted_under_fixture_only_policy",
            "TestNet FixtureOnly + valid fixture attestation -> AcceptedFixtureCustody",
        ),
    ] {
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(BoundaryScenario {
            id: id.into(),
            note: note.into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::AcceptedFixtureCustody,
        });
    }
    for (env, policy, id, note) in [
        (
            TrustBundleEnvironment::Devnet,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            "A3_devnet_local_operator_accepted_under_devnet_local_policy",
            "DevNet DevnetLocalAllowed + LocalOperatorKey attestation -> AcceptedLocalOperatorCustody",
        ),
        (
            TrustBundleEnvironment::Testnet,
            AuthorityCustodyPolicy::TestnetLocalAllowed,
            "A4_testnet_local_operator_accepted_under_testnet_local_policy",
            "TestNet TestnetLocalAllowed + LocalOperatorKey attestation -> AcceptedLocalOperatorCustody",
        ),
    ] {
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: id.into(),
            note: note.into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy,
            expect: Expect::AcceptedLocalOperatorCustody,
        });
    }
    {
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(BoundaryScenario {
            id: "A5_genesisbound_path_unchanged_when_custody_not_required".into(),
            note: "Default Disabled policy + GenesisBound path remains unchanged (PolicyRefusesCustodyClass typed reject without invoking any custody backend)".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::Disabled,
            expect: Expect::PolicyRefusesCustodyClass,
        });
    }
    for (class, expected, label) in [
        (AuthorityCustodyClass::Kms, Expect::KmsUnavailable, "kms"),
        (AuthorityCustodyClass::Hsm, Expect::HsmUnavailable, "hsm"),
        (
            AuthorityCustodyClass::RemoteSigner,
            Expect::RemoteSignerUnavailable,
            "remote_signer",
        ),
    ] {
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, class);
        scenarios.push(BoundaryScenario {
            id: format!("A8_production_custody_boundary_returns_typed_unavailable_{}", label),
            note: format!(
                "DevNet ProductionCustodyRequired + {} placeholder -> {}_unavailable",
                label, label
            ),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: expected,
        });
    }

    // ---------------- Rejection scenarios R1..R29 (boundary surface)
    {
        // R1
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(BoundaryScenario {
            id: "R1_fixture_custody_rejected_under_production_custody_policy".into(),
            note: "DevNet ProductionCustodyRequired + FixtureLocalKey -> ProductionCustodyUnavailable".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: Expect::ProductionCustodyUnavailable,
        });
    }
    {
        // R2
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: "R2_local_operator_custody_rejected_under_production_custody_policy".into(),
            note: "DevNet ProductionCustodyRequired + LocalOperatorKey -> ProductionCustodyUnavailable".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: Expect::ProductionCustodyUnavailable,
        });
    }
    {
        // R3 — fixture custody rejected for MainNet (under FixtureOnly).
        let env = TrustBundleEnvironment::Mainnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(BoundaryScenario {
            id: "R3_fixture_custody_rejected_for_mainnet".into(),
            note: "MainNet FixtureOnly + FixtureLocalKey -> FixtureCustodyRejectedForMainNet".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::FixtureCustodyRejectedForMainNet,
        });
    }
    {
        // R4 — local-operator custody rejected for MainNet under
        // MainnetProductionCustodyRequired.
        let env = TrustBundleEnvironment::Mainnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: "R4_local_operator_custody_rejected_for_mainnet".into(),
            note: "MainNet MainnetProductionCustodyRequired + LocalOperatorKey -> LocalCustodyRejectedForMainNet".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
            expect: Expect::LocalCustodyRejectedForMainNet,
        });
    }
    {
        // R5..R7 — production placeholders fail closed (under FixtureOnly,
        // mirroring Run 188 tests so the placeholder-class routing is shown
        // to be independent of the policy gate).
        for (class, expected, label) in [
            (AuthorityCustodyClass::Kms, Expect::KmsUnavailable, "kms"),
            (AuthorityCustodyClass::Hsm, Expect::HsmUnavailable, "hsm"),
            (
                AuthorityCustodyClass::RemoteSigner,
                Expect::RemoteSignerUnavailable,
                "remote_signer",
            ),
        ] {
            let env = TrustBundleEnvironment::Devnet;
            let cand = rotate_candidate(env);
            let att = good_fixture_attestation(env, &cand, class);
            let id = match label {
                "kms" => "R5_kms_placeholder_rejected_as_unavailable",
                "hsm" => "R6_hsm_placeholder_rejected_as_unavailable",
                _ => "R7_remote_signer_placeholder_rejected_as_unavailable",
            };
            scenarios.push(BoundaryScenario {
                id: id.into(),
                note: format!("DevNet FixtureOnly + {} placeholder -> {}_unavailable", label, label),
                att,
                candidate: cand,
                trust_domain: domain_for(env),
                policy: AuthorityCustodyPolicy::FixtureOnly,
                expect: expected,
            });
        }
    }
    {
        // R8 — Unknown custody class rejected.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Unknown);
        scenarios.push(BoundaryScenario {
            id: "R8_unknown_custody_class_rejected".into(),
            note: "DevNet FixtureOnly + Unknown class -> UnknownCustodyClassRejected".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::UnknownCustodyClassRejected,
        });
    }
    {
        // R9 — wrong environment.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.environment = TrustBundleEnvironment::Testnet;
        scenarios.push(BoundaryScenario {
            id: "R9_wrong_environment_rejected".into(),
            note: "DevNet candidate + TestNet attestation env -> WrongEnvironment".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongEnvironment,
        });
    }
    {
        // R10 — wrong chain.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.chain_id = OTHER_CHAIN.to_string();
        scenarios.push(BoundaryScenario {
            id: "R10_wrong_chain_rejected".into(),
            note: "DevNet + foreign chain_id -> WrongChain".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongChain,
        });
    }
    {
        // R11 — wrong genesis.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.genesis_hash = OTHER_GENESIS.to_string();
        scenarios.push(BoundaryScenario {
            id: "R11_wrong_genesis_rejected".into(),
            note: "DevNet + foreign genesis_hash -> WrongGenesis".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongGenesis,
        });
    }
    {
        // R12 — wrong authority root.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
        scenarios.push(BoundaryScenario {
            id: "R12_wrong_authority_root_rejected".into(),
            note: "DevNet + foreign authority_root_fingerprint -> WrongAuthorityRoot".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongAuthorityRoot,
        });
    }
    {
        // R13 — wrong signing-key fingerprint.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.bundle_signing_key_fingerprint = KEY_A.to_string();
        scenarios.push(BoundaryScenario {
            id: "R13_wrong_signing_key_fingerprint_rejected".into(),
            note: "DevNet + non-matching bundle_signing_key_fingerprint -> WrongSigningKeyFingerprint".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongSigningKeyFingerprint,
        });
    }
    {
        // R14 — wrong candidate digest.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.candidate_digest = DIGEST_OTHER.to_string();
        scenarios.push(BoundaryScenario {
            id: "R14_wrong_candidate_digest_rejected".into(),
            note: "DevNet + foreign candidate_digest -> WrongCandidateDigest".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongCandidateDigest,
        });
    }
    {
        // R15 — wrong authority-domain sequence.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.authority_domain_sequence = 99;
        scenarios.push(BoundaryScenario {
            id: "R15_wrong_authority_domain_sequence_rejected".into(),
            note: "DevNet + non-matching authority_domain_sequence -> WrongAuthorityDomainSequence".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongAuthorityDomainSequence,
        });
    }
    {
        // R16 — wrong lifecycle action.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.lifecycle_action = LocalLifecycleAction::EmergencyRevoke;
        scenarios.push(BoundaryScenario {
            id: "R16_wrong_lifecycle_action_rejected".into(),
            note: "DevNet + EmergencyRevoke lifecycle_action against Rotate expectation -> WrongLifecycleAction".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::WrongLifecycleAction,
        });
    }
    {
        // R17 — missing custody attestation digest.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.custody_attestation_digest = String::new();
        scenarios.push(BoundaryScenario {
            id: "R17_missing_custody_attestation_rejected".into(),
            note: "DevNet + empty custody_attestation_digest -> CustodyAttestationMissing".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyAttestationMissing,
        });
    }
    {
        // R18 — malformed custody attestation (empty key id).
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.custody_key_id = String::new();
        scenarios.push(BoundaryScenario {
            id: "R18_malformed_custody_attestation_rejected".into(),
            note: "DevNet + empty custody_key_id -> CustodyAttestationMalformed".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyAttestationMalformed,
        });
    }
    {
        // R18b — malformed when only one of freshness/expiry set.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.freshness_unix = Some(FRESH);
        att.expires_at_unix = None;
        scenarios.push(BoundaryScenario {
            id: "R18b_malformed_when_only_one_of_freshness_expiry_set".into(),
            note: "DevNet + freshness without expiry -> CustodyAttestationMalformed".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyAttestationMalformed,
        });
    }
    {
        // R19 — expired custody attestation.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.expires_at_unix = Some(NOW - 1);
        att.freshness_unix = Some(NOW - 100);
        scenarios.push(BoundaryScenario {
            id: "R19_expired_custody_attestation_rejected".into(),
            note: "DevNet + expires_at_unix < now -> CustodyAttestationExpired".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyAttestationExpired,
        });
    }
    {
        // R20 — custody key id mismatch with expectation.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.custody_key_id = "different-key-id".to_string();
        scenarios.push(BoundaryScenario {
            id: "R20_custody_key_id_mismatch_rejected".into(),
            note: "DevNet + custody_key_id != Some(CUSTODY_KEY_ID) expectation -> CustodyKeyIdMismatch".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyKeyIdMismatch,
        });
    }
    {
        // R21 — unsupported custody suite.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.custody_suite_id = 0xFE;
        scenarios.push(BoundaryScenario {
            id: "R21_unsupported_custody_suite_rejected".into(),
            note: "DevNet + custody_suite_id=0xFE -> UnsupportedCustodySuite".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::UnsupportedCustodySuite,
        });
    }
    {
        // R22 — custody valid but governance class mismatch (typed as
        // CustodyAttestationMalformed in Run 188 surface).
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.governance_authority_class = GovernanceAuthorityClass::EmergencyCouncil;
        scenarios.push(BoundaryScenario {
            id: "R22_custody_valid_but_governance_proof_invalid_rejected".into(),
            note: "DevNet + governance_authority_class != expected -> CustodyAttestationMalformed".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::CustodyAttestationMalformed,
        });
    }
    {
        // R26 — local-operator under MainnetProductionCustodyRequired ->
        // typed LocalCustodyRejectedForMainNet.
        let env = TrustBundleEnvironment::Mainnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: "R26_local_operator_alone_cannot_satisfy_mainnet_production_custody".into(),
            note: "MainNet MainnetProductionCustodyRequired + LocalOperatorKey -> LocalCustodyRejectedForMainNet".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
            expect: Expect::LocalCustodyRejectedForMainNet,
        });
    }
    {
        // R25 (boundary side) — even a "claims KMS" attestation on
        // MainNet routes through KmsUnavailable (placeholder layered
        // ahead of the policy gate).
        let env = TrustBundleEnvironment::Mainnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Kms);
        scenarios.push(BoundaryScenario {
            id: "R25_mainnet_kms_placeholder_routes_through_kms_unavailable".into(),
            note: "MainNet MainnetProductionCustodyRequired + Kms placeholder -> KmsUnavailable (placeholder ahead of policy)".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
            expect: Expect::KmsUnavailable,
        });
    }
    {
        // Mainnet production custody under fixture material with the
        // mainnet policy: typed FixtureCustodyRejectedForMainNet at
        // the symbol layered ahead of the placeholder/policy gate.
        let env = TrustBundleEnvironment::Mainnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(BoundaryScenario {
            id: "R3b_mainnet_production_policy_with_fixture_custody_surfaces_fixture_rejected".into(),
            note: "MainNet MainnetProductionCustodyRequired + FixtureLocalKey -> FixtureCustodyRejectedForMainNet".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
            expect: Expect::FixtureCustodyRejectedForMainNet,
        });
    }
    {
        // PolicyRefusesCustodyClass — DevnetLocalAllowed + Kms placeholder
        // (placeholder routed through KmsUnavailable ahead of policy gate).
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Kms);
        scenarios.push(BoundaryScenario {
            id: "R5b_devnet_local_policy_refuses_kms_placeholder_with_typed_unavailable".into(),
            note: "DevNet DevnetLocalAllowed + Kms placeholder -> KmsUnavailable".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::DevnetLocalAllowed,
            expect: Expect::KmsUnavailable,
        });
    }
    {
        // FixtureOnly + LocalOperatorKey -> typed PolicyRefusesCustodyClass.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: "Rb_fixture_only_policy_refuses_local_operator".into(),
            note: "DevNet FixtureOnly + LocalOperatorKey -> PolicyRefusesCustodyClass".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::PolicyRefusesCustodyClass,
        });
    }
    {
        // DevnetLocalAllowed evaluated on a TestNet trust domain ->
        // typed PolicyRefusesCustodyClass at the symbol.
        let env = TrustBundleEnvironment::Testnet;
        let cand = rotate_candidate(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(BoundaryScenario {
            id: "Rc_devnet_local_policy_on_testnet_domain_is_refused_by_policy".into(),
            note: "TestNet DevnetLocalAllowed + LocalOperatorKey -> PolicyRefusesCustodyClass".into(),
            att,
            candidate: cand,
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::DevnetLocalAllowed,
            expect: Expect::PolicyRefusesCustodyClass,
        });
    }

    // -------- Run scenarios --------
    for s in &scenarios {
        let scenario_dir = scenarios_dir.join(&s.id);
        fs::create_dir_all(&scenario_dir)?;
        let cand_before = s.candidate.clone();
        let att_before = s.att.clone();
        let dom_before = s.trust_domain.clone();

        let outcome = validate(&s.att, &s.candidate, &s.trust_domain, s.policy);

        let no_mut = s.candidate == cand_before
            && s.att == att_before
            && s.trust_domain == dom_before;
        let matched = s.expect.matches_boundary(&outcome) && no_mut;

        fs::write(scenario_dir.join("note.txt"), format!("{}\n", s.note))?;
        fs::write(
            scenario_dir.join("policy.txt"),
            format!("policy={:?}\n", s.policy),
        )?;
        fs::write(
            scenario_dir.join("expected.txt"),
            format!("{}\n", s.expect.label()),
        )?;
        fs::write(scenario_dir.join("actual.txt"), format!("{:?}\n", outcome))?;
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
                "[run-189-helper] FAIL boundary scenario {} expected {} got {:?} no_mut={}",
                s.id,
                s.expect.label(),
                outcome,
                no_mut
            );
        }
    }
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Combined helper scenarios driven through
// `validate_lifecycle_governance_and_custody`.
// ---------------------------------------------------------------------------

struct ComboScenario {
    id: String,
    note: String,
    att: AuthorityCustodyAttestation,
    candidate: PersistentAuthorityStateRecordV2,
    persisted: Option<PersistentAuthorityStateRecordVersioned>,
    trust_domain: AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expect: Expect,
}

fn run_combo_scenarios(
    out_dir: &Path,
    manifest: &mut String,
    expected: &mut String,
    actual: &mut String,
) -> std::io::Result<(usize, usize)> {
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut scenarios: Vec<ComboScenario> = Vec::new();

    {
        // A6 combined accepted DevNet fixture
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(ComboScenario {
            id: "A6_combined_lifecycle_governance_fixture_custody_accepted_devnet".into(),
            note: "DevNet FixtureOnly + valid lifecycle + valid fixture custody -> Accepted".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::ComboAccepted,
        });
    }
    {
        // A7 combined accepted TestNet local-operator
        let env = TrustBundleEnvironment::Testnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::LocalOperatorKey);
        scenarios.push(ComboScenario {
            id: "A7_combined_lifecycle_governance_local_custody_accepted_testnet".into(),
            note: "TestNet TestnetLocalAllowed + valid lifecycle + valid local-operator -> Accepted".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::TestnetLocalAllowed,
            expect: Expect::ComboAccepted,
        });
    }
    {
        // R23 — lifecycle accepted + custody invalid (empty digest).
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let mut att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        att.custody_attestation_digest = String::new();
        scenarios.push(ComboScenario {
            id: "R23_governance_proof_valid_but_custody_invalid_rejected".into(),
            note: "DevNet FixtureOnly + valid lifecycle + missing custody digest -> CustodyRejected(CustodyAttestationMissing)".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::ComboCustodyRejected,
        });
    }
    {
        // R24 — lifecycle valid + governance valid + custody placeholder
        // unavailable (Kms) under ProductionCustodyRequired.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Kms);
        scenarios.push(ComboScenario {
            id: "R24_lifecycle_valid_governance_valid_custody_placeholder_unavailable_rejected".into(),
            note: "DevNet ProductionCustodyRequired + valid lifecycle + Kms placeholder -> CustodyRejected(KmsUnavailable)".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: Expect::ComboCustodyRejected,
        });
    }
    {
        // R28 — validation-only rejection non-mutating (Hsm placeholder).
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Hsm);
        scenarios.push(ComboScenario {
            id: "R28_validation_only_rejection_remains_non_mutating".into(),
            note: "DevNet ProductionCustodyRequired + Hsm placeholder -> CustodyRejected(HsmUnavailable); inputs bit-equal after".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: Expect::ComboCustodyRejected,
        });
    }
    {
        // R29 — mutating preflight rejection produces no Run 070 / live-trust /
        // sequence / marker mutation. Modeled by the helper running in pure
        // validation-only mode and asserting bit-equality of inputs.
        let env = TrustBundleEnvironment::Devnet;
        let cand = rotate_candidate(env);
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::RemoteSigner);
        scenarios.push(ComboScenario {
            id: "R29_mutating_preflight_rejection_produces_no_run_070_call".into(),
            note: "DevNet ProductionCustodyRequired + RemoteSigner placeholder -> CustodyRejected; helper captures bit-equality (no Run 070, no marker, no sequence, no live trust swap)".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::ProductionCustodyRequired,
            expect: Expect::ComboCustodyRejected,
        });
    }
    {
        // Lifecycle reject — wrong-environment candidate against the trust
        // domain produces a typed `LifecycleRejected` short-circuit (custody
        // validation is never invoked).
        let env = TrustBundleEnvironment::Devnet;
        let cand = build_v2(
            TrustBundleEnvironment::Testnet,
            KEY_B,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(KEY_A),
            DIGEST_2,
        );
        let prior = prior_versioned(env);
        let att = good_fixture_attestation(env, &rotate_candidate(env), AuthorityCustodyClass::FixtureLocalKey);
        scenarios.push(ComboScenario {
            id: "Lifecycle_short_circuits_combo_helper_when_lifecycle_rejects".into(),
            note: "DevNet trust domain + TestNet candidate -> LifecycleRejected; custody validation skipped".into(),
            att,
            candidate: cand,
            persisted: Some(prior),
            trust_domain: domain_for(env),
            policy: AuthorityCustodyPolicy::FixtureOnly,
            expect: Expect::ComboLifecycleRejected,
        });
    }

    for s in &scenarios {
        let scenario_dir = scenarios_dir.join(&s.id);
        fs::create_dir_all(&scenario_dir)?;
        let cand_before = s.candidate.clone();
        let prior_before = s.persisted.clone();
        let att_before = s.att.clone();
        let dom_before = s.trust_domain.clone();

        let outcome = validate_lifecycle_governance_and_custody(
            &s.att,
            &s.candidate,
            s.persisted.as_ref(),
            &s.trust_domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            s.policy,
            NOW,
        );

        let no_mut = s.candidate == cand_before
            && s.persisted == prior_before
            && s.att == att_before
            && s.trust_domain == dom_before;
        let matched = s.expect.matches_combo(&outcome) && no_mut;

        fs::write(scenario_dir.join("note.txt"), format!("{}\n", s.note))?;
        fs::write(
            scenario_dir.join("policy.txt"),
            format!("policy={:?} (combo helper)\n", s.policy),
        )?;
        fs::write(
            scenario_dir.join("expected.txt"),
            format!("{}\n", s.expect.label()),
        )?;
        fs::write(scenario_dir.join("actual.txt"), format!("{:?}\n", outcome))?;

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
                "[run-189-helper] FAIL combo scenario {} expected {} got {:?} no_mut={}",
                s.id,
                s.expect.label(),
                outcome,
                no_mut
            );
        }
    }

    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Custody class & policy table.
// ---------------------------------------------------------------------------

fn run_custody_class_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut record = |label: &str, ok: bool, val: String| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-189-helper] FAIL class row {} got {}", label, val);
        }
        buf.push_str(&format!("{}\tok={}\tval={}\n", label, ok, val));
    };

    record(
        "AuthorityCustodyClass::FixtureLocalKey.is_local_only",
        AuthorityCustodyClass::FixtureLocalKey.is_local_only(),
        format!("{}", AuthorityCustodyClass::FixtureLocalKey.is_local_only()),
    );
    record(
        "AuthorityCustodyClass::LocalOperatorKey.is_local_only",
        AuthorityCustodyClass::LocalOperatorKey.is_local_only(),
        format!("{}", AuthorityCustodyClass::LocalOperatorKey.is_local_only()),
    );
    record(
        "!AuthorityCustodyClass::Kms.is_local_only",
        !AuthorityCustodyClass::Kms.is_local_only(),
        format!("{}", AuthorityCustodyClass::Kms.is_local_only()),
    );
    record(
        "AuthorityCustodyClass::Kms.is_production_placeholder",
        AuthorityCustodyClass::Kms.is_production_placeholder(),
        format!("{}", AuthorityCustodyClass::Kms.is_production_placeholder()),
    );
    record(
        "AuthorityCustodyClass::Hsm.is_production_placeholder",
        AuthorityCustodyClass::Hsm.is_production_placeholder(),
        format!("{}", AuthorityCustodyClass::Hsm.is_production_placeholder()),
    );
    record(
        "AuthorityCustodyClass::RemoteSigner.is_production_placeholder",
        AuthorityCustodyClass::RemoteSigner.is_production_placeholder(),
        format!("{}", AuthorityCustodyClass::RemoteSigner.is_production_placeholder()),
    );
    record(
        "!AuthorityCustodyClass::FixtureLocalKey.is_production_placeholder",
        !AuthorityCustodyClass::FixtureLocalKey.is_production_placeholder(),
        format!("{}", AuthorityCustodyClass::FixtureLocalKey.is_production_placeholder()),
    );
    record(
        "!AuthorityCustodyClass::Unknown.is_production_placeholder",
        !AuthorityCustodyClass::Unknown.is_production_placeholder(),
        format!("{}", AuthorityCustodyClass::Unknown.is_production_placeholder()),
    );

    record(
        "AuthorityCustodyClass::Hsm.tag()==\"hsm\"",
        AuthorityCustodyClass::Hsm.tag() == "hsm",
        AuthorityCustodyClass::Hsm.tag().to_string(),
    );
    record(
        "AuthorityCustodyClass::Kms.tag()==\"kms\"",
        AuthorityCustodyClass::Kms.tag() == "kms",
        AuthorityCustodyClass::Kms.tag().to_string(),
    );
    record(
        "AuthorityCustodyClass::RemoteSigner.tag()==\"remote-signer\"",
        AuthorityCustodyClass::RemoteSigner.tag() == "remote-signer",
        AuthorityCustodyClass::RemoteSigner.tag().to_string(),
    );

    // Policy helpers.
    record(
        "AuthorityCustodyPolicy::default()==Disabled",
        AuthorityCustodyPolicy::default() == AuthorityCustodyPolicy::Disabled,
        format!("{:?}", AuthorityCustodyPolicy::default()),
    );
    record(
        "AuthorityCustodyPolicy::ProductionCustodyRequired.requires_production_custody",
        AuthorityCustodyPolicy::ProductionCustodyRequired.requires_production_custody(),
        format!(
            "{}",
            AuthorityCustodyPolicy::ProductionCustodyRequired.requires_production_custody()
        ),
    );
    record(
        "AuthorityCustodyPolicy::MainnetProductionCustodyRequired.requires_production_custody",
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired.requires_production_custody(),
        format!(
            "{}",
            AuthorityCustodyPolicy::MainnetProductionCustodyRequired.requires_production_custody()
        ),
    );
    record(
        "AuthorityCustodyPolicy::FixtureOnly.allows_fixture",
        AuthorityCustodyPolicy::FixtureOnly.allows_fixture(),
        format!("{}", AuthorityCustodyPolicy::FixtureOnly.allows_fixture()),
    );
    record(
        "AuthorityCustodyPolicy::DevnetLocalAllowed.allows_local_operator",
        AuthorityCustodyPolicy::DevnetLocalAllowed.allows_local_operator(),
        format!(
            "{}",
            AuthorityCustodyPolicy::DevnetLocalAllowed.allows_local_operator()
        ),
    );
    record(
        "AuthorityCustodyPolicy::TestnetLocalAllowed.allows_local_operator",
        AuthorityCustodyPolicy::TestnetLocalAllowed.allows_local_operator(),
        format!(
            "{}",
            AuthorityCustodyPolicy::TestnetLocalAllowed.allows_local_operator()
        ),
    );
    record(
        "AuthorityCustodyPolicy::MainnetProductionCustodyRequired.tag()",
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired.tag()
            == "mainnet-production-custody-required",
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired.tag().to_string(),
    );

    fs::write(out_dir.join("custody_class_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Named helpers table — MainNet refusal / peer-majority / local-operator
// MainNet rules.
// ---------------------------------------------------------------------------

fn run_named_helpers_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut record = |label: &str, ok: bool, got: String| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-189-helper] FAIL named-helper row {} got {}", label, got);
        }
        buf.push_str(&format!("{}\tok={}\tgot={}\n", label, ok, got));
    };

    let mn = mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Mainnet,
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary(MainNet)",
        mn,
        format!("{}", mn),
    );
    let dn = mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Devnet,
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary(DevNet)==false",
        !dn,
        format!("{}", dn),
    );
    let tn = mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
        TrustBundleEnvironment::Testnet,
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary(TestNet)==false",
        !tn,
        format!("{}", tn),
    );

    let pm = peer_majority_cannot_satisfy_custody();
    record("peer_majority_cannot_satisfy_custody==true", pm, format!("{}", pm));
    let lo = local_operator_config_alone_cannot_satisfy_mainnet_production_custody();
    record(
        "local_operator_config_alone_cannot_satisfy_mainnet_production_custody==true",
        lo,
        format!("{}", lo),
    );

    // Run 186 default still Disabled.
    let kind_default = OnChainGovernanceVerifierKind::default();
    record(
        "OnChainGovernanceVerifierKind::default()==Disabled",
        kind_default == OnChainGovernanceVerifierKind::Disabled,
        format!("{:?}", kind_default),
    );
    let policy_default = OnChainGovernanceVerifierPolicy::default();
    record(
        "OnChainGovernanceVerifierPolicy::default()==disabled()",
        policy_default == OnChainGovernanceVerifierPolicy::disabled(),
        format!("{:?}", policy_default),
    );

    fs::write(out_dir.join("named_helpers_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// No-mutation evidence: rejecting validation does not touch any input.
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let cand_before = cand.clone();
    let dom = domain_for(env);
    let dom_before = dom.clone();
    let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::Kms);
    let att_before = att.clone();
    let prior = prior_versioned(env);
    let prior_before = prior.clone();

    let outcome_b = validate_authority_custody_attestation(
        &att,
        &cand,
        &dom,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        NOW,
    );
    let outcome_c = validate_lifecycle_governance_and_custody(
        &att,
        &cand,
        Some(&prior),
        &dom,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        AuthorityCustodyPolicy::ProductionCustodyRequired,
        NOW,
    );

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-189-helper] FAIL no-mutation invariant: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    record("boundary_outcome_is_reject", outcome_b.is_reject());
    record("combo_outcome_is_reject", outcome_c.is_reject());
    record("candidate_unchanged", cand == cand_before);
    record("trust_domain_unchanged", dom == dom_before);
    record("attestation_unchanged", att == att_before);
    record("prior_unchanged", prior == prior_before);

    buf.push_str(&format!("boundary_outcome\t{:?}\n", outcome_b));
    buf.push_str(&format!("combo_outcome\t{:?}\n", outcome_c));
    fs::write(out_dir.join("no_mutation_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Determinism: 32 evaluations of the accepted DevNet fixture combo yield the
// same typed Accepted outcome.
// ---------------------------------------------------------------------------

fn run_determinism_check(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let prior = prior_versioned(env);
    let dom = domain_for(env);
    let att = good_fixture_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);

    let mut outcomes = Vec::new();
    for _ in 0..32 {
        outcomes.push(validate_lifecycle_governance_and_custody(
            &att,
            &cand,
            Some(&prior),
            &dom,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            NOW,
        ));
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
    Ok((
        if all_eq && first_accept { 1 } else { 0 },
        if all_eq && first_accept { 0 } else { 1 },
    ))
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
                "usage: run_189_authority_custody_boundary_release_binary_helper <OUT_DIR>"
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
    let (c_pass, c_fail) = run_combo_scenarios(&out_dir, &mut manifest, &mut expected, &mut actual)
        .expect("combo scenarios");
    let (k_pass, k_fail) = run_custody_class_table(&out_dir).expect("custody class table");
    let (h_pass, h_fail) = run_named_helpers_table(&out_dir).expect("named helpers table");
    let (n_pass, n_fail) = run_no_mutation_evidence(&out_dir).expect("no mutation evidence");
    let (d_pass, d_fail) = run_determinism_check(&out_dir).expect("determinism check");

    fs::write(out_dir.join("manifest.txt"), &manifest).expect("write manifest");
    fs::write(out_dir.join("expected_outcomes.txt"), &expected).expect("write expected");
    fs::write(out_dir.join("actual_outcomes.txt"), &actual).expect("write actual");

    let total_pass = b_pass + c_pass + k_pass + h_pass + n_pass + d_pass;
    let total_fail = b_fail + c_fail + k_fail + h_fail + n_fail + d_fail;
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };

    let mut summary = fs::File::create(out_dir.join("helper_summary.txt"))
        .expect("create helper_summary.txt");
    writeln!(
        summary,
        "Run 189 helper — release-mode authority-custody boundary corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(summary, "total_pass: {}\ntotal_fail: {}", total_pass, total_fail).unwrap();
    writeln!(summary, "boundary_pass: {}\nboundary_fail: {}", b_pass, b_fail).unwrap();
    writeln!(summary, "combo_pass: {}\ncombo_fail: {}", c_pass, c_fail).unwrap();
    writeln!(
        summary,
        "custody_class_pass: {}\ncustody_class_fail: {}",
        k_pass, k_fail
    )
    .unwrap();
    writeln!(
        summary,
        "named_helpers_pass: {}\nnamed_helpers_fail: {}",
        h_pass, h_fail
    )
    .unwrap();
    writeln!(summary, "no_mutation_pass: {}\nno_mutation_fail: {}", n_pass, n_fail).unwrap();
    writeln!(summary, "determinism_pass: {}\ndeterminism_fail: {}", d_pass, d_fail).unwrap();
    writeln!(summary, "production_symbols_exercised:").unwrap();
    for s in &[
        "qbind_node::pqc_authority_custody::AuthorityCustodyClass",
        "qbind_node::pqc_authority_custody::AuthorityCustodyPolicy",
        "qbind_node::pqc_authority_custody::AuthorityCustodyAttestation",
        "qbind_node::pqc_authority_custody::AuthorityCustodyValidationOutcome",
        "qbind_node::pqc_authority_custody::LifecycleGovernanceCustodyOutcome",
        "qbind_node::pqc_authority_custody::validate_authority_custody_attestation",
        "qbind_node::pqc_authority_custody::validate_lifecycle_governance_and_custody",
        "qbind_node::pqc_authority_custody::mainnet_peer_driven_apply_remains_refused_under_custody_boundary",
        "qbind_node::pqc_authority_custody::peer_majority_cannot_satisfy_custody",
        "qbind_node::pqc_authority_custody::local_operator_config_alone_cannot_satisfy_mainnet_production_custody",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifierKind",
        "qbind_node::pqc_onchain_governance_verifier::OnChainGovernanceVerifierPolicy",
    ] {
        writeln!(summary, "  - {}", s).unwrap();
    }
    writeln!(summary, "honest_limits:").unwrap();
    for line in &[
        "default AuthorityCustodyPolicy::Disabled fail-closed on every surface",
        "FixtureLocalKey / LocalOperatorKey are DevNet/TestNet evidence-only",
        "Fixture / local custody refused on MainNet (FixtureCustodyRejectedForMainNet / LocalCustodyRejectedForMainNet)",
        "RemoteSigner / Kms / Hsm placeholders fail closed (RemoteSignerUnavailable / KmsUnavailable / HsmUnavailable)",
        "ProductionCustodyRequired / MainnetProductionCustodyRequired always fail closed in Run 189",
        "no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend wired in Run 189",
        "no MainNet peer-driven apply enablement",
        "no governance execution / no real on-chain proof verifier / no validator-set rotation",
        "no schema/wire/metric drift; no marker write; no sequence write; pure validation",
    ] {
        writeln!(summary, "  {}", line).unwrap();
    }

    if total_fail != 0 {
        std::process::exit(1);
    }
}