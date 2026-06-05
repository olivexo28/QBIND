//! Run 193 — release-built helper that exercises the Run 192 hidden
//! authority-custody policy selector and the seven Run 192 per-surface
//! preflight wrappers **in release mode** through the production library
//! symbols
//! [`qbind_node::pqc_authority_custody_policy_surface`],
//! [`qbind_node::pqc_authority_custody_payload_carrying`], and
//! [`qbind_node::pqc_authority_custody`].
//!
//! Per `task/RUN_193_TASK.txt`, Run 193 is the release-binary evidence
//! run for the Run 192 source/test hidden authority-custody policy
//! selector. This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–192 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance
//!   any sequence, swap any live trust, evict any session, or invoke
//!   Run 070;
//! * does NOT open any P2P socket;
//! * does NOT implement any real KMS / HSM / cloud-KMS / PKCS#11 /
//!   remote-signer backend; every `RemoteSigner` / `Kms` / `Hsm`
//!   placeholder routes to the Run 188 typed `*Unavailable` reject;
//! * never elevates fixture / local-operator custody into MainNet
//!   production custody (MainNet always refuses at the typed
//!   boundary ahead of the policy gate);
//! * exists alongside (and does NOT replace) the Run 192 source/test
//!   target
//!   `crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one row per scenario
//! <OUT_DIR>/expected_outcomes.txt
//! <OUT_DIR>/actual_outcomes.txt
//! <OUT_DIR>/scenarios/<id>/{policy,expected,actual,note}.txt
//! <OUT_DIR>/selector_parser_table.txt
//! <OUT_DIR>/precedence_table.txt
//! <OUT_DIR>/preflight_wrappers_table.txt
//! <OUT_DIR>/binding_mismatch_table.txt
//! <OUT_DIR>/no_mutation_evidence.txt
//! <OUT_DIR>/determinism_evidence.txt
//! <OUT_DIR>/helper_summary.txt
//! ```
//!
//! The helper exits non-zero if any scenario does not match its
//! expected typed outcome.
//!
//! Usage:
//! ```text
//! run_193_authority_custody_policy_release_binary_helper <OUT_DIR>
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
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
    AuthorityCustodyValidationOutcome, LifecycleGovernanceCustodyOutcome,
};
use qbind_node::pqc_authority_custody_payload_carrying::{
    parse_optional_authority_custody_attestation_sibling_from_json_value,
    AuthorityCustodyAttestationWire, AuthorityCustodyLoadStatus,
    AuthorityCustodyPayloadCarryingDecisionOutcome,
    AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
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

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 190 / Run 191 / Run 192
// fixtures so the typed selector + payload-carrying semantics carry over
// end-to-end in release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-193";
const CUSTODY_KEY_ID: &str = "custody-key-id-193";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror `tests/run_192_authority_custody_policy_selector_tests.rs`.
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
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

fn sibling_value_for(att: &AuthorityCustodyAttestation) -> serde_json::Value {
    serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD:
            serde_json::to_value(AuthorityCustodyAttestationWire::from_attestation(att)).unwrap()
    })
}

fn loaded_for(att: &AuthorityCustodyAttestation) -> AuthorityCustodyLoadStatus {
    parse_optional_authority_custody_attestation_sibling_from_json_value(&sibling_value_for(att))
}

fn loaded_absent() -> AuthorityCustodyLoadStatus {
    parse_optional_authority_custody_attestation_sibling_from_json_value(&serde_json::json!({}))
}

fn loaded_malformed_json() -> AuthorityCustodyLoadStatus {
    parse_optional_authority_custody_attestation_sibling_from_json_value(&serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: "not-an-object"
    }))
}

// ---------------------------------------------------------------------------
// Per-surface dispatch using the Run 192 preflight wrappers (production
// library symbols `pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_*`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Surface {
    ReloadCheck,
    ReloadApply,
    StartupP2pTrustBundle,
    Sighup,
    LocalPeerCandidateCheck,
    LiveInbound0x05,
    PeerDrivenDrain,
}

impl Surface {
    const ALL: [Surface; 7] = [
        Surface::ReloadCheck,
        Surface::ReloadApply,
        Surface::StartupP2pTrustBundle,
        Surface::Sighup,
        Surface::LocalPeerCandidateCheck,
        Surface::LiveInbound0x05,
        Surface::PeerDrivenDrain,
    ];

    fn label(self) -> &'static str {
        match self {
            Surface::ReloadCheck => "reload_check",
            Surface::ReloadApply => "reload_apply",
            Surface::StartupP2pTrustBundle => "startup_p2p_trust_bundle",
            Surface::Sighup => "sighup",
            Surface::LocalPeerCandidateCheck => "local_peer_candidate_check",
            Surface::LiveInbound0x05 => "live_inbound_0x05",
            Surface::PeerDrivenDrain => "peer_driven_drain",
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn route(
        self,
        persisted: Option<&PersistentAuthorityStateRecordVersioned>,
        candidate: &PersistentAuthorityStateRecordV2,
        domain: &AuthorityTrustDomain,
        policy: AuthorityCustodyPolicy,
        loaded: &AuthorityCustodyLoadStatus,
    ) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
        match self {
            Surface::ReloadCheck => preflight_v2_marker_authority_custody_for_reload_check(
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
            ),
            Surface::ReloadApply => preflight_v2_marker_authority_custody_for_reload_apply(
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
            ),
            Surface::StartupP2pTrustBundle => {
                preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle(
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
            Surface::Sighup => preflight_v2_marker_authority_custody_for_sighup(
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
            ),
            Surface::LocalPeerCandidateCheck => {
                preflight_v2_marker_authority_custody_for_local_peer_candidate_check(
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
            Surface::LiveInbound0x05 => {
                preflight_v2_marker_authority_custody_for_live_inbound_0x05(
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
            Surface::PeerDrivenDrain => preflight_v2_marker_authority_custody_for_peer_driven_drain(
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
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Symbolic expected outcome.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    NoCustodyAttestationSupplied,
    MalformedAuthorityCustodyAttestationPayload,
    CustodyAttestationRequiredButAbsent,
    MainNetPeerDrivenApplyRefused,
    CallsiteAcceptedFixture,
    CallsiteAcceptedLocalOperator,
    CallsiteCustodyRejectedKmsUnavailable,
    CallsiteCustodyRejectedHsmUnavailable,
    CallsiteCustodyRejectedRemoteSignerUnavailable,
    CallsiteCustodyRejectedFixtureOnMainNet,
    CallsiteCustodyRejectedLocalOnMainNet,
    CallsiteCustodyRejectedPolicyRefusesClass,
    CallsiteCustodyRejectedProductionUnavailable,
    CallsiteCustodyRejectedMainNetProductionUnavailable,
}

fn matches_expect(
    actual: &AuthorityCustodyPayloadCarryingDecisionOutcome,
    expected: &Expect,
) -> bool {
    use AuthorityCustodyPayloadCarryingDecisionOutcome as O;
    match (actual, expected) {
        (O::NoCustodyAttestationSupplied, Expect::NoCustodyAttestationSupplied) => true,
        (
            O::MalformedAuthorityCustodyAttestationPayload(_),
            Expect::MalformedAuthorityCustodyAttestationPayload,
        ) => true,
        (
            O::CustodyAttestationRequiredButAbsent { .. },
            Expect::CustodyAttestationRequiredButAbsent,
        ) => true,
        (O::MainNetPeerDrivenApplyRefused, Expect::MainNetPeerDrivenApplyRefused) => true,
        (O::Callsite(c), e) => match (c, e) {
            (
                LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
                Expect::CallsiteAcceptedFixture,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
                Expect::CallsiteAcceptedLocalOperator,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedKmsUnavailable,
            ) => matches!(custody_outcome, AuthorityCustodyValidationOutcome::KmsUnavailable),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedHsmUnavailable,
            ) => matches!(custody_outcome, AuthorityCustodyValidationOutcome::HsmUnavailable),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedRemoteSignerUnavailable,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::RemoteSignerUnavailable
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedFixtureOnMainNet,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedLocalOnMainNet,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedPolicyRefusesClass,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedProductionUnavailable,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedMainNetProductionUnavailable,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::MainNetProductionCustodyUnavailable
            ),
            _ => false,
        },
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Selector source matrix — captures Run 192 selector parser behavior in
// release mode through the production library symbols.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Selector {
    /// Both CLI and env unset (relies on the helper's at-startup env-clear).
    NoneSet,
    /// CLI value set, env unset.
    CliOnly(&'static str),
    /// CLI unset, env set.
    EnvOnly(&'static str),
    /// CLI set, env set; CLI must win.
    CliAndEnv {
        cli: &'static str,
        env: &'static str,
    },
    /// Used for invalid-selector cases (CLI invalid, env unset; or env
    /// invalid, CLI unset).
    InvalidCli(&'static str),
    InvalidEnv(&'static str),
}

#[derive(Debug)]
enum SelectorOutcome {
    Resolved(AuthorityCustodyPolicy),
    ParseError(AuthorityCustodyPolicySelectorParseError),
}

/// Resolves the selector via the Run 192 production library functions.
/// The env var is set/unset around the call so the env-only and
/// CLI-and-env cases exercise the real `std::env::var` read inside
/// `authority_custody_policy_env_selector`.
///
/// Note: `std::env::set_var` / `remove_var` are not thread-safe in
/// general, but this helper is single-threaded (synchronous main).
fn resolve_selector(sel: &Selector) -> SelectorOutcome {
    let key = QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV;
    // Always clear first, then set if needed.
    std::env::remove_var(key);
    match sel {
        Selector::NoneSet => match authority_custody_policy_from_cli_or_env(None) {
            Ok(p) => SelectorOutcome::Resolved(p),
            Err(e) => SelectorOutcome::ParseError(e),
        },
        Selector::CliOnly(v) => match authority_custody_policy_from_cli_or_env(Some(v)) {
            Ok(p) => SelectorOutcome::Resolved(p),
            Err(e) => SelectorOutcome::ParseError(e),
        },
        Selector::EnvOnly(v) => {
            std::env::set_var(key, v);
            let r = authority_custody_policy_from_cli_or_env(None);
            std::env::remove_var(key);
            match r {
                Ok(p) => SelectorOutcome::Resolved(p),
                Err(e) => SelectorOutcome::ParseError(e),
            }
        }
        Selector::CliAndEnv { cli, env } => {
            std::env::set_var(key, env);
            let r = authority_custody_policy_from_cli_or_env(Some(cli));
            std::env::remove_var(key);
            match r {
                Ok(p) => SelectorOutcome::Resolved(p),
                Err(e) => SelectorOutcome::ParseError(e),
            }
        }
        Selector::InvalidCli(v) => match authority_custody_policy_from_cli_or_env(Some(v)) {
            Ok(p) => SelectorOutcome::Resolved(p),
            Err(e) => SelectorOutcome::ParseError(e),
        },
        Selector::InvalidEnv(v) => {
            std::env::set_var(key, v);
            let r = authority_custody_policy_from_cli_or_env(None);
            std::env::remove_var(key);
            match r {
                Ok(p) => SelectorOutcome::Resolved(p),
                Err(e) => SelectorOutcome::ParseError(e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario corpus (A1–A12 / R1–R29 from `task/RUN_193_TASK.txt`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Carrier {
    Absent,
    Present(AuthorityCustodyClass),
    PresentWithEnv {
        class: AuthorityCustodyClass,
        attestation_env: TrustBundleEnvironment,
    },
    MalformedJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurfaceSet {
    All,
    PeerDrivenDrainOnly,
}

struct Scenario {
    id: &'static str,
    note: &'static str,
    selector: Selector,
    expected_policy: Option<AuthorityCustodyPolicy>,
    expected_parse_error: bool,
    env: TrustBundleEnvironment,
    carrier: Carrier,
    surfaces: SurfaceSet,
    expected: Option<Expect>,
    /// If true, the peer-driven drain surface refuses with
    /// `MainNetPeerDrivenApplyRefused` regardless of `expected`.
    peer_drain_mainnet: bool,
}

fn corpus() -> Vec<Scenario> {
    use AuthorityCustodyClass::*;
    use AuthorityCustodyPolicy::*;
    use Carrier::*;
    use TrustBundleEnvironment::*;

    vec![
        // ============= A1–A12 accepted / compatible cases =============
        Scenario {
            id: "A1_unset_resolves_disabled_no_carrier",
            note: "no CLI, no env => Disabled; absent carrier => NoCustodyAttestationSupplied",
            selector: Selector::NoneSet,
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A2_cli_disabled_resolves_disabled",
            note: "CLI=disabled => Disabled; absent carrier => bypass",
            selector: Selector::CliOnly("disabled"),
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A3_env_disabled_resolves_disabled",
            note: "env=disabled, CLI unset => Disabled",
            selector: Selector::EnvOnly("disabled"),
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A4_cli_fixture_only_devnet_fixture_accept",
            note: "CLI=fixture-only + DevNet fixture custody accepted",
            selector: Selector::CliOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteAcceptedFixture),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A5_env_fixture_only_testnet_fixture_accept",
            note: "env=fixture-only + TestNet fixture custody accepted",
            selector: Selector::EnvOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Testnet,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteAcceptedFixture),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A6_cli_devnet_local_allowed_devnet_local_accept",
            note: "CLI=devnet-local-allowed + DevNet local-operator accepted",
            selector: Selector::CliOnly("devnet-local-allowed"),
            expected_policy: Some(DevnetLocalAllowed),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteAcceptedLocalOperator),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A7_env_testnet_local_allowed_testnet_local_accept",
            note: "env=testnet-local-allowed + TestNet local-operator accepted",
            selector: Selector::EnvOnly("testnet-local-allowed"),
            expected_policy: Some(TestnetLocalAllowed),
            expected_parse_error: false,
            env: Testnet,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteAcceptedLocalOperator),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A8_cli_production_required_kms_unavailable",
            note: "CLI=production-custody-required + KMS placeholder => KmsUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(Kms),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedKmsUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A9_env_mainnet_production_required_refusal",
            note: "env=mainnet-production-custody-required + MainNet trust domain => MainNet refusal/unavailable; peer-drain refuses MainNet ahead",
            selector: Selector::EnvOnly("mainnet-production-custody-required"),
            expected_policy: Some(MainnetProductionCustodyRequired),
            expected_parse_error: false,
            env: Mainnet,
            carrier: PresentWithEnv {
                class: Kms,
                attestation_env: Mainnet,
            },
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedMainNetProductionUnavailable),
            peer_drain_mainnet: true,
        },
        Scenario {
            id: "A10_cli_over_env_precedence_disabled_wins",
            note: "env=fixture-only, CLI=disabled => CLI wins; resolved=Disabled",
            selector: Selector::CliAndEnv {
                cli: "disabled",
                env: "fixture-only",
            },
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A11_default_disabled_no_custody_payload_compatible",
            note: "default Disabled + absent carrier remains compatible",
            selector: Selector::NoneSet,
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Testnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "A12_genesis_bound_no_custody_disabled_compatible",
            note: "GenesisBound proof path under Disabled + absent carrier => compatible",
            selector: Selector::CliOnly("disabled"),
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        // ============= R1–R29 rejection cases =============
        Scenario {
            id: "R1_invalid_cli_value_typed_parse_error",
            note: "CLI=not-a-policy => UnknownValue parse error",
            selector: Selector::InvalidCli("not-a-policy"),
            expected_policy: None,
            expected_parse_error: true,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: None,
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R2_invalid_env_value_typed_parse_error",
            note: "env=garbage => UnknownValue parse error",
            selector: Selector::InvalidEnv("garbage-policy"),
            expected_policy: None,
            expected_parse_error: true,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: None,
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R3_unrelated_env_does_not_enable_policy",
            note: "no CLI, no QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY env => Disabled",
            selector: Selector::NoneSet,
            expected_policy: Some(Disabled),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::NoCustodyAttestationSupplied),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R4_no_custody_under_fixture_only_required_but_absent",
            note: "FixtureOnly + absent carrier => CustodyAttestationRequiredButAbsent",
            selector: Selector::CliOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CustodyAttestationRequiredButAbsent),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R5_no_custody_under_devnet_local_allowed_required_but_absent",
            note: "DevnetLocalAllowed + absent carrier => CustodyAttestationRequiredButAbsent",
            selector: Selector::CliOnly("devnet-local-allowed"),
            expected_policy: Some(DevnetLocalAllowed),
            expected_parse_error: false,
            env: Devnet,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CustodyAttestationRequiredButAbsent),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R6_fixture_under_production_required_unavailable",
            note: "ProductionCustodyRequired + fixture custody => ProductionCustodyUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedProductionUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R7_local_under_production_required_unavailable",
            note: "ProductionCustodyRequired + local-operator custody => ProductionCustodyUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedProductionUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R8_fixture_on_mainnet_rejected",
            note: "fixture custody on MainNet => FixtureCustodyRejectedForMainNet (peer-drain refuses ahead)",
            selector: Selector::CliOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Mainnet,
            carrier: PresentWithEnv {
                class: FixtureLocalKey,
                attestation_env: Mainnet,
            },
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedFixtureOnMainNet),
            peer_drain_mainnet: true,
        },
        Scenario {
            id: "R9_local_on_mainnet_rejected",
            note: "local-operator custody on MainNet => LocalCustodyRejectedForMainNet",
            selector: Selector::CliOnly("devnet-local-allowed"),
            expected_policy: Some(DevnetLocalAllowed),
            expected_parse_error: false,
            env: Mainnet,
            carrier: PresentWithEnv {
                class: LocalOperatorKey,
                attestation_env: Mainnet,
            },
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedLocalOnMainNet),
            peer_drain_mainnet: true,
        },
        Scenario {
            id: "R10_devnet_local_under_testnet_local_allowed_refuses_class",
            note: "TestnetLocalAllowed + DevNet local-operator => PolicyRefusesCustodyClass",
            selector: Selector::CliOnly("testnet-local-allowed"),
            expected_policy: Some(TestnetLocalAllowed),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedPolicyRefusesClass),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R11_testnet_local_under_devnet_local_allowed_refuses_class",
            note: "DevnetLocalAllowed + TestNet local-operator => PolicyRefusesCustodyClass",
            selector: Selector::CliOnly("devnet-local-allowed"),
            expected_policy: Some(DevnetLocalAllowed),
            expected_parse_error: false,
            env: Testnet,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedPolicyRefusesClass),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R12_kms_under_production_required_unavailable",
            note: "ProductionCustodyRequired + KMS placeholder => KmsUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(Kms),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedKmsUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R13_hsm_under_production_required_unavailable",
            note: "ProductionCustodyRequired + HSM placeholder => HsmUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(Hsm),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedHsmUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R14_remote_signer_under_production_required_unavailable",
            note: "ProductionCustodyRequired + RemoteSigner placeholder => RemoteSignerUnavailable",
            selector: Selector::CliOnly("production-custody-required"),
            expected_policy: Some(ProductionCustodyRequired),
            expected_parse_error: false,
            env: Devnet,
            carrier: Present(RemoteSigner),
            surfaces: SurfaceSet::All,
            expected: Some(Expect::CallsiteCustodyRejectedRemoteSignerUnavailable),
            peer_drain_mainnet: false,
        },
        Scenario {
            id: "R15_malformed_custody_metadata_short_circuits",
            note: "FixtureOnly + malformed JSON sibling => MalformedAuthorityCustodyAttestationPayload",
            selector: Selector::CliOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Devnet,
            carrier: Carrier::MalformedJson,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::MalformedAuthorityCustodyAttestationPayload),
            peer_drain_mainnet: false,
        },
        // R28 — invalid live 0x05 candidate not propagated/staged/applied:
        // exercised by the MalformedJson scenario above on the
        // LiveInbound0x05 surface, which short-circuits at the Run 190
        // routing helper without staging. Recorded explicitly.
        Scenario {
            id: "R28_live_0x05_invalid_candidate_short_circuits",
            note: "live 0x05 surface short-circuits malformed custody payload before staging",
            selector: Selector::CliOnly("fixture-only"),
            expected_policy: Some(FixtureOnly),
            expected_parse_error: false,
            env: Devnet,
            carrier: Carrier::MalformedJson,
            surfaces: SurfaceSet::All,
            expected: Some(Expect::MalformedAuthorityCustodyAttestationPayload),
            peer_drain_mainnet: false,
        },
        // R29 — MainNet peer-driven apply remains refused even with
        // mainnet-production-custody-required and metadata claiming
        // KMS/HSM.
        Scenario {
            id: "R29_mainnet_peer_drain_refused_with_kms_metadata",
            note: "MainNet peer-driven drain refuses regardless of KMS custody metadata under mainnet-production-custody-required",
            selector: Selector::EnvOnly("mainnet-production-custody-required"),
            expected_policy: Some(MainnetProductionCustodyRequired),
            expected_parse_error: false,
            env: Mainnet,
            carrier: PresentWithEnv {
                class: Kms,
                attestation_env: Mainnet,
            },
            surfaces: SurfaceSet::PeerDrivenDrainOnly,
            expected: Some(Expect::MainNetPeerDrivenApplyRefused),
            peer_drain_mainnet: true,
        },
    ]
}

fn build_loaded(scn: &Scenario) -> AuthorityCustodyLoadStatus {
    match &scn.carrier {
        Carrier::Absent => loaded_absent(),
        Carrier::Present(class) => {
            let cand = rotate_candidate(scn.env);
            let att = good_attestation(scn.env, &cand, *class);
            loaded_for(&att)
        }
        Carrier::PresentWithEnv {
            class,
            attestation_env,
        } => {
            let cand = rotate_candidate(scn.env);
            let mut att = good_attestation(scn.env, &cand, *class);
            att.environment = *attestation_env;
            loaded_for(&att)
        }
        Carrier::MalformedJson => loaded_malformed_json(),
    }
}

fn run_scenarios(
    out_dir: &Path,
    manifest: &mut String,
    expected_buf: &mut String,
    actual_buf: &mut String,
) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let scenarios = corpus();
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;

    for scn in &scenarios {
        let scn_dir = scenarios_dir.join(scn.id);
        fs::create_dir_all(&scn_dir)?;
        fs::write(scn_dir.join("note.txt"), format!("{}\n", scn.note))?;
        fs::write(
            scn_dir.join("expected.txt"),
            format!(
                "selector_expected_policy={:?} parse_error={} routing_expected={:?} peer_drain_mainnet={}\n",
                scn.expected_policy, scn.expected_parse_error, scn.expected, scn.peer_drain_mainnet
            ),
        )?;

        // Step 1: resolve selector via Run 192 production library symbols.
        let selector_outcome = resolve_selector(&scn.selector);
        let sel_actual: String;
        let selector_match = match (&selector_outcome, &scn.expected_policy, scn.expected_parse_error) {
            (SelectorOutcome::Resolved(p), Some(want), false) => {
                sel_actual = format!("Resolved({:?})", p);
                p == want
            }
            (SelectorOutcome::ParseError(e), None, true) => {
                sel_actual = format!("ParseError({:?})", e);
                true
            }
            (SelectorOutcome::Resolved(p), _, true) => {
                sel_actual = format!("Resolved({:?}) (UNEXPECTED — expected parse error)", p);
                false
            }
            (SelectorOutcome::ParseError(e), _, false) => {
                sel_actual = format!("ParseError({:?}) (UNEXPECTED — expected resolved)", e);
                false
            }
            (SelectorOutcome::Resolved(p), None, false) => {
                sel_actual = format!("Resolved({:?}) (UNEXPECTED — no expected policy and no parse error)", p);
                false
            }
            (SelectorOutcome::ParseError(e), Some(_), true) => {
                sel_actual = format!("ParseError({:?}) (UNEXPECTED — expected both resolved and parse error)", e);
                false
            }
        };
        fs::write(scn_dir.join("policy.txt"), format!("{}\n", sel_actual))?;
        if selector_match {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-193-helper] FAIL selector resolution: {}", scn.id);
        }

        // Step 2: if selector failed-as-expected (parse error), there is
        // no routing dispatch — record and continue.
        let policy = match &selector_outcome {
            SelectorOutcome::Resolved(p) => *p,
            SelectorOutcome::ParseError(_) => {
                let line = format!(
                    "{}\tselector\t{}\tmatch={}\n",
                    scn.id, sel_actual, selector_match
                );
                manifest.push_str(&line);
                expected_buf.push_str(&format!(
                    "{}\tselector\texpected_parse_error={}\texpected_policy={:?}\n",
                    scn.id, scn.expected_parse_error, scn.expected_policy
                ));
                actual_buf.push_str(&format!("{}\tselector\t{}\n", scn.id, sel_actual));
                fs::write(scn_dir.join("actual.txt"), format!("{}\n", sel_actual))?;
                continue;
            }
        };

        // Step 3: dispatch through the seven Run 192 preflight wrappers.
        let cand = rotate_candidate(scn.env);
        let prior = prior_versioned(scn.env);
        let dom = domain_for(scn.env);
        let loaded = build_loaded(scn);

        let surfaces: Vec<Surface> = match scn.surfaces {
            SurfaceSet::All => Surface::ALL.to_vec(),
            SurfaceSet::PeerDrivenDrainOnly => vec![Surface::PeerDrivenDrain],
        };

        let mut actual_lines = String::new();
        actual_lines.push_str(&format!("selector\t{}\n", sel_actual));

        if let Some(want) = &scn.expected {
            for surface in surfaces {
                let outcome = surface.route(Some(&prior), &cand, &dom, policy, &loaded);
                let expected =
                    if matches!(surface, Surface::PeerDrivenDrain) && scn.peer_drain_mainnet {
                        Expect::MainNetPeerDrivenApplyRefused
                    } else {
                        want.clone()
                    };
                let m = matches_expect(&outcome, &expected);
                if m {
                    pass += 1;
                } else {
                    fail += 1;
                    eprintln!(
                        "[run-193-helper] FAIL scenario={} surface={} expected={:?} actual={:?}",
                        scn.id,
                        surface.label(),
                        expected,
                        outcome
                    );
                }
                let line = format!(
                    "{}\t{}\t{:?}\t{:?}\tmatch={}\n",
                    scn.id,
                    surface.label(),
                    expected,
                    outcome,
                    m
                );
                actual_lines.push_str(&line);
                manifest.push_str(&line);
                expected_buf.push_str(&format!(
                    "{}\t{}\t{:?}\n",
                    scn.id,
                    surface.label(),
                    expected
                ));
                actual_buf.push_str(&format!(
                    "{}\t{}\t{:?}\n",
                    scn.id,
                    surface.label(),
                    outcome
                ));
            }
        }
        fs::write(scn_dir.join("actual.txt"), actual_lines)?;
    }
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Selector parser table — direct calls into Run 192 production parsers.
// ---------------------------------------------------------------------------

fn run_selector_parser_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let cases: Vec<(&str, Result<AuthorityCustodyPolicy, &'static str>)> = vec![
        ("disabled", Ok(AuthorityCustodyPolicy::Disabled)),
        ("Disabled", Ok(AuthorityCustodyPolicy::Disabled)),
        ("  fixture-only ", Ok(AuthorityCustodyPolicy::FixtureOnly)),
        ("FIXTURE-ONLY", Ok(AuthorityCustodyPolicy::FixtureOnly)),
        ("devnet-local-allowed", Ok(AuthorityCustodyPolicy::DevnetLocalAllowed)),
        ("testnet-local-allowed", Ok(AuthorityCustodyPolicy::TestnetLocalAllowed)),
        (
            "production-custody-required",
            Ok(AuthorityCustodyPolicy::ProductionCustodyRequired),
        ),
        (
            "mainnet-production-custody-required",
            Ok(AuthorityCustodyPolicy::MainnetProductionCustodyRequired),
        ),
        ("", Err("empty")),
        ("   ", Err("empty")),
        ("not-a-policy", Err("unknown-value")),
        ("kms-required", Err("unknown-value")),
    ];

    for (input, expected) in cases {
        let actual = authority_custody_policy_from_selector(input);
        let ok = match (expected, &actual) {
            (Ok(want), Ok(got)) => &want == got,
            (Err("empty"), Err(AuthorityCustodyPolicySelectorParseError::Empty)) => true,
            (Err("unknown-value"), Err(AuthorityCustodyPolicySelectorParseError::UnknownValue { .. })) => {
                true
            }
            _ => false,
        };
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-193-helper] FAIL selector parser: input={:?} expected={:?} actual={:?}",
                input, expected, actual
            );
        }
        buf.push_str(&format!(
            "input={:?}\texpected={:?}\tactual={:?}\tok={}\n",
            input, expected, actual, ok
        ));
    }

    fs::write(out_dir.join("selector_parser_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Precedence table — CLI vs env explicit truth table.
// ---------------------------------------------------------------------------

fn run_precedence_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let key = QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV;

    // Always clear env up-front to avoid cross-test contamination.
    std::env::remove_var(key);

    let cases: Vec<(Option<&str>, Option<&str>, Result<AuthorityCustodyPolicy, &'static str>)> = vec![
        // Both unset => Disabled.
        (None, None, Ok(AuthorityCustodyPolicy::Disabled)),
        // CLI only.
        (
            Some("fixture-only"),
            None,
            Ok(AuthorityCustodyPolicy::FixtureOnly),
        ),
        // Env only.
        (
            None,
            Some("testnet-local-allowed"),
            Ok(AuthorityCustodyPolicy::TestnetLocalAllowed),
        ),
        // CLI wins over env.
        (
            Some("disabled"),
            Some("fixture-only"),
            Ok(AuthorityCustodyPolicy::Disabled),
        ),
        (
            Some("production-custody-required"),
            Some("disabled"),
            Ok(AuthorityCustodyPolicy::ProductionCustodyRequired),
        ),
        // Invalid CLI is a typed parse error even when env is valid.
        (Some("nope"), Some("fixture-only"), Err("unknown-value")),
        // Invalid env (CLI absent) is a typed parse error.
        (None, Some("nope"), Err("unknown-value")),
    ];

    for (cli, env_val, expected) in cases {
        std::env::remove_var(key);
        if let Some(v) = env_val {
            std::env::set_var(key, v);
        }
        let actual = authority_custody_policy_from_cli_or_env(cli);
        std::env::remove_var(key);
        let ok = match (expected, &actual) {
            (Ok(want), Ok(got)) => &want == got,
            (Err("unknown-value"), Err(AuthorityCustodyPolicySelectorParseError::UnknownValue { .. })) => true,
            (Err("empty"), Err(AuthorityCustodyPolicySelectorParseError::Empty)) => true,
            _ => false,
        };
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-193-helper] FAIL precedence: cli={:?} env={:?} expected={:?} actual={:?}",
                cli, env_val, expected, actual
            );
        }
        buf.push_str(&format!(
            "cli={:?}\tenv={:?}\texpected={:?}\tactual={:?}\tok={}\n",
            cli, env_val, expected, actual, ok
        ));
    }

    // Direct env-selector helper coverage.
    std::env::remove_var(key);
    let env_unset = authority_custody_policy_env_selector();
    let unset_ok = matches!(env_unset, Ok(None));
    if unset_ok { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "env_unset_returns_none\tactual={:?}\tok={}\n",
        env_unset, unset_ok
    ));
    std::env::set_var(key, "fixture-only");
    let env_set = authority_custody_policy_env_selector();
    let set_ok = matches!(env_set, Ok(Some(AuthorityCustodyPolicy::FixtureOnly)));
    if set_ok { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "env_set_fixture_only_returns_some\tactual={:?}\tok={}\n",
        env_set, set_ok
    ));
    std::env::remove_var(key);

    fs::write(out_dir.join("precedence_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Preflight wrappers table — every Run 192 preflight wrapper reaches a
// production routing decision. Smoke-level baseline accept/refusal across
// all seven surfaces.
// ---------------------------------------------------------------------------

fn run_preflight_wrappers_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    // DevNet baseline accept under FixtureOnly.
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let prior = prior_versioned(env);
    let dom = domain_for(env);
    let att = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = loaded_for(&att);

    for surface in Surface::ALL {
        let outcome = surface.route(
            Some(&prior),
            &cand,
            &dom,
            AuthorityCustodyPolicy::FixtureOnly,
            &loaded,
        );
        let accept = outcome.is_accept();
        if accept {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-193-helper] FAIL preflight wrapper accept: {}",
                surface.label()
            );
        }
        buf.push_str(&format!(
            "preflight_v2_marker_authority_custody_for_{}\taccept={}\toutcome={:?}\n",
            surface.label(),
            accept,
            outcome
        ));
    }

    // MainNet peer-driven drain refusal is layered ahead of the
    // validator regardless of policy or attestation contents.
    let mn_dom = domain_for(TrustBundleEnvironment::Mainnet);
    let mn_cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let mn_outcome = preflight_v2_marker_authority_custody_for_peer_driven_drain(
        None,
        &mn_cand,
        &mn_dom,
        AuthorityCustodyPolicy::MainnetProductionCustodyRequired,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
        &loaded,
    );
    let refused = mn_outcome.is_mainnet_peer_driven_apply_refused();
    if refused { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "preflight_v2_marker_authority_custody_for_peer_driven_drain_mainnet_refused\trefused={}\toutcome={:?}\n",
        refused, mn_outcome
    ));

    // Named helpers — explicit grep-verifiable refusal helpers.
    let mn_helper =
        mainnet_peer_driven_apply_remains_refused_under_custody_boundary(TrustBundleEnvironment::Mainnet);
    if mn_helper { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary_mainnet\tok={}\n",
        mn_helper
    ));
    let dn_helper =
        !mainnet_peer_driven_apply_remains_refused_under_custody_boundary(TrustBundleEnvironment::Devnet);
    if dn_helper { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary_devnet_false\tok={}\n",
        dn_helper
    ));
    let pmaj = peer_majority_cannot_satisfy_custody();
    if pmaj { pass += 1; } else { fail += 1; }
    buf.push_str(&format!("peer_majority_cannot_satisfy_custody\tok={}\n", pmaj));
    let local_alone = local_operator_config_alone_cannot_satisfy_mainnet_production_custody();
    if local_alone { pass += 1; } else { fail += 1; }
    buf.push_str(&format!(
        "local_operator_config_alone_cannot_satisfy_mainnet_production_custody\tok={}\n",
        local_alone
    ));

    fs::write(out_dir.join("preflight_wrappers_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Binding-mismatch table (R16–R25) — exercises the Run 188 typed validator
// directly so each binding-tuple mismatch surfaces as the typed
// `*Mismatch` / `Wrong*` outcome and never silently passes under any
// non-Disabled policy.
// ---------------------------------------------------------------------------

fn run_binding_mismatch_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let dom = domain_for(env);
    let base = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);

    let validate = |att: &AuthorityCustodyAttestation| -> AuthorityCustodyValidationOutcome {
        validate_authority_custody_attestation(
            att,
            &cand,
            &dom,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            NOW,
        )
    };

    let mut record = |label: &str, ok: bool, outcome: &AuthorityCustodyValidationOutcome| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-193-helper] FAIL binding mismatch: {} actual={:?}",
                label, outcome
            );
        }
        buf.push_str(&format!("{}\tok={}\toutcome={:?}\n", label, ok, outcome));
    };

    // R16 wrong environment.
    {
        let mut a = base.clone();
        a.environment = TrustBundleEnvironment::Testnet;
        let o = validate(&a);
        record(
            "R16_wrong_environment",
            matches!(o, AuthorityCustodyValidationOutcome::WrongEnvironment { .. }),
            &o,
        );
    }
    // R17 wrong chain.
    {
        let mut a = base.clone();
        a.chain_id = "ffffffffffffffff".to_string();
        let o = validate(&a);
        record(
            "R17_wrong_chain",
            matches!(o, AuthorityCustodyValidationOutcome::WrongChain { .. }),
            &o,
        );
    }
    // R18 wrong genesis.
    {
        let mut a = base.clone();
        a.genesis_hash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let o = validate(&a);
        record(
            "R18_wrong_genesis",
            matches!(o, AuthorityCustodyValidationOutcome::WrongGenesis { .. }),
            &o,
        );
    }
    // R19 wrong authority root.
    {
        let mut a = base.clone();
        a.authority_root_fingerprint = "ffffffffffffffffffffffffffffffffffffffff".to_string();
        let o = validate(&a);
        record(
            "R19_wrong_authority_root",
            matches!(o, AuthorityCustodyValidationOutcome::WrongAuthorityRoot { .. }),
            &o,
        );
    }
    // R20 wrong signing-key fingerprint.
    {
        let mut a = base.clone();
        a.bundle_signing_key_fingerprint = KEY_A.to_string();
        let o = validate(&a);
        record(
            "R20_wrong_signing_key_fingerprint",
            matches!(o, AuthorityCustodyValidationOutcome::WrongSigningKeyFingerprint { .. }),
            &o,
        );
    }
    // R21 wrong candidate digest.
    {
        let mut a = base.clone();
        a.candidate_digest = PRIOR_DIGEST.to_string();
        let o = validate(&a);
        record(
            "R21_wrong_candidate_digest",
            matches!(o, AuthorityCustodyValidationOutcome::WrongCandidateDigest { .. }),
            &o,
        );
    }
    // R22 wrong authority-domain sequence.
    {
        let mut a = base.clone();
        a.authority_domain_sequence = 99;
        let o = validate(&a);
        record(
            "R22_wrong_authority_domain_sequence",
            matches!(o, AuthorityCustodyValidationOutcome::WrongAuthorityDomainSequence { .. }),
            &o,
        );
    }
    // R23 expired attestation.
    {
        let mut a = base.clone();
        a.expires_at_unix = Some(NOW - 1);
        let o = validate(&a);
        record(
            "R23_expired_attestation",
            matches!(o, AuthorityCustodyValidationOutcome::CustodyAttestationExpired { .. }),
            &o,
        );
    }
    // R24 custody-key-id mismatch.
    {
        let mut a = base.clone();
        a.custody_key_id = "different-key-id".to_string();
        let o = validate(&a);
        record(
            "R24_custody_key_id_mismatch",
            matches!(o, AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch { .. }),
            &o,
        );
    }
    // R25 unsupported custody suite.
    {
        let mut a = base.clone();
        a.custody_suite_id = 0xFE;
        let o = validate(&a);
        record(
            "R25_unsupported_custody_suite",
            matches!(o, AuthorityCustodyValidationOutcome::UnsupportedCustodySuite { .. }),
            &o,
        );
    }

    fs::write(out_dir.join("binding_mismatch_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// No-mutation evidence: a rejecting routing pass (KMS under
// ProductionCustodyRequired) leaves every input bit-equal — no marker write,
// no sequence write, no live trust swap, no session eviction, no Run 070
// call. R26/R27 are reflected here.
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let cand_before = cand.clone();
    let prior = prior_versioned(env);
    let prior_before = prior.clone();
    let dom = domain_for(env);
    let dom_before = dom.clone();
    let att = good_attestation(env, &cand, AuthorityCustodyClass::Kms);
    let att_before = att.clone();
    let loaded = loaded_for(&att);
    let loaded_before = loaded.clone();

    let mut outcomes = Vec::new();
    for surface in Surface::ALL {
        outcomes.push((
            surface.label(),
            surface.route(
                Some(&prior),
                &cand,
                &dom,
                AuthorityCustodyPolicy::ProductionCustodyRequired,
                &loaded,
            ),
        ));
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-193-helper] FAIL no-mutation invariant: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    let all_reject = outcomes.iter().all(|(_, o)| o.is_reject());
    record(
        "all_surfaces_reject_kms_under_production_required",
        all_reject,
    );
    record("candidate_unchanged_after_rejection", cand == cand_before);
    record("prior_unchanged_after_rejection", prior == prior_before);
    record("trust_domain_unchanged_after_rejection", dom == dom_before);
    record("attestation_unchanged_after_rejection", att == att_before);
    record("loaded_status_unchanged_after_rejection", loaded == loaded_before);

    for (label, outcome) in &outcomes {
        buf.push_str(&format!("surface_outcome\t{}\t{:?}\n", label, outcome));
    }
    fs::write(out_dir.join("no_mutation_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Determinism: 32 dispatches of the accepted DevNet fixture scenario yield
// identical Accept outcome on every Run 192 preflight wrapper.
// ---------------------------------------------------------------------------

fn run_determinism_check(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let prior = prior_versioned(env);
    let dom = domain_for(env);
    let att = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = loaded_for(&att);

    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;

    for surface in Surface::ALL {
        let mut samples = Vec::new();
        for _ in 0..32 {
            samples.push(surface.route(
                Some(&prior),
                &cand,
                &dom,
                AuthorityCustodyPolicy::FixtureOnly,
                &loaded,
            ));
        }
        let first = samples[0].clone();
        let all_eq = samples.iter().all(|o| *o == first);
        let first_accept = first.is_accept();
        let ok = all_eq && first_accept;
        if ok { pass += 1; } else { fail += 1; }
        buf.push_str(&format!(
            "surface\t{}\tsamples=32\tall_equal={}\tfirst_accept={}\tsample={:?}\n",
            surface.label(),
            all_eq,
            first_accept,
            first
        ));
    }

    fs::write(out_dir.join("determinism_evidence.txt"), buf)?;
    Ok((pass, fail))
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
                "usage: run_193_authority_custody_policy_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).expect("create out_dir");

    // Always start with a clean env so neither helper run nor parent
    // shell pollutes the selector under test. The scenarios manage the
    // env var explicitly.
    std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV);

    let mut manifest = String::new();
    let mut expected_buf = String::new();
    let mut actual_buf = String::new();

    let (s_pass, s_fail) = run_scenarios(
        &out_dir,
        &mut manifest,
        &mut expected_buf,
        &mut actual_buf,
    )
    .expect("scenario corpus");
    let (p_pass, p_fail) =
        run_selector_parser_table(&out_dir).expect("selector parser table");
    let (c_pass, c_fail) = run_precedence_table(&out_dir).expect("precedence table");
    let (w_pass, w_fail) =
        run_preflight_wrappers_table(&out_dir).expect("preflight wrappers table");
    let (b_pass, b_fail) = run_binding_mismatch_table(&out_dir).expect("binding mismatch table");
    let (n_pass, n_fail) = run_no_mutation_evidence(&out_dir).expect("no mutation evidence");
    let (d_pass, d_fail) = run_determinism_check(&out_dir).expect("determinism check");

    fs::write(out_dir.join("manifest.txt"), &manifest).expect("write manifest");
    fs::write(out_dir.join("expected_outcomes.txt"), &expected_buf).expect("write expected");
    fs::write(out_dir.join("actual_outcomes.txt"), &actual_buf).expect("write actual");

    let total_pass = s_pass + p_pass + c_pass + w_pass + b_pass + n_pass + d_pass;
    let total_fail = s_fail + p_fail + c_fail + w_fail + b_fail + n_fail + d_fail;
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };

    let mut summary = fs::File::create(out_dir.join("helper_summary.txt"))
        .expect("create helper_summary.txt");
    writeln!(
        summary,
        "Run 193 helper - release-mode authority-custody policy selector corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(summary, "total_pass: {}\ntotal_fail: {}", total_pass, total_fail).unwrap();
    writeln!(summary, "scenarios_pass: {}\nscenarios_fail: {}", s_pass, s_fail).unwrap();
    writeln!(summary, "parser_pass: {}\nparser_fail: {}", p_pass, p_fail).unwrap();
    writeln!(summary, "precedence_pass: {}\nprecedence_fail: {}", c_pass, c_fail).unwrap();
    writeln!(summary, "wrappers_pass: {}\nwrappers_fail: {}", w_pass, w_fail).unwrap();
    writeln!(
        summary,
        "binding_mismatch_pass: {}\nbinding_mismatch_fail: {}",
        b_pass, b_fail
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
        "qbind_node::pqc_authority_custody_policy_surface::QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV",
        "qbind_node::pqc_authority_custody_policy_surface::AuthorityCustodyPolicySelectorParseError",
        "qbind_node::pqc_authority_custody_policy_surface::authority_custody_policy_from_selector",
        "qbind_node::pqc_authority_custody_policy_surface::authority_custody_policy_env_selector",
        "qbind_node::pqc_authority_custody_policy_surface::authority_custody_policy_from_cli_or_env",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_reload_check",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_reload_apply",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_sighup",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_local_peer_candidate_check",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_live_inbound_0x05",
        "qbind_node::pqc_authority_custody_policy_surface::preflight_v2_marker_authority_custody_for_peer_driven_drain",
        "qbind_node::pqc_authority_custody_payload_carrying::parse_optional_authority_custody_attestation_sibling_from_json_value",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyAttestationWire",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyLoadStatus",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyPayloadCarryingDecisionOutcome",
        "qbind_node::pqc_authority_custody::AuthorityCustodyPolicy",
        "qbind_node::pqc_authority_custody::AuthorityCustodyClass",
        "qbind_node::pqc_authority_custody::validate_authority_custody_attestation",
        "qbind_node::pqc_authority_custody::AuthorityCustodyValidationOutcome",
        "qbind_node::pqc_authority_custody::LifecycleGovernanceCustodyOutcome",
        "qbind_node::pqc_authority_custody::mainnet_peer_driven_apply_remains_refused_under_custody_boundary",
        "qbind_node::pqc_authority_custody::peer_majority_cannot_satisfy_custody",
        "qbind_node::pqc_authority_custody::local_operator_config_alone_cannot_satisfy_mainnet_production_custody",
    ] {
        writeln!(summary, "  - {}", s).unwrap();
    }
    writeln!(summary, "honest_limits:").unwrap();
    for line in &[
        "default AuthorityCustodyPolicy::Disabled preserved when CLI and env are both absent",
        "hidden CLI flag --p2p-trust-bundle-authority-custody-policy is hidden from --help",
        "env QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY activates the selector when set",
        "CLI-over-env precedence is deterministic",
        "invalid selector values surface as typed AuthorityCustodyPolicySelectorParseError",
        "fixture/local custody remains DevNet/TestNet evidence-only",
        "fixture/local custody cannot satisfy MainNet production custody",
        "RemoteSigner / Kms / Hsm placeholders fail closed regardless of policy or environment",
        "MainNet peer-driven apply remains refused (Run 147 FATAL invariant)",
        "no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend is wired",
        "no real on-chain governance proof verifier / no governance execution / no validator-set rotation",
        "no schema/wire/metric drift in Run 193 (release-binary evidence only)",
    ] {
        writeln!(summary, "  - {}", line).unwrap();
    }

    if total_fail != 0 {
        eprintln!(
            "[run-193-helper] FAIL total_pass={} total_fail={}",
            total_pass, total_fail
        );
        std::process::exit(1);
    }
}